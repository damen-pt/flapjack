// Package gens keeps each node's overlay generations, the way NixOS keeps
// system generations: every switch that changes what a node should have
// records a new numbered, immutable generation, and the node's current
// generation is a pointer that can move back (rollback) or forward without
// rebuilding anything.
package gens

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/damen-pt/flapjack/internal/overlay"
)

// Generation is one immutable overlay state for a node.
type Generation struct {
	Number   int              `json:"number"`
	Created  time.Time        `json:"created"`
	Digest   string           `json:"digest"` // overlay.ManifestDigest
	Actor    string           `json:"actor,omitempty"`
	Message  string           `json:"message,omitempty"`
	Overlays []string         `json:"overlays,omitempty"`
	Manifest overlay.Manifest `json:"manifest"`
}

// Summary is a generation without its manifest, for listings.
type Summary struct {
	Number   int       `json:"number"`
	Created  time.Time `json:"created"`
	Digest   string    `json:"digest"`
	Actor    string    `json:"actor,omitempty"`
	Message  string    `json:"message,omitempty"`
	Overlays []string  `json:"overlays,omitempty"`
	Paths    int       `json:"paths"`
	Current  bool      `json:"current"`
}

// ErrNone is returned for a node with no generations.
var ErrNone = errors.New("no generations")

// Store keeps generations under Dir/<node>/<number>.json, with the current
// number in Dir/<node>/current.
//
// Each node's current generation is cached in memory once read, since
// agents and tentacles ask for it on every request. The returned
// manifest is shared: callers must not modify it.
type Store struct {
	Dir string
	mu  sync.Mutex
	cur map[string]Generation // dir → current generation
}

func (s *Store) remember(dir string, g Generation) {
	if s.cur == nil {
		s.cur = map[string]Generation{}
	}
	s.cur[dir] = g
}

func (s *Store) nodeDir(node string) (string, error) {
	if node == "" || strings.ContainsAny(node, `/\`) || strings.HasPrefix(node, ".") {
		return "", fmt.Errorf("invalid node name %q", node)
	}
	return filepath.Join(s.Dir, node), nil
}

// Add records m as a new generation and makes it current, unless it is
// identical to the current generation; changed reports which.
func (s *Store) Add(node string, m overlay.Manifest, actor, message string, overlays []string) (g Generation, changed bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dir, err := s.nodeDir(node)
	if err != nil {
		return g, false, err
	}
	digest := overlay.ManifestDigest(m)
	if cur, err := s.current(dir); err == nil && cur.Digest == digest {
		return cur, false, nil
	} else if err != nil && !errors.Is(err, ErrNone) {
		return g, false, err
	}
	nums, err := numbers(dir)
	if err != nil {
		return g, false, err
	}
	next := 1
	if len(nums) > 0 {
		next = nums[len(nums)-1] + 1
	}
	m.Generation = uint64(next)
	g = Generation{Number: next, Created: time.Now().UTC(), Digest: digest, Actor: actor, Message: message, Overlays: overlays, Manifest: m}
	b, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return g, false, err
	}
	if err := writeAtomic(filepath.Join(dir, strconv.Itoa(next)+".json"), b); err != nil {
		return g, false, err
	}
	delete(s.cur, dir)
	if err := writeAtomic(filepath.Join(dir, "current"), []byte(strconv.Itoa(next)+"\n")); err != nil {
		return g, true, err
	}
	s.remember(dir, g)
	return g, true, nil
}

// Current returns the node's current generation.
func (s *Store) Current(node string) (Generation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dir, err := s.nodeDir(node)
	if err != nil {
		return Generation{}, err
	}
	return s.current(dir)
}

func (s *Store) current(dir string) (Generation, error) {
	if g, ok := s.cur[dir]; ok {
		return g, nil
	}
	b, err := os.ReadFile(filepath.Join(dir, "current"))
	if errors.Is(err, fs.ErrNotExist) {
		return Generation{}, ErrNone
	} else if err != nil {
		return Generation{}, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return Generation{}, err
	}
	g, err := read(dir, n)
	if err == nil {
		s.remember(dir, g)
	}
	return g, err
}

// Get returns generation n.
func (s *Store) Get(node string, n int) (Generation, error) {
	dir, err := s.nodeDir(node)
	if err != nil {
		return Generation{}, err
	}
	return read(dir, n)
}

// List returns the node's generations, oldest first.
func (s *Store) List(node string) ([]Summary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dir, err := s.nodeDir(node)
	if err != nil {
		return nil, err
	}
	nums, err := numbers(dir)
	if err != nil {
		return nil, err
	}
	cur, _ := s.current(dir)
	var out []Summary
	for _, n := range nums {
		g, err := read(dir, n)
		if err != nil {
			return nil, err
		}
		out = append(out, Summary{Number: g.Number, Created: g.Created, Digest: g.Digest, Actor: g.Actor, Message: g.Message,
			Overlays: g.Overlays, Paths: len(g.Manifest.Entries), Current: g.Number == cur.Number})
	}
	return out, nil
}

// SetCurrent points the node at an existing generation. to == 0 means the
// generation before the current one.
func (s *Store) SetCurrent(node string, to int) (Generation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dir, err := s.nodeDir(node)
	if err != nil {
		return Generation{}, err
	}
	if to == 0 {
		cur, err := s.current(dir)
		if err != nil {
			return Generation{}, err
		}
		nums, err := numbers(dir)
		if err != nil {
			return Generation{}, err
		}
		i := slices.Index(nums, cur.Number)
		if i <= 0 {
			return Generation{}, fmt.Errorf("%s: generation %d is the oldest; nothing to roll back to", node, cur.Number)
		}
		to = nums[i-1]
	}
	g, err := read(dir, to)
	if err != nil {
		return g, err
	}
	delete(s.cur, dir)
	if err := writeAtomic(filepath.Join(dir, "current"), []byte(strconv.Itoa(to)+"\n")); err != nil {
		return g, err
	}
	s.remember(dir, g)
	return g, nil
}

func read(dir string, n int) (Generation, error) {
	var g Generation
	b, err := os.ReadFile(filepath.Join(dir, strconv.Itoa(n)+".json"))
	if errors.Is(err, fs.ErrNotExist) {
		return g, fmt.Errorf("generation %d: %w", n, fs.ErrNotExist)
	} else if err != nil {
		return g, err
	}
	if err := json.Unmarshal(b, &g); err != nil {
		return g, err
	}
	if g.Manifest.Entries == nil {
		g.Manifest.Entries = map[string]overlay.Entry{}
	}
	return g, nil
}

func numbers(dir string) ([]int, error) {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var out []int
	for _, e := range ents {
		if n, err := strconv.Atoi(strings.TrimSuffix(e.Name(), ".json")); err == nil && strings.HasSuffix(e.Name(), ".json") {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out, nil
}

func writeAtomic(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
