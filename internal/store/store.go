// Package store holds cluster state (classes and nodes) for the control
// plane, in a single JSON file.
package store

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/events"
)

// ErrNotFound is returned for unknown nodes.
var ErrNotFound = errors.New("not found")

// ErrReadOnly is returned by mutations on a store opened with OpenReadOnly.
var ErrReadOnly = errors.New("store is read-only")

type state struct {
	Classes map[string]v1.NodeClass `json:"classes"`
	Nodes   map[string]v1.Node      `json:"nodes"`
}

// Store is cluster state persisted to one file. Every phase change is
// recorded on the event log with the actor that made it.
type Store struct {
	mu     sync.RWMutex
	path   string
	st     state
	Events *events.Log

	// readOnly stores reload the file when it changes, so a long-running
	// reader (the MCP server) sees what the API server writes.
	readOnly bool
	loaded   fs.FileInfo

	// Indexes over st.Nodes, rebuilt on load and kept current by writes:
	// boot and agent requests look nodes up by MAC and IP on every call.
	byMAC map[string]string // lower-case MAC -> node
	byIP  map[string]string

	// AgentFlush is how long agent reports may wait before the state file
	// is written (default 2s). Reports are soft state that agents repeat,
	// so a thousand nodes applying a generation cost a few writes, not a
	// thousand. Every other change is written before it returns.
	AgentFlush time.Duration
	flushing   *time.Timer

	// Group commit. Each change bumps seq under mu; a writer then waits
	// for a write of the file that includes its change. One write covers
	// every change made before it took its snapshot, so a thousand nodes
	// enrolling at once cost a handful of writes, and the file is written
	// outside mu, so lookups (DHCP, boot) never wait on the disk.
	seq      uint64 // changes made; guarded by mu
	cmu      sync.Mutex
	written  *sync.Cond // signalled when a write finishes
	saving   bool
	saved    uint64 // changes on disk
	finished uint64 // writes finished, failed ones included
	lastUpto uint64 // changes the last finished write covered
	lastErr  error  // and how it went
}

func emptyState() state {
	return state{Classes: map[string]v1.NodeClass{}, Nodes: map[string]v1.Node{}}
}

// Open loads state from path, starting empty if it does not exist.
func Open(path string, log *events.Log) (*Store, error) {
	s := &Store{path: path, Events: log, st: emptyState()}
	s.written = sync.NewCond(&s.cmu)
	s.reindex()
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// OpenReadOnly opens state for reading only. Mutations fail with
// ErrReadOnly and reads pick up changes another process saves.
func OpenReadOnly(path string, log *events.Log) (*Store, error) {
	s, err := Open(path, log)
	if err != nil {
		return nil, err
	}
	s.readOnly = true
	return s, nil
}

// load reads the state file if it changed since the last load. The writer
// replaces the file atomically, so a reader never sees half a file.
// Stat-then-read can pair a new file with the old stat; the next load
// then sees a different identity and reads again, so nothing is lost.
func (s *Store) load() error {
	fi, err := os.Stat(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	// Every save renames a new file into place, so file identity changes
	// on each write even when size and mtime do not.
	if s.loaded != nil && os.SameFile(s.loaded, fi) && fi.ModTime().Equal(s.loaded.ModTime()) && fi.Size() == s.loaded.Size() {
		return nil
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	st := emptyState()
	if err := json.Unmarshal(b, &st); err != nil {
		return fmt.Errorf("%s: %w", s.path, err)
	}
	if st.Classes == nil {
		st.Classes = map[string]v1.NodeClass{}
	}
	if st.Nodes == nil {
		st.Nodes = map[string]v1.Node{}
	}
	for name, n := range st.Nodes {
		// Spare was the hot-spare phase, since removed: such a node is
		// ready to schedule.
		if n.Status.Phase == "Spare" {
			n.Status.Phase = v1.PhaseReady
			st.Nodes[name] = n
		}
	}
	s.st, s.loaded = st, fi
	s.reindex()
	return nil
}

func (s *Store) reindex() {
	s.byMAC, s.byIP = map[string]string{}, map[string]string{}
	for _, n := range s.st.Nodes {
		s.index(n)
	}
}

func (s *Store) index(n v1.Node) {
	for _, i := range n.Interfaces {
		if i.MAC != "" {
			s.byMAC[strings.ToLower(i.MAC)] = n.Name
		}
		if i.IP != "" {
			s.byIP[i.IP] = n.Name
		}
	}
}

func (s *Store) unindex(n v1.Node) {
	for _, i := range n.Interfaces {
		if k := strings.ToLower(i.MAC); i.MAC != "" && s.byMAC[k] == n.Name {
			delete(s.byMAC, k)
		}
		if i.IP != "" && s.byIP[i.IP] == n.Name {
			delete(s.byIP, i.IP)
		}
	}
}

// putNode replaces a node in the state and the indexes.
func (s *Store) putNode(n v1.Node) {
	if old, ok := s.st.Nodes[n.Name]; ok {
		s.unindex(old)
	}
	s.st.Nodes[n.Name] = n
	s.index(n)
}

// rlock takes the read lock. Read-only stores take the write lock instead
// and reload first; on a reload error they keep serving the last good state.
func (s *Store) rlock() func() {
	if s.readOnly {
		s.mu.Lock()
		s.load()
		return s.mu.Unlock
	}
	s.mu.RLock()
	return s.mu.RUnlock
}

// write saves the state as of now and returns the changes it covers. Only
// commit calls it, one at a time.
func (s *Store) write() (uint64, error) {
	s.mu.RLock()
	seq := s.seq
	b, err := json.Marshal(s.st)
	s.mu.RUnlock()
	if err != nil {
		return seq, err
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".state-*")
	if err != nil {
		return seq, err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(b); err != nil {
		f.Close()
		return seq, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return seq, err
	}
	if err := f.Close(); err != nil {
		return seq, err
	}
	return seq, os.Rename(f.Name(), s.path)
}

// commit returns once change seq is on disk, writing the file itself if
// no write is under way. It fails if a write that covered seq failed after
// commit was called; the change stays in memory, and the next write that
// succeeds saves it.
func (s *Store) commit(seq uint64) error {
	s.cmu.Lock()
	defer s.cmu.Unlock()
	start := s.finished
	for {
		switch {
		case s.saved >= seq:
			return nil
		case s.finished != start && s.lastErr != nil && s.lastUpto >= seq:
			return s.lastErr
		case !s.saving:
			s.saving = true
			s.cmu.Unlock()
			upto, err := s.write()
			s.cmu.Lock()
			s.saving = false
			s.finished++
			s.lastUpto, s.lastErr = upto, err
			if err == nil {
				s.saved = max(s.saved, upto)
			}
			s.written.Broadcast()
		default:
			s.written.Wait()
		}
	}
}

// mutate applies fn under the write lock and returns once its change is
// on disk. If fn fails nothing changes.
func (s *Store) mutate(fn func() error) error {
	s.mu.Lock()
	if s.readOnly {
		s.mu.Unlock()
		return ErrReadOnly
	}
	if err := fn(); err != nil {
		s.mu.Unlock()
		return err
	}
	s.seq++
	seq := s.seq
	s.mu.Unlock()
	return s.commit(seq)
}

// Flush writes agent reports still waiting for the coalesced write. The
// server calls it on shutdown.
func (s *Store) Flush() error {
	s.mu.Lock()
	if s.flushing != nil {
		s.flushing.Stop()
		s.flushing = nil
	}
	seq, ro := s.seq, s.readOnly
	s.mu.Unlock()
	if ro {
		return nil
	}
	return s.commit(seq)
}

// later schedules a write of the agent reports held in memory. Call it
// with mu held.
func (s *Store) later() {
	s.seq++
	if s.flushing != nil {
		return
	}
	d := s.AgentFlush
	if d <= 0 {
		d = 2 * time.Second
	}
	s.flushing = time.AfterFunc(d, func() {
		s.mu.Lock()
		s.flushing = nil
		seq := s.seq
		s.mu.Unlock()
		s.commit(seq) // a failure is retried by the next write
	})
}

// Nodes returns nodes sorted by name, optionally only those in phase.
func (s *Store) Nodes(phase v1.Phase) []v1.Node {
	defer s.rlock()()
	var out []v1.Node
	for _, n := range s.st.Nodes {
		if phase == "" || n.Status.Phase == phase {
			out = append(out, n)
		}
	}
	slices.SortFunc(out, func(a, b v1.Node) int { return cmp.Compare(a.Name, b.Name) })
	return out
}

func (s *Store) Node(name string) (v1.Node, error) {
	defer s.rlock()()
	n, ok := s.st.Nodes[name]
	if !ok {
		return v1.Node{}, fmt.Errorf("node %s: %w", name, ErrNotFound)
	}
	return n, nil
}

// NodeByMAC finds the node with an interface whose MAC is mac, and that
// interface.
func (s *Store) NodeByMAC(mac string) (v1.Node, v1.Interface, bool) {
	defer s.rlock()()
	n, ok := s.st.Nodes[s.byMAC[strings.ToLower(mac)]]
	if ok {
		for _, i := range n.Interfaces {
			if strings.EqualFold(i.MAC, mac) {
				return n, i, true
			}
		}
	}
	return v1.Node{}, v1.Interface{}, false
}

// NodeByIP finds the node with an interface addressed ip.
func (s *Store) NodeByIP(ip string) (v1.Node, bool) {
	defer s.rlock()()
	if ip == "" {
		return v1.Node{}, false
	}
	n, ok := s.st.Nodes[s.byIP[ip]]
	return n, ok
}

// ReportAgent records a node agent's report and returns the previous one.
func (s *Store) ReportAgent(name string, st v1.AgentStatus) (*v1.AgentStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readOnly {
		return nil, ErrReadOnly
	}
	n, ok := s.st.Nodes[name]
	if !ok {
		return nil, fmt.Errorf("node %s: %w", name, ErrNotFound)
	}
	prev := n.Status.Agent
	n.Status.Agent = &st
	s.st.Nodes[name] = n
	// Heartbeats only move Seen; write the file when something changed,
	// and then coalesced with other agents' reports.
	if prev == nil || prev.Applied != st.Applied || prev.Error != st.Error || !slices.Equal(prev.Drift, st.Drift) {
		s.later()
	}
	return prev, nil
}

func (s *Store) Class(name string) (v1.NodeClass, error) {
	defer s.rlock()()
	c, ok := s.st.Classes[name]
	if !ok {
		return v1.NodeClass{}, fmt.Errorf("class %s: %w", name, ErrNotFound)
	}
	return c, nil
}

// Classes returns all classes sorted by name.
func (s *Store) Classes() []v1.NodeClass {
	defer s.rlock()()
	out := slices.Collect(maps.Values(s.st.Classes))
	slices.SortFunc(out, func(a, b v1.NodeClass) int { return cmp.Compare(a.Name, b.Name) })
	return out
}

// PutClass creates or replaces a class.
func (s *Store) PutClass(c v1.NodeClass) error {
	return s.mutate(func() error {
		s.st.Classes[c.Name] = c
		return nil
	})
}

// ErrConflict is returned when a node would share a MAC or IP with another.
var ErrConflict = errors.New("conflict")

// PutNode creates or replaces a node's spec, keeping its status. MACs and
// IPs must be unique across nodes: DHCP reservations are built from them.
func (s *Store) PutNode(n v1.Node) error {
	return s.mutate(func() error {
		for _, a := range n.Interfaces {
			if o, ok := s.byMAC[strings.ToLower(a.MAC)]; a.MAC != "" && ok && o != n.Name {
				return fmt.Errorf("MAC %s already belongs to %s: %w", a.MAC, o, ErrConflict)
			}
			if o, ok := s.byIP[a.IP]; a.IP != "" && ok && o != n.Name {
				return fmt.Errorf("IP %s already belongs to %s: %w", a.IP, o, ErrConflict)
			}
		}
		if old, ok := s.st.Nodes[n.Name]; ok {
			n.Status = old.Status
		} else {
			// Identity is earned at enrollment, never declared in a spec.
			n.Status.CertsFrom, n.Status.SealKey = time.Time{}, nil
			if n.Status.Phase == "" {
				n.Status.Phase = v1.PhaseDiscovered
			}
		}
		s.putNode(n)
		return nil
	})
}

// Update applies fn to a node under the store lock, so read-modify-write
// sequences (health verdicts, enrollment) cannot race. fn may change the
// node's status; any phase change must be one the lifecycle allows. The
// events fn returns are appended once the state is saved. If fn returns
// an error nothing changes.
func (s *Store) Update(name string, fn func(n *v1.Node) ([]events.Event, error)) (v1.Node, error) {
	var old, n v1.Node
	var evs []events.Event
	err := s.mutate(func() error {
		var ok bool
		if old, ok = s.st.Nodes[name]; !ok {
			return fmt.Errorf("node %s: %w", name, ErrNotFound)
		}
		n = old
		n.Labels = maps.Clone(old.Labels)
		n.Interfaces = slices.Clone(old.Interfaces)
		var err error
		if evs, err = fn(&n); err != nil {
			return err
		}
		n.Name = name
		if !v1.CanTransition(old.Status.Phase, n.Status.Phase) {
			return fmt.Errorf("node %s cannot go from %s to %s", name, old.Status.Phase, n.Status.Phase)
		}
		s.putNode(n)
		return nil
	})
	if err != nil {
		return old, err
	}
	if s.Events != nil {
		for _, e := range evs {
			if e.Node == "" {
				e.Node = name
			}
			if err := s.Events.Append(e); err != nil {
				return n, err
			}
		}
	}
	return n, nil
}

// PhaseEvent is the timeline entry for a phase change.
func PhaseEvent(from, to v1.Phase, reason, actor string) events.Event {
	return events.Event{Category: events.Scheduler, Type: "node.phase", Actor: actor,
		Message: reason, Data: map[string]string{"from": string(from), "to": string(to)}}
}

// SetPhase moves a node to a new phase if the lifecycle allows it, and
// records who did it and why.
func (s *Store) SetPhase(name string, to v1.Phase, reason, actor string) (v1.Node, error) {
	return s.Update(name, func(n *v1.Node) ([]events.Event, error) {
		from := n.Status.Phase
		n.Status.Phase, n.Status.Reason = to, reason
		if to != from {
			n.Status.Failures = 0
		}
		return []events.Event{PhaseEvent(from, to, reason, actor)}, nil
	})
}

// Explanation answers "why is this node in this state?".
type Explanation struct {
	Node   v1.Node        `json:"node"`
	Recent []events.Event `json:"recent"`
	// PrecedingChanges are change events in the window before the node's
	// first health or hardware event in the period, most recent first.
	PrecedingChanges []events.Event `json:"precedingChanges"`
}

// Explain gathers a node's state and its timeline since since.
func (s *Store) Explain(name string, since time.Time) (Explanation, error) {
	n, err := s.Node(name)
	if err != nil {
		return Explanation{}, err
	}
	ex := Explanation{Node: n}
	if s.Events == nil {
		return ex, nil
	}
	evs, err := s.Events.Query(events.Filter{Nodes: []string{name}, Since: since})
	if err != nil {
		return ex, err
	}
	ex.Recent = evs
	first := slices.IndexFunc(evs, func(e events.Event) bool {
		return e.Category == events.Health || e.Category == events.Hardware
	})
	if first >= 0 {
		for i := first - 1; i >= 0; i-- {
			if evs[i].Category == events.Change {
				ex.PrecedingChanges = append(ex.PrecedingChanges, evs[i])
			}
		}
	}
	return ex, nil
}
