package overlay

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
)

const (
	appliedFile = "applied.json"
	pendingFile = "pending.json"
	hooksFile   = "hooks.json"
)

// State persists, on the node, the manifest last applied, so the next
// generation knows what to remove. An apply is bracketed by Begin and Commit.
// If the agent dies in between, Load returns the union of the applied and
// pending manifests, so anything the interrupted apply may have written is
// still removed when a later generation drops it.
type State struct {
	Dir string
}

// Load returns the manifest to pass as old to Applier.Apply.
func (s State) Load() (Manifest, error) {
	applied, err := s.read(appliedFile)
	if err != nil {
		return Manifest{}, err
	}
	pending, err := s.read(pendingFile)
	if err != nil {
		return Manifest{}, err
	}
	for p, e := range pending.Entries {
		applied.Entries[p] = e
	}
	for _, d := range pending.Exclusive {
		if !slices.Contains(applied.Exclusive, d) {
			applied.Exclusive = append(applied.Exclusive, d)
		}
	}
	return applied, nil
}

// Begin records next as in flight before it is applied.
func (s State) Begin(next Manifest) error { return s.write(pendingFile, next) }

// Commit records m as applied and clears the in-flight record.
func (s State) Commit(m Manifest) error {
	if err := s.write(appliedFile, m); err != nil {
		return err
	}
	err := os.Remove(filepath.Join(s.Dir, pendingFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// Hooks returns the hooks owed by earlier applies: their files were
// written, but the apply stopped (an error, or the agent died) before the
// hooks ran. A retry finds those files already in place, so it does not see
// them as changes; without this record their hooks would never run.
func (s State) Hooks() ([]string, error) {
	var h []string
	b, err := os.ReadFile(filepath.Join(s.Dir, hooksFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return h, json.Unmarshal(b, &h)
}

// OweHooks adds hooks to those owed. The agent calls it as soon as an apply
// returns, before anything can fail, and runs the owed hooks once an apply
// completes.
func (s State) OweHooks(hooks []string) error {
	if len(hooks) == 0 {
		return nil
	}
	owed, err := s.Hooks()
	if err != nil {
		return err
	}
	for _, h := range hooks {
		if !slices.Contains(owed, h) {
			owed = append(owed, h)
		}
	}
	return s.write(hooksFile, owed)
}

// PaidHooks clears the owed hooks once they have run.
func (s State) PaidHooks() error {
	err := os.Remove(filepath.Join(s.Dir, hooksFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func (s State) read(name string) (Manifest, error) {
	m := Manifest{Entries: map[string]Entry{}}
	b, err := os.ReadFile(filepath.Join(s.Dir, name))
	if errors.Is(err, fs.ErrNotExist) {
		return m, nil
	} else if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, err
	}
	if m.Entries == nil {
		m.Entries = map[string]Entry{}
	}
	return m, nil
}

func (s State) write(name string, m any) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.Dir, "."+name+"-*")
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
	return os.Rename(f.Name(), filepath.Join(s.Dir, name))
}
