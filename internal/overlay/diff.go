package overlay

import (
	"slices"
	"strings"
)

// Action is what applying a manifest does to one path.
type Action string

const (
	ActionCreate Action = "create"
	ActionUpdate Action = "update" // content, kind or symlink target changed
	ActionMeta   Action = "meta"   // only mode, ownership, label or secrecy changed
	ActionRemove Action = "remove"
)

// Change is one planned or applied change. Old is nil for creates and New is
// nil for removes.
type Change struct {
	Action Action `json:"action"`
	Path   string `json:"path"`
	Old    *Entry `json:"old,omitempty"`
	New    *Entry `json:"new,omitempty"`
}

// Diff plans the transition from old to new at the manifest level, without
// looking at the node. Removals come first, deepest path first, so a
// directory empties before it is removed or replaced by a file; writes follow
// in path order so parents exist before children.
func Diff(old, new Manifest) []Change {
	var removes, writes []Change
	for p, o := range old.Entries {
		if _, ok := new.Entries[p]; !ok {
			removes = append(removes, Change{Action: ActionRemove, Path: p, Old: &o})
		}
	}
	for p, n := range new.Entries {
		o, ok := old.Entries[p]
		switch {
		case !ok:
			writes = append(writes, Change{Action: ActionCreate, Path: p, New: &n})
		case o.Kind != n.Kind || o.Digest != n.Digest || o.Target != n.Target:
			writes = append(writes, Change{Action: ActionUpdate, Path: p, Old: &o, New: &n})
		case o.mode() != n.mode() || o.UID != n.UID || o.GID != n.GID || o.Owner != n.Owner || o.Group != n.Group || o.SEContext != n.SEContext || o.Secret != n.Secret:
			writes = append(writes, Change{Action: ActionMeta, Path: p, Old: &o, New: &n})
		}
	}
	slices.SortFunc(removes, func(a, b Change) int { return strings.Compare(b.Path, a.Path) })
	slices.SortFunc(writes, func(a, b Change) int { return strings.Compare(a.Path, b.Path) })
	return append(removes, writes...)
}
