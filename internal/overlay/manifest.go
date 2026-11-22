// Package overlay defines Flapjack overlay manifests and the node-side
// reconciler that applies them.
//
// Unlike Warewulf's wwclient, which only ever writes files, the reconciler
// tracks what it owns. A manifest is the complete set of paths an overlay
// generation manages; applying generation N+1 over N writes what changed and
// removes what left the overlay, restoring the booted image's version of a
// path when the overlay had been shadowing one.
package overlay

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"strconv"
	"strings"
)

// Kind is the type of filesystem object an entry manages.
type Kind string

const (
	KindFile    Kind = "file"
	KindDir     Kind = "dir"
	KindSymlink Kind = "symlink"
)

// Policy decides who owns an entry's content once Flapjack has written it.
type Policy string

const (
	// PolicyEnforce: Flapjack owns the content. Local edits are drift and are
	// reverted on apply; the path is removed when it leaves the overlay even
	// if it was edited locally. This is the default.
	PolicyEnforce Policy = "enforce"
	// PolicyReport: local edits are reported as drift but kept until the
	// overlay itself changes the file. Edited files survive removal.
	PolicyReport Policy = "report"
	// PolicySeed: written only when absent (or still untouched since
	// Flapjack wrote it); the node owns it afterwards.
	PolicySeed Policy = "seed"
)

// Mode holds Unix permission bits including setuid, setgid and sticky.
// It is encoded in JSON as an octal string such as "0644".
type Mode uint32

func (m Mode) String() string { return fmt.Sprintf("%04o", uint32(m)) }

func (m Mode) MarshalJSON() ([]byte, error) { return json.Marshal(m.String()) }

func (m *Mode) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("mode must be an octal string: %w", err)
	}
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil || v > 0o7777 {
		return fmt.Errorf("invalid mode %q", s)
	}
	*m = Mode(v)
	return nil
}

func (m Mode) fileMode() fs.FileMode {
	fm := fs.FileMode(m & 0o777)
	if m&0o4000 != 0 {
		fm |= fs.ModeSetuid
	}
	if m&0o2000 != 0 {
		fm |= fs.ModeSetgid
	}
	if m&0o1000 != 0 {
		fm |= fs.ModeSticky
	}
	return fm
}

func modeOf(fm fs.FileMode) Mode {
	m := Mode(fm.Perm())
	if fm&fs.ModeSetuid != 0 {
		m |= 0o4000
	}
	if fm&fs.ModeSetgid != 0 {
		m |= 0o2000
	}
	if fm&fs.ModeSticky != 0 {
		m |= 0o1000
	}
	return m
}

// Entry describes one managed path. Entries are produced by an overlay
// engine (Go template or Nix) and are engine-agnostic from here on.
type Entry struct {
	Kind   Kind   `json:"kind"`
	Digest string `json:"digest,omitempty"` // "sha256:<hex>" of the content; files only
	Target string `json:"target,omitempty"` // symlinks only
	Mode   Mode   `json:"mode,omitempty"`   // defaults to 0644 for files, 0755 for dirs
	UID    int    `json:"uid,omitempty"`
	GID    int    `json:"gid,omitempty"`
	// Owner and Group name the owner when the numeric IDs differ between
	// image and node (system users created at install time). The agent
	// resolves them against the node's /etc/passwd and /etc/group before
	// applying; they take precedence over UID and GID.
	Owner string `json:"owner,omitempty"`
	Group string `json:"group,omitempty"`
	// SEContext is the SELinux label for the path. It is recorded in the
	// manifest but not yet applied by the reconciler.
	SEContext string   `json:"seContext,omitempty"`
	Policy    Policy   `json:"policy,omitempty"`
	OnChange  []string `json:"onChange,omitempty"` // hook commands run after the path is written
	OnRemove  []string `json:"onRemove,omitempty"` // hook commands run after the path is removed
	// Overlay names the source overlay that produced the entry, so drift and
	// diffs can say where a path comes from. It does not affect the node.
	Overlay string `json:"overlay,omitempty"`
	// Secret says the content comes from the secrets directory. It is only
	// ever served sealed to the node (pki.Seal), so relays and their caches
	// never hold it in the clear.
	Secret bool `json:"secret,omitempty"`
}

func (e Entry) policy() Policy {
	if e.Policy == "" {
		return PolicyEnforce
	}
	return e.Policy
}

// EffectiveMode is the mode the entry is applied with: its own, or 0644 for
// files and 0755 for directories when unset.
func (e Entry) EffectiveMode() Mode { return e.mode() }

func (e Entry) mode() Mode {
	switch {
	case e.Mode != 0:
		return e.Mode
	case e.Kind == KindDir:
		return 0o755
	default:
		return 0o644
	}
}

// Manifest is the full set of paths one overlay generation manages on a node.
type Manifest struct {
	Generation uint64           `json:"generation"`
	Entries    map[string]Entry `json:"entries"`
	// Exclusive lists directories whose contents must be exactly what the
	// manifest declares; anything else found in them is deleted on apply.
	Exclusive []string `json:"exclusive,omitempty"`
}

// Validate checks that every path is absolute and clean and every entry is
// well formed. Exclusive directories must be at least two levels deep so a
// typo cannot wipe /etc or /usr.
func (m Manifest) Validate() error {
	for p, e := range m.Entries {
		if err := checkPath(p); err != nil {
			return err
		}
		switch e.Kind {
		case KindFile:
			if !strings.HasPrefix(e.Digest, "sha256:") {
				return fmt.Errorf("%s: file entry needs a sha256 digest", p)
			}
		case KindSymlink:
			if e.Target == "" {
				return fmt.Errorf("%s: symlink entry needs a target", p)
			}
		case KindDir:
		default:
			return fmt.Errorf("%s: unknown kind %q", p, e.Kind)
		}
		switch e.Policy {
		case "", PolicyEnforce, PolicyReport, PolicySeed:
		default:
			return fmt.Errorf("%s: unknown policy %q", p, e.Policy)
		}
	}
	for _, d := range m.Exclusive {
		if err := checkPath(d); err != nil {
			return err
		}
		if strings.Count(d, "/") < 2 {
			return fmt.Errorf("exclusive directory %s is too shallow", d)
		}
	}
	return nil
}

func checkPath(p string) error {
	if !path.IsAbs(p) || path.Clean(p) != p || p == "/" {
		return fmt.Errorf("invalid managed path %q: must be absolute, clean and not /", p)
	}
	return nil
}
