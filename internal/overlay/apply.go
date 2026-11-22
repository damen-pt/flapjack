package overlay

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"slices"
	"strings"
	"syscall"
)

// ContentStore serves overlay file content by digest.
type ContentStore interface {
	Open(digest string) (io.ReadCloser, error)
}

// Applier reconciles a node filesystem to an overlay manifest.
type Applier struct {
	// Root is the node filesystem. All access goes through os.Root, so
	// symlinks on the node cannot redirect writes or removals outside it.
	Root    *os.Root
	Content ContentStore
	// Pristine is a read-only view of the booted image. When a path leaves
	// the overlay and the image has its own version, that version is
	// restored instead of the path being deleted. In production this is the
	// image's lower layer, mounted read-only by the boot agent.
	Pristine fs.FS
	// Chown sets ownership on written paths. It requires root.
	Chown bool
}

// Skip records a path the applier deliberately left alone.
type Skip struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// Result reports what Apply did to the node.
type Result struct {
	Applied []Change `json:"applied"`
	Skipped []Skip   `json:"skipped,omitempty"`
	// Hooks are the OnChange and OnRemove commands of everything that
	// changed, de-duplicated, in the order they were first triggered.
	Hooks []string `json:"hooks,omitempty"`
}

func (r *Result) hook(cmds []string) {
	for _, c := range cmds {
		if !slices.Contains(r.Hooks, c) {
			r.Hooks = append(r.Hooks, c)
		}
	}
}

// Apply moves the node from the old manifest (what was last applied) to the
// new one. Paths only in old are removed or restored to the image version;
// every path in new is converged, so Apply(m, m) repairs drift. Apply is
// idempotent: re-running it after a failure picks up where it stopped.
func (a *Applier) Apply(old, new Manifest) (Result, error) {
	var res Result
	if err := old.Validate(); err != nil {
		return res, fmt.Errorf("previous manifest: %w", err)
	}
	if err := new.Validate(); err != nil {
		return res, err
	}
	for _, c := range Diff(old, new) {
		if c.Action != ActionRemove {
			break
		}
		if err := a.remove(c.Path, *c.Old, &res); err != nil {
			return res, fmt.Errorf("remove %s: %w", c.Path, err)
		}
	}
	for _, p := range slices.Sorted(maps.Keys(new.Entries)) {
		var prev *Entry
		if o, ok := old.Entries[p]; ok {
			prev = &o
		}
		if err := a.ensure(p, new.Entries[p], prev, &res); err != nil {
			return res, fmt.Errorf("write %s: %w", p, err)
		}
	}
	for _, d := range new.Exclusive {
		extra, err := a.unmanaged(d, new)
		if err != nil {
			return res, fmt.Errorf("prune %s: %w", d, err)
		}
		for _, p := range extra {
			if err := a.Root.RemoveAll(rel(p)); err != nil {
				return res, fmt.Errorf("prune %s: %w", p, err)
			}
			res.Applied = append(res.Applied, Change{Action: ActionRemove, Path: p})
		}
	}
	return res, nil
}

func (a *Applier) remove(p string, old Entry, res *Result) error {
	r := rel(p)
	fi, err := a.Root.Lstat(r)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if exists && old.policy() != PolicyEnforce {
		modified, err := a.differs(r, fi, old)
		if err != nil {
			return err
		}
		if modified {
			res.Skipped = append(res.Skipped, Skip{p, fmt.Sprintf("locally modified; kept under %s policy", old.policy())})
			return nil
		}
	}

	restored, err := a.restore(r, fi)
	if err != nil {
		return err
	}
	if !restored {
		if !exists {
			return nil
		}
		if err := a.Root.Remove(r); err != nil {
			if errors.Is(err, syscall.ENOTEMPTY) || errors.Is(err, syscall.EEXIST) {
				res.Skipped = append(res.Skipped, Skip{p, "directory not empty"})
				return nil
			}
			return err
		}
	}
	res.Applied = append(res.Applied, Change{Action: ActionRemove, Path: p, Old: &old})
	res.hook(old.OnRemove)
	return nil
}

// restore puts the image's version of r back in place. It reports false if
// the image has nothing at r. cur is the current on-disk info, or nil.
func (a *Applier) restore(r string, cur fs.FileInfo) (bool, error) {
	if a.Pristine == nil {
		return false, nil
	}
	pfi, err := fs.Lstat(a.Pristine, r)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	uid, gid, hasOwner := owner(pfi)
	chown := a.Chown && hasOwner

	switch {
	case pfi.IsDir():
		// Never remove a directory the image ships; on an overlayfs root that
		// would hide the image's copy.
		if cur != nil && !cur.IsDir() {
			if err := a.Root.Remove(r); err != nil {
				return false, err
			}
		}
		if err := a.Root.MkdirAll(r, 0o755); err != nil {
			return false, err
		}
		return true, a.setMeta(r, modeOf(pfi.Mode()), uid, gid, chown)
	case pfi.Mode()&fs.ModeSymlink != 0:
		target, err := fs.ReadLink(a.Pristine, r)
		if err != nil {
			return false, err
		}
		if err := a.clearDir(r, cur); err != nil {
			return false, err
		}
		return true, a.symlink(r, target, uid, gid, chown)
	default:
		f, err := a.Pristine.Open(r)
		if err != nil {
			return false, err
		}
		defer f.Close()
		if err := a.clearDir(r, cur); err != nil {
			return false, err
		}
		return true, a.writeFile(r, f, "", modeOf(pfi.Mode()), uid, gid, chown)
	}
}

func (a *Applier) ensure(p string, e Entry, prev *Entry, res *Result) error {
	r := rel(p)
	fi, err := a.Root.Lstat(r)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	action := ActionCreate
	if exists {
		action = ActionUpdate
		modified, err := a.differs(r, fi, e)
		if err != nil {
			return err
		}
		if !modified {
			if e.policy() != PolicyEnforce {
				return nil
			}
			changed, err := a.fixMeta(r, fi, e)
			if changed {
				res.Applied = append(res.Applied, Change{Action: ActionMeta, Path: p, Old: prev, New: &e})
				res.hook(e.OnChange)
			}
			return err
		}
		switch e.policy() {
		case PolicySeed:
			untouched := false
			if prev != nil {
				d, err := a.differs(r, fi, *prev)
				if err != nil {
					return err
				}
				untouched = !d
			}
			if !untouched {
				res.Skipped = append(res.Skipped, Skip{p, "seed policy; node owns content"})
				return nil
			}
		case PolicyReport:
			if prev != nil && prev.Kind == e.Kind && prev.Digest == e.Digest && prev.Target == e.Target {
				res.Skipped = append(res.Skipped, Skip{p, "locally modified; kept under report policy"})
				return nil
			}
		}
	}

	switch e.Kind {
	case KindDir:
		if exists && !fi.IsDir() {
			if err := a.Root.Remove(r); err != nil {
				return err
			}
		}
		if err := a.Root.MkdirAll(r, 0o755); err != nil {
			return err
		}
		if err := a.setMeta(r, e.mode(), e.UID, e.GID, a.Chown); err != nil {
			return err
		}
	case KindFile:
		if err := a.clearDir(r, fi); err != nil {
			return err
		}
		src, err := a.Content.Open(e.Digest)
		if err != nil {
			return err
		}
		defer src.Close()
		if err := a.writeFile(r, src, e.Digest, e.mode(), e.UID, e.GID, a.Chown); err != nil {
			return err
		}
	case KindSymlink:
		if err := a.clearDir(r, fi); err != nil {
			return err
		}
		if err := a.symlink(r, e.Target, e.UID, e.GID, a.Chown); err != nil {
			return err
		}
	}
	res.Applied = append(res.Applied, Change{Action: action, Path: p, Old: prev, New: &e})
	res.hook(e.OnChange)
	return nil
}

// Drift is a managed path that no longer matches its manifest entry.
type Drift struct {
	Path    string `json:"path"`
	Policy  Policy `json:"policy,omitempty"`
	Problem string `json:"problem"`
}

// Verify compares the node against m without changing anything. The agent
// reports the result upstream; Apply(m, m) repairs enforce-policy drift.
// Seed-policy paths are owned by the node and never reported.
func (a *Applier) Verify(m Manifest) ([]Drift, error) {
	var drift []Drift
	for _, p := range slices.Sorted(maps.Keys(m.Entries)) {
		e := m.Entries[p]
		if e.policy() == PolicySeed {
			continue
		}
		r := rel(p)
		fi, err := a.Root.Lstat(r)
		if errors.Is(err, fs.ErrNotExist) {
			drift = append(drift, Drift{p, e.policy(), "missing"})
			continue
		} else if err != nil {
			return nil, err
		}
		modified, err := a.differs(r, fi, e)
		if err != nil {
			return nil, err
		}
		uid, gid, hasOwner := owner(fi)
		switch {
		case modified:
			drift = append(drift, Drift{p, e.policy(), "content"})
		case e.Kind != KindSymlink && modeOf(fi.Mode()) != e.mode():
			drift = append(drift, Drift{p, e.policy(), fmt.Sprintf("mode %s, want %s", modeOf(fi.Mode()), e.mode())})
		case a.Chown && hasOwner && (uid != e.UID || gid != e.GID):
			drift = append(drift, Drift{p, e.policy(), fmt.Sprintf("owner %d:%d, want %d:%d", uid, gid, e.UID, e.GID)})
		}
	}
	for _, d := range m.Exclusive {
		extra, err := a.unmanaged(d, m)
		if err != nil {
			return nil, err
		}
		for _, p := range extra {
			drift = append(drift, Drift{Path: p, Problem: "unmanaged path in exclusive directory " + d})
		}
	}
	return drift, nil
}

// unmanaged lists paths under the exclusive directory dir that m does not
// declare. A directory is kept if it holds something m declares.
func (a *Applier) unmanaged(dir string, m Manifest) ([]string, error) {
	keep := map[string]bool{}
	for p := range m.Entries {
		for r := rel(p); r != "."; r = path.Dir(r) {
			keep[r] = true
		}
	}
	root := rel(dir)
	var extra []string
	err := fs.WalkDir(a.Root.FS(), root, func(r string, d fs.DirEntry, err error) error {
		if err != nil {
			if r == root && errors.Is(err, fs.ErrNotExist) {
				return fs.SkipAll
			}
			return err
		}
		if r == root || keep[r] {
			return nil
		}
		extra = append(extra, "/"+r)
		if d.IsDir() {
			return fs.SkipDir
		}
		return nil
	})
	return extra, err
}

// differs reports whether the on-disk object at r has different content
// (kind, digest or symlink target) than e.
func (a *Applier) differs(r string, fi fs.FileInfo, e Entry) (bool, error) {
	switch e.Kind {
	case KindDir:
		return !fi.IsDir(), nil
	case KindSymlink:
		if fi.Mode()&fs.ModeSymlink == 0 {
			return true, nil
		}
		target, err := a.Root.Readlink(r)
		return target != e.Target, err
	default:
		if !fi.Mode().IsRegular() {
			return true, nil
		}
		d, err := a.fileDigest(r)
		return d != e.Digest, err
	}
}

func (a *Applier) fixMeta(r string, fi fs.FileInfo, e Entry) (bool, error) {
	uid, gid, hasOwner := owner(fi)
	ownerOK := !a.Chown || !hasOwner || (uid == e.UID && gid == e.GID)
	if e.Kind == KindSymlink {
		if ownerOK {
			return false, nil
		}
		return true, a.Root.Lchown(r, e.UID, e.GID)
	}
	if ownerOK && modeOf(fi.Mode()) == e.mode() {
		return false, nil
	}
	return true, a.setMeta(r, e.mode(), e.UID, e.GID, !ownerOK)
}

// setMeta sets r's owner and mode. The root is the node's whole
// filesystem, so os.Root confines nothing here, and a path-based chmod
// follows a symlink swapped in after the path was checked: a user who
// can write a managed path's directory could aim it at /etc/shadow. So
// the change goes through a descriptor, and only if the descriptor is
// the object Lstat found at r (not what a symlink there points to).
func (a *Applier) setMeta(r string, m Mode, uid, gid int, chown bool) error {
	fi, err := a.Root.Lstat(r)
	if err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; not changing what it points to", r)
	}
	f, err := a.Root.OpenFile(r, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrPermission) && os.Geteuid() != 0 {
		// An unprivileged agent (tests) cannot open a 0000 file. Nobody
		// else's files are at stake then.
		if chown {
			if err := a.Root.Lchown(r, uid, gid); err != nil {
				return err
			}
		}
		return a.Root.Chmod(r, m.fileMode())
	}
	if err != nil {
		return err
	}
	defer f.Close()
	got, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(fi, got) {
		return fmt.Errorf("%s was replaced while being updated", r)
	}
	return setFileMeta(f, m, uid, gid, chown)
}

// setFileMeta changes ownership before mode, because chown clears setuid
// and setgid bits on Linux.
func setFileMeta(f *os.File, m Mode, uid, gid int, chown bool) error {
	if chown {
		if err := f.Chown(uid, gid); err != nil {
			return err
		}
	}
	return f.Chmod(m.fileMode())
}

// clearDir removes an empty directory standing where a file or symlink is
// about to go. A non-empty one fails the apply rather than losing data.
func (a *Applier) clearDir(r string, cur fs.FileInfo) error {
	if cur != nil && cur.IsDir() {
		return a.Root.Remove(r)
	}
	return nil
}

// writeFile atomically replaces r with the content of src. If digest is set,
// the content must match it or nothing is written.
func (a *Applier) writeFile(r string, src io.Reader, digest string, m Mode, uid, gid int, chown bool) (err error) {
	tmp, err := a.tempName(r)
	if err != nil {
		return err
	}
	f, err := a.Root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			a.Root.Remove(tmp)
		}
	}()
	h := sha256.New()
	if _, err = io.Copy(io.MultiWriter(f, h), src); err != nil {
		return err
	}
	if got := "sha256:" + hex.EncodeToString(h.Sum(nil)); digest != "" && got != digest {
		return fmt.Errorf("content digest %s does not match manifest %s", got, digest)
	}
	// Through the descriptor: the temporary name sits in a directory
	// someone else may be able to write.
	if err = setFileMeta(f, m, uid, gid, chown); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return a.Root.Rename(tmp, r)
}

func (a *Applier) symlink(r, target string, uid, gid int, chown bool) error {
	tmp, err := a.tempName(r)
	if err != nil {
		return err
	}
	if err := a.Root.Symlink(target, tmp); err != nil {
		return err
	}
	if chown {
		if err := a.Root.Lchown(tmp, uid, gid); err != nil {
			a.Root.Remove(tmp)
			return err
		}
	}
	if err := a.Root.Rename(tmp, r); err != nil {
		a.Root.Remove(tmp)
		return err
	}
	return nil
}

// tempName returns a fresh sibling of r for atomic replacement, creating
// r's parent directories if needed.
func (a *Applier) tempName(r string) (string, error) {
	dir := path.Dir(r)
	if err := a.Root.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return path.Join(dir, ".flapjack-"+rand.Text()), nil
}

func (a *Applier) fileDigest(r string) (string, error) {
	f, err := a.Root.Open(r)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// Digest returns the manifest digest of b.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func owner(fi fs.FileInfo) (uid, gid int, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}

func rel(p string) string { return strings.TrimPrefix(p, "/") }
