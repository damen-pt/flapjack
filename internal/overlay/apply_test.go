package overlay

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"testing/fstest"
)

type memStore map[string][]byte

func (s memStore) Open(d string) (io.ReadCloser, error) {
	b, ok := s[d]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

func (s memStore) file(content string, mods ...func(*Entry)) Entry {
	d := Digest([]byte(content))
	s[d] = []byte(content)
	e := Entry{Kind: KindFile, Digest: d}
	for _, m := range mods {
		m(&e)
	}
	return e
}

func policy(p Policy) func(*Entry) { return func(e *Entry) { e.Policy = p } }

type node struct {
	t     *testing.T
	dir   string
	a     *Applier
	store memStore
}

func newNode(t *testing.T, pristine fs.FS) *node {
	t.Helper()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	store := memStore{}
	return &node{t, dir, &Applier{Root: root, Content: store, Pristine: pristine}, store}
}

func (n *node) apply(old, new Manifest) Result {
	n.t.Helper()
	res, err := n.a.Apply(old, new)
	if err != nil {
		n.t.Fatal(err)
	}
	return res
}

func (n *node) put(p, content string) {
	n.t.Helper()
	full := filepath.Join(n.dir, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		n.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		n.t.Fatal(err)
	}
}

func (n *node) read(p string) (string, bool) {
	b, err := os.ReadFile(filepath.Join(n.dir, p))
	if errors.Is(err, fs.ErrNotExist) {
		return "", false
	} else if err != nil {
		n.t.Fatal(err)
	}
	return string(b), true
}

func (n *node) exists(p string) bool {
	_, err := os.Lstat(filepath.Join(n.dir, p))
	return err == nil
}

func manifest(entries map[string]Entry) Manifest { return Manifest{Entries: entries} }

var empty = manifest(map[string]Entry{})

func TestRemovedFromOverlayIsRemovedDownstream(t *testing.T) {
	n := newNode(t, nil)
	conf := n.store.file("a=1\n", func(e *Entry) {
		e.Mode = 0o640
		e.OnRemove = []string{"systemctl try-restart foo"}
	})
	gen1 := manifest(map[string]Entry{
		"/etc/foo":        {Kind: KindDir},
		"/etc/foo/a.conf": conf,
	})
	n.apply(empty, gen1)
	if got, _ := n.read("etc/foo/a.conf"); got != "a=1\n" {
		t.Fatalf("a.conf = %q", got)
	}
	fi, _ := os.Stat(filepath.Join(n.dir, "etc/foo/a.conf"))
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v", fi.Mode())
	}

	res := n.apply(gen1, empty)
	if n.exists("etc/foo/a.conf") || n.exists("etc/foo") {
		t.Fatal("file and directory should be removed once they leave the overlay")
	}
	if !slices.Equal(res.Hooks, []string{"systemctl try-restart foo"}) {
		t.Fatalf("hooks = %v", res.Hooks)
	}
}

func TestRemovalRestoresImageVersion(t *testing.T) {
	pristine := fstest.MapFS{"etc/chrony.conf": {Data: []byte("pool image\n"), Mode: 0o644}}
	n := newNode(t, pristine)
	n.put("etc/chrony.conf", "pool image\n")

	gen1 := manifest(map[string]Entry{"/etc/chrony.conf": n.store.file("server ctl\n")})
	n.apply(empty, gen1)
	if got, _ := n.read("etc/chrony.conf"); got != "server ctl\n" {
		t.Fatalf("overlay not applied: %q", got)
	}

	n.apply(gen1, empty)
	if got, ok := n.read("etc/chrony.conf"); !ok || got != "pool image\n" {
		t.Fatalf("image version not restored: %q (exists=%v)", got, ok)
	}
}

func TestLocalEditsSurviveRemovalOnlyUnderReportPolicy(t *testing.T) {
	n := newNode(t, nil)
	gen1 := manifest(map[string]Entry{
		"/etc/enforced": n.store.file("x\n"),
		"/etc/reported": n.store.file("y\n", policy(PolicyReport)),
	})
	n.apply(empty, gen1)
	n.put("etc/enforced", "edited\n")
	n.put("etc/reported", "edited\n")

	res := n.apply(gen1, empty)
	if n.exists("etc/enforced") {
		t.Error("enforced file should be removed even when edited")
	}
	if got, _ := n.read("etc/reported"); got != "edited\n" {
		t.Error("edited report-policy file should be kept")
	}
	if len(res.Skipped) != 1 || res.Skipped[0].Path != "/etc/reported" {
		t.Errorf("skipped = %v", res.Skipped)
	}
}

func TestDriftIsReportedAndEnforcedDriftRepaired(t *testing.T) {
	n := newNode(t, nil)
	m := manifest(map[string]Entry{
		"/etc/enforced": n.store.file("x\n"),
		"/etc/reported": n.store.file("y\n", policy(PolicyReport)),
		"/etc/mode":     n.store.file("z\n"),
	})
	n.apply(empty, m)
	n.put("etc/enforced", "edited\n")
	n.put("etc/reported", "edited\n")
	os.Chmod(filepath.Join(n.dir, "etc/mode"), 0o600)

	drift, err := n.a.Verify(m)
	if err != nil {
		t.Fatal(err)
	}
	if len(drift) != 3 {
		t.Fatalf("drift = %v", drift)
	}

	n.apply(m, m)
	drift, _ = n.a.Verify(m)
	if len(drift) != 1 || drift[0].Path != "/etc/reported" {
		t.Fatalf("after repair drift = %v", drift)
	}
	if got, _ := n.read("etc/enforced"); got != "x\n" {
		t.Errorf("enforced content not repaired: %q", got)
	}
}

func TestSeedIsWrittenOnceThenOwnedByNode(t *testing.T) {
	n := newNode(t, nil)
	gen1 := manifest(map[string]Entry{"/etc/seed": n.store.file("v1\n", policy(PolicySeed))})
	gen2 := manifest(map[string]Entry{"/etc/seed": n.store.file("v2\n", policy(PolicySeed))})

	n.apply(empty, gen1)
	n.apply(gen1, gen2)
	if got, _ := n.read("etc/seed"); got != "v2\n" {
		t.Fatalf("untouched seed should follow the overlay, got %q", got)
	}

	n.put("etc/seed", "mine\n")
	gen3 := manifest(map[string]Entry{"/etc/seed": n.store.file("v3\n", policy(PolicySeed))})
	n.apply(gen2, gen3)
	if got, _ := n.read("etc/seed"); got != "mine\n" {
		t.Fatalf("edited seed should be kept, got %q", got)
	}
}

func TestExclusiveDirectoryIsPruned(t *testing.T) {
	n := newNode(t, nil)
	n.put("etc/slurm/stale.conf", "old\n")
	n.put("etc/slurm/plugstack.conf.d/x.conf", "old\n")
	n.put("etc/other.conf", "untouched\n")
	m := manifest(map[string]Entry{"/etc/slurm/slurm.conf": n.store.file("ClusterName=c\n")})
	m.Exclusive = []string{"/etc/slurm"}

	drift, _ := n.a.Verify(m)
	if len(drift) != 3 { // missing slurm.conf plus two unmanaged paths
		t.Fatalf("drift = %v", drift)
	}
	n.apply(empty, m)
	if n.exists("etc/slurm/stale.conf") || n.exists("etc/slurm/plugstack.conf.d") {
		t.Error("unmanaged paths in exclusive directory should be pruned")
	}
	if !n.exists("etc/slurm/slurm.conf") || !n.exists("etc/other.conf") {
		t.Error("managed and out-of-scope files should remain")
	}
}

func TestSymlinkLifecycle(t *testing.T) {
	n := newNode(t, nil)
	link := func(target string) Manifest {
		return manifest(map[string]Entry{"/etc/localtime": {Kind: KindSymlink, Target: target}})
	}
	gen1, gen2 := link("../usr/share/zoneinfo/UTC"), link("../usr/share/zoneinfo/America/Chicago")
	n.apply(empty, gen1)
	n.apply(gen1, gen2)
	if got, _ := os.Readlink(filepath.Join(n.dir, "etc/localtime")); got != "../usr/share/zoneinfo/America/Chicago" {
		t.Fatalf("target = %q", got)
	}
	n.apply(gen2, empty)
	if n.exists("etc/localtime") {
		t.Fatal("symlink should be removed")
	}
}

func TestDirectoryReplacedByFile(t *testing.T) {
	n := newNode(t, nil)
	gen1 := manifest(map[string]Entry{
		"/etc/x":   {Kind: KindDir},
		"/etc/x/y": n.store.file("y\n"),
	})
	gen2 := manifest(map[string]Entry{"/etc/x": n.store.file("x\n")})
	n.apply(empty, gen1)
	n.apply(gen1, gen2)
	if got, _ := n.read("etc/x"); got != "x\n" {
		t.Fatalf("etc/x = %q", got)
	}
}

func TestDigestMismatchWritesNothing(t *testing.T) {
	n := newNode(t, nil)
	e := n.store.file("good\n")
	n.store[e.Digest] = []byte("tampered\n")
	_, err := n.a.Apply(empty, manifest(map[string]Entry{"/etc/f": e}))
	if err == nil {
		t.Fatal("expected digest mismatch error")
	}
	left, _ := os.ReadDir(filepath.Join(n.dir, "etc"))
	if len(left) != 0 {
		t.Fatalf("files left behind: %v", left)
	}
}

func TestInterruptedApplyIsStillCleanedUp(t *testing.T) {
	n := newNode(t, nil)
	s := State{Dir: t.TempDir()}
	gen1 := manifest(map[string]Entry{"/etc/a": n.store.file("a\n")})
	gen2 := manifest(map[string]Entry{"/etc/a": gen1.Entries["/etc/a"], "/etc/b": n.store.file("b\n")})

	n.apply(empty, gen1)
	if err := s.Commit(gen1); err != nil {
		t.Fatal(err)
	}
	if err := s.Begin(gen2); err != nil {
		t.Fatal(err)
	}
	n.apply(gen1, gen2) // agent dies before Commit

	old, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	n.apply(old, empty)
	if n.exists("etc/a") || n.exists("etc/b") {
		t.Fatal("files from the interrupted generation should be removed")
	}
}

func TestDiffOrder(t *testing.T) {
	f := Entry{Kind: KindFile, Digest: Digest(nil)}
	d := Entry{Kind: KindDir}
	old := manifest(map[string]Entry{"/a": d, "/a/b": f, "/k": f, "/s": f})
	new := manifest(map[string]Entry{"/c": d, "/c/d": f, "/k": {Kind: KindFile, Digest: f.Digest, Mode: 0o600},
		"/s": {Kind: KindFile, Digest: f.Digest, Secret: true}})
	var got []string
	for _, c := range Diff(old, new) {
		got = append(got, string(c.Action)+" "+c.Path)
	}
	want := []string{"remove /a/b", "remove /a", "create /c", "create /c/d", "meta /k", "meta /s"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestValidateRejectsUnsafeManifests(t *testing.T) {
	f := Entry{Kind: KindFile, Digest: Digest(nil)}
	for name, m := range map[string]Manifest{
		"relative":          manifest(map[string]Entry{"etc/x": f}),
		"dotdot":            manifest(map[string]Entry{"/etc/../x": f}),
		"root":              manifest(map[string]Entry{"/": {Kind: KindDir}}),
		"no digest":         manifest(map[string]Entry{"/etc/x": {Kind: KindFile}}),
		"shallow exclusive": {Entries: map[string]Entry{}, Exclusive: []string{"/etc"}},
	} {
		if m.Validate() == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestModeJSON(t *testing.T) {
	var e Entry
	if err := json.Unmarshal([]byte(`{"kind":"file","mode":"4755"}`), &e); err != nil {
		t.Fatal(err)
	}
	if e.Mode != 0o4755 || e.Mode.fileMode()&fs.ModeSetuid == 0 {
		t.Fatalf("mode = %v", e.Mode)
	}
	b, _ := json.Marshal(e.Mode)
	if string(b) != `"4755"` {
		t.Fatalf("marshal = %s", b)
	}
}

func TestResolveOwners(t *testing.T) {
	root := fstest.MapFS{
		"etc/passwd": {Data: []byte("root:x:0:0::/root:/bin/bash\nmunge:x:991:989::/run/munge:/sbin/nologin\n")},
		"etc/group":  {Data: []byte("root:x:0:\nmunge:x:989:\n")},
	}
	m := manifest(map[string]Entry{"/etc/munge/munge.key": {Kind: KindFile, Digest: "sha256:x", Owner: "munge", Group: "munge"}})
	got, err := ResolveOwners(m, root)
	if err != nil {
		t.Fatal(err)
	}
	if e := got.Entries["/etc/munge/munge.key"]; e.UID != 991 || e.GID != 989 || e.Owner != "" {
		t.Fatalf("resolved = %+v", e)
	}
	if m.Entries["/etc/munge/munge.key"].Owner != "munge" {
		t.Fatal("input manifest was modified")
	}
	m.Entries["/x"] = Entry{Kind: KindDir, Owner: "slurm"}
	if _, err := ResolveOwners(m, root); err == nil {
		t.Fatal("unknown user accepted")
	}
	a, b := manifest(map[string]Entry{"/a": {Kind: KindDir}}), manifest(map[string]Entry{"/a": {Kind: KindDir}})
	b.Generation = 7
	if ManifestDigest(a) != ManifestDigest(b) {
		t.Fatal("generation number changed the digest")
	}
}

// TestMetadataNeverFollowsASymlink: the agent's root is the node's whole
// filesystem, so a managed path someone swapped for a symlink must not
// have its owner or mode changes land on the symlink's target.
func TestMetadataNeverFollowsASymlink(t *testing.T) {
	n := newNode(t, nil)
	n.put("/etc/shadow", "root:x\n")
	os.Chmod(filepath.Join(n.dir, "etc/shadow"), 0o600)
	os.MkdirAll(filepath.Join(n.dir, "home/alice"), 0o755)
	// Relative, so it resolves inside the test root as /etc/shadow does on
	// a node, where the root is /.
	os.Symlink("../../etc/shadow", filepath.Join(n.dir, "home/alice/managed"))
	if err := n.a.setMeta("home/alice/managed", 0o644, 0, 0, false); err == nil {
		t.Fatal("changed metadata through a symlink")
	}
	if fi, _ := os.Stat(filepath.Join(n.dir, "etc/shadow")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("target mode now %v", fi.Mode())
	}
	n.put("/etc/motd", "hi\n")
	if err := n.a.setMeta("etc/motd", 0o640, 0, 0, false); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(n.dir, "etc/motd")); fi.Mode().Perm() != 0o640 {
		t.Fatalf("regular file mode %v", fi.Mode())
	}
}
