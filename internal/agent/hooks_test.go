package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/damen-pt/flapjack/internal/overlay"
	"github.com/damen-pt/flapjack/internal/server"
)

// TestHooksOfAnInterruptedApplyStillRun: an apply that writes one file and
// then fails owes that file's hook. The retry finds the file already in
// place, so only the record makes it run the hook, once the apply completes.
// The record survives the agent restarting in between.
func TestHooksOfAnInterruptedApplyStillRun(t *testing.T) {
	a1, b1 := []byte("network config\n"), []byte("munge key\n")
	da, db := overlay.Digest(a1), overlay.Digest(b1)
	var failB atomic.Bool
	failB.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimPrefix(r.URL.Path, "/agent/v1/content/") {
		case da:
			w.Write(a1)
		case db:
			if failB.Load() {
				http.Error(w, "not yet", http.StatusServiceUnavailable)
				return
			}
			w.Write(b1)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	nodeDir := filepath.Join(dir, "node")
	os.MkdirAll(filepath.Join(nodeDir, "etc"), 0o755)
	os.WriteFile(filepath.Join(nodeDir, "etc/passwd"), []byte("root:x:0:0::/root:/bin/sh\n"), 0o644)
	os.WriteFile(filepath.Join(nodeDir, "etc/group"), []byte("root:x:0:\n"), 0o644)
	root, _ := os.OpenRoot(nodeDir)
	defer root.Close()
	var ran []string
	newAgent := func() *Agent {
		return &Agent{Server: srv.URL, Client: srv.Client(), Node: "n1", Root: root, Pristine: os.DirFS(filepath.Join(dir, "image")),
			State: overlay.State{Dir: filepath.Join(dir, "state")},
			Hook:  func(_ context.Context, cmd string) (string, error) { ran = append(ran, cmd); return "", nil }}
	}
	m := overlay.Manifest{Generation: 1, Entries: map[string]overlay.Entry{
		"/etc/a": {Kind: overlay.KindFile, Digest: da, OnChange: []string{"reload-network"}},
		"/etc/b": {Kind: overlay.KindFile, Digest: db, OnChange: []string{"restart-munge"}},
	}}
	r := server.AgentManifest{Generation: 1, Manifest: m}

	applied := overlay.Manifest{Entries: map[string]overlay.Entry{}}
	if rep := newAgent().apply(context.Background(), &applied, r); !strings.Contains(rep.Error, "/etc/b") {
		t.Fatalf("the first apply should fail on /etc/b: %q", rep.Error)
	}
	if len(ran) != 0 {
		t.Fatalf("hooks ran for an incomplete apply: %v", ran)
	}
	// The agent restarts, and the head now serves /etc/b.
	failB.Store(false)
	a := newAgent()
	applied, err := a.State.Load()
	if err != nil {
		t.Fatal(err)
	}
	rep := a.apply(context.Background(), &applied, r)
	if rep.Error != "" {
		t.Fatal(rep.Error)
	}
	if !slices.Equal(ran, []string{"reload-network", "restart-munge"}) {
		t.Fatalf("hooks run: %v", ran)
	}
	if owed, _ := a.State.Hooks(); len(owed) != 0 {
		t.Fatalf("hooks still owed after running: %v", owed)
	}
	// Nothing is owed now, so a repeat apply runs nothing.
	ran = nil
	a.apply(context.Background(), &applied, r)
	if len(ran) != 0 {
		t.Fatalf("hooks ran with nothing changed: %v", ran)
	}
}
