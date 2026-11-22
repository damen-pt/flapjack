package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/apiserver"
	"github.com/damen-pt/flapjack/internal/events"
	"github.com/damen-pt/flapjack/internal/gens"
	"github.com/damen-pt/flapjack/internal/overlay"
	"github.com/damen-pt/flapjack/internal/pki"
	"github.com/damen-pt/flapjack/internal/render"
	"github.com/damen-pt/flapjack/internal/server"
	"github.com/damen-pt/flapjack/internal/staging"
	"github.com/damen-pt/flapjack/internal/store"
)

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestAgentFollowsGenerations(t *testing.T) {
	dir := t.TempDir()
	log, _ := events.Open(filepath.Join(dir, "events.jsonl"))
	defer log.Close()
	st, _ := store.Open(filepath.Join(dir, "state.json"), log)
	st.PutClass(v1.NodeClass{Name: "c", Overlays: []string{"base"}})
	st.PutNode(v1.Node{Name: "n1", Class: "c", Interfaces: []v1.Interface{{MAC: "52:54:00:00:00:01", IP: "127.0.0.1"}}})
	src := filepath.Join(dir, "overlays", "base", "rootfs")
	put := func(p, c string) {
		os.MkdirAll(filepath.Dir(filepath.Join(src, p)), 0o755)
		os.WriteFile(filepath.Join(src, p), []byte(c), 0o644)
	}
	put("etc/motd.ww", "hello {{.Node.Name}}\n")
	put("etc/extra", "temporary\n")
	genPub, genKey, _ := ed25519.GenerateKey(rand.Reader)
	ov := &server.Overlays{Store: st, Gens: &gens.Store{Dir: filepath.Join(dir, "gens")}, Content: staging.Store{Dir: filepath.Join(dir, "content")},
		Renderer: &render.Renderer{Dir: filepath.Join(dir, "overlays")}, Signer: &pki.Signer{Key: genKey}}
	srv, client := agentServer(t, ov, "n1")

	// The node: an image that ships its own /etc/motd.
	nodeDir := filepath.Join(dir, "node")
	os.MkdirAll(filepath.Join(nodeDir, "etc"), 0o755)
	os.WriteFile(filepath.Join(nodeDir, "etc/passwd"), []byte("root:x:0:0::/root:/bin/sh\n"), 0o644)
	os.WriteFile(filepath.Join(nodeDir, "etc/group"), []byte("root:x:0:\n"), 0o644)
	os.WriteFile(filepath.Join(nodeDir, "etc/motd"), []byte("image motd\n"), 0o644)
	pristine := os.DirFS(filepath.Join(dir, "image"))
	os.MkdirAll(filepath.Join(dir, "image", "etc"), 0o755)
	os.WriteFile(filepath.Join(dir, "image", "etc/motd"), []byte("image motd\n"), 0o644)
	root, _ := os.OpenRoot(nodeDir)
	defer root.Close()
	read := func(p string) string {
		b, err := os.ReadFile(filepath.Join(nodeDir, p))
		if err != nil {
			return "<missing>"
		}
		return string(b)
	}

	var mu sync.Mutex
	var hooks []string
	ready := make(chan struct{})
	a := &Agent{Server: srv.URL, Client: client, Node: "n1", TrustKey: genPub, Root: root, Pristine: pristine, State: overlay.State{Dir: filepath.Join(dir, "agent")},
		Verify: 200 * time.Millisecond, ReadyAfter: time.Hour, Ready: func() { close(ready) },
		Hook: func(_ context.Context, cmd string) (string, error) {
			mu.Lock()
			hooks = append(hooks, cmd)
			mu.Unlock()
			return "", nil
		}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	switchAll := func(msg string) {
		if _, err := ov.Build(apiserver.BuildRequest{All: true, Switch: true, Message: msg}, "test"); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-ready:
		t.Fatal("ready before anything was applied") // generation 0 applies instantly but is empty
	default:
	}
	switchAll("first")
	eventually(t, "generation 1 on the node", func() bool { return read("etc/motd") == "hello n1\n" && read("etc/extra") == "temporary\n" })
	<-ready

	// Bi-directional: removing a file from the overlay removes it on the node,
	// and a file the image ships is restored rather than deleted.
	os.Remove(filepath.Join(src, "etc/extra"))
	os.Remove(filepath.Join(src, "etc/motd.ww"))
	put("etc/issue", "new\n")
	switchAll("second")
	eventually(t, "generation 2 on the node", func() bool {
		return read("etc/extra") == "<missing>" && read("etc/motd") == "image motd\n" && read("etc/issue") == "new\n"
	})

	// Local edits to an enforced file are repaired and reported.
	os.WriteFile(filepath.Join(nodeDir, "etc/issue"), []byte("hand edited\n"), 0o644)
	eventually(t, "drift repaired", func() bool { return read("etc/issue") == "new\n" })
	eventually(t, "repair recorded", func() bool {
		evs, _ := log.Query(events.Filter{Types: []string{"overlay.repaired"}})
		return len(evs) > 0
	})

	// Rollback restores generation 1 exactly.
	if _, err := ov.Rollback("n1", 1, "test", "undo"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "rollback on the node", func() bool {
		return read("etc/motd") == "hello n1\n" && read("etc/extra") == "temporary\n" && read("etc/issue") == "<missing>"
	})
	eventually(t, "status reports generation 1", func() bool {
		n, _ := st.Node("n1")
		return n.Status.Agent != nil && n.Status.Agent.Applied == 1 && len(n.Status.Agent.Drift) == 0
	})
}

func TestKernelArgs(t *testing.T) {
	got := KernelArgs("BOOT_IMAGE=x flapjack.node=r1n01 flapjack.server=http://10.99.0.1 quiet")
	if got["node"] != "r1n01" || got["server"] != "http://10.99.0.1" || len(got) != 2 {
		t.Fatalf("%v", got)
	}
	if !strings.HasPrefix(tail("abcdef", 3), "def") {
		t.Fatal("tail")
	}
}

// agentServer serves ov's agent routes over mTLS, as the head does, and
// returns a client holding node's certificate.
func agentServer(t *testing.T, ov *server.Overlays, node string) (*httptest.Server, *http.Client) {
	t.Helper()
	ca, err := pki.NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	head, _ := ca.Issue(pki.Identity{Role: pki.Head, Name: "head"}, time.Hour)
	nc, _ := ca.Issue(pki.Identity{Role: pki.Node, Name: node}, time.Hour)
	srv := httptest.NewUnstartedServer(ov.AgentHandler())
	srv.TLS = pki.ServerConfig(pki.Static(head), ca.Pool, pki.AnyOf(pki.Node), false)
	srv.TLS.Certificates = []tls.Certificate{head} // or StartTLS adds its own
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, &http.Client{Transport: &http.Transport{TLSClientConfig: pki.ClientConfig(pki.Static(nc), ca.Pool, pki.AnyOf(pki.Head))}}
}
