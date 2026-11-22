package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
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
	"github.com/damen-pt/flapjack/internal/pki"
	"github.com/damen-pt/flapjack/internal/render"
	"github.com/damen-pt/flapjack/internal/staging"
	"github.com/damen-pt/flapjack/internal/store"
)

func overlaySetup(t *testing.T) (*Overlays, string) {
	dir := t.TempDir()
	log, _ := events.Open(filepath.Join(dir, "events.jsonl"))
	t.Cleanup(func() { log.Close() })
	st, _ := store.Open(filepath.Join(dir, "state.json"), log)
	st.PutClass(v1.NodeClass{Name: "compute", Overlays: []string{"base"}})
	st.PutNode(v1.Node{Name: "n1", Class: "compute", Rack: "r1", Interfaces: []v1.Interface{{MAC: "52:54:00:00:00:11", IP: "10.0.0.11"}}})
	st.PutNode(v1.Node{Name: "n2", Class: "compute", Rack: "r1", Interfaces: []v1.Interface{{MAC: "52:54:00:00:00:12", IP: "10.0.0.12"}}})
	for p, c := range map[string]string{
		"overlays/base/rootfs/etc/motd.ww": "hello {{.Node.Name}}\n",
		"overlays/base/rootfs/etc/old":     "remove me later\n",
	} {
		os.MkdirAll(filepath.Join(dir, filepath.Dir(p)), 0o755)
		os.WriteFile(filepath.Join(dir, p), []byte(c), 0o644)
	}
	return &Overlays{Store: st, Gens: &gens.Store{Dir: filepath.Join(dir, "gens")}, Content: staging.Store{Dir: filepath.Join(dir, "content")},
		Renderer: &render.Renderer{Dir: filepath.Join(dir, "overlays")}, Server: "10.0.0.1"}, dir
}

var testCA = sync.OnceValue(func() *pki.CA {
	ca, err := pki.NewCA("test")
	if err != nil {
		panic(err)
	}
	return ca
})

// asNode makes r arrive over mTLS with node's certificate ("" for none).
func asNode(r *http.Request, node string) {
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	if node == "" {
		return
	}
	c, err := testCA().Issue(pki.Identity{Role: pki.Node, Name: node}, time.Hour)
	if err != nil {
		panic(err)
	}
	r.TLS.PeerCertificates = []*x509.Certificate{c.Leaf}
	r.TLS.VerifiedChains = [][]*x509.Certificate{{c.Leaf, testCA().Cert}}
}

// agentGet fetches path as node's agent ("" for no certificate).
func agentGet(t *testing.T, h http.Handler, path, node string) (int, []byte) {
	r := httptest.NewRequest("GET", path, nil)
	r.RemoteAddr = "10.0.0.250:5000" // the address never identifies anyone
	asNode(r, node)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	b, _ := io.ReadAll(w.Result().Body)
	return w.Code, b
}

type manifestReply struct {
	Generation int
	Manifest   struct {
		Entries map[string]struct{ Digest string }
	}
}

func TestBuildSwitchAgentRollback(t *testing.T) {
	o, dir := overlaySetup(t)
	res, err := o.Build(apiserver.BuildRequest{Classes: []string{"compute"}}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	rs := res.([]NodeResult)
	if len(rs) != 2 || rs[0].To != 0 || len(rs[0].Changes) != 2 {
		t.Fatalf("dry run = %+v", rs)
	}
	if _, err := o.Gens.Current("n1"); err != gens.ErrNone {
		t.Fatal("a dry run published a generation")
	}

	// An agent with nothing applied gets generation 0 (empty) at once.
	h := o.AgentHandler()
	code, body := agentGet(t, h, "/agent/v1/manifest?have=-1", "n1")
	var m manifestReply
	json.Unmarshal(body, &m)
	if code != 200 || m.Generation != 0 {
		t.Fatalf("initial manifest = %d %s", code, body)
	}

	// A long-polling agent wakes up when its node is switched.
	got := make(chan manifestReply, 1)
	go func() {
		_, b := agentGet(t, h, "/agent/v1/manifest?have=0&wait=10s", "n1")
		var m manifestReply
		json.Unmarshal(b, &m)
		got <- m
	}()
	time.Sleep(50 * time.Millisecond)
	res, err = o.Build(apiserver.BuildRequest{Nodes: []string{"n1"}, Switch: true, Message: "first"}, "alice")
	if err != nil || res.([]NodeResult)[0].To != 1 {
		t.Fatalf("switch = %+v %v", res, err)
	}
	select {
	case m = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("long poll did not wake on switch")
	}
	if m.Generation != 1 || len(m.Manifest.Entries) != 2 {
		t.Fatalf("woken manifest = %+v", m)
	}

	// Content is only served to the node whose generation references it.
	d := m.Manifest.Entries["/etc/motd"].Digest
	if code, b := agentGet(t, h, "/agent/v1/content/"+d, "n1"); code != 200 || string(b) != "hello n1\n" {
		t.Fatalf("content = %d %q", code, b)
	}
	if code, _ := agentGet(t, h, "/agent/v1/content/"+d, "n2"); code != 404 {
		t.Fatalf("n2 read n1's content: %d", code)
	}
	if code, _ := agentGet(t, h, "/agent/v1/manifest", ""); code != 401 {
		t.Fatalf("no certificate = %d", code)
	}
	if code, _ := agentGet(t, h, "/agent/v1/manifest", "n9"); code != 403 {
		t.Fatalf("certificate for an unknown node = %d", code)
	}

	// Switching again with nothing changed makes no generation.
	res, _ = o.Build(apiserver.BuildRequest{Nodes: []string{"n1"}, Switch: true}, "alice")
	if r := res.([]NodeResult)[0]; r.To != 1 || len(r.Changes) != 0 {
		t.Fatalf("no-op switch = %+v", r)
	}

	// Removing a file from the overlay shows up as a removal.
	os.Remove(filepath.Join(dir, "overlays/base/rootfs/etc/old"))
	res, _ = o.Build(apiserver.BuildRequest{Nodes: []string{"n1"}, Switch: true, Message: "drop old"}, "alice")
	r := res.([]NodeResult)[0]
	if r.To != 2 || len(r.Changes) != 1 || r.Changes[0].Action != "remove" || r.Changes[0].Path != "/etc/old" {
		t.Fatalf("removal switch = %+v", r)
	}

	// Agent reports land in node status and the timeline.
	if err := o.report("n1", AgentReport{Generation: 2, Drift: nil}); err != nil {
		t.Fatal(err)
	}
	n, _ := o.Store.Node("n1")
	if n.Status.Agent == nil || n.Status.Agent.Applied != 2 {
		t.Fatalf("agent status = %+v", n.Status.Agent)
	}

	back, err := o.Rollback("n1", 0, "alice", "bad change")
	if err != nil || back.(map[string]any)["to"] != 1 {
		t.Fatalf("rollback = %v %v", back, err)
	}
	diff, _ := o.Diff("n1", 2, 1)
	if cs := diff.(map[string]any)["changes"]; !strings.Contains(jsonOf(cs), `"/etc/old"`) {
		t.Fatalf("diff 2→1 = %s", jsonOf(cs))
	}
	evs, _ := o.Store.Events.Query(events.Filter{Types: []string{"overlay."}})
	var types []string
	for _, e := range evs {
		types = append(types, e.Type)
	}
	if strings.Join(types, ",") != "overlay.switch,overlay.switch,overlay.applied,overlay.rollback" {
		t.Fatalf("events = %v", types)
	}
}

func jsonOf(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
