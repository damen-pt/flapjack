package apiserver

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/events"
	"github.com/damen-pt/flapjack/internal/pki"
	"github.com/damen-pt/flapjack/internal/store"
)

func setup(t *testing.T) (*httptest.Server, *store.Store) {
	dir := t.TempDir()
	log, _ := events.Open(filepath.Join(dir, "events.jsonl"))
	t.Cleanup(func() { log.Close() })
	s, _ := store.Open(filepath.Join(dir, "state.json"), log)
	s.PutNode(v1.Node{Name: "n1", Status: v1.NodeStatus{Phase: v1.PhaseQuarantined}})
	s.PutNode(v1.Node{Name: "n2"})
	srv := httptest.NewServer((&Server{Store: s, Tokens: map[string]Principal{
		HashToken("view-token"): {Name: "grafana", Role: Viewer},
		HashToken("ops-token"):  {Name: "alice", Role: Operator},
	}}).Handler())
	t.Cleanup(srv.Close)
	return srv, s
}

func call(t *testing.T, srv *httptest.Server, method, path, token, body string) (int, string) {
	req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestAuthAndRoles(t *testing.T) {
	srv, _ := setup(t)
	if code, _ := call(t, srv, "GET", "/v1/nodes", "", ""); code != 401 {
		t.Fatalf("no token: %d", code)
	}
	if code, _ := call(t, srv, "GET", "/v1/nodes", "wrong", ""); code != 401 {
		t.Fatalf("bad token: %d", code)
	}
	code, body := call(t, srv, "GET", "/v1/nodes?phase=Quarantined", "view-token", "")
	var nodes []v1.Node
	json.Unmarshal([]byte(body), &nodes)
	if code != 200 || len(nodes) != 1 || nodes[0].Name != "n1" {
		t.Fatalf("%d %s", code, body)
	}
	if code, _ := call(t, srv, "POST", "/v1/nodes/n1/release", "view-token", `{"reason":"x"}`); code != 403 {
		t.Fatalf("viewer must not mutate: %d", code)
	}
	if code, _ := call(t, srv, "GET", "/v1/nodes/nope", "view-token", ""); code != 404 {
		t.Fatalf("unknown node: %d", code)
	}
}

func TestReleaseIsAudited(t *testing.T) {
	srv, s := setup(t)
	if code, _ := call(t, srv, "POST", "/v1/nodes/n1/release", "ops-token", `{}`); code != 400 {
		t.Fatalf("release without reason: %d", code)
	}
	code, body := call(t, srv, "POST", "/v1/nodes/n1/release", "ops-token", `{"reason":"GPU3 reseated, RMA-4411"}`)
	if code != 200 || !strings.Contains(body, `"phase":"BurnIn"`) {
		t.Fatalf("%d %s", code, body)
	}
	if code, body := call(t, srv, "POST", "/v1/nodes/n2/drain", "ops-token", `{"reason":"x"}`); code != 409 {
		t.Fatalf("Discovered → Draining must conflict: %d %s", code, body)
	}
	evs, _ := s.Events.Query(events.Filter{Nodes: []string{"n1"}})
	if len(evs) != 1 || evs[0].Actor != "alice" || evs[0].Message != "GPU3 reseated, RMA-4411" {
		t.Fatalf("audit = %+v", evs)
	}
	code, body = call(t, srv, "GET", "/v1/events?node=n1&since=1h", "view-token", "")
	if code != 200 || !strings.Contains(body, "node.phase") {
		t.Fatalf("%d %s", code, body)
	}
	if code, _ := call(t, srv, "GET", "/v1/events?since=yesterday", "view-token", ""); code != 400 {
		t.Fatalf("bad since: %d", code)
	}
}

func TestPutNodesAndClasses(t *testing.T) {
	srv, s := setup(t)
	s.Events.Close()
	dir := t.TempDir()
	log, _ := events.Open(filepath.Join(dir, "e.jsonl"))
	defer log.Close()
	s.Events = log
	srv.Config.Handler = (&Server{Store: s, Tokens: map[string]Principal{
		HashToken("ops-token"):   {Name: "alice", Role: Operator},
		HashToken("admin-token"): {Name: "root", Role: Admin},
	}}).Handler()

	node := `{"class":"compute","interfaces":[{"mac":"52:54:00:01:01:01","ip":"10.99.1.1"}]}`
	if code, _ := call(t, srv, "PUT", "/v1/nodes/r1n01", "ops-token", node); code != http.StatusForbidden {
		t.Fatalf("operator PUT = %d, want 403", code)
	}
	if code, body := call(t, srv, "PUT", "/v1/nodes/r1n01", "admin-token", node); code != 200 || !strings.Contains(body, `"phase":"Discovered"`) {
		t.Fatalf("PUT = %d %s", code, body)
	}
	if code, _ := call(t, srv, "PUT", "/v1/nodes/other", "admin-token", `{"name":"r1n01"}`); code != 400 {
		t.Fatalf("name mismatch = %d, want 400", code)
	}
	if code, _ := call(t, srv, "PUT", "/v1/nodes/bad", "admin-token", `{"interfaces":[{"mac":"nope"}]}`); code != 400 {
		t.Fatalf("bad MAC = %d, want 400", code)
	}
	dup := `{"interfaces":[{"mac":"52:54:00:01:01:01","ip":"10.99.1.2"}]}`
	if code, body := call(t, srv, "PUT", "/v1/nodes/r1n02", "admin-token", dup); code != 409 || !strings.Contains(body, "r1n01") {
		t.Fatalf("duplicate MAC = %d %s", code, body)
	}
	if code, _ := call(t, srv, "PUT", "/v1/classes/compute", "admin-token", `{"image":"el9"}`); code != 200 {
		t.Fatalf("PUT class = %d", code)
	}
	if code, body := call(t, srv, "GET", "/v1/classes", "ops-token", ""); code != 200 || !strings.Contains(body, `"image":"el9"`) {
		t.Fatalf("GET classes = %d %s", code, body)
	}
	if evs, _ := log.Query(events.Filter{Types: []string{"node.put"}}); len(evs) != 1 || evs[0].Actor != "root" {
		t.Fatalf("audit = %+v", evs)
	}
}

func TestHealthReportsAreNodeScoped(t *testing.T) {
	dir := t.TempDir()
	log, _ := events.Open(filepath.Join(dir, "events.jsonl"))
	t.Cleanup(func() { log.Close() })
	s, _ := store.Open(filepath.Join(dir, "state.json"), log)
	s.PutClass(v1.NodeClass{Name: "gpu", Health: v1.HealthPolicy{Checks: []string{"gpu"}, Critical: []string{"gpu"}}})
	s.PutNode(v1.Node{Name: "n1", Class: "gpu", Status: v1.NodeStatus{Phase: v1.PhaseReady}})
	s.PutNode(v1.Node{Name: "n2", Class: "gpu", Status: v1.NodeStatus{Phase: v1.PhaseReady}})
	srv := httptest.NewServer((&Server{Store: s, Tokens: map[string]Principal{
		HashToken("n1-agent"): {Name: "agent/n1", Role: Operator, Node: "n1"},
		HashToken("viewer"):   {Name: "grafana", Role: Viewer},
	}}).Handler())
	t.Cleanup(srv.Close)

	now := time.Now().UTC().Format(time.RFC3339Nano)
	fail := `{"node":"n1","time":"` + now + `","status":"fail","results":[{"check":"gpu","status":"fail","message":"Xid 79"}]}`
	if code, _ := call(t, srv, "POST", "/v1/nodes/n2/health", "n1-agent", strings.Replace(fail, `"n1"`, `"n2"`, 1)); code != 403 {
		t.Fatalf("agent reported for another node: %d", code)
	}
	if code, _ := call(t, srv, "POST", "/v1/nodes/n1/drain", "n1-agent", `{"reason":"x"}`); code != 403 {
		t.Fatalf("scoped token used an operator route: %d", code)
	}
	if code, _ := call(t, srv, "POST", "/v1/nodes/n1/health", "viewer", fail); code != 403 {
		t.Fatalf("viewer posted health: %d", code)
	}
	if code, _ := call(t, srv, "POST", "/v1/nodes/n1/health", "n1-agent", strings.Replace(fail, `"node":"n1"`, `"node":"n2"`, 1)); code != 400 {
		t.Fatalf("mismatched report node: %d", code)
	}
	future := strings.Replace(fail, now, time.Now().Add(time.Hour).UTC().Format(time.RFC3339), 1)
	if code, _ := call(t, srv, "POST", "/v1/nodes/n1/health", "n1-agent", future); code != 400 {
		t.Fatalf("future report: %d", code)
	}
	code, body := call(t, srv, "POST", "/v1/nodes/n1/health", "n1-agent", fail)
	if code != 200 || !strings.Contains(body, `"phase":"Quarantined"`) {
		t.Fatalf("%d %s", code, body)
	}
	if code, _ := call(t, srv, "POST", "/v1/nodes/n1/health", "n1-agent", fail); code != 409 {
		t.Fatalf("replayed report: %d", code)
	}
}

// TestTokensNeedTheirCertificate: with RequireCert, an admin token only
// works with an admin certificate and a node token with that node's; a
// token alone, or with the wrong certificate, is refused.
func TestTokensNeedTheirCertificate(t *testing.T) {
	ca, err := pki.NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	log, _ := events.Open(filepath.Join(dir, "events.jsonl"))
	t.Cleanup(func() { log.Close() })
	s, _ := store.Open(filepath.Join(dir, "state.json"), log)
	s.PutNode(v1.Node{Name: "n1"})
	var armed []string
	api := &Server{Store: s, RequireCert: true, Tokens: map[string]Principal{
		HashToken("ops-token"): {Name: "alice", Role: Operator},
		HashToken("n1-token"):  {Name: "n1-agent", Role: Operator, Node: "n1"},
	}, ArmBoot: func(node, actor string) error { armed = append(armed, node+" "+actor); return nil }}
	head, _ := ca.Issue(pki.Identity{Role: pki.Head, Name: "head"}, time.Hour)
	srv := httptest.NewUnstartedServer(api.Handler())
	srv.TLS = pki.ServerConfig(pki.Static(head), ca.Pool, pki.AnyOf(pki.Admin, pki.Node), true)
	srv.TLS.Certificates = []tls.Certificate{head}
	srv.StartTLS()
	defer srv.Close()
	as := func(id *pki.Identity, method, path, token string) int {
		cert := func() *tls.Certificate { return nil }
		if id != nil {
			c, _ := ca.Issue(*id, time.Hour)
			cert = pki.Static(c)
		}
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: pki.ClientConfig(cert, ca.Pool, pki.AnyOf(pki.Head))}}
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(`{"node":"n1","status":"pass"}`))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	admin := &pki.Identity{Role: pki.Admin, Name: "alice"}
	n1, n2 := &pki.Identity{Role: pki.Node, Name: "n1"}, &pki.Identity{Role: pki.Node, Name: "n2"}
	for name, c := range map[string]struct {
		id                  *pki.Identity
		method, path, token string
		want                int
	}{
		"admin":                    {admin, "GET", "/v1/nodes", "ops-token", 200},
		"admin token, no cert":     {nil, "GET", "/v1/nodes", "ops-token", 403},
		"admin token, node cert":   {n1, "GET", "/v1/nodes", "ops-token", 403},
		"node token, its own cert": {n1, "POST", "/v1/nodes/n1/health", "n1-token", 0}, // past auth
		"node token, another node": {n2, "POST", "/v1/nodes/n1/health", "n1-token", 403},
		"node token, admin cert":   {admin, "POST", "/v1/nodes/n1/health", "n1-token", 403},
		"open a boot window":       {admin, "POST", "/v1/nodes/n1/boot", "ops-token", 200},
		"a window for no node":     {admin, "POST", "/v1/nodes/nope/boot", "ops-token", 404},
	} {
		got := as(c.id, c.method, c.path, c.token)
		if c.want == 0 && (got == 401 || got == 403) || c.want != 0 && got != c.want {
			t.Errorf("%s: %d, want %d", name, got, c.want)
		}
	}
	if len(armed) == 0 || armed[0] != "n1 api/alice" {
		t.Fatalf("armed = %v", armed)
	}
}
