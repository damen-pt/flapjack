package apiserver

import (
	"crypto/tls"
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

// TestNamesAndArgsCannotInject: what reaches iPXE scripts, kernel command
// lines, paths and certificates is validated.
func TestNamesAndArgsCannotInject(t *testing.T) {
	srv, s := setup(t)
	srv.Config.Handler = (&Server{Store: s, Tokens: map[string]Principal{
		HashToken("admin-token"): {Name: "root", Role: Admin},
	}}).Handler()
	for path, body := range map[string]string{
		"/v1/nodes/n%0Aimgfetch": `{}`,
		"/v1/nodes/n%20x":        `{}`,
		"/v1/nodes/ok":           `{"rack":"r1 flapjack.ticket=x"}`,
		"/v1/nodes/ok2":          `{"class":"c${x}"}`,
		"/v1/classes/c%0Aboot":   `{}`,
		"/v1/classes/args":       `{"bootArgs":["console=ttyS0 init=/bin/sh"]}`,
		"/v1/classes/ctrl":       `{"bootArgs":["a\nb"]}`,
		"/v1/classes/expand":     `{"bootArgs":["x=${net0/ip}"]}`,
		"/v1/classes/reserved":   `{"bootArgs":["flapjack.rootfs="]}`,
		"/v1/classes/image":      `{"image":"el9\nchain http://evil/"}`,
		"/v1/classes/.hidden":    `{}`,
	} {
		if code, out := call(t, srv, "PUT", path, "admin-token", body); code != http.StatusBadRequest {
			t.Errorf("PUT %s %s = %d %s, want 400", path, body, code, out)
		}
	}
	for path, body := range map[string]string{
		"/v1/classes/compute": `{"image":"rocky9@3f2a9c1b7d0e","bootArgs":["console=ttyS0,115200","quiet"]}`,
		"/v1/nodes/r1n01":     `{"class":"compute","rack":"r1","interfaces":[{"mac":"52:54:00:01:01:01","ip":"10.99.1.1"}]}`,
	} {
		if code, out := call(t, srv, "PUT", path, "admin-token", body); code != 200 {
			t.Errorf("PUT %s = %d %s", path, code, out)
		}
	}
	// A new node's spec cannot declare an identity it never enrolled.
	call(t, srv, "PUT", "/v1/nodes/r1n02", "admin-token", `{"status":{"certsFrom":"2000-01-01T00:00:00Z","sealKey":"AAAA"}}`)
	if n, _ := s.Node("r1n02"); len(n.Status.SealKey) != 0 || !n.Status.CertsFrom.IsZero() {
		t.Fatalf("declared status kept: %+v", n.Status)
	}
}

// TestRevokeCutsOffNodeCertificates: an admin revokes a node; its node
// token then works only with a certificate issued afterwards, and admin
// tokens bound to a certificate name want that certificate.
func TestRevokeCutsOffNodeCertificates(t *testing.T) {
	ca, _ := pki.NewCA("test")
	dir := t.TempDir()
	log, _ := events.Open(filepath.Join(dir, "events.jsonl"))
	t.Cleanup(func() { log.Close() })
	s, _ := store.Open(filepath.Join(dir, "state.json"), log)
	s.PutNode(v1.Node{Name: "n1"})
	var revoked []string
	api := &Server{Store: s, RequireCert: true, Tokens: map[string]Principal{
		HashToken("root-token"): {Name: "root", Role: Admin, Cert: "root"},
		HashToken("ops-token"):  {Name: "alice", Role: Operator},
		HashToken("n1-token"):   {Name: "n1-agent", Role: Operator, Node: "n1"},
	}, Revoked: func(n string) { revoked = append(revoked, n) }}
	head, _ := ca.Issue(pki.Identity{Role: pki.Head, Name: "head"}, time.Hour)
	srv := httptest.NewUnstartedServer(api.Handler())
	srv.TLS = pki.ServerConfig(pki.Static(head), ca.Pool, pki.AnyOf(pki.Admin, pki.Node), true)
	srv.TLS.Certificates = []tls.Certificate{head}
	srv.StartTLS()
	defer srv.Close()
	as := func(c tls.Certificate, method, path, token, body string) int {
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: pki.ClientConfig(pki.Static(c), ca.Pool, pki.AnyOf(pki.Head))}}
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	root, _ := ca.Issue(pki.Identity{Role: pki.Admin, Name: "root"}, time.Hour)
	bob, _ := ca.Issue(pki.Identity{Role: pki.Admin, Name: "bob"}, time.Hour)
	old, _ := ca.Issue(pki.Identity{Role: pki.Node, Name: "n1"}, time.Hour)
	health := `{"node":"n1","status":"pass"}`

	if code := as(bob, "GET", "/v1/nodes", "root-token", ""); code != 403 {
		t.Errorf("root's token with bob's certificate: %d", code)
	}
	if code := as(bob, "GET", "/v1/nodes", "ops-token", ""); code != 200 {
		t.Errorf("an unbound token with any admin certificate: %d", code)
	}
	if code := as(old, "POST", "/v1/nodes/n1/health", "n1-token", health); code == 401 || code == 403 {
		t.Fatalf("node token before revocation: %d", code)
	}
	if code := as(bob, "POST", "/v1/nodes/n1/revoke", "ops-token", `{"reason":"x"}`); code != 403 {
		t.Errorf("an operator revoked: %d", code)
	}
	if code := as(root, "POST", "/v1/nodes/n1/revoke", "root-token", `{}`); code != 400 {
		t.Errorf("revoke without a reason: %d", code)
	}
	if code := as(root, "POST", "/v1/nodes/n1/revoke", "root-token", `{"reason":"stolen"}`); code != 200 {
		t.Fatalf("revoke: %d", code)
	}
	if code := as(old, "POST", "/v1/nodes/n1/health", "n1-token", health); code != 403 {
		t.Errorf("node token with a revoked certificate: %d", code)
	}
	fresh, _ := ca.Issue(pki.Identity{Role: pki.Node, Name: "n1"}, time.Hour)
	if code := as(fresh, "POST", "/v1/nodes/n1/health", "n1-token", health); code == 401 || code == 403 {
		t.Errorf("node token with a certificate issued after: %d", code)
	}
	if len(revoked) != 1 || revoked[0] != "n1" {
		t.Errorf("relays told: %v", revoked)
	}
	if evs, _ := log.Query(events.Filter{Types: []string{"pki.revoked"}}); len(evs) != 1 || evs[0].Actor != "root" || evs[0].Message != "stolen" {
		t.Errorf("audit: %+v", evs)
	}
}

// TestClientEventsAreLimited: an admin tool records firmware and BIOS
// changes on a node's timeline, as itself; no client can write boot, PKI
// or audit history, and operators cannot write at all.
func TestClientEventsAreLimited(t *testing.T) {
	srv, s := setup(t)
	srv.Config.Handler = (&Server{Store: s, Tokens: map[string]Principal{
		HashToken("admin-token"): {Name: "root", Role: Admin},
		HashToken("ops-token"):   {Name: "alice", Role: Operator},
	}}).Handler()
	ok := `{"type":"firmware.flashed","message":"BMC 1.0 → 1.1","actor":"someone-else","category":"admin","data":{"component":"BMC"}}`
	if code, out := call(t, srv, "POST", "/v1/nodes/n1/events", "ops-token", ok); code != http.StatusForbidden {
		t.Fatalf("operator recorded an event: %d %s", code, out)
	}
	for _, body := range []string{`{"type":"pki.enrolled"}`, `{"type":"boot.window_opened"}`, `{"type":"class.put"}`, `{}`} {
		if code, out := call(t, srv, "POST", "/v1/nodes/n1/events", "admin-token", body); code != http.StatusBadRequest {
			t.Errorf("event %s: %d %s", body, code, out)
		}
	}
	if code, out := call(t, srv, "POST", "/v1/nodes/nope/events", "admin-token", ok); code != http.StatusNotFound {
		t.Errorf("event for an unknown node: %d %s", code, out)
	}
	if code, out := call(t, srv, "POST", "/v1/nodes/n1/events", "admin-token", ok); code != 200 {
		t.Fatalf("firmware event: %d %s", code, out)
	}
	evs, _ := s.Events.Query(events.Filter{Types: []string{"firmware.flashed"}})
	if len(evs) != 1 || evs[0].Actor != "root" || evs[0].Category != events.Change || evs[0].Node != "n1" || evs[0].Data["component"] != "BMC" {
		t.Fatalf("recorded %+v", evs)
	}
	s.PutClass(v1.NodeClass{Name: "compute"})
	if code, out := call(t, srv, "GET", "/v1/classes/compute", "admin-token", ""); code != 200 || !strings.Contains(out, `"compute"`) {
		t.Fatalf("GET class: %d %s", code, out)
	}
	if code, _ := call(t, srv, "GET", "/v1/classes/nope", "admin-token", ""); code != http.StatusNotFound {
		t.Fatalf("GET unknown class: %d", code)
	}
}
