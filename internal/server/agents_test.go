package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/attest"
	"github.com/damen-pt/flapjack/internal/bmc"
	"github.com/damen-pt/flapjack/internal/events"
	"github.com/damen-pt/flapjack/internal/pki"
)

// TestHeadAgentsEnrollOverMTLS: a node of a rack without a tentacle
// enrolls with the head using its boot ticket, then reads its overlays
// with the certificate; nothing is served without one, and a tentacle
// rack's node is sent to its tentacle.
func TestHeadAgentsEnrollOverMTLS(t *testing.T) {
	o, _ := overlaySetup(t)
	ca := testCA()
	tk := &attest.Tickets{Key: make([]byte, 32), TTL: time.Minute, Armed: true}
	h := &HeadAgents{Overlays: o, CA: ca, Tickets: tk, Windows: &Windows{Store: o.Store, Tickets: tk},
		Tentacles: map[string]string{"r9": "https://10.9.9.1:8443"}}
	head, _ := ca.Issue(pki.Identity{Role: pki.Head, Name: "head"}, time.Hour)
	srv := httptest.NewUnstartedServer(h.Handler())
	srv.TLS = pki.ServerConfig(pki.Static(head), ca.Pool, h.Allow, true)
	srv.TLS.Certificates = []tls.Certificate{head}
	srv.StartTLS()
	defer srv.Close()

	var cert *tls.Certificate
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: pki.ClientConfig(func() *tls.Certificate { return cert }, ca.Pool, pki.AnyOf(pki.Head))}}
	get := func(path string) int {
		resp, err := client.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := get("/agent/v1/manifest?have=-1"); code != http.StatusUnauthorized {
		t.Fatalf("manifest without a certificate = %d", code)
	}

	key, csr, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	seal, _ := pki.NewSealKey()
	enroll := func(req EnrollRequest) (int, EnrollResponse) {
		if req.Ticket != "" && req.SealKey == nil {
			req.SealKey = seal.PublicKey().Bytes()
		}
		b, _ := json.Marshal(req)
		resp, err := client.Post(srv.URL+"/agent/v1/enroll", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out EnrollResponse
		json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	if code, _ := enroll(EnrollRequest{Node: "n1", MAC: "52:54:00:00:00:11", Ticket: "forged.x", CSR: csr}); code != http.StatusForbidden {
		t.Fatalf("forged ticket = %d", code)
	}
	tk.Arm("52:54:00:00:00:11")
	ticket, _ := tk.Issue("52:54:00:00:00:11")
	if code, _ := enroll(EnrollRequest{Node: "n2", MAC: "52:54:00:00:00:11", Ticket: ticket, CSR: csr}); code != http.StatusForbidden {
		t.Fatalf("n1's ticket enrolled n2: %d", code)
	}
	// A ticket is only good from the node's own address (n1 is 10.0.0.11;
	// this client is 127.0.0.1), and a refusal there does not spend it.
	if code, _ := enroll(EnrollRequest{Node: "n1", MAC: "52:54:00:00:00:11", Ticket: ticket, CSR: csr}); code != http.StatusForbidden {
		t.Fatalf("a ticket enrolled from another address: %d", code)
	}
	n1, _ := o.Store.Node("n1")
	n1.Interfaces[0].IP = "127.0.0.1"
	if err := o.Store.PutNode(n1); err != nil {
		t.Fatal(err)
	}
	code, out := enroll(EnrollRequest{Node: "n1", MAC: "52:54:00:00:00:11", Ticket: ticket, CSR: csr})
	if code != 200 {
		t.Fatalf("enroll = %d", code)
	}
	leaf, err := pki.ParseCert(out.Cert)
	if err != nil {
		t.Fatal(err)
	}
	cert = &tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}
	client.CloseIdleConnections() // as the agent does: the next handshake presents it
	if code := get("/agent/v1/manifest?have=-1"); code != 200 {
		t.Fatalf("manifest with the certificate = %d", code)
	}
	if code, _ := enroll(EnrollRequest{Node: "n1", MAC: "52:54:00:00:00:11", Ticket: ticket, CSR: csr}); code != http.StatusForbidden {
		t.Fatalf("a ticket enrolled twice: %d", code)
	}

	// Its reboot announcement opens its window.
	resp, err := client.Post(srv.URL+"/agent/v1/rebooting", "", nil)
	if err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("rebooting = %v %v", resp, err)
	}
	if _, err := tk.Issue("52:54:00:00:00:11"); err != nil {
		t.Fatalf("no window after the reboot announcement: %v", err)
	}

	// A tentacle rack's node enrolls through its tentacle only.
	n, _ := o.Store.Node("n2")
	n.Rack = "r9"
	o.Store.PutNode(n)
	tk.Arm("52:54:00:00:00:12")
	t2, _ := tk.Issue("52:54:00:00:00:12")
	_, csr2, _ := pki.NewKey()
	if code, _ := enroll(EnrollRequest{Node: "n2", MAC: "52:54:00:00:00:12", Ticket: t2, CSR: csr2}); code != http.StatusForbidden {
		t.Fatalf("a tentacle rack's node enrolled with the head: %d", code)
	}
}

type flakyBMC struct {
	bmc.Fake
	state string
	err   error
}

func (f *flakyBMC) PowerState(context.Context) (string, error) { return f.state, f.err }

// TestPowerWatchArmsOnPowerOn: the watcher opens a window when the BMC
// sees a node go from off to on, and on its first look (or after the BMC
// was unreachable) only while the agent is silent; once per power-on.
func TestPowerWatchArmsOnPowerOn(t *testing.T) {
	o, _ := overlaySetup(t)
	tk := &attest.Tickets{Key: make([]byte, 32), TTL: time.Minute, Armed: true}
	now := time.Unix(1_700_000_000, 0)
	b1, b2 := &flakyBMC{state: "off"}, &flakyBMC{state: "on"}
	w := &PowerWatch{Windows: &Windows{Store: o.Store, Tickets: tk}, Now: func() time.Time { return now },
		Driver: func(n v1.Node) bmc.Driver {
			if n.Name == "n1" {
				return b1
			}
			return b2
		}}
	opened := func(mac string) bool {
		_, err := tk.Issue(mac)
		return err == nil
	}
	// n2 is on and its agent reported just now: a running node.
	o.Store.ReportAgent("n2", v1.AgentStatus{Seen: now})
	w.Poll(context.Background())
	if opened("52:54:00:00:00:11") || opened("52:54:00:00:00:12") {
		t.Fatal("a window opened for an off node or a running one")
	}
	b1.state = "on" // n1 powers on
	w.Poll(context.Background())
	if !opened("52:54:00:00:00:11") {
		t.Fatal("no window after the BMC saw a power-on")
	}
	w.Poll(context.Background())
	if opened("52:54:00:00:00:11") {
		t.Fatal("a second window for the same power-on")
	}
	// n2's BMC drops out and comes back with the agent silent: a site
	// outage, say.
	b2.state, b2.err = "", context.DeadlineExceeded
	w.Poll(context.Background())
	now = now.Add(10 * time.Minute)
	b2.state, b2.err = "on", nil
	w.Poll(context.Background())
	if !opened("52:54:00:00:00:12") {
		t.Fatal("no window after the BMC came back with the node on and its agent silent")
	}
	evs, _ := o.Store.Events.Query(events.Filter{Types: []string{"boot.window_opened"}})
	if len(evs) != 2 || evs[0].Actor != "bmc-watch" {
		t.Fatalf("events = %+v", evs)
	}
}

func TestRedactTokens(t *testing.T) {
	for in, want := range map[string]string{
		"/images/el9@abc/eyJ.sig/vmlinuz": "/images/el9@abc/…/vmlinuz",
		"/boot/52-54.ipxe":                "/boot/52-54.ipxe",
		"/images/el9":                     "/images/el9",
	} {
		if got := redactTokens(in); got != want {
			t.Errorf("%s → %s", in, got)
		}
	}
	if strings.Contains(redactTokens("https://h/images/v/SECRET/rootfs.squashfs"), "SECRET") {
		t.Error("token in a DHCP file name logged")
	}
}
