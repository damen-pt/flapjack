package server

import (
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/apiserver"
	"github.com/damen-pt/flapjack/internal/attest"
	"github.com/damen-pt/flapjack/internal/events"
	"github.com/damen-pt/flapjack/internal/pki"
)

// manifestWith fetches the agent manifest presenting cert.
func manifestWith(o *Overlays, cert *x509.Certificate) int {
	r := httptest.NewRequest("GET", "/agent/v1/manifest?have=-1", nil)
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains: [][]*x509.Certificate{{cert, testCA().Cert}}}
	w := httptest.NewRecorder()
	o.AgentHandler().ServeHTTP(w, r)
	return w.Code
}

// TestEnrollmentKeepsOneIdentity: a ticket enrollment revokes the node's
// earlier certificates everywhere (agent routes and renewal), a ticket is
// only good from the node's address, a class's minimum tier stops
// ticket (legacy) enrollment, and a retired node gets nothing.
func TestEnrollmentKeepsOneIdentity(t *testing.T) {
	o, _ := overlaySetup(t)
	ca := testCA()
	tk := &attest.Tickets{Key: make([]byte, 32), TTL: time.Minute, Armed: true}
	addr := net.ParseIP("10.0.0.11")
	n1 := func() v1.Node { n, _ := o.Store.Node("n1"); return n }
	ticket := func() string {
		tk.Arm("52:54:00:00:00:11")
		s, err := tk.Issue("52:54:00:00:00:11")
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	type identity struct {
		key  ed25519.PrivateKey
		cert *x509.Certificate
	}
	enroll := func(tkt string, from net.IP) (identity, error) {
		key, csr, _ := pki.NewKey()
		seal, _ := pki.NewSealKey()
		c, err := o.enroll(ca, tk, time.Hour, n1(), EnrollRequest{Node: "n1", MAC: "52:54:00:00:00:11", Ticket: tkt, CSR: csr,
			SealKey: seal.PublicKey().Bytes()}, from)
		return identity{key, c}, err
	}
	renew := func(id identity) error {
		_, csr, _ := pki.NewKey()
		_, err := o.enroll(ca, tk, time.Hour, n1(), EnrollRequest{Node: "n1", CSR: csr, Cert: id.cert.Raw,
			Proof: ed25519.Sign(id.key, RenewMessage(csr))}, nil)
		return err
	}

	tkt := ticket()
	if _, err := enroll(tkt, net.ParseIP("10.0.0.99")); err == nil || !strings.Contains(err.Error(), "own address") {
		t.Fatalf("a ticket enrolled from another address: %v", err)
	}
	_, csr, _ := pki.NewKey()
	if _, err := o.enroll(ca, tk, time.Hour, n1(), EnrollRequest{Node: "n1", MAC: "52:54:00:00:00:11", Ticket: tkt, CSR: csr}, addr); err == nil ||
		!strings.Contains(err.Error(), "seal key") {
		t.Fatalf("enrolled without a seal key: %v", err)
	}
	first, err := enroll(tkt, addr) // the refusal above did not spend it
	if err != nil {
		t.Fatal(err)
	}
	if st := n1().Status; !st.CertsFrom.Equal(pki.IssuedAt(first.cert)) || len(st.SealKey) == 0 {
		t.Fatalf("after enrollment: certsFrom %v, seal key %d bytes", st.CertsFrom, len(st.SealKey))
	}
	if code := manifestWith(o, first.cert); code != 200 {
		t.Fatalf("enrolled certificate: %d", code)
	}
	if err := renew(first); err != nil {
		t.Fatalf("renewal: %v", err)
	}

	// An impostor with a fresh ticket takes the identity: the first
	// certificate is refused from then on, renewal included.
	second, err := enroll(ticket(), addr)
	if err != nil {
		t.Fatal(err)
	}
	if code := manifestWith(o, first.cert); code != 403 {
		t.Fatalf("superseded certificate: %d", code)
	}
	if err := renew(first); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("renewed a superseded certificate: %v", err)
	}
	if code := manifestWith(o, second.cert); code != 200 {
		t.Fatalf("current certificate: %d", code)
	}
	if evs, _ := o.Store.Events.Query(events.Filter{Types: []string{"pki.superseded"}}); len(evs) != 1 {
		t.Fatalf("superseded events: %+v", evs)
	}

	third, err := enroll(ticket(), addr)
	if err != nil {
		t.Fatal(err)
	}

	// Retired: nothing, not even its current certificate.
	if _, err := o.Store.SetPhase("n1", v1.PhaseRetired, "decommissioned", "test"); err != nil {
		t.Fatal(err)
	}
	if code := manifestWith(o, third.cert); code != 403 {
		t.Fatalf("retired node's certificate: %d", code)
	}
	if err := renew(third); err == nil {
		t.Fatal("a retired node renewed")
	}
	if _, err := enroll(ticket(), addr); err == nil {
		t.Fatal("a retired node enrolled")
	}
}

// TestSecretsAreSealedToTheNode: a secret's content is only ever served
// sealed to the node's current seal key, and only that key, bound to that
// node and digest, opens it. Other content stays in the clear.
func TestSecretsAreSealedToTheNode(t *testing.T) {
	o, dir := overlaySetup(t)
	o.Renderer.SecretsDir = filepath.Join(dir, "secrets")
	os.MkdirAll(o.Renderer.SecretsDir, 0o750)
	os.WriteFile(filepath.Join(o.Renderer.SecretsDir, "munge.key"), []byte("MUNGE-SECRET"), 0o600)
	os.WriteFile(filepath.Join(dir, "overlays/base/overlay.json"), []byte(`{"secrets": {"/etc/munge/munge.key": {"secret": "munge.key"}}}`), 0o644)
	if _, err := o.Build(apiserver.BuildRequest{Nodes: []string{"n1"}, Switch: true}, "test"); err != nil {
		t.Fatal(err)
	}
	g, _ := o.Gens.Current("n1")
	secret, motd := g.Manifest.Entries["/etc/munge/munge.key"], g.Manifest.Entries["/etc/motd"]
	if !secret.Secret || motd.Secret {
		t.Fatalf("secret flags: %+v %+v", secret, motd)
	}
	ca := testCA()
	get := func(cert *x509.Certificate, d string) (int, string, []byte) {
		r := httptest.NewRequest("GET", "/agent/v1/content/"+d, nil)
		r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{cert},
			VerifiedChains: [][]*x509.Certificate{{cert, ca.Cert}}}
		w := httptest.NewRecorder()
		o.AgentHandler().ServeHTTP(w, r)
		return w.Code, w.Header().Get("Content-Type"), w.Body.Bytes()
	}
	unenrolled, _ := ca.Issue(pki.Identity{Role: pki.Node, Name: "n1"}, time.Hour)
	if code, _, _ := get(unenrolled.Leaf, secret.Digest); code != http.StatusConflict {
		t.Fatalf("secret for a node with no seal key: %d", code)
	}

	tk := &attest.Tickets{Key: make([]byte, 32), TTL: time.Minute, Armed: true}
	enroll := func() (*x509.Certificate, hpke.PrivateKey) {
		tk.Arm("52:54:00:00:00:11")
		tkt, _ := tk.Issue("52:54:00:00:00:11")
		seal, _ := pki.NewSealKey()
		_, csr, _ := pki.NewKey()
		n, _ := o.Store.Node("n1")
		c, err := o.enroll(ca, tk, time.Hour, n, EnrollRequest{Node: "n1", MAC: "52:54:00:00:00:11", Ticket: tkt, CSR: csr,
			SealKey: seal.PublicKey().Bytes()}, net.ParseIP("10.0.0.11"))
		if err != nil {
			t.Fatal(err)
		}
		return c, seal
	}
	cert, k1 := enroll()
	code, ctype, blob := get(cert, secret.Digest)
	if code != 200 || ctype != pki.SealedContentType || strings.Contains(string(blob), "MUNGE-SECRET") {
		t.Fatalf("secret served %d %q %q", code, ctype, blob)
	}
	if plain, err := pki.Unseal(k1, "n1", secret.Digest, blob); err != nil || string(plain) != "MUNGE-SECRET" {
		t.Fatalf("unseal: %q %v", plain, err)
	}
	if _, err := pki.Unseal(k1, "n2", secret.Digest, blob); err == nil {
		t.Error("a blob for n1 opened as n2's")
	}
	if _, err := pki.Unseal(k1, "n1", motd.Digest, blob); err == nil {
		t.Error("a blob for one file opened as another")
	}
	if code, ctype, body := get(cert, motd.Digest); code != 200 || ctype == pki.SealedContentType || string(body) != "hello n1\n" {
		t.Errorf("plain content served %d %q %q", code, ctype, body)
	}

	// Booted again: a new key, and the old one opens nothing new.
	cert2, k2 := enroll()
	_, _, blob = get(cert2, secret.Digest)
	if _, err := pki.Unseal(k1, "n1", secret.Digest, blob); err == nil {
		t.Error("the previous boot's key opened a secret")
	}
	if plain, err := pki.Unseal(k2, "n1", secret.Digest, blob); err != nil || string(plain) != "MUNGE-SECRET" {
		t.Errorf("current key: %q %v", plain, err)
	}
}

// TestRebootNotices: a relayed reboot announcement opens a window only
// with the node's own fresh, unused signature from a certificate it still
// accepts.
func TestRebootNotices(t *testing.T) {
	o, _ := overlaySetup(t)
	ca := testCA()
	n1, _ := o.Store.Node("n1")
	c1, _ := ca.Issue(pki.Identity{Role: pki.Node, Name: "n1"}, time.Hour)
	c2, _ := ca.Issue(pki.Identity{Role: pki.Node, Name: "n2"}, time.Hour)
	k1, k2 := c1.PrivateKey.(ed25519.PrivateKey), c2.PrivateKey.(ed25519.PrivateKey)
	now := time.Now()
	var s notices
	good := SignRebootNotice("n1", c1.Leaf.Raw, k1, now, "nonce-1")
	if err := s.check(ca, n1, &good, now); err != nil {
		t.Fatal(err)
	}
	stale := SignRebootNotice("n1", c1.Leaf.Raw, k1, now.Add(-10*time.Minute), "nonce-3")
	forged := good
	forged.Nonce = "nonce-4" // signature no longer covers it
	theirs := SignRebootNotice("n1", c2.Leaf.Raw, k2, now, "nonce-5")
	for name, rn := range map[string]*RebootNotice{
		"none (a tentacle on its own)": nil,
		"replayed":                     &good,
		"stale":                        &stale,
		"altered":                      &forged,
		"another node's certificate":   &theirs,
	} {
		if err := s.check(ca, n1, rn, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	revoked := n1
	revoked.Status.CertsFrom = now.Add(time.Second)
	fresh := SignRebootNotice("n1", c1.Leaf.Raw, k1, now, "nonce-6")
	if err := s.check(ca, revoked, &fresh, now); err == nil {
		t.Error("a revoked certificate's notice was accepted")
	}
}
