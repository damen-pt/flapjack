package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIdentityRoundTrip(t *testing.T) {
	ca, err := NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ca.Issue(Identity{Tentacle, "r1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	id, err := IdentityOf(c.Leaf)
	if err != nil || id != (Identity{Tentacle, "r1"}) || id.String() != "flapjack://tentacle/r1" {
		t.Fatalf("identity = %v %v", id, err)
	}
	for _, bad := range []Identity{{"operator", "x"}, {Node, "../etc"}, {Node, ""}} {
		if _, err := ca.Issue(bad, time.Hour); err == nil {
			t.Errorf("issued %v", bad)
		}
	}
}

func TestCSRIdentityIsTheCAs(t *testing.T) {
	ca, _ := NewCA("test")
	key, csr, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.SignCSR(csr, Identity{Node, "r1n01"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !key.Public().(ed25519.PublicKey).Equal(cert.PublicKey) {
		t.Fatal("certificate is not over the CSR's key")
	}
	if _, err := ca.SignCSR(append(csr[:len(csr)-1:len(csr)-1], csr[len(csr)-1]^1), Identity{Node, "r1n01"}, time.Hour); err == nil {
		t.Fatal("signed a corrupted CSR")
	}
}

// TestIssuedAtOrdersCertificates: certificates carry their exact issue
// time, so "revoke everything issued before T" separates certificates
// issued within the same second; old certificates with random serials
// fall back to their validity window.
func TestIssuedAtOrdersCertificates(t *testing.T) {
	ca, _ := NewCA("test")
	id := Identity{Node, "r1n01"}
	for _, ttl := range []time.Duration{24 * time.Hour, 3 * time.Second} {
		a, _ := ca.Issue(id, ttl)
		mid := time.Now()
		b, _ := ca.Issue(id, ttl)
		ia, ib := IssuedAt(a.Leaf), IssuedAt(b.Leaf)
		if !ia.Before(mid) || ib.Before(mid) {
			t.Errorf("ttl %s: issued %v and %v around %v", ttl, ia, ib, mid)
		}
		if d := time.Since(ia); d < 0 || d > time.Minute {
			t.Errorf("ttl %s: issued %v, now %v", ttl, ia, time.Now())
		}
	}
	// A pre-existing certificate: random serial, validity backdated a
	// minute.
	legacy := *must(ca.Issue(id, time.Hour)).Leaf
	legacy.SerialNumber = serial()
	if got := IssuedAt(&legacy); !got.Equal(legacy.NotBefore.Add(time.Minute)) {
		t.Errorf("random-serial fallback: %v, NotBefore %v", got, legacy.NotBefore)
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// serve runs an HTTPS echo of the peer identity with cfg.
func serve(t *testing.T, cfg *tls.Config) string {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := PeerIdentity(r)
		if !ok {
			io.WriteString(w, "anonymous")
			return
		}
		io.WriteString(w, id.String())
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return "https://" + ln.Addr().String()
}

func get(cfg *tls.Config, url string) (string, error) {
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

func TestMutualTLS(t *testing.T) {
	ca, _ := NewCA("cluster")
	other, _ := NewCA("someone else")
	tent, _ := ca.Issue(Identity{Tentacle, "r1"}, time.Hour)
	node, _ := ca.Issue(Identity{Node, "r1n01"}, time.Hour)
	head, _ := ca.Issue(Identity{Head, "head"}, time.Hour)
	stranger, _ := other.Issue(Identity{Node, "r1n01"}, time.Hour)
	expired, _ := ca.Issue(Identity{Node, "r1n02"}, -time.Minute)

	url := serve(t, ServerConfig(Static(tent), ca.Pool, AnyOf(Node), false))
	nodeCert := Static(node)
	if got, err := get(ClientConfig(nodeCert, ca.Pool, Only(Identity{Tentacle, "r1"})), url); err != nil || got != "flapjack://node/r1n01" {
		t.Fatalf("node → tentacle: %q %v", got, err)
	}
	// The client refuses a server that is not the identity it expects.
	if _, err := get(ClientConfig(nodeCert, ca.Pool, Only(Identity{Tentacle, "r2"})), url); err == nil || !strings.Contains(err.Error(), "not who") {
		t.Fatalf("connected to the wrong tentacle: %v", err)
	}
	// The server refuses: no certificate, another CA, a role it does not
	// serve, an expired certificate.
	for name, c := range map[string]func() *tls.Certificate{
		"none": func() *tls.Certificate { return nil }, "other CA": Static(stranger), "head role": Static(head), "expired": Static(expired),
	} {
		if _, err := get(ClientConfig(c, ca.Pool, nil), url); err == nil {
			t.Errorf("%s: connected", name)
		}
	}
	// A client that does not trust the cluster CA refuses the server.
	if _, err := get(ClientConfig(nodeCert, other.Pool, nil), url); err == nil {
		t.Fatal("trusted a server from another CA")
	}
	// Optional client auth lets enrollment through without a certificate,
	// but still verifies one if given.
	url = serve(t, ServerConfig(Static(tent), ca.Pool, AnyOf(Node), true))
	if got, err := get(ClientConfig(func() *tls.Certificate { return nil }, ca.Pool, nil), url); err != nil || got != "anonymous" {
		t.Fatalf("enrollment connection: %q %v", got, err)
	}
	if _, err := get(ClientConfig(Static(stranger), ca.Pool, nil), url); err == nil {
		t.Fatal("optional mode accepted a certificate from another CA")
	}
	// TLS 1.2 is refused outright.
	cfg := ClientConfig(nodeCert, ca.Pool, nil)
	cfg.MaxVersion = tls.VersionTLS12
	if _, err := get(cfg, url); err == nil {
		t.Fatal("TLS 1.2 connected")
	}
}

func TestEnvelope(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	e := SignGeneration(key, "r1n01", 3, "abc", 100)
	if err := e.Check(pub, "r1n01", 3, "abc"); err != nil {
		t.Fatal(err)
	}
	for name, check := range map[string]func() error{
		"other node":   func() error { return e.Check(pub, "r1n02", 3, "abc") },
		"other gen":    func() error { return e.Check(pub, "r1n01", 4, "abc") },
		"other digest": func() error { return e.Check(pub, "r1n01", 3, "abd") },
		"relabelled": func() error {
			f := e
			f.Node = "r1n02"
			return f.Check(pub, "r1n02", 3, "abc")
		},
		"no key": func() error { return e.Check(nil, "r1n01", 3, "abc") },
		"backdated": func() error {
			f := e
			f.Issued = 50
			return f.Check(pub, "r1n01", 3, "abc")
		},
	} {
		if check() == nil {
			t.Errorf("%s: verified", name)
		}
	}
}

func TestSignerFreshness(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	frozen := time.Unix(1000, 0)
	s := &Signer{Key: key, Now: func() time.Time { return frozen }}
	a, b := s.Sign("n", 1, "d"), s.Sign("n", 1, "d")
	if b.Issued <= a.Issued {
		t.Fatalf("issue times %d, %d do not increase on a frozen clock", a.Issued, b.Issued)
	}
	if err := b.Fresh(a.Issued); err != nil {
		t.Fatal(err)
	}
	if err := a.Fresh(a.Issued); err != nil {
		t.Fatal("the same envelope again is not a replay:", err)
	}
	if err := a.Fresh(b.Issued); !errors.Is(err, ErrReplayed) {
		t.Fatalf("older envelope: %v", err)
	}
}

func TestSignerFloorSurvivesClockStepBack(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	floor := filepath.Join(t.TempDir(), "floor")
	clock := time.Unix(5000, 0)
	s := &Signer{Key: key, Floor: floor, Now: func() time.Time { return clock }}
	first := s.Sign("n", 1, "d")
	clock = clock.Add(10 * time.Second)
	second := s.Sign("n", 2, "d")
	// The head restarts with its clock an hour behind.
	clock = clock.Add(-time.Hour)
	restarted := &Signer{Key: key, Floor: floor, Now: func() time.Time { return clock }}
	third := restarted.Sign("n", 3, "d")
	if third.Fresh(second.Issued) != nil || third.Issued <= first.Issued {
		t.Fatalf("after a clock step back, issued %d is not after %d", third.Issued, second.Issued)
	}
}
