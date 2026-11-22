package agent

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/damen-pt/flapjack/internal/pki"
)

// TestSealKeySurvivesARestart: a restarted agent reloads its seal key with
// its certificate and still opens its secrets; an identity saved without
// one is not loaded, so the agent enrolls again instead of running without
// its secrets.
func TestSealKeySurvivesARestart(t *testing.T) {
	ca, _ := pki.NewCA("test")
	c, _ := ca.Issue(pki.Identity{Role: pki.Node, Name: "n1"}, time.Hour)
	key := c.PrivateKey.(ed25519.PrivateKey)
	seal, _ := pki.NewSealKey()
	dir := t.TempDir()
	if err := (&Credentials{Node: "n1", Dir: dir}).save(key, c.Leaf, seal); err != nil {
		t.Fatal(err)
	}
	blob, err := pki.Seal(seal.PublicKey().Bytes(), "n1", "sha256:abc", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	again := &Credentials{Node: "n1", Dir: dir}
	if !again.Load() {
		t.Fatal("saved identity not loaded")
	}
	if plain, err := again.Unseal("sha256:abc", blob); err != nil || string(plain) != "secret" {
		t.Fatalf("unseal after restart: %q %v", plain, err)
	}

	bare := t.TempDir()
	(&Credentials{Node: "n1", Dir: bare}).save(key, c.Leaf, nil)
	if (&Credentials{Node: "n1", Dir: bare}).Load() {
		t.Fatal("loaded an identity with no seal key")
	}
	if _, err := (&Credentials{Node: "n1"}).Unseal("sha256:abc", blob); err == nil {
		t.Fatal("unsealed without a key")
	}
}
