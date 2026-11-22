package pki

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestInitIsIdempotentAndComplete(t *testing.T) {
	dir := t.TempDir()
	wrote, err := Init(InitOptions{Dir: dir, BootHosts: []string{"10.99.0.1", "head.cluster"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{CACertFile, CAKeyFile, GenKeyFile, GenPubFile, TicketKeyFile, HeadCertFile, HeadKeyFile,
		BootCACertFile, BootCAKeyFile, BootCertFile, BootKeyFile} {
		if !slices.Contains(wrote, filepath.Join(dir, f)) {
			t.Errorf("Init did not write %s", f)
		}
	}
	before, _ := os.ReadFile(filepath.Join(dir, CAKeyFile))
	again, err := Init(InitOptions{Dir: dir, BootHosts: []string{"10.99.0.1"}})
	if err != nil || len(again) != 0 {
		t.Fatalf("rerun wrote %v, %v", again, err)
	}
	if after, _ := os.ReadFile(filepath.Join(dir, CAKeyFile)); string(after) != string(before) {
		t.Fatal("rerun replaced the CA key")
	}
	if fi, _ := os.Stat(filepath.Join(dir, CAKeyFile)); fi.Mode().Perm()&0o007 != 0 {
		t.Fatalf("CA key mode %v is world-accessible", fi.Mode())
	}

	// The pieces fit together.
	ca, err := LoadCA(filepath.Join(dir, CACertFile), filepath.Join(dir, CAKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	head, err := tls.LoadX509KeyPair(filepath.Join(dir, HeadCertFile), filepath.Join(dir, HeadKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if id, err := Verify(ca.Pool, []*x509.Certificate{head.Leaf}, x509.ExtKeyUsageServerAuth); err != nil || id != (Identity{Head, "head"}) {
		t.Fatalf("head certificate: %v %v", id, err)
	}
	key, err := LoadSigningKey(filepath.Join(dir, GenKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := LoadTrustKey(filepath.Join(dir, GenPubFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := (&Signer{Key: key}).Sign("n", 1, "d").Check(pub, "n", 1, "d"); err != nil {
		t.Fatal(err)
	}
	boot, err := tls.LoadX509KeyPair(filepath.Join(dir, BootCertFile), filepath.Join(dir, BootKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := boot.PrivateKey.(*rsa.PrivateKey); !ok {
		t.Fatalf("boot key is %T; iPXE needs RSA", boot.PrivateKey)
	}
	bootCA, _ := LoadPool(filepath.Join(dir, BootCACertFile))
	if _, err := boot.Leaf.Verify(x509.VerifyOptions{Roots: bootCA, DNSName: "10.99.0.1"}); err != nil {
		t.Fatalf("boot certificate for 10.99.0.1: %v", err)
	}
	if _, err := boot.Leaf.Verify(x509.VerifyOptions{Roots: ca.Pool, DNSName: "10.99.0.1"}); err == nil {
		t.Fatal("boot certificate verifies against the cluster CA")
	}
}

func TestFileCertReloads(t *testing.T) {
	dir := t.TempDir()
	ca, _ := NewCA("t")
	cp, kp := filepath.Join(dir, "t.pem"), filepath.Join(dir, "t.key")
	first, _ := ca.Issue(Identity{Tentacle, "r1"}, time.Hour)
	if err := WriteIdentity(cp, kp, first); err != nil {
		t.Fatal(err)
	}
	if err := WriteIdentity(cp, kp, first); err == nil {
		t.Fatal("WriteIdentity overwrote a certificate")
	}
	get, err := FileCert(cp, kp)
	if err != nil {
		t.Fatal(err)
	}
	if get().Leaf.SerialNumber.Cmp(first.Leaf.SerialNumber) != 0 {
		t.Fatal("wrong certificate")
	}
	second, _ := ca.Issue(Identity{Tentacle, "r1"}, time.Hour)
	os.Remove(cp)
	os.Remove(kp)
	WriteIdentity(cp, kp, second)
	later := time.Now().Add(time.Second)
	os.Chtimes(cp, later, later)
	if get().Leaf.SerialNumber.Cmp(second.Leaf.SerialNumber) != 0 {
		t.Fatal("re-issued certificate not picked up")
	}
	os.WriteFile(kp, []byte("garbage"), 0o600)
	os.Chtimes(kp, later.Add(time.Second), later.Add(time.Second))
	if get().Leaf.SerialNumber.Cmp(second.Leaf.SerialNumber) != 0 {
		t.Fatal("a broken key replaced the working pair")
	}
}
