package pki

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetachedSignatures(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(InitOptions{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	s, err := LoadCodeSigner(dir)
	if err != nil {
		t.Fatal(err)
	}
	roots, _ := LoadPool(filepath.Join(dir, BootCACertFile))
	kernel := bytes.Repeat([]byte("vmlinuz "), 100000)
	sig, err := s.SignDetached(bytes.NewReader(kernel))
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := s.SignDetached(bytes.NewReader(kernel)); !bytes.Equal(again, sig) {
		t.Fatal("signatures are not deterministic")
	}
	if err := VerifyDetached(sig, kernel, roots); err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Clone(kernel)
	tampered[5000] ^= 1
	if VerifyDetached(sig, tampered, roots) == nil {
		t.Fatal("tampered content verified")
	}
	// Signed by a key the boot CA did not certify (a tentacle's own).
	other := t.TempDir()
	Init(InitOptions{Dir: other})
	os2, _ := LoadCodeSigner(other)
	forged, _ := os2.SignDetached(bytes.NewReader(tampered))
	if VerifyDetached(forged, tampered, roots) == nil {
		t.Fatal("a signature from another boot CA verified")
	}
	if b, err := os.ReadFile(filepath.Join(dir, IPXEEmbedFile)); err != nil || !strings.Contains(string(b), "imgtrust --permanent") {
		t.Fatalf("embed script: %v", err)
	}

	// OpenSSL, independently: the format iPXE reads is the one
	// `openssl cms -sign -binary -noattr` writes.
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("no openssl to cross-check with")
	}
	w := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(w, name)
		os.WriteFile(p, b, 0o644)
		return p
	}
	sigPath, kPath, tPath := write("vmlinuz.sig", sig), write("vmlinuz", kernel), write("tampered", tampered)
	verify := func(content string) ([]byte, error) {
		return exec.Command(openssl, "cms", "-verify", "-binary", "-inform", "DER", "-in", sigPath, "-content", content,
			"-CAfile", filepath.Join(dir, BootCACertFile), "-purpose", "codesign", "-out", os.DevNull).CombinedOutput()
	}
	if out, err := verify(kPath); err != nil {
		t.Fatalf("openssl refuses the signature: %v\n%s", err, out)
	}
	if out, err := verify(tPath); err == nil {
		t.Fatalf("openssl accepted tampered content:\n%s", out)
	}
	// And the other way: what openssl signs, we verify.
	osig := filepath.Join(w, "openssl.sig")
	if out, err := exec.Command(openssl, "cms", "-sign", "-binary", "-noattr", "-outform", "DER", "-in", kPath, "-out", osig,
		"-signer", filepath.Join(dir, CodeSignCertFile), "-inkey", filepath.Join(dir, CodeSignKeyFile), "-md", "sha256").CombinedOutput(); err != nil {
		t.Fatalf("openssl sign: %v\n%s", err, out)
	}
	ob, _ := os.ReadFile(osig)
	if err := VerifyDetached(ob, kernel, roots); err != nil {
		t.Fatalf("openssl's signature: %v", err)
	}
}
