package server

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/damen-pt/flapjack/internal/pki"
)

// TestSignedBoot: with signing on, a script imgverifies the kernel and
// initrd against signatures the head serves, carries the root
// filesystem's digest for the initrd, and is itself signed, with the
// signature only served to the node's address.
func TestSignedBoot(t *testing.T) {
	pkiDir, _ := testPKI()
	roots, _ := pki.LoadPool(filepath.Join(pkiDir, pki.BootCACertFile))
	b, dir := bootSetup(t)
	files := map[string][]byte{"vmlinuz": []byte("kernel"), "initrd.img": []byte("initrd"), "rootfs.squashfs": []byte("root filesystem")}
	for f, c := range files {
		os.WriteFile(filepath.Join(dir, "images", "el9", f), c, 0o644)
	}
	h := b.Handler()
	b.Tickets.Arm("52:54:00:01:01:01")

	code, script := getTLS(h, "/boot/52-54-00-01-01-01.ipxe", "10.99.1.1", true)
	if code != 200 {
		t.Fatalf("%d %s", code, script)
	}
	sum := sha256.Sum256(files["rootfs.squashfs"])
	_, tok := imageToken(t, script)
	img := "https://10.99.0.1/images/el9/" + tok
	for _, want := range []string{
		"imgverify vmlinuz " + img + "/vmlinuz.sig",
		"imgverify initrd.img " + img + "/initrd.img.sig",
		"flapjack.rootfs=sha256:" + hex.EncodeToString(sum[:]),
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %q:\n%s", want, script)
		}
	}
	// Every other image must go before the kernel: iPXE on UEFI gives the
	// kernel all images it holds as one initrd (seen in the lab: the
	// script itself came first and broke initramfs unpacking).
	if i, k := strings.Index(script, "\nimgfree\n"), strings.Index(script, "\nkernel "); i < 0 || i > k {
		t.Fatalf("no imgfree before the kernel:\n%s", script)
	}
	if strings.Index(script, "imgverify initrd.img") > strings.Index(script, "\nboot") {
		t.Fatalf("boots before verifying:\n%s", script)
	}

	// The script's signature: to the node only, and over exactly what it got.
	if code, _ := getTLS(h, "/boot/52-54-00-01-01-01.ipxe.sig", "10.99.1.9", true); code != 403 {
		t.Fatalf("signature served to another address: %d", code)
	}
	code, sig := getTLS(h, "/boot/52-54-00-01-01-01.ipxe.sig", "10.99.1.1", true)
	if code != 200 {
		t.Fatalf("script signature: %d %s", code, sig)
	}
	if err := pki.VerifyDetached([]byte(sig), []byte(script), roots); err != nil {
		t.Fatalf("script signature does not verify: %v", err)
	}
	altered := strings.Replace(script, "console=ttyAMA0", "console=ttyAMA0 init=/bin/sh", 1)
	if pki.VerifyDetached([]byte(sig), []byte(altered), roots) == nil {
		t.Fatal("an altered script verified")
	}
	if code, _ := getTLS(h, "/boot/52-54-00-01-02-01.ipxe.sig", "10.99.1.2", true); code != 404 {
		t.Fatalf("signature for a script never served: %d", code)
	}

	// Kernel and initrd signatures.
	for _, f := range []string{"vmlinuz", "initrd.img"} {
		code, sig := getTLS(h, "/images/el9/"+tok+"/"+f+".sig", "10.99.1.1", true)
		if code != 200 || pki.VerifyDetached([]byte(sig), files[f], roots) != nil {
			t.Fatalf("%s.sig: %d", f, code)
		}
		if pki.VerifyDetached([]byte(sig), []byte("backdoored "+f), roots) == nil {
			t.Fatalf("%s.sig verified other content", f)
		}
	}
	nope, _ := b.Tokens.Mint("nope", net.ParseIP("10.99.1.1"))
	for _, p := range []string{"/images/el9/" + tok + "/rootfs.squashfs.sig", "/images/el9/" + tok + "/vmlinuz.sig.sig", "/images/nope/" + nope + "/vmlinuz.sig"} {
		if code, _ := getTLS(h, p, "10.99.1.1", true); code != 404 {
			t.Errorf("%s: %d", p, code)
		}
	}

	// A waiting node re-fetches its script through imgverify too: with
	// iPXE refusing unverified images, a plain chain would fail.
	os.Remove(filepath.Join(dir, "images", "el9", "vmlinuz"))
	_, wait := getTLS(h, "/boot/52-54-00-01-01-01.ipxe", "10.99.1.1", true)
	if !strings.Contains(wait, "imgfetch --name next https://10.99.0.1/boot/52-54-00-01-01-01.ipxe && imgverify next https://10.99.0.1/boot/52-54-00-01-01-01.ipxe.sig && chain --replace --autofree next") {
		t.Fatalf("wait script:\n%s", wait)
	}
	_, wsig := getTLS(h, "/boot/52-54-00-01-01-01.ipxe.sig", "10.99.1.1", true)
	if pki.VerifyDetached([]byte(wsig), []byte(wait), roots) != nil {
		t.Fatal("the wait script's signature is not the latest script's")
	}
}
