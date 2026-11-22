package image

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fakeVersion(t *testing.T, dir, name, id string, created time.Time) {
	v := filepath.Join(dir, name+"@"+id)
	os.MkdirAll(v, 0o755)
	os.WriteFile(filepath.Join(v, "rootfs.squashfs"), []byte(id), 0o644)
	b, _ := json.Marshal(Info{Name: name, Version: name + "@" + id, Created: created})
	os.WriteFile(filepath.Join(v, "image.json"), b, 0o644)
}

func TestUseAndList(t *testing.T) {
	dir := t.TempDir()
	b := &Builder{Dir: dir}
	now := time.Now()
	fakeVersion(t, dir, "el9", "aaa", now.Add(-time.Hour))
	fakeVersion(t, dir, "el9", "bbb", now)
	if err := b.Use("el9", "el9@bbb"); err != nil {
		t.Fatal(err)
	}
	if err := b.Use("el9", "el9@aaa"); err != nil { // roll back
		t.Fatal(err)
	}
	if target, _ := os.Readlink(filepath.Join(dir, "el9")); target != "el9@aaa" {
		t.Fatalf("link = %s", target)
	}
	vs, err := b.List()
	if err != nil || len(vs) != 2 || vs[0].Version != "el9@bbb" || vs[0].Current || !vs[1].Current {
		t.Fatalf("list = %+v %v", vs, err)
	}
	for _, bad := range [][2]string{{"el9", "el9@zzz"}, {"el9", "other@aaa"}, {"el9", "el9@../x"}, {"../el9", "../el9@aaa"}} {
		if err := b.Use(bad[0], bad[1]); err == nil {
			t.Errorf("Use(%s, %s) accepted", bad[0], bad[1])
		}
	}
	os.MkdirAll(filepath.Join(dir, "plain"), 0o755)
	fakeVersion(t, dir, "plain", "x", now)
	if err := b.Use("plain", "plain@x"); err == nil {
		t.Error("replaced a real directory with a link")
	}
}

func TestInstallTrustCopiesOnlyPublicFiles(t *testing.T) {
	pkiDir, root := t.TempDir(), t.TempDir()
	for _, f := range []string{"ca.pem", "ca.key", "generation.pub", "generation.key", "boot-ca.pem", "boot-ca.key", "ticket.key"} {
		os.WriteFile(filepath.Join(pkiDir, f), []byte(f), 0o600)
	}
	var ran []string
	b := &Builder{PKIDir: pkiDir, Exec: func(name string, args ...string) error {
		ran = append(ran, name+" "+strings.Join(args, " "))
		return nil
	}}
	if err := b.installTrust(root); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Join(root, "etc/flapjack/pki"))
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	if strings.Join(got, ",") != "boot-ca.pem,ca.pem,generation.pub" {
		t.Fatalf("image carries %v", got)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "etc/pki/ca-trust/source/anchors/flapjack-boot-ca.pem")); string(b) != "boot-ca.pem" {
		t.Fatal("boot CA not anchored")
	}
	if len(ran) != 1 || !strings.Contains(ran[0], "update-ca-trust extract") {
		t.Fatalf("ran %v", ran)
	}
}

func TestHostReleasePackage(t *testing.T) {
	dir := t.TempDir()
	for id, want := range map[string]string{`"rocky"`: "rocky-release", "almalinux": "almalinux-release", "plan9": "almalinux-release"} {
		p := filepath.Join(dir, "os-release")
		os.WriteFile(p, []byte("NAME=x\nID="+id+"\nVERSION_ID=9\n"), 0o644)
		if got := HostReleasePackage(p); got != want {
			t.Errorf("ID=%s: %s, want %s", id, got, want)
		}
	}
	if got := HostReleasePackage(filepath.Join(dir, "missing")); got != "almalinux-release" {
		t.Errorf("missing os-release: %s", got)
	}
}
