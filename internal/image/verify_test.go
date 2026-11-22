package image

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestVerifyHook runs the dracut hook under /bin/sh against a fake /sys
// with dracut's helpers stubbed.
func TestVerifyHook(t *testing.T) {
	dir := t.TempDir()
	hook := filepath.Join(dir, "hook.sh")
	os.WriteFile(hook, []byte(VerifyHook), 0o755)
	image := filepath.Join(dir, "run", "rootfs.squashfs")
	inner := filepath.Join(dir, "run", "initramfs", "squashfs", "LiveOS", "rootfs.img")
	os.MkdirAll(filepath.Dir(inner), 0o755)
	genuine := []byte("squashfs image v1\n")
	os.WriteFile(image, genuine, 0o644)
	os.WriteFile(inner, []byte("inner ext4"), 0o644)
	sum := sha256.Sum256(genuine)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	sys := filepath.Join(dir, "sys")
	loop := func(n, backing string) {
		p := filepath.Join(sys, "block", n, "loop")
		os.MkdirAll(p, 0o755)
		os.WriteFile(filepath.Join(p, "backing_file"), []byte(backing+"\n"), 0o644)
	}
	loop("loop0", image)
	loop("loop1", inner)

	run := func(cmdline string) (string, bool) {
		script := `getarg() { for a in $CMDLINE; do case "$a" in "$1"*) echo "${a#"$1"}"; return 0;; esac; done; return 1; }
info() { echo "INFO $*"; }
warn() { echo "WARN $*"; }
die() { echo "DIE $*"; exit 1; }
. "$HOOK"
echo PIVOT`
		cmd := exec.Command("/bin/sh", "-c", script)
		cmd.Env = append(os.Environ(), "HOOK="+hook, "FLAPJACK_SYSFS="+sys, "CMDLINE="+cmdline)
		out, _ := cmd.CombinedOutput()
		return string(out), strings.Contains(string(out), "PIVOT")
	}
	if out, ok := run("root=live:https://x/rootfs.squashfs flapjack.rootfs=" + digest); !ok || !strings.Contains(out, "verified") {
		t.Fatalf("genuine image refused:\n%s", out)
	}
	if out, ok := run("root=live:https://x/rootfs.squashfs"); !ok {
		t.Fatalf("unsigned boot (no flapjack.rootfs=) must pass through:\n%s", out)
	}
	os.WriteFile(image, []byte("squashfs image v1 with a backdoor\n"), 0o644)
	if out, ok := run("flapjack.rootfs=" + digest); ok || !strings.Contains(out, "DIE") {
		t.Fatalf("altered image accepted:\n%s", out)
	}
	os.RemoveAll(filepath.Join(sys, "block", "loop0"))
	if out, ok := run("flapjack.rootfs=" + digest); ok {
		t.Fatalf("no image to check, but booted:\n%s", out)
	}
}

func TestInitramfsAddsVerifyModule(t *testing.T) {
	root := t.TempDir()
	var dracut []string
	b := &Builder{Exec: func(name string, args ...string) error {
		if len(args) > 1 && args[1] == "dracut" {
			dracut = args
			os.WriteFile(filepath.Join(root, "tmp", "flapjack-initrd.img"), []byte("initrd"), 0o644)
		}
		return nil
	}}
	os.MkdirAll(filepath.Join(root, "tmp"), 0o755)
	for _, m := range []string{"proc", "sys", "dev"} {
		os.MkdirAll(filepath.Join(root, m), 0o755)
	}
	if err := b.initramfs(root, "6.1", filepath.Join(t.TempDir(), "initrd.img")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(dracut, " "), "flapjack-verify") {
		t.Fatalf("dracut not asked for the module: %v", dracut)
	}
	for _, f := range []string{"module-setup.sh", "flapjack-verify-rootfs.sh"} {
		if fi, err := os.Stat(filepath.Join(root, verifyModuleDir, f)); err != nil || fi.Mode().Perm()&0o100 == 0 {
			t.Fatalf("%s not installed executable: %v", f, err)
		}
	}
}
