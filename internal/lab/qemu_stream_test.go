package lab

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestQEMUStreamConnects starts QEMU with no firmware and no disk, only a
// NIC on a switch, and checks it connects with the netdev arguments VM
// uses. Nothing boots, so no frames flow. Needs Homebrew QEMU.
func TestQEMUStreamConnects(t *testing.T) {
	bin := "/opt/homebrew/bin/qemu-system-aarch64"
	if _, err := os.Stat(bin); err != nil {
		t.Skip("no QEMU")
	}
	sw, path := startSwitch(t, nil, nil)
	v := VM{Name: "probe", Arch: ARM64, Boot: BootUEFI, NICs: []NIC{{MAC: "52:54:00:99:99:99", Switch: path}}}
	args, err := v.Args()
	if err != nil {
		t.Fatal(err)
	}
	var netdev []string
	for i, a := range args {
		if a == "-netdev" || (a == "-device" && i+1 < len(args) && args[i+1][:10] == "virtio-net") {
			netdev = append(netdev, a, args[i+1])
		}
	}
	dir := shortDir(t)
	cmd := exec.Command(bin, append([]string{"-M", "virt", "-accel", "tcg", "-nodefaults", "-display", "none", "-S",
		"-pidfile", filepath.Join(dir, "pid")}, netdev...)...)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		sw.mu.Lock()
		n := len(sw.ports)
		sw.mu.Unlock()
		if n == 1 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("QEMU did not connect to the switch (args %q)", netdev)
}
