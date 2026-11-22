package lab

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Arch is a VM CPU architecture.
type Arch string

const (
	// ARM64 runs under Apple's hypervisor at near-native speed.
	ARM64 Arch = "aarch64"
	// AMD64 is emulated: slow, but the only way to exercise legacy BIOS
	// PXE and x86 Secure Boot on Apple silicon.
	AMD64 Arch = "x86_64"
)

// Boot is a VM's firmware.
type Boot string

const (
	BootUEFI       Boot = "uefi"
	BootUEFISecure Boot = "uefi-secure" // x86_64 only: Homebrew's aarch64 edk2 has no Secure Boot build
	BootBIOS       Boot = "bios"        // x86_64 only: SeaBIOS + iPXE option ROM
)

// NIC attaches a VM to a network.
type NIC struct {
	MAC string
	// Switch is the lab switch's socket for this NIC's network. If empty,
	// the NIC uses QEMU user networking (NAT to the host) with HostFwd.
	Switch string
	// Port names this NIC on the switch (it connects; nothing listens here).
	Port    string
	HostFwd []string
}

// VM is one QEMU virtual machine.
type VM struct {
	Name      string
	Arch      Arch
	Boot      Boot
	CPUs      int
	MemoryMiB int
	TPM       bool
	NICs      []NIC
	Disk      string // qcow2; empty for stateless nodes
	// BootROM is an EFI network-boot program (iPXE) presented to the
	// firmware as a small read-only FAT disk, standing in for iPXE flashed
	// into the NIC. aarch64 nodes need it: under Apple's hypervisor there
	// is no hardware RNG, and since the 2024 PixieFail fixes edk2's own
	// network stack refuses to load without one.
	BootROM string
	// SMBIOSSerial sets the system serial number; cloud-init reads its
	// NoCloud seed URL from here.
	SMBIOSSerial string
	Dir          string // per-VM state: NVRAM, TPM state, sockets, logs
	FirmwareDir  string // QEMU's share/qemu
	QEMUBin      string // directory holding qemu-system-*; empty uses PATH
	SwtpmBin     string
}

func (v VM) path(name string) string { return filepath.Join(v.Dir, name) }

// QMPPath is the VM's QEMU Machine Protocol socket.
func (v VM) QMPPath() string { return v.path("qmp.sock") }

func (v VM) pidPath() string { return v.path("qemu.pid") }

// ConsoleLog is the serial console capture.
func (v VM) ConsoleLog() string { return v.path("console.log") }

func (v VM) varsPath() string { return v.path("efivars.fd") }

func (v VM) bootROMDir() string { return v.path("bootrom") }

func (v VM) bin(name string) string {
	if v.QEMUBin != "" {
		return filepath.Join(v.QEMUBin, name)
	}
	return name
}

// Args returns the QEMU command line.
func (v VM) Args() ([]string, error) {
	fw := func(f string) string { return filepath.Join(v.FirmwareDir, f) }
	cpus, mem := max(v.CPUs, 1), max(v.MemoryMiB, 512)
	var a []string
	switch v.Arch {
	case ARM64:
		if v.Boot != BootUEFI {
			return nil, fmt.Errorf("%s: %s boot is not available on aarch64", v.Name, v.Boot)
		}
		a = []string{"-M", "virt", "-accel", "hvf", "-cpu", "host",
			"-drive", "if=pflash,format=raw,readonly=on,file=" + fw("edk2-aarch64-code.fd"),
			"-drive", "if=pflash,format=raw,file=" + v.varsPath()}
	case AMD64:
		a = []string{"-accel", "tcg", "-cpu", "max"}
		switch v.Boot {
		case BootBIOS:
			a = append(a, "-M", "q35")
		case BootUEFI:
			a = append(a, "-M", "q35",
				"-drive", "if=pflash,format=raw,readonly=on,file="+fw("edk2-x86_64-code.fd"),
				"-drive", "if=pflash,format=raw,file="+v.varsPath())
		case BootUEFISecure:
			a = append(a, "-M", "q35,smm=on",
				"-global", "driver=cfi.pflash01,property=secure,value=on",
				"-drive", "if=pflash,format=raw,unit=0,readonly=on,file="+fw("edk2-x86_64-secure-code.fd"),
				"-drive", "if=pflash,format=raw,unit=1,file="+v.varsPath())
		default:
			return nil, fmt.Errorf("%s: unknown boot %q", v.Name, v.Boot)
		}
	default:
		return nil, fmt.Errorf("%s: unknown arch %q", v.Name, v.Arch)
	}
	a = append(a, "-name", v.Name, "-smp", strconv.Itoa(cpus), "-m", strconv.Itoa(mem),
		"-display", "none", "-serial", "file:"+v.ConsoleLog(), "-monitor", "none",
		"-qmp", "unix:"+v.QMPPath()+",server=on,wait=off",
		"-pidfile", v.pidPath(), "-daemonize")
	if v.SMBIOSSerial != "" {
		a = append(a, "-smbios", "type=1,serial="+v.SMBIOSSerial)
	}
	if v.TPM {
		// The TPM's physical-presence RAM region is smaller than Apple
		// silicon's 16 KiB page and HVF refuses to map it; Flapjack never
		// uses PPI, so it is turned off.
		dev := "tpm-tis-device,ppi=off"
		if v.Arch == AMD64 {
			dev = "tpm-crb"
		}
		a = append(a, "-chardev", "socket,id=chrtpm,path="+v.path("swtpm.sock"),
			"-tpmdev", "emulator,id=tpm0,chardev=chrtpm", "-device", dev+",tpmdev=tpm0")
	}
	a = append(a, "-device", "virtio-rng-pci")
	boot := 1
	if v.BootROM != "" {
		a = append(a, "-drive", "if=none,id=bootrom,format=raw,readonly=on,file=fat:"+v.bootROMDir(),
			"-device", "virtio-blk-pci,drive=bootrom,bootindex=0")
	}
	if v.Disk != "" {
		a = append(a, "-drive", "if=none,id=disk0,format=qcow2,file="+v.Disk,
			"-device", "virtio-blk-pci,drive=disk0,bootindex=0")
	}
	for i, n := range v.NICs {
		id := fmt.Sprintf("net%d", i)
		if n.Switch != "" {
			// A connected stream to the switch (never path-addressed
			// datagrams: see Switch), reconnecting if the switch restarts.
			a = append(a, "-netdev", fmt.Sprintf("stream,id=%s,server=off,addr.type=unix,addr.path=%s,reconnect-ms=1000", id, n.Switch))
		} else {
			nd := "user,id=" + id
			for _, f := range n.HostFwd {
				nd += ",hostfwd=" + f
			}
			a = append(a, "-netdev", nd)
		}
		dev := fmt.Sprintf("virtio-net-pci,netdev=%s,mac=%s", id, n.MAC)
		if n.Switch != "" && v.Disk == "" {
			// stateless nodes network-boot from the provisioning NIC
			dev += fmt.Sprintf(",bootindex=%d", boot)
			boot++
		}
		if v.Arch == ARM64 {
			dev += ",romfile=" // edk2 has its own virtio-net driver; the x86 iPXE ROM is useless here
		}
		a = append(a, "-device", dev)
	}
	return a, nil
}

func (v VM) qemu() string { return v.bin("qemu-system-" + string(v.Arch)) }

// Running reports whether the VM's QEMU process is alive.
func (v VM) Running() bool {
	pid, err := readPid(v.pidPath())
	return err == nil && syscall.Kill(pid, 0) == nil
}

// Start launches the VM (and its TPM emulator). It returns once QEMU has
// daemonized. NVRAM and TPM state persist across starts, as on hardware.
func (v VM) Start() error {
	if v.Running() {
		return nil
	}
	if err := os.MkdirAll(v.Dir, 0o755); err != nil {
		return err
	}
	if v.Boot != BootBIOS {
		if _, err := os.Stat(v.varsPath()); errors.Is(err, os.ErrNotExist) {
			tmpl := "edk2-arm-vars.fd"
			if v.Arch == AMD64 {
				tmpl = "edk2-i386-vars.fd"
			}
			if err := copyFile(filepath.Join(v.FirmwareDir, tmpl), v.varsPath()); err != nil {
				return fmt.Errorf("NVRAM template: %w", err)
			}
		}
	}
	if v.BootROM != "" {
		name := "BOOTAA64.EFI"
		if v.Arch == AMD64 {
			name = "BOOTX64.EFI"
		}
		dir := filepath.Join(v.bootROMDir(), "EFI", "BOOT")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if _, err := os.Stat(v.BootROM); errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("no signed iPXE yet (%s): the head builds it on its first boot; follow it with flapjack lab ssh -- journalctl -fu fj-sync", v.BootROM)
		}
		if err := copyFile(v.BootROM, filepath.Join(dir, name)); err != nil {
			return fmt.Errorf("boot ROM: %w", err)
		}
		// The embedded script retries by rebooting; an autoexec.ipxe would
		// run instead of it, unverified.
		os.Remove(filepath.Join(v.bootROMDir(), "autoexec.ipxe"))
	}
	os.Remove(v.QMPPath())
	if v.TPM {
		if err := v.startTPM(); err != nil {
			return err
		}
	}
	args, err := v.Args()
	if err != nil {
		return err
	}
	out, err := exec.Command(v.qemu(), args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", v.qemu(), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// startTPM runs swtpm for the VM. It exits by itself when QEMU disconnects
// (--terminate), so each start launches a fresh process over the same
// persistent state directory.
func (v VM) startTPM() error {
	state := v.path("tpm")
	if err := os.MkdirAll(state, 0o700); err != nil {
		return err
	}
	sock := v.path("swtpm.sock")
	os.Remove(sock)
	bin := v.SwtpmBin
	if bin == "" {
		bin = "swtpm"
	}
	out, err := exec.Command(bin, "socket", "--tpm2", "--tpmstate", "dir="+state,
		"--ctrl", "type=unixio,path="+sock, "--terminate", "--daemon",
		"--pid", "file="+v.path("swtpm.pid"), "--log", "file="+v.path("swtpm.log")).CombinedOutput()
	if err != nil {
		return fmt.Errorf("swtpm: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return waitFor(func() bool { _, err := os.Stat(sock); return err == nil }, 5*time.Second)
}

// QMP runs one QEMU Machine Protocol command and returns its result.
func (v VM) QMP(command string, args map[string]any) (json.RawMessage, error) {
	c, err := net.DialTimeout("unix", v.QMPPath(), 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(c)
	if _, err := r.ReadBytes('\n'); err != nil { // greeting
		return nil, err
	}
	call := func(cmd string, args map[string]any) (json.RawMessage, error) {
		req := map[string]any{"execute": cmd}
		if args != nil {
			req["arguments"] = args
		}
		if err := json.NewEncoder(c).Encode(req); err != nil {
			return nil, err
		}
		for {
			line, err := r.ReadBytes('\n')
			if err != nil {
				return nil, err
			}
			var resp struct {
				Return json.RawMessage `json:"return"`
				Error  *struct {
					Desc string `json:"desc"`
				} `json:"error"`
				Event string `json:"event"`
			}
			if err := json.Unmarshal(line, &resp); err != nil {
				return nil, err
			}
			if resp.Event != "" {
				continue
			}
			if resp.Error != nil {
				return nil, fmt.Errorf("qmp %s: %s", cmd, resp.Error.Desc)
			}
			return resp.Return, nil
		}
	}
	if _, err := call("qmp_capabilities", nil); err != nil {
		return nil, err
	}
	out, err := call(command, args)
	if errors.Is(err, io.EOF) && command == "quit" {
		return nil, nil // QEMU exits before answering
	}
	return out, err
}

// Stop powers the VM off immediately and waits for QEMU to exit.
func (v VM) Stop() error {
	if !v.Running() {
		return nil
	}
	if _, err := v.QMP("quit", nil); err != nil {
		if pid, perr := readPid(v.pidPath()); perr == nil {
			syscall.Kill(pid, syscall.SIGKILL)
		}
	}
	return waitFor(func() bool { return !v.Running() }, 10*time.Second)
}

func readPid(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}

func waitFor(cond func() bool, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			return errors.New("timed out")
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
