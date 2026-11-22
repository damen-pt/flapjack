package lab

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestARM64Args(t *testing.T) {
	v := VM{Name: "r1n01", Arch: ARM64, Boot: BootUEFI, CPUs: 2, MemoryMiB: 1024, TPM: true, Dir: "/l/r1n01", FirmwareDir: "/fw",
		NICs: []NIC{{MAC: "52:54:00:01:01:01", Switch: "/l/sw.sock", Port: "/l/r1n01/p0.sock"}}}
	a, err := v.Args()
	if err != nil {
		t.Fatal(err)
	}
	line := strings.Join(a, " ")
	for _, want := range []string{
		"-M virt -accel hvf -cpu host",
		"file=/fw/edk2-aarch64-code.fd",
		"file=/l/r1n01/efivars.fd",
		"stream,id=net0,server=off,addr.type=unix,addr.path=/l/sw.sock,reconnect-ms=1000",
		"virtio-net-pci,netdev=net0,mac=52:54:00:01:01:01,bootindex=1,romfile=",
		"tpm-tis-device,ppi=off,tpmdev=tpm0",
		"-daemonize",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("missing %q in:\n%s", want, line)
		}
	}
	v.Boot = BootBIOS
	if _, err := v.Args(); err == nil {
		t.Error("BIOS boot on aarch64 must be rejected")
	}
}

func TestAMD64SecureBootArgs(t *testing.T) {
	v := VM{Name: "x", Arch: AMD64, Boot: BootUEFISecure, TPM: true, Dir: "/l/x", FirmwareDir: "/fw",
		NICs: []NIC{{MAC: "52:54:00:09:09:09", Switch: "/l/sw.sock", Port: "/l/x/p0.sock"}}}
	a, _ := v.Args()
	line := strings.Join(a, " ")
	for _, want := range []string{"q35,smm=on", "property=secure,value=on", "edk2-x86_64-secure-code.fd", "tpm-crb", "-accel tcg"} {
		if !strings.Contains(line, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(line, "romfile=") {
		t.Error("x86 VMs keep the iPXE option ROM")
	}
}

func TestHeadArgs(t *testing.T) {
	v := VM{Name: "head", Arch: ARM64, Boot: BootUEFI, Dir: "/l/head", FirmwareDir: "/fw", Disk: "/l/head/disk.qcow2",
		SMBIOSSerial: "ds=nocloud;s=http://10.0.2.2:7400/",
		NICs: []NIC{
			{MAC: "52:54:00:00:00:02", HostFwd: []string{"tcp:127.0.0.1:2222-:22"}},
			{MAC: "52:54:00:00:00:01", Switch: "/l/sw.sock", Port: "/l/head/p0.sock"},
		}}
	a, _ := v.Args()
	line := strings.Join(a, " ")
	for _, want := range []string{"virtio-blk-pci,drive=disk0,bootindex=0", "user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22", "type=1,serial=ds=nocloud;s=http://10.0.2.2:7400/"} {
		if !strings.Contains(line, want) {
			t.Errorf("missing %q in %s", want, line)
		}
	}
	if strings.Contains(line, "bootindex=1") {
		t.Error("a VM with a disk must not network-boot")
	}
}

// firmwareDir finds Homebrew QEMU's firmware, or skips.
func firmwareDir(t *testing.T) string {
	if os.Getenv("FLAPJACK_LAB_IT") == "" {
		t.Skip("set FLAPJACK_LAB_IT=1 to run QEMU integration tests")
	}
	out, err := exec.Command("brew", "--prefix", "qemu").Output()
	if err != nil {
		t.Skip("Homebrew QEMU not found")
	}
	return filepath.Join(strings.TrimSpace(string(out)), "share", "qemu")
}

// dhcpDiscoverFrom reports whether frame is a DHCPDISCOVER sent by mac.
func dhcpDiscoverFrom(frame []byte, mac net.HardwareAddr) bool {
	if len(frame) < 14+20+8+240 || !bytes.Equal(frame[6:12], mac) || binary.BigEndian.Uint16(frame[12:]) != 0x0800 {
		return false
	}
	ihl := int(frame[14]&0x0f) * 4
	if frame[14+9] != 17 { // UDP
		return false
	}
	udp := frame[14+ihl:]
	if binary.BigEndian.Uint16(udp[2:]) != 67 {
		return false
	}
	opts := udp[8+240:]
	for i := 0; i+1 < len(opts) && opts[i] != 255; {
		if opts[i] == 0 {
			i++
			continue
		}
		if opts[i] == 53 && opts[i+1] == 1 && i+2 < len(opts) {
			return opts[i+2] == 1
		}
		i += 2 + int(opts[i+1])
	}
	return false
}

type tap struct {
	frames chan []byte
}

func (t *tap) Write(p []byte) (int, error) {
	if len(p) > 16 {
		select {
		case t.frames <- bytes.Clone(p[16:]):
		default:
		}
	}
	return len(p), nil
}

func TestIntegrationUEFINodeSendsDHCPDiscover(t *testing.T) {
	fw := firmwareDir(t)
	d := shortDir(t)
	swPath, port := filepath.Join(d, "sw.sock"), filepath.Join(d, "n1.sock")
	tp := &tap{frames: make(chan []byte, 1024)}
	sw, err := NewSwitch(swPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	sw.pcap, _ = newPcap(tp)
	go sw.Serve()
	defer sw.Close()

	mac := "52:54:00:aa:00:01"
	home, _ := os.UserHomeDir()
	ipxe := filepath.Join(home, ".flapjack", "cache", "ipxe-arm64", "ipxe.efi")
	if _, err := os.Stat(ipxe); err != nil {
		t.Skip("arm64 ipxe.efi not cached: " + err.Error())
	}
	v := VM{Name: "it-n1", Arch: ARM64, Boot: BootUEFI, MemoryMiB: 1024, TPM: true, Dir: filepath.Join(d, "n1"), FirmwareDir: fw,
		BootROM: ipxe, NICs: []NIC{{MAC: mac, Switch: swPath, Port: port}}}
	if err := v.Start(); err != nil {
		t.Fatal(err)
	}
	defer v.Stop()
	if st, err := v.QMP("query-status", nil); err != nil || !strings.Contains(string(st), `"running"`) {
		t.Fatalf("query-status = %s %v", st, err)
	}

	hw, _ := net.ParseMAC(mac)
	deadline := time.After(90 * time.Second)
	for {
		select {
		case f := <-tp.frames:
			if dhcpDiscoverFrom(f, hw) {
				t.Logf("DHCPDISCOVER from %s after %d frames", mac, sw.Frames.Load())
				if err := v.Stop(); err != nil || v.Running() {
					t.Fatalf("stop: %v", err)
				}
				return
			}
		case <-deadline:
			b, _ := os.ReadFile(v.ConsoleLog())
			t.Fatalf("no DHCPDISCOVER within 90s (%d frames). console:\n%s", sw.Frames.Load(), b)
		}
	}
}

func TestIntegrationX86NodesSendDHCPDiscover(t *testing.T) {
	fw := firmwareDir(t)
	for i, boot := range []Boot{BootBIOS, BootUEFISecure} {
		t.Run(string(boot), func(t *testing.T) {
			d := shortDir(t)
			swPath, port := filepath.Join(d, "sw.sock"), filepath.Join(d, "n.sock")
			tp := &tap{frames: make(chan []byte, 1024)}
			sw, err := NewSwitch(swPath, nil)
			if err != nil {
				t.Fatal(err)
			}
			sw.pcap, _ = newPcap(tp)
			go sw.Serve()
			defer sw.Close()
			mac := fmt.Sprintf("52:54:00:bb:00:%02x", i+1)
			v := VM{Name: "it-x" + string(boot), Arch: AMD64, Boot: boot, MemoryMiB: 1024, TPM: boot != BootBIOS,
				Dir: filepath.Join(d, "n"), FirmwareDir: fw, NICs: []NIC{{MAC: mac, Switch: swPath, Port: port}}}
			start := time.Now()
			if err := v.Start(); err != nil {
				t.Fatal(err)
			}
			defer v.Stop()
			hw, _ := net.ParseMAC(mac)
			deadline := time.After(3 * time.Minute)
			for {
				select {
				case f := <-tp.frames:
					if dhcpDiscoverFrom(f, hw) {
						t.Logf("%s: DHCPDISCOVER after %s", boot, time.Since(start).Round(100*time.Millisecond))
						return
					}
				case <-deadline:
					b, _ := os.ReadFile(v.ConsoleLog())
					t.Fatalf("no DHCPDISCOVER (%d frames). console tail:\n%s", sw.Frames.Load(), tail(b, 2000))
				}
			}
		})
	}
}

func tail(b []byte, n int) []byte {
	if len(b) > n {
		return b[len(b)-n:]
	}
	return b
}
