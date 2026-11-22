package lab

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/bmc"
)

// Spec describes the lab to build.
type Spec struct {
	Racks        int `json:"racks"`
	NodesPerRack int `json:"nodesPerRack"` // aarch64 UEFI nodes, near-native speed
	// Emulated x86_64 nodes added to rack 1, for the boot paths that need
	// them: legacy BIOS PXE and UEFI Secure Boot.
	X86BIOS       int  `json:"x86BIOS"`
	X86Secure     int  `json:"x86Secure"`
	NodeMemoryMiB int  `json:"nodeMemoryMiB"`
	HeadMemoryMiB int  `json:"headMemoryMiB"`
	Head          bool `json:"head"`
	PowerOn       bool `json:"powerOn"` // power nodes on at start (otherwise they wait for Redfish)

	RedfishBasePort int `json:"redfishBasePort"`
	SeedPort        int `json:"seedPort"`
	SSHPort         int `json:"sshPort"` // head; tentacle rN gets SSHPort+N

	// Tentacles builds the HPC layout instead of one flat provisioning
	// network: a tentacle VM per rack that runs the rack's DHCP and boot,
	// racks the head cannot reach, a cluster network joining the head and
	// every node, and Slurm (slurmctld and slurmrestd on the head,
	// configless slurmd on the nodes). See hpc.go.
	Tentacles         bool `json:"tentacles,omitempty"`
	TentacleMemoryMiB int  `json:"tentacleMemoryMiB,omitempty"`
	// LoginNodes are added to rack 1 in the tentacle layout: the users'
	// way in, with Slurm's client commands and the shared homes.
	LoginNodes int `json:"loginNodes,omitempty"`
	RESTPort   int `json:"restPort,omitempty"` // slurmrestd, forwarded to 127.0.0.1

	// SwitchMbps and SwitchFPS cap each lab network (defaults 100 Mbit/s
	// and 4,000 frames/s). The switches pass every frame through the
	// Mac's kernel, which is shared with everything else; see Switch.
	SwitchMbps int `json:"switchMbps,omitempty"`
	SwitchFPS  int `json:"switchFPS,omitempty"`
}

func (s *Spec) defaults() {
	s.Racks = max(s.Racks, 1)
	if s.NodesPerRack == 0 {
		s.NodesPerRack = 2
	}
	s.NodeMemoryMiB = max(s.NodeMemoryMiB, 1024)
	s.HeadMemoryMiB = max(s.HeadMemoryMiB, 4096)
	if s.RedfishBasePort == 0 {
		s.RedfishBasePort = 8100
	}
	if s.SeedPort == 0 {
		s.SeedPort = 7400
	}
	if s.SSHPort == 0 {
		s.SSHPort = 2222
	}
	if s.Tentacles {
		s.TentacleMemoryMiB = max(s.TentacleMemoryMiB, 1024)
		if s.RESTPort == 0 {
			s.RESTPort = 6820
		}
	}
}

// NodeInfo is one lab node.
type NodeInfo struct {
	Name    string `json:"name"`
	Rack    string `json:"rack"`
	MAC     string `json:"mac"`
	Arch    Arch   `json:"arch"`
	Boot    Boot   `json:"boot"`
	Serial  string `json:"serial"`
	Redfish string `json:"redfish"` // http://127.0.0.1:<port>
	IP      string `json:"ip"`      // reserved provisioning address
	// Tentacle layout: the node's NIC on the cluster network.
	ClusterMAC string `json:"clusterMAC,omitempty"`
	ClusterIP  string `json:"clusterIP,omitempty"`
	// Role is "compute" or "login" in the tentacle layout. Login nodes
	// also have a public NIC: NAT, with SSH forwarded from the Mac.
	Role      string `json:"role,omitempty"`
	PublicMAC string `json:"publicMAC,omitempty"`
	SSHPort   int    `json:"sshPort,omitempty"`
}

// State is the lab as built; it is written to lab.json.
type State struct {
	Spec        Spec           `json:"spec"`
	Dir         string         `json:"dir"`
	Nodes       []NodeInfo     `json:"nodes"`
	Tentacles   []TentacleInfo `json:"tentacles,omitempty"`
	FirmwareDir string         `json:"firmwareDir"`
	QEMUBin     string         `json:"qemuBin"`
	Swtpm       string         `json:"swtpm"`
	IPXEARM64   string         `json:"ipxeArm64"`
	IPXEX86     string         `json:"ipxeX86"`  // x86_64 UEFI iPXE, for PXE ROMs via TFTP
	IPXEBIOS    string         `json:"ipxeBIOS"` // undionly.kpxe, for legacy BIOS PXE ROMs via TFTP
	HeadImage   string         `json:"headImage,omitempty"`
	HeadBinary  string         `json:"headBinary,omitempty"` // linux/arm64 flapjack served to the head node
	NixBin      string         `json:"nixBin,omitempty"`     // static nix for the head node
	Nixpkgs     string         `json:"nixpkgs,omitempty"`    // pinned nixpkgs tarball (its lib/ is used)
	RedfishUser string         `json:"redfishUser"`
}

// HeadProvMAC and HeadMgmtMAC are the head node's NICs: provisioning
// network (the lab switch; the management core in the tentacle layout)
// and management (NAT to the Mac).
const (
	HeadProvMAC = "52:54:00:00:00:01"
	HeadMgmtMAC = "52:54:00:00:00:02"
	HeadProvIP  = "10.99.0.1/16"
)

// HeadAddress is the head's flapjack address: on the provisioning network,
// or on the management core in the tentacle layout.
func (st State) HeadAddress() string {
	if st.Spec.Tentacles {
		return HeadCoreIP
	}
	return HeadProvIP
}

// Layout computes the lab's nodes. MACs, serials and addresses are
// deterministic so DHCP reservations, inventory and purchase manifests can
// be written once. Rack R's nodes are 10.99.R.0/24: aarch64 nodes from .1,
// legacy BIOS nodes from .101, Secure Boot nodes from .151.
func Layout(s Spec) []NodeInfo {
	s.defaults()
	if s.Tentacles {
		return hpcLayout(s)
	}
	var out []NodeInfo
	port := s.RedfishBasePort
	add := func(name string, rack int, idx int, arch Arch, boot Boot, kind byte) {
		host := map[byte]int{0x01: 0, 0x02: 100, 0x03: 150}[kind] + idx
		out = append(out, NodeInfo{
			Name: name, Rack: fmt.Sprintf("r%d", rack),
			MAC:  fmt.Sprintf("52:54:00:%02x:%02x:%02x", rack, idx, kind),
			IP:   fmt.Sprintf("10.99.%d.%d", rack, host),
			Arch: arch, Boot: boot,
			Serial:  fmt.Sprintf("FJLAB-%s", strings.ToUpper(name)),
			Redfish: fmt.Sprintf("http://127.0.0.1:%d", port),
		})
		port++
	}
	for r := 1; r <= s.Racks; r++ {
		for n := 1; n <= s.NodesPerRack; n++ {
			add(fmt.Sprintf("r%dn%02d", r, n), r, n, ARM64, BootUEFI, 0x01)
		}
	}
	for i := 1; i <= s.X86BIOS; i++ {
		add(fmt.Sprintf("r1b%02d", i), 1, i, AMD64, BootBIOS, 0x02)
	}
	for i := 1; i <= s.X86Secure; i++ {
		add(fmt.Sprintf("r1s%02d", i), 1, i, AMD64, BootUEFISecure, 0x03)
	}
	return out
}

// Paths within the lab directory. Socket paths must stay under macOS's
// 104-byte limit, so the default directory is short (~/.flapjack/lab).
// The flat layout's one network keeps its original socket and capture
// names; the tentacle layout's networks are named after it.
func (st State) switchSock(network string) string {
	if network == NetProv {
		return filepath.Join(st.Dir, "sw.sock")
	}
	return filepath.Join(st.Dir, "sw-"+network+".sock")
}

func (st State) portSock(vm, network string) string {
	if network == NetProv {
		return filepath.Join(st.Dir, "ports", vm+".sock")
	}
	return filepath.Join(st.Dir, "ports", vm+"-"+network+".sock")
}

func (st State) vmDir(name string) string { return filepath.Join(st.Dir, "vms", name) }

func (st State) nic(mac, vm, network string) NIC {
	return NIC{MAC: mac, Switch: st.switchSock(network), Port: st.portSock(vm, network)}
}

// PcapPath is the capture of every frame on a network.
func (st State) PcapPath(network string) string { return filepath.Join(st.Dir, network+".pcap") }

// NetProv is the flat layout's provisioning network.
const NetProv = "prov"

// Networks maps each lab network to the switch ports (VM NIC sockets) on it.
func (st State) Networks() map[string][]string {
	if st.Spec.Tentacles {
		return st.hpcNetworks()
	}
	ports := []string{st.portSock("head", NetProv)}
	for _, n := range st.Nodes {
		ports = append(ports, st.portSock(n.Name, NetProv))
	}
	return map[string][]string{NetProv: ports}
}

func (st State) daemonPid() string    { return filepath.Join(st.Dir, "daemon.pid") }
func (st State) readyPath() string    { return filepath.Join(st.Dir, "ready") }
func (st State) passwordPath() string { return filepath.Join(st.Dir, "redfish-password") }

// SSHKey is the private key for the head node's flapjack user.
func (st State) SSHKey() string { return filepath.Join(st.Dir, "id_ed25519") }

// RedfishPassword reads the lab BMC password.
func (st State) RedfishPassword() (string, error) {
	b, err := os.ReadFile(st.passwordPath())
	return strings.TrimSpace(string(b)), err
}

// VM returns the QEMU definition for a node.
func (st State) VM(n NodeInfo) VM {
	v := VM{Name: n.Name, Arch: n.Arch, Boot: n.Boot, CPUs: 2, MemoryMiB: st.Spec.NodeMemoryMiB,
		TPM: n.Boot != BootBIOS, Dir: st.vmDir(n.Name), FirmwareDir: st.FirmwareDir, QEMUBin: st.QEMUBin, SwtpmBin: st.Swtpm,
		SMBIOSSerial: n.Serial,
		NICs:         []NIC{st.nic(n.MAC, n.Name, NetProv)}}
	if st.Spec.Tentacles {
		// Boots from its rack's network; jobs use the cluster network.
		v.NICs = []NIC{st.nic(n.MAC, n.Name, n.Rack), st.nic(n.ClusterMAC, n.Name, NetCluster)}
		if n.PublicMAC != "" {
			// Last, so iPXE's dhcp tries the rack network first.
			v.NICs = append(v.NICs, NIC{MAC: n.PublicMAC, HostFwd: []string{fmt.Sprintf("tcp:127.0.0.1:%d-:22", n.SSHPort)}})
		}
	}
	if n.Arch == ARM64 {
		// The head's signed iPXE: stock iPXE neither trusts the head's
		// boot CA nor verifies what it boots, and the head serves nothing
		// to anything else.
		v.BootROM = st.SignedIPXE()
	}
	return v
}

// SignedIPXE is where the arm64 iPXE the head built against its boot CA
// is kept, once the head has sent it.
func (st State) SignedIPXE() string { return filepath.Join(st.Dir, "ipxe-arm64.efi") }

// HeadVM returns the head node's QEMU definition.
func (st State) HeadVM() VM {
	v := VM{Name: "head", Arch: ARM64, Boot: BootUEFI, CPUs: 4, MemoryMiB: st.Spec.HeadMemoryMiB,
		Dir: st.vmDir("head"), FirmwareDir: st.FirmwareDir, QEMUBin: st.QEMUBin,
		Disk:         filepath.Join(st.vmDir("head"), "disk.qcow2"),
		SMBIOSSerial: fmt.Sprintf("ds=nocloud-net;s=http://10.0.2.2:%d/", st.Spec.SeedPort),
		NICs: []NIC{
			{MAC: HeadMgmtMAC, HostFwd: []string{fmt.Sprintf("tcp:127.0.0.1:%d-:22", st.Spec.SSHPort)}},
			st.nic(HeadProvMAC, "head", NetProv),
		}}
	if st.Spec.Tentacles {
		v.NICs = []NIC{
			{MAC: HeadMgmtMAC, HostFwd: []string{fmt.Sprintf("tcp:127.0.0.1:%d-:22", st.Spec.SSHPort),
				fmt.Sprintf("tcp:127.0.0.1:%d-:6820", st.Spec.RESTPort)}},
			st.nic(HeadProvMAC, "head", NetCore),
			st.nic(HeadClusterMAC, "head", NetCluster),
		}
	}
	return v
}

// infraVMs is every VM in the lab but the nodes: the head and the tentacles.
func (st State) infraVMs() []VM {
	var out []VM
	if st.Spec.Head {
		out = append(out, st.HeadVM())
	}
	for _, t := range st.Tentacles {
		out = append(out, st.TentacleVM(t))
	}
	return out
}

// Load reads lab.json.
func Load(dir string) (State, error) {
	var st State
	b, err := os.ReadFile(filepath.Join(dir, "lab.json"))
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(b, &st)
}

func (st State) save() error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(st.Dir, "lab.json"), b, 0o644)
}

// Running reports whether the lab daemon is alive.
func (st State) Running() bool {
	pid, err := readPid(st.daemonPid())
	return err == nil && syscall.Kill(pid, 0) == nil
}

// Options locate the tools Up needs.
type Options struct {
	Dir        string
	HeadBinary string    // linux/arm64 flapjack for the head node; optional
	Log        io.Writer // progress output
}

const (
	// ipxeRev is the iPXE source the lab head builds signed iPXE from.
	ipxeRev      = "e6555a5"
	ipxeARM64URL = "https://boot.ipxe.org/arm64-efi/ipxe.efi"
	ipxeX86URL   = "https://boot.ipxe.org/x86_64-efi/ipxe.efi"
	ipxeBIOSURL  = "https://boot.ipxe.org/undionly.kpxe"

	// Nix for the head node's nix overlay engine, pinned by hash: a static
	// aarch64 build of Nix 2.35.5 from Hydra, and nixpkgs 26.05 (only its
	// lib/ is used, for the module system).
	nixURL        = "https://hydra.nixos.org/build/351751017/download/1/nix"
	nixSHA256     = "e1f2ac2d70425a030d0267bd7afa91e3f11d966edc4fd507042e23bdfbe0dfd5"
	nixpkgsRev    = "7dcdd87373d72e7a2173e4db02e20d3d7f495cfd"
	nixpkgsURL    = "https://github.com/NixOS/nixpkgs/archive/" + nixpkgsRev + ".tar.gz"
	nixpkgsSHA256 = "9a7231386a5e240ba1708f318a4492acbb324ff24bb60592a813f52e2ac1be5f"
	// The head and tentacles run Rocky Linux 9; node images are built from
	// the head's repositories, so they are Rocky 9 too.
	baseImagesURL = "https://dl.rockylinux.org/pub/rocky/9/images/aarch64/"
	baseImage     = "Rocky-9-GenericCloud-Base.latest.aarch64.qcow2"
)

// Up builds the lab and starts its daemon, which owns the switch, the
// Redfish BMCs and the VMs and keeps running after Up returns.
func Up(spec Spec, o Options) (State, error) {
	spec.defaults()
	logf := func(format string, args ...any) {
		if o.Log != nil {
			fmt.Fprintf(o.Log, format+"\n", args...)
		}
	}
	st := State{Spec: spec, Dir: o.Dir, Nodes: Layout(spec), RedfishUser: "admin", HeadBinary: o.HeadBinary}
	if spec.Tentacles {
		if !spec.Head {
			return st, errors.New("the tentacle layout needs the head node")
		}
		if spec.X86BIOS+spec.X86Secure > 0 {
			return st, errors.New("the tentacle layout has aarch64 nodes only")
		}
		st.Tentacles = TentacleLayout(spec)
	}
	if old, err := Load(o.Dir); err == nil && old.Running() {
		return old, errors.New("lab is already running; run 'flapjack lab down' first")
	}
	if b, err := os.ReadFile(filepath.Join(o.Dir, "safety-stop")); err == nil {
		logf("note: the safety watchdog stopped this lab last time:\n  %s  starting again", strings.TrimSpace(string(b)))
		os.Remove(filepath.Join(o.Dir, "safety-stop"))
	}
	if old, err := Load(o.Dir); err == nil && old.Spec.Tentacles != spec.Tentacles {
		layout := map[bool]string{true: "tentacles", false: "flat"}[old.Spec.Tentacles]
		return old, fmt.Errorf("the lab in %s has the %s layout: pass --layout %s, or run 'flapjack lab destroy' first", o.Dir, layout, layout)
	}
	for _, d := range []string{o.Dir, filepath.Join(o.Dir, "ports"), filepath.Join(o.Dir, "vms")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return st, err
		}
	}
	if spec.X86BIOS+spec.X86Secure > 0 {
		logf("warning: x86_64 nodes will not boot: boot is signed, and the lab head only builds signed iPXE for arm64")
	}
	if len(st.switchSock(NetCluster)) > 100 {
		return st, fmt.Errorf("lab directory %s is too long for Unix socket paths; use a shorter --dir", o.Dir)
	}

	prefix, err := exec.Command("brew", "--prefix", "qemu").Output()
	if err != nil {
		return st, errors.New("Homebrew QEMU not found: brew install qemu swtpm")
	}
	q := strings.TrimSpace(string(prefix))
	st.QEMUBin, st.FirmwareDir = filepath.Join(q, "bin"), filepath.Join(q, "share", "qemu")
	if st.Swtpm, err = exec.LookPath("swtpm"); err != nil {
		if _, err := os.Stat("/opt/homebrew/bin/swtpm"); err != nil {
			return st, errors.New("swtpm not found: brew install swtpm")
		}
		st.Swtpm = "/opt/homebrew/bin/swtpm"
	}

	home, _ := os.UserHomeDir()
	cache := filepath.Join(home, ".flapjack", "cache")
	st.IPXEARM64 = filepath.Join(cache, "ipxe-arm64", "ipxe.efi")
	st.IPXEX86 = filepath.Join(cache, "ipxe-x86_64", "ipxe.efi")
	st.IPXEBIOS = filepath.Join(cache, "ipxe-bios", "undionly.kpxe")
	for url, dest := range map[string]string{ipxeARM64URL: st.IPXEARM64, ipxeX86URL: st.IPXEX86, ipxeBIOSURL: st.IPXEBIOS} {
		if err := download(url, dest, "", logf); err != nil {
			return st, err
		}
	}

	if _, err := os.Stat(st.passwordPath()); errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(st.passwordPath(), []byte(rand.Text()+"\n"), 0o600); err != nil {
			return st, err
		}
	}

	if spec.Head {
		// Head and tentacle disks are qcow2 overlays on the base image, so
		// a lab keeps the one it was created with.
		if old, err := Load(o.Dir); err == nil && old.HeadImage != "" {
			if _, err := os.Stat(old.HeadImage); err == nil {
				st.HeadImage = old.HeadImage
			}
		}
		if st.HeadImage == "" {
			sum, err := baseChecksum()
			if err != nil {
				return st, err
			}
			// Named by checksum: a newer upstream release must be a new
			// file, never a replacement (replacing it in place corrupts
			// every existing disk).
			st.HeadImage = filepath.Join(cache, "rocky", sum[:16]+"-"+baseImage)
			if err := download(baseImagesURL+baseImage, st.HeadImage, sum, logf); err != nil {
				return st, err
			}
		}
		if _, err := os.Stat(st.SSHKey()); errors.Is(err, os.ErrNotExist) {
			if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "flapjack-lab", "-f", st.SSHKey()).CombinedOutput(); err != nil {
				return st, fmt.Errorf("ssh-keygen: %v: %s", err, out)
			}
		}
		for _, v := range st.infraVMs() {
			size := "20G"
			if v.Name != "head" {
				size = "10G"
			}
			if _, err := os.Stat(v.Disk); errors.Is(err, os.ErrNotExist) {
				os.MkdirAll(filepath.Dir(v.Disk), 0o755)
				out, err := exec.Command(filepath.Join(st.QEMUBin, "qemu-img"), "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", st.HeadImage, v.Disk, size).CombinedOutput()
				if err != nil {
					return st, fmt.Errorf("qemu-img: %v: %s", err, out)
				}
			}
		}
		if st.HeadBinary == "" {
			logf("warning: no --head-binary; the head node will boot without flapjack installed")
		}
		st.NixBin = filepath.Join(cache, "nix", "nix-2.35.5-aarch64-static")
		st.Nixpkgs = filepath.Join(cache, "nix", "nixpkgs-"+nixpkgsRev[:12]+".tar.gz")
		if err := download(nixURL, st.NixBin, nixSHA256, logf); err != nil {
			return st, err
		}
		if err := download(nixpkgsURL, st.Nixpkgs, nixpkgsSHA256, logf); err != nil {
			return st, err
		}
	}
	if err := st.save(); err != nil {
		return st, err
	}

	os.Remove(st.readyPath())
	self, err := os.Executable()
	if err != nil {
		return st, err
	}
	logFile, err := os.OpenFile(filepath.Join(o.Dir, "daemon.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return st, err
	}
	defer logFile.Close()
	cmd := exec.Command(self, "lab", "daemon", "--dir", o.Dir)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return st, err
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	deadline := time.After(2 * time.Minute)
	for {
		if _, err := os.Stat(st.readyPath()); err == nil {
			cmd.Process.Release()
			return st, nil
		}
		select {
		case err := <-exited:
			return st, fmt.Errorf("lab daemon exited (%v); see %s", err, filepath.Join(o.Dir, "daemon.log"))
		case <-deadline:
			return st, errors.New("lab daemon did not become ready within 2 minutes")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// Down stops the lab daemon, which powers off every VM. VMs left behind
// by a crashed daemon are stopped directly.
func Down(dir string) error {
	st, err := Load(dir)
	if err != nil {
		return err
	}
	if pid, err := readPid(st.daemonPid()); err == nil {
		syscall.Kill(pid, syscall.SIGTERM)
		waitFor(func() bool { return !st.Running() }, time.Minute)
	}
	var errs []error
	for _, n := range st.Nodes {
		errs = append(errs, st.VM(n).Stop())
	}
	errs = append(errs, st.HeadVM().Stop())
	for _, t := range st.Tentacles {
		errs = append(errs, st.TentacleVM(t).Stop())
	}
	return errors.Join(errs...)
}

// Destroy stops the lab and deletes its VMs, NVRAM, TPM state, keys and
// capture. Downloads in ~/.flapjack/cache are kept, so the next Up is fast.
func Destroy(dir string) error {
	// Only ever delete a directory that is recognisably a lab.
	if _, err := os.Stat(filepath.Join(dir, "lab.json")); err != nil {
		return fmt.Errorf("%s is not a lab directory (no lab.json)", dir)
	}
	if err := Down(dir); err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

// Machine is a lab VM with a BMC: power goes to QEMU, while inventory,
// BIOS settings and firmware versions are emulated by bmc.Fake (staged
// changes apply on the next boot, as on hardware).
type Machine struct {
	*bmc.Fake
	VM VM
}

func (m *Machine) PowerState(context.Context) (string, error) {
	if m.VM.Running() {
		return bmc.PowerStatusOn, nil
	}
	return bmc.PowerStatusOff, nil
}

func (m *Machine) SetPower(ctx context.Context, a bmc.PowerAction) error {
	var err error
	switch a {
	case bmc.PowerOn:
		err = m.VM.Start()
	case bmc.PowerOff:
		err = m.VM.Stop()
	case bmc.PowerSoft:
		if m.VM.Running() {
			_, err = m.VM.QMP("system_powerdown", nil)
		}
	case bmc.PowerReset:
		if m.VM.Running() {
			_, err = m.VM.QMP("system_reset", nil)
		} else {
			err = m.VM.Start()
		}
	case bmc.PowerCycle:
		if err = m.VM.Stop(); err == nil {
			err = m.VM.Start()
		}
	default:
		return fmt.Errorf("unknown power action %q", a)
	}
	if err != nil {
		return err
	}
	return m.Fake.SetPower(ctx, a)
}

// Daemon runs the lab until SIGTERM: the switch, one Redfish BMC per node
// on 127.0.0.1, the head node's cloud-init seed, and the VMs.
func Daemon(dir string) error {
	st, err := Load(dir)
	if err != nil {
		return err
	}
	if err := os.WriteFile(st.daemonPid(), []byte(fmt.Sprint(os.Getpid())), 0o644); err != nil {
		return err
	}
	defer os.Remove(st.daemonPid())
	defer os.Remove(st.readyPath())

	switches := map[string]*Switch{}
	var captures []*flushWriter
	for network, ports := range st.Networks() {
		pcap, err := os.Create(st.PcapPath(network))
		if err != nil {
			return err
		}
		defer pcap.Close()
		capture := &flushWriter{w: bufio.NewWriterSize(pcap, 1<<20)}
		captures = append(captures, capture)
		_ = ports // the switch learns its ports as VMs connect
		sw, err := NewSwitch(st.switchSock(network), capture)
		if err != nil {
			return fmt.Errorf("%s switch: %w", network, err)
		}
		if st.Spec.SwitchMbps > 0 {
			sw.Rate = int64(st.Spec.SwitchMbps) * 1_000_000 / 8
		}
		if st.Spec.SwitchFPS > 0 {
			sw.FrameRate = int64(st.Spec.SwitchFPS)
		}
		go sw.Serve()
		defer sw.Close()
		switches[network] = sw
	}
	flush := func() {
		for _, c := range captures {
			c.Flush()
		}
	}

	pw, err := st.RedfishPassword()
	if err != nil {
		return err
	}
	var servers []*http.Server
	var powerOn []*Machine
	for _, n := range st.Nodes {
		m := &Machine{VM: st.VM(n), Fake: &bmc.Fake{
			Power: bmc.PowerStatusOff,
			Inv: bmc.Inventory{Manufacturer: "Flapjack", Model: "Lab VM (" + string(n.Arch) + ")", Serial: n.Serial,
				Firmware: map[string]string{"BIOS": "lab-1.0", "BMC": "lab-1.0", "NIC1": "lab-1.0"},
				BIOS:     map[string]string{"SMTMode": "Enabled", "BootMode": bootMode(n.Boot)}},
		}}
		addr := strings.TrimPrefix(n.Redfish, "http://")
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("%s BMC: %w", n.Name, err)
		}
		srv := &http.Server{Handler: &bmc.RedfishServer{Driver: m, User: st.RedfishUser, Password: pw}, ReadHeaderTimeout: 10 * time.Second}
		servers = append(servers, srv)
		go srv.Serve(ln)
		if st.Spec.PowerOn {
			powerOn = append(powerOn, m)
		}
	}
	defer func() {
		for _, s := range servers {
			s.Close()
		}
	}()

	if st.Spec.Head {
		seed, err := st.seedServer()
		if err != nil {
			return err
		}
		defer seed.Close()
		for _, v := range st.infraVMs() {
			if err := v.Start(); err != nil {
				return fmt.Errorf("%s: %w", v.Name, err)
			}
		}
	}
	// On a fresh lab the head has not built signed iPXE yet, so nodes
	// powered on at start are switched on once it has.
	stopPower := make(chan struct{})
	defer close(stopPower)
	go powerOnWhenReady(powerOn, st.SignedIPXE(), stopPower)

	stats := filepath.Join(dir, "switch-stats.json")
	if err := os.WriteFile(st.readyPath(), nil, 0o644); err != nil {
		return err
	}
	// The safety watchdog: pause everything the moment mDNSResponder stops
	// answering (see safety.go).
	tripped := make(chan string, 1)
	if _, err := exec.LookPath("dns-sd"); err == nil {
		stopWatch := make(chan struct{})
		defer close(stopWatch)
		go watchdog(func() error { return probeMDNS(3 * time.Second) }, 2*time.Second, 2, func(reason string) {
			for _, sw := range switches {
				sw.Paused.Store(true)
			}
			tripped <- reason
		}, stopWatch)
	} else {
		fmt.Fprintln(os.Stderr, "warning: dns-sd not found; the lab runs without its safety watchdog")
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case reason := <-tripped:
			msg := fmt.Sprintf("%s: SAFETY STOP: %s. The lab paused its switches and powered off its VMs before macOS's watchdog could act. "+
				"See docs/testing/mac-lab.md (Findings) before starting it again.\n", time.Now().Format(time.DateTime), reason)
			fmt.Fprint(os.Stderr, msg)
			os.WriteFile(st.SafetyStopPath(), []byte(msg), 0o644)
			stopAll(st)
			flush()
			return errors.New("safety stop: " + reason)
		case <-sig:
			var wg sync.WaitGroup
			for _, n := range st.Nodes {
				wg.Go(func() { st.VM(n).Stop() })
			}
			for _, v := range st.infraVMs() {
				wg.Go(func() { v.Stop() })
			}
			wg.Wait()
			flush()
			return nil
		case <-tick.C:
			all := map[string]map[string]int64{}
			for network, sw := range switches {
				all[network] = map[string]int64{"frames": sw.Frames.Load(), "dropped": sw.Dropped.Load(), "waits": sw.Waits.Load()}
			}
			b, _ := json.Marshal(all)
			os.WriteFile(stats, b, 0o644)
			flush()
		}
	}
}

// stopAll powers off every VM at once: QEMU exits immediately (QMP quit,
// then SIGKILL), which ends all of its socket traffic.
func stopAll(st State) {
	var wg sync.WaitGroup
	for _, n := range st.Nodes {
		wg.Go(func() { st.VM(n).Stop() })
	}
	for _, v := range st.infraVMs() {
		wg.Go(func() { v.Stop() })
	}
	wg.Wait()
}

// powerOnWhenReady powers machines on as soon as the signed iPXE they boot
// exists, retrying until each is on.
func powerOnWhenReady(ms []*Machine, ipxe string, stop <-chan struct{}) {
	logged := false
	for len(ms) > 0 {
		if _, err := os.Stat(ipxe); err == nil {
			var left []*Machine
			for _, m := range ms {
				if err := m.SetPower(context.Background(), bmc.PowerOn); err != nil {
					fmt.Fprintf(os.Stderr, "%s: not powered on yet: %v\n", m.VM.Name, err)
					left = append(left, m)
				}
			}
			ms = left
		} else if !logged {
			fmt.Fprintf(os.Stderr, "nodes wait for the head's signed iPXE (%s) before powering on\n", ipxe)
			logged = true
		}
		if len(ms) == 0 {
			return
		}
		select {
		case <-stop:
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func bootMode(b Boot) string {
	if b == BootBIOS {
		return "Legacy"
	}
	return "Uefi"
}

// flushWriter buffers the pcap and flushes it periodically, so the capture
// can be opened in Wireshark while the lab runs.
type flushWriter struct {
	mu sync.Mutex
	w  *bufio.Writer
}

func (f *flushWriter) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.w.Write(p)
}

func (f *flushWriter) Flush() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.w.Flush()
}

// LabOverlays are the example overlays every lab class uses: base
// (Warewulf-style templates), then site and rack-overrides (NixOS-style
// modules, evaluated together).
var LabOverlays = []string{"base", "site", "rack-overrides"}

// hosts is the /etc/hosts block naming the lab's nodes on the head node.
func (st State) hosts() string {
	if st.Spec.Tentacles {
		return st.hpcHosts()
	}
	var b strings.Builder
	b.WriteString("# BEGIN flapjack-lab\n")
	for _, n := range st.Nodes {
		fmt.Fprintf(&b, "%s  %s.cluster %s\n", n.IP, n.Name, n.Name)
	}
	b.WriteString("# END flapjack-lab\n")
	return b.String()
}

// Lab classes, one per architecture.
const (
	ClassARM64 = "lab-arm64"
	ClassX86   = "lab-x86_64"
)

// Cluster is the lab's nodes as Flapjack sees them, loaded into the head
// node's flapjack.service on every boot. BMC addresses use 10.0.2.2, which
// is how the head node reaches this Mac's loopback.
func (st State) Cluster() v1.Cluster {
	if st.Spec.Tentacles {
		return st.hpcCluster()
	}
	c := v1.Cluster{Classes: []v1.NodeClass{
		{Name: ClassARM64, Image: "el9-aarch64", Rootfs: v1.RootfsTmpfs, BootArgs: []string{"console=ttyAMA0"},
			Overlays: LabOverlays},
	}}
	if st.Spec.X86BIOS+st.Spec.X86Secure > 0 {
		c.Classes = append(c.Classes, v1.NodeClass{Name: ClassX86, Image: "el9-x86_64", Rootfs: v1.RootfsTmpfs, BootArgs: []string{"console=ttyS0"},
			Overlays: LabOverlays})
	}
	for _, n := range st.Nodes {
		class, fw := ClassARM64, v1.FirmwareUEFI
		if n.Arch == AMD64 {
			class = ClassX86
		}
		if n.Boot == BootBIOS {
			fw = v1.FirmwareBIOS
		}
		c.Nodes = append(c.Nodes, v1.Node{
			Name: n.Name, Class: class, Rack: n.Rack, Block: n.Rack, Firmware: fw, Serial: n.Serial,
			Labels:     map[string]string{"arch": string(n.Arch), "lab": "true"},
			BMC:        v1.BMC{Driver: v1.BMCRedfish, Address: strings.Replace(n.Redfish, "127.0.0.1", "10.0.2.2", 1)},
			Interfaces: []v1.Interface{{Name: "prov", MAC: n.MAC, Network: "provisioning", IP: n.IP}},
		})
	}
	return c
}

// baseChecksum fetches the published SHA-256 of the head and tentacle
// image. Rocky lists it BSD-style ("SHA256 (file) = sum"); GNU style
// ("sum  file") is accepted too.
func baseChecksum() (string, error) {
	resp, err := http.Get(baseImagesURL + "CHECKSUM")
	if err != nil {
		return "", fmt.Errorf("fetch image CHECKSUM: %w", err)
	}
	defer resp.Body.Close()
	sum, ok := findChecksum(resp.Body, baseImage)
	if !ok {
		return "", errors.New("image CHECKSUM does not list " + baseImage)
	}
	return sum, nil
}

func findChecksum(r io.Reader, file string) (string, bool) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		switch {
		case len(f) == 4 && f[0] == "SHA256" && f[1] == "("+file+")" && f[2] == "=":
			return strings.ToLower(f[3]), true
		case len(f) == 2 && strings.TrimPrefix(f[1], "*") == file:
			return strings.ToLower(f[0]), true
		}
	}
	return "", false
}

// download fetches url to dest unless dest already exists (and matches
// sha256, if given). Downloads go to a temp file and are verified before
// being moved into place.
func download(url, dest, sha string, logf func(string, ...any)) error {
	if b, err := os.Open(dest); err == nil {
		h := sha256.New()
		io.Copy(h, b)
		b.Close()
		got := hex.EncodeToString(h.Sum(nil))
		if sha == "" || got == sha {
			return nil
		}
		logf("%s is out of date; downloading again", filepath.Base(dest))
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	logf("downloading %s", url)
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", url, resp.Status)
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".download-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), resp.Body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if sha != "" && got != sha {
		return fmt.Errorf("%s: sha256 %s, expected %s", url, got, sha)
	}
	logf("  sha256 %s", got)
	return os.Rename(tmp.Name(), dest)
}

//go:embed head-setup.sh
var headSetupSrc string

var headSetup = template.Must(template.New("head-setup").Parse(headSetupSrc))

// exampleOverlays are installed into /etc/flapjack/overlays on a fresh
// head node.
//
//go:embed all:overlays
var exampleOverlays embed.FS

// tarFS writes dir of fsys as a gzipped tar, with ordinary permissions.
func tarFS(w io.Writer, fsys fs.FS, dir string) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	err := fs.WalkDir(fsys, dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == dir {
			return err
		}
		name := strings.TrimPrefix(p, dir+"/")
		if d.IsDir() {
			return tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: name + "/", Mode: 0o755})
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Size: int64(len(b))}); err != nil {
			return err
		}
		_, err = tw.Write(b)
		return err
	})
	if err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}
