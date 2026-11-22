package main

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/damen-pt/flapjack/internal/lab"
)

func defaultLabDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".flapjack", "lab")
}

func labUp(args []string) error {
	fs := flags("lab up", "")
	dir := fs.String("dir", defaultLabDir(), "lab state directory (keep it short: Unix socket path limit)")
	var spec lab.Spec
	layout := fs.String("layout", "tentacles", `"tentacles": head, one tentacle per rack, compute nodes and Slurm; "flat": head and nodes on one network`)
	fs.IntVar(&spec.Racks, "racks", 2, "racks")
	fs.IntVar(&spec.NodesPerRack, "nodes", 2, "aarch64 nodes per rack (fast, HVF)")
	fs.IntVar(&spec.X86BIOS, "x86-bios", 0, "flat layout: emulated x86_64 legacy-BIOS nodes (slow)")
	fs.IntVar(&spec.X86Secure, "x86-secure", 0, "flat layout: emulated x86_64 Secure Boot nodes (slow)")
	fs.IntVar(&spec.NodeMemoryMiB, "node-mem", 0, "node memory in MiB (default 1024, 1536 with tentacles)")
	fs.IntVar(&spec.TentacleMemoryMiB, "tentacle-mem", 1024, "tentacle memory in MiB")
	fs.IntVar(&spec.LoginNodes, "login-nodes", 1, "tentacles layout: login nodes (rack 1), with users and shared /c/home")
	fs.BoolVar(&spec.Head, "head", true, "start the Rocky Linux 9 head node")
	fs.BoolVar(&spec.PowerOn, "power-on", true, "power nodes on as soon as the head has built their iPXE (otherwise use Redfish)")
	fs.IntVar(&spec.SSHPort, "ssh-port", 2222, "head SSH on 127.0.0.1 (tentacle rN: this + N)")
	fs.IntVar(&spec.SeedPort, "seed-port", 7400, "cloud-init seed server on 127.0.0.1")
	fs.IntVar(&spec.RedfishBasePort, "redfish-port", 8100, "first node BMC on 127.0.0.1")
	fs.IntVar(&spec.RESTPort, "rest-port", 6820, "tentacles layout: slurmrestd forwarded to 127.0.0.1")
	fs.IntVar(&spec.SwitchMbps, "switch-mbps", 100, "byte-rate cap per lab network, in Mbit/s")
	fs.IntVar(&spec.SwitchFPS, "switch-fps", 4000, "frame-rate cap per lab network, frames/s; keep it modest: every frame is work for the Mac's kernel (see docs/testing/mac-lab.md)")
	headBin := fs.String("head-binary", "", "linux/arm64 flapjack for the head node (default: flapjack-linux-arm64 next to this binary)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if spec.SwitchMbps < 1 || spec.SwitchMbps > 1000 {
		return fmt.Errorf("--switch-mbps %d: want 1-1000", spec.SwitchMbps)
	}
	if spec.SwitchFPS < 100 || spec.SwitchFPS > 20000 {
		return fmt.Errorf("--switch-fps %d: want 100-20000 (25,000 frames/s has hung macOS)", spec.SwitchFPS)
	}
	switch *layout {
	case "tentacles":
		spec.Tentacles = true
		if spec.NodeMemoryMiB == 0 {
			spec.NodeMemoryMiB = 1536 // the Slurm image's root filesystem lives in RAM
		}
	case "flat":
	default:
		return fmt.Errorf("--layout %q: want tentacles or flat", *layout)
	}
	if *headBin == "" {
		if self, err := os.Executable(); err == nil {
			if p := filepath.Join(filepath.Dir(self), "flapjack-linux-arm64"); fileExists(p) {
				*headBin = p
			}
		}
	}
	if *headBin != "" {
		abs, err := filepath.Abs(*headBin)
		if err != nil {
			return err
		}
		*headBin = abs
	}
	st, err := lab.Up(spec, lab.Options{Dir: *dir, HeadBinary: *headBin, Log: os.Stderr})
	if err != nil {
		return err
	}
	return printLab(st)
}

func labDown(args []string) error {
	fs := flags("lab down", "")
	dir := fs.String("dir", defaultLabDir(), "lab state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return lab.Down(*dir)
}

func labStatus(args []string) error {
	fs := flags("lab status", "")
	dir := fs.String("dir", defaultLabDir(), "lab state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := lab.Load(*dir)
	if err != nil {
		return fmt.Errorf("no lab in %s: %w", *dir, err)
	}
	return printLab(st)
}

func labDestroy(args []string) error {
	fs := flags("lab destroy", "")
	dir := fs.String("dir", defaultLabDir(), "lab state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := lab.Destroy(*dir); err != nil {
		return err
	}
	fmt.Printf("destroyed %s (downloads in ~/.flapjack/cache kept)\n", *dir)
	return nil
}

// labSSH replaces this process with ssh to the head node; extra arguments
// are run as a remote command.
func labSSH(args []string) error {
	fs := flags("lab ssh", "[command...]")
	dir := fs.String("dir", defaultLabDir(), "lab state directory")
	vm := fs.String("vm", "head", "head, a tentacle (tentacle-r1, ...) or a login node (login01, ...)")
	user := fs.String("user", "", "user to log in as (default flapjack; alice on login nodes)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := lab.Load(*dir)
	if err != nil {
		return fmt.Errorf("no lab in %s: %w", *dir, err)
	}
	if !st.Spec.Head {
		return errors.New("this lab has no head node")
	}
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		return err
	}
	port := st.Spec.SSHPort
	if *vm != "head" {
		port = 0
		for _, t := range st.Tentacles {
			if t.Name == *vm || t.Rack == *vm {
				port = t.SSHPort
			}
		}
		for _, n := range st.Nodes {
			if n.Name == *vm && n.SSHPort > 0 {
				port = n.SSHPort
				if *user == "" {
					*user = lab.LabUsers[0].Name
				}
			}
		}
		if port == 0 {
			return fmt.Errorf("no VM %q in this lab", *vm)
		}
	}
	argv := []string{"ssh", "-i", st.SSHKey(), "-p", strconv.Itoa(port),
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
		cmp.Or(*user, "flapjack") + "@127.0.0.1"}
	return syscall.Exec(ssh, append(argv, fs.Args()...), os.Environ())
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func labDaemon(args []string) error {
	fs := flags("lab daemon", "")
	dir := fs.String("dir", defaultLabDir(), "lab state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return lab.Daemon(*dir)
}

func printLab(st lab.State) error {
	state := "stopped"
	if st.Running() {
		state = "running"
	}
	fmt.Printf("lab %s in %s\n\n", state, st.Dir)
	if b, err := os.ReadFile(st.SafetyStopPath()); err == nil {
		fmt.Printf("%s\n", strings.TrimSpace(string(b)))
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NODE\tRACK\tARCH\tBOOT\tPOWER\tMAC\tSERIAL\tREDFISH")
	for _, n := range st.Nodes {
		power := "off"
		if st.VM(n).Running() {
			power = "on"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", n.Name, n.Rack, n.Arch, n.Boot, power, n.MAC, n.Serial, n.Redfish)
	}
	tw.Flush()
	power := func(v lab.VM) string {
		if v.Running() {
			return "on"
		}
		return "off"
	}
	if len(st.Tentacles) > 0 {
		fmt.Println()
		tw = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "TENTACLE\tRACK\tPOWER\tCORE\tRACK NETWORK\tSSH")
		for _, t := range st.Tentacles {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\tflapjack lab ssh --vm %s\n", t.Name, t.Rack, power(st.TentacleVM(t)), t.CoreIP, t.RackSubnet(), t.Name)
		}
		tw.Flush()
	}
	for _, n := range st.Nodes {
		if n.SSHPort > 0 {
			fmt.Printf("\nLogin:    %s for users %s: flapjack lab ssh --vm %s [--user NAME]  (127.0.0.1:%d)", n.Name, userNames(), n.Name, n.SSHPort)
		}
	}
	pw, _ := st.RedfishPassword()
	fmt.Printf("\nRedfish:  user %s, password %s\n", st.RedfishUser, pw)
	nets := slices.Sorted(maps.Keys(st.Networks()))
	var caps []string
	for _, n := range nets {
		caps = append(caps, filepath.Base(st.PcapPath(n)))
	}
	fmt.Printf("Capture:  %s/{%s} (open in Wireshark)\n", st.Dir, strings.Join(caps, ","))
	if st.Spec.Head {
		fmt.Printf("Head:     %s, flapjack on %s; connect with: flapjack lab ssh\n", power(st.HeadVM()), st.HeadAddress())
		if st.Spec.Tentacles {
			fmt.Printf("Slurm:    slurmctld and slurmrestd on the head; REST API on http://127.0.0.1:%d (JWT from: flapjack lab ssh -- scontrol token)\n", st.Spec.RESTPort)
		}
	}
	return nil
}

func userNames() string {
	var names []string
	for _, u := range lab.LabUsers {
		names = append(names, u.Name)
	}
	return strings.Join(names, ", ")
}
