package lab

import (
	"fmt"
	"path/filepath"
	"strings"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/server"
	"github.com/damen-pt/flapjack/internal/topology"
)

// The tentacle (HPC) layout, `flapjack lab up --layout tentacles`:
//
//	                       ┌──────────── fj-head ────────────┐
//	                       │ flapjack.service · slurmctld    │
//	                       │ slurmrestd · munge              │
//	                       └──┬──────────────────────────┬───┘
//	         core 10.98.0.0/24│                          │cluster 10.100.0.0/16
//	          ┌───────────────┴──┐   ┌──────────────┐    │ (Slurm, ssh, jobs)
//	          │ tentacle-r1      │   │ tentacle-r2  │    │
//	          │ DHCP · boot · mTLS   │ ...          │    │
//	          └────────┬─────────┘   └──────┬───────┘    │
//	        r1 10.1.1.0/24             r2 10.1.2.0/24    │
//	          r1n01  r1n02             r2n01  r2n02 ─────┘
//
// Each rack's management network reaches only its tentacle: firmware,
// iPXE, boot scripts, images, overlays and enrollment all come through it,
// exactly as in docs/design/tentacles.md. The head reaches the nodes, and
// the nodes reach slurmctld, over the cluster network, which carries no
// flapjack traffic (the head's flapjack listeners are on the core address).

// Networks of the tentacle layout; rack networks are named after the rack.
const (
	NetCore    = "core"
	NetCluster = "cluster"
)

// Head addresses in the tentacle layout.
const (
	HeadCoreIP     = "10.98.0.1/24"
	HeadClusterMAC = "52:54:00:00:00:03"
	HeadClusterIP  = "10.100.0.1/16"
	TentaclePort   = 7444 // the head's tentacle listener, on the core
)

// The classes and the image both boot: login nodes run the compute image
// with different overlays.
const (
	ClassCompute = "compute"
	ClassLogin   = "login"
	ComputeImage = "rocky9-aarch64"
)

// HPCOverlays are the compute class's overlays: base (templates), then
// site, rack-overrides, fabric, accounts, home and slurm (NixOS-style
// modules, evaluated together). Login nodes add login (templates).
var HPCOverlays = []string{"base", "site", "rack-overrides", "fabric", "accounts", "home", "slurm"}

// LoginOverlays are the login class's overlays.
var LoginOverlays = append(append([]string{}, HPCOverlays...), "login")

// HomeRoot is where users' homes live: exported by the head over NFS on
// the cluster network and automounted on every node.
const HomeRoot = "/c/home"

// LabUser is a cluster user, the same on the head and every node.
type LabUser struct {
	Name string `json:"name"`
	UID  int    `json:"uid"`
}

// LabUsers must match the accounts overlay's defaults
// (overlays/accounts/default.nix); TestLabUsersMatchAccounts checks.
var LabUsers = []LabUser{{"alice", 2001}, {"bob", 2002}, {"carol", 2003}, {"dave", 2004}}

// TentacleInfo is one rack's tentacle VM.
type TentacleInfo struct {
	Rack    string `json:"rack"`
	Name    string `json:"name"` // tentacle-r1
	MgmtMAC string `json:"mgmtMAC"`
	CoreMAC string `json:"coreMAC"`
	RackMAC string `json:"rackMAC"`
	CoreIP  string `json:"coreIP"` // on the management core, no prefix
	RackIP  string `json:"rackIP"` // on the rack's management network, no prefix
	SSHPort int    `json:"sshPort"`
}

// RackSubnet is the tentacle's rack network with prefix.
func (t TentacleInfo) RackSubnet() string { return t.RackIP + "/24" }

// TentacleLayout computes the tentacles: rack R's is 10.98.0.(10+R) on the
// core and 10.1.R.1 on its rack.
func TentacleLayout(s Spec) []TentacleInfo {
	s.defaults()
	var out []TentacleInfo
	for r := 1; r <= s.Racks; r++ {
		out = append(out, TentacleInfo{
			Rack: fmt.Sprintf("r%d", r), Name: fmt.Sprintf("tentacle-r%d", r),
			MgmtMAC: fmt.Sprintf("52:54:00:f0:%02x:01", r),
			CoreMAC: fmt.Sprintf("52:54:00:f0:%02x:02", r),
			RackMAC: fmt.Sprintf("52:54:00:f0:%02x:03", r),
			CoreIP:  fmt.Sprintf("10.98.0.%d", 10+r),
			RackIP:  fmt.Sprintf("10.1.%d.1", r),
			SSHPort: s.SSHPort + r,
		})
	}
	return out
}

// hpcLayout computes the compute nodes: node N of rack R is 10.1.R.(10+N)
// on its rack and 10.100.R.(10+N) on the cluster network.
func hpcLayout(s Spec) []NodeInfo {
	var out []NodeInfo
	port := s.RedfishBasePort
	for r := 1; r <= s.Racks; r++ {
		for n := 1; n <= s.NodesPerRack; n++ {
			name := fmt.Sprintf("r%dn%02d", r, n)
			out = append(out, NodeInfo{
				Name: name, Rack: fmt.Sprintf("r%d", r), Arch: ARM64, Boot: BootUEFI, Role: ClassCompute,
				MAC:        fmt.Sprintf("52:54:00:%02x:%02x:01", r, n),
				IP:         fmt.Sprintf("10.1.%d.%d", r, 10+n),
				ClusterMAC: fmt.Sprintf("52:54:00:%02x:%02x:11", r, n),
				ClusterIP:  fmt.Sprintf("10.100.%d.%d", r, 10+n),
				Serial:     "FJLAB-" + strings.ToUpper(name),
				Redfish:    fmt.Sprintf("http://127.0.0.1:%d", port),
			})
			port++
		}
	}
	// Login nodes, in rack 1: 10.1.1.(100+N), cluster 10.100.1.(100+N).
	for i := 1; i <= s.LoginNodes; i++ {
		name := fmt.Sprintf("login%02d", i)
		out = append(out, NodeInfo{
			Name: name, Rack: "r1", Arch: ARM64, Boot: BootUEFI, Role: ClassLogin,
			MAC:        fmt.Sprintf("52:54:00:01:%02x:01", 0xa0+i),
			IP:         fmt.Sprintf("10.1.1.%d", 100+i),
			ClusterMAC: fmt.Sprintf("52:54:00:01:%02x:11", 0xa0+i),
			ClusterIP:  fmt.Sprintf("10.100.1.%d", 100+i),
			PublicMAC:  fmt.Sprintf("52:54:00:01:%02x:21", 0xa0+i),
			SSHPort:    s.SSHPort + 9 + i,
			Serial:     "FJLAB-" + strings.ToUpper(name),
			Redfish:    fmt.Sprintf("http://127.0.0.1:%d", port),
		})
		port++
	}
	return out
}

// isCompute reports whether a tentacle-layout node runs jobs.
func (n NodeInfo) isCompute() bool { return n.Role == "" || n.Role == ClassCompute }

// hpcNetworks: the core joins the head and the tentacles, each rack its
// tentacle and nodes, and the cluster network the head and every node.
func (st State) hpcNetworks() map[string][]string {
	nets := map[string][]string{
		NetCore:    {st.portSock("head", NetCore)},
		NetCluster: {st.portSock("head", NetCluster)},
	}
	for _, t := range st.Tentacles {
		nets[NetCore] = append(nets[NetCore], st.portSock(t.Name, NetCore))
		nets[t.Rack] = append(nets[t.Rack], st.portSock(t.Name, t.Rack))
	}
	for _, n := range st.Nodes {
		nets[n.Rack] = append(nets[n.Rack], st.portSock(n.Name, n.Rack))
		nets[NetCluster] = append(nets[NetCluster], st.portSock(n.Name, NetCluster))
	}
	return nets
}

// TentacleVM returns a tentacle's QEMU definition: a Rocky 9 disk like the
// head's, a NIC on the core, one on its rack, and NAT for SSH from the Mac.
func (st State) TentacleVM(t TentacleInfo) VM {
	return VM{Name: t.Name, Arch: ARM64, Boot: BootUEFI, CPUs: 2, MemoryMiB: st.Spec.TentacleMemoryMiB,
		Dir: st.vmDir(t.Name), FirmwareDir: st.FirmwareDir, QEMUBin: st.QEMUBin,
		Disk:         filepath.Join(st.vmDir(t.Name), "disk.qcow2"),
		SMBIOSSerial: fmt.Sprintf("ds=nocloud-net;s=http://10.0.2.2:%d/tentacle/%s/", st.Spec.SeedPort, t.Rack),
		NICs: []NIC{
			{MAC: t.MgmtMAC, HostFwd: []string{fmt.Sprintf("tcp:127.0.0.1:%d-:22", t.SSHPort)}},
			st.nic(t.CoreMAC, t.Name, NetCore),
			st.nic(t.RackMAC, t.Name, t.Rack),
		}}
}

func (st State) tentacle(rack string) (TentacleInfo, bool) {
	for _, t := range st.Tentacles {
		if t.Rack == rack {
			return t, true
		}
	}
	return TentacleInfo{}, false
}

func bare(cidr string) string { return strings.Split(cidr, "/")[0] }

// hpcCluster is the tentacle layout's cluster.json: one compute class, and
// nodes with a provisioning NIC on their rack and a cluster NIC. Labels
// tell the templates where the node's time server (its tentacle) and the
// head (on the cluster network) are, since neither is .Server.
func (st State) hpcCluster() v1.Cluster {
	c := v1.Cluster{Classes: []v1.NodeClass{{Name: ClassCompute, Image: ComputeImage, Rootfs: v1.RootfsTmpfs,
		BootArgs: []string{"console=ttyAMA0"}, Overlays: HPCOverlays}}}
	if st.Spec.LoginNodes > 0 {
		c.Classes = append(c.Classes, v1.NodeClass{Name: ClassLogin, Image: ComputeImage, Rootfs: v1.RootfsTmpfs,
			BootArgs: []string{"console=ttyAMA0"}, Overlays: LoginOverlays})
	}
	for _, n := range st.Nodes {
		t, _ := st.tentacle(n.Rack)
		class := ClassCompute
		if !n.isCompute() {
			class = n.Role
		}
		c.Nodes = append(c.Nodes, v1.Node{
			Name: n.Name, Class: class, Rack: n.Rack, Block: n.Rack, Firmware: v1.FirmwareUEFI, Serial: n.Serial,
			Labels: map[string]string{"arch": string(n.Arch), "lab": "true", "role": class,
				"tentacle": t.RackIP, "head": bare(HeadClusterIP)},
			BMC: v1.BMC{Driver: v1.BMCRedfish, Address: strings.Replace(n.Redfish, "127.0.0.1", "10.0.2.2", 1)},
			Interfaces: []v1.Interface{
				{Name: "mgmt", MAC: n.MAC, Network: "provisioning", IP: n.IP},
				{Name: "cluster", MAC: n.ClusterMAC, Network: "cluster", IP: n.ClusterIP},
			},
		})
	}
	return c
}

// ServerConfig is the head's server.json in the tentacle layout: flapjack
// listens on the core, every rack is served, booted and leased by its
// tentacle, and the head's own DHCP answers nobody.
func (st State) ServerConfig() server.Config {
	// bootWindow dhcp: the lab powers its VMs on itself, and its rack
	// networks are private QEMU switches (see head-setup.sh).
	c := server.Config{Address: HeadCoreIP, Domain: "cluster", BootWindow: server.BootWindowDHCP,
		TentacleListen: fmt.Sprintf("%s:%d", bare(HeadCoreIP), TentaclePort),
		Tentacles:      map[string]string{}, TentacleBoot: map[string]string{}}
	for _, t := range st.Tentacles {
		c.Tentacles[t.Rack] = "https://" + t.RackIP + ":8443"
		c.TentacleBoot[t.Rack] = "https://" + t.RackIP
		c.TentacleDHCP = append(c.TentacleDHCP, t.Rack)
	}
	return c
}

// SlurmConf is the head's /etc/slurm/slurm.conf. Nodes run configless
// (slurmd --conf-server), so this is the only copy.
func (st State) SlurmConf() string {
	var b strings.Builder
	b.WriteString(`# Generated by flapjack lab. The nodes run configless: slurmd fetches this
# file from slurmctld, so it is the only copy. Edit it here and run
# 'sudo scontrol reconfigure'.
ClusterName=flapjack-lab
SlurmctldHost=fj-head(` + bare(HeadClusterIP) + `)
SlurmctldParameters=enable_configless
SlurmUser=slurm
AuthType=auth/munge
# slurmrestd authenticates users with JWTs from 'scontrol token'.
AuthAltTypes=auth/jwt
AuthAltParameters=jwt_key=/etc/slurm/jwt_hs256.key
StateSaveLocation=/var/spool/slurmctld
SlurmdSpoolDir=/var/spool/slurmd
SchedulerType=sched/backfill
SelectType=select/cons_tres
SelectTypeParameters=CR_Core
ProctrackType=proctrack/linuxproc
TaskPlugin=task/none
JobAcctGatherType=jobacct_gather/none
AccountingStorageType=accounting_storage/none
MpiDefault=none
ReturnToService=2
SlurmdTimeout=120

`)
	var all []string
	byRack := map[string][]string{}
	for _, n := range st.Nodes {
		if !n.isCompute() {
			continue // login nodes only submit
		}
		fmt.Fprintf(&b, "NodeName=%s NodeAddr=%s CPUs=2 Feature=rack_%s State=UNKNOWN\n", n.Name, n.ClusterIP, n.Rack)
		all = append(all, n.Name)
		byRack[n.Rack] = append(byRack[n.Rack], n.Name)
	}
	fmt.Fprintf(&b, "\nPartitionName=compute Nodes=%s Default=YES MaxTime=INFINITE State=UP\n", topology.Hostlist(all))
	for _, t := range st.Tentacles {
		if len(byRack[t.Rack]) > 0 {
			fmt.Fprintf(&b, "PartitionName=%s Nodes=%s MaxTime=INFINITE State=UP\n", t.Rack, topology.Hostlist(byRack[t.Rack]))
		}
	}
	return b.String()
}

// hpcHosts names everything for the head and the tentacles: nodes by
// their cluster address (where the head reaches them), tentacles on the
// core, and the head on the cluster network, where srun and slurmd talk.
func (st State) hpcHosts() string {
	var b strings.Builder
	b.WriteString("# BEGIN flapjack-lab\n")
	fmt.Fprintf(&b, "%s  fj-head.cluster fj-head head\n", bare(HeadClusterIP))
	for _, t := range st.Tentacles {
		fmt.Fprintf(&b, "%s  %s.cluster %s\n", t.CoreIP, t.Name, t.Name)
	}
	for _, n := range st.Nodes {
		fmt.Fprintf(&b, "%s  %s.cluster %s\n", n.ClusterIP, n.Name, n.Name)
		fmt.Fprintf(&b, "%s  %s-mgmt.cluster %s-mgmt\n", n.IP, n.Name, n.Name)
	}
	b.WriteString("# END flapjack-lab\n")
	return b.String()
}

// loginNodes are the tentacle layout's login nodes.
func (st State) loginNodes() []NodeInfo {
	var out []NodeInfo
	for _, n := range st.Nodes {
		if n.Role == ClassLogin {
			out = append(out, n)
		}
	}
	return out
}
