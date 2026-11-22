package lab

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/damen-pt/flapjack/internal/render"
	"github.com/damen-pt/flapjack/internal/server"
)

func TestClusterAddressesAreUnique(t *testing.T) {
	st := State{Spec: Spec{Racks: 3, NodesPerRack: 4, X86BIOS: 2, X86Secure: 2}}
	st.Nodes = Layout(st.Spec)
	c := st.Cluster()
	if len(c.Nodes) != 16 || len(c.Classes) != 2 {
		t.Fatalf("%d nodes, %d classes", len(c.Nodes), len(c.Classes))
	}
	macs, ips := map[string]string{}, map[string]string{}
	for _, n := range c.Nodes {
		i := n.Interfaces[0]
		if other, dup := macs[i.MAC]; dup {
			t.Errorf("%s and %s share MAC %s", n.Name, other, i.MAC)
		}
		if other, dup := ips[i.IP]; dup {
			t.Errorf("%s and %s share IP %s", n.Name, other, i.IP)
		}
		macs[i.MAC], ips[i.IP] = n.Name, n.Name
		if !strings.HasPrefix(n.BMC.Address, "http://10.0.2.2:") {
			t.Errorf("%s BMC %s is not reachable from the head node", n.Name, n.BMC.Address)
		}
	}
	if ips["10.99.1.101"] != "r1b01" || ips["10.99.1.151"] != "r1s01" || ips["10.99.3.4"] != "r3n04" {
		t.Errorf("addresses = %v", ips)
	}
}

func TestSeedServer(t *testing.T) {
	dir := shortDir(t)
	key := filepath.Join(dir, "id_ed25519")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil {
		t.Skipf("ssh-keygen: %v %s", err, out)
	}
	boot := filepath.Join(dir, "undionly.kpxe")
	os.WriteFile(boot, []byte("kpxe"), 0o644)
	st := State{Dir: dir, Spec: Spec{SeedPort: 17400, Racks: 1, NodesPerRack: 1}, IPXEBIOS: boot}
	st.Nodes = Layout(st.Spec)
	srv, err := st.seedServer()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	get := func(p string) string {
		resp, err := http.Get("http://127.0.0.1:17400" + p)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	ud := get("/user-data")
	for _, want := range []string{"ssh-ed25519 ", "/52:54:00:00:00:01/", "ipv4.addresses 10.99.0.1/16", "S=http://10.0.2.2:17400",
		"Before=flapjack.service"} {
		if !strings.Contains(ud, want) {
			t.Errorf("user-data lacks %q", want)
		}
	}
	if strings.Contains(ud, "%!") {
		t.Errorf("user-data has a formatting error:\n%s", ud)
	}
	if c := get("/cluster.json"); !strings.Contains(c, `"ip": "10.99.1.1"`) {
		t.Errorf("cluster.json = %s", c)
	}
	if b := get("/boot/undionly.kpxe"); b != "kpxe" {
		t.Errorf("boot file = %q", b)
	}
	setup := get("/head-setup.sh")
	for _, want := range []string{"SEED=http://10.0.2.2:17400", "server install --address 10.99.0.1/16 --boot-window dhcp --no-start", nixSHA256, nixpkgsRev} {
		if !strings.Contains(setup, want) {
			t.Errorf("head-setup.sh lacks %q", want)
		}
	}
	if h := get("/hosts"); !strings.Contains(h, "10.99.1.1  r1n01.cluster r1n01") {
		t.Errorf("hosts = %q", h)
	}
	resp, err := http.Get("http://127.0.0.1:17400/overlays.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		names = append(names, h.Name)
	}
	for _, want := range []string{"base/overlay.json", "base/rootfs/etc/hosts.ww", "site/default.nix", "rack-overrides/default.nix"} {
		if !slices.Contains(names, want) {
			t.Errorf("overlays.tar.gz lacks %s: %v", want, names)
		}
	}
}

// TestExampleOverlaysRender renders the shipped base overlay (the nix ones
// need nix and are exercised on the head node).
func TestExampleOverlaysRender(t *testing.T) {
	dir := t.TempDir()
	if err := os.CopyFS(dir, mustSub(t, "overlays")); err != nil {
		t.Fatal(err)
	}
	files := filepath.Join(t.TempDir(), "files")
	os.MkdirAll(filepath.Join(files, "ssh"), 0o755)
	os.WriteFile(filepath.Join(files, "ssh", "authorized_keys"), []byte("ssh-ed25519 KEY flapjack@fj-head\n"), 0o644)
	st := State{Spec: Spec{Racks: 2, NodesPerRack: 2}}
	st.Nodes = Layout(st.Spec)
	c := st.Cluster()
	cl := render.Cluster{Server: "10.99.0.1", Domain: "cluster"}
	var nodes []render.Node
	for _, n := range c.Nodes {
		nodes = append(nodes, render.NodeOf(n))
	}
	cl.Nodes = nodes
	r := &render.Renderer{Dir: dir, FilesDir: files}
	class := c.Classes[0]
	class.Overlays = []string{"base"}
	out, err := r.Render(class, nodes, cl)
	if err != nil {
		t.Fatal(err)
	}
	o := out["r2n02"]
	hosts := string(o.Content[o.Manifest.Entries["/etc/hosts"].Digest])
	if !strings.Contains(hosts, "10.99.0.1  head.cluster head\n") || !strings.Contains(hosts, "10.99.2.2  r2n02.cluster r2n02\n") {
		t.Errorf("hosts:\n%s", hosts)
	}
	if e := o.Manifest.Entries["/etc/sudoers.d/admins"]; e.Mode != 0o440 || len(o.Manifest.Exclusive) != 1 {
		t.Errorf("sudoers = %+v, exclusive %v", e, o.Manifest.Exclusive)
	}
	if k := string(o.Content[o.Manifest.Entries["/root/.ssh/authorized_keys"].Digest]); k != "ssh-ed25519 KEY flapjack@fj-head\n" {
		t.Errorf("authorized_keys = %q (dot-directories must be embedded)", k)
	}
	if motd := string(o.Content[o.Manifest.Entries["/etc/motd"].Digest]); !strings.Contains(motd, "r2n02 · rack r2 · class lab-arm64") {
		t.Errorf("motd = %q", motd)
	}
}

func mustSub(t *testing.T, dir string) fs.FS {
	sub, err := fs.Sub(exampleOverlays, dir)
	if err != nil {
		t.Fatal(err)
	}
	return sub
}

func hpcState(dir string) State {
	st := State{Dir: dir, Spec: Spec{Racks: 2, NodesPerRack: 2, Head: true, Tentacles: true, SeedPort: 17401, LoginNodes: 1}}
	st.Spec.defaults()
	st.Nodes = Layout(st.Spec)
	st.Tentacles = TentacleLayout(st.Spec)
	return st
}

func TestHPCLayout(t *testing.T) {
	st := hpcState(t.TempDir())
	if len(st.Nodes) != 5 || len(st.Tentacles) != 2 || len(st.loginNodes()) != 1 {
		t.Fatalf("%d nodes, %d tentacles", len(st.Nodes), len(st.Tentacles))
	}
	macs := map[string]string{HeadProvMAC: "head", HeadMgmtMAC: "head", HeadClusterMAC: "head"}
	add := func(who string, ms ...string) {
		for _, m := range ms {
			if other, dup := macs[m]; dup {
				t.Errorf("%s and %s share MAC %s", who, other, m)
			}
			macs[m] = who
		}
	}
	for _, n := range st.Nodes {
		add(n.Name, n.MAC, n.ClusterMAC)
		if n.PublicMAC != "" {
			add(n.Name, n.PublicMAC)
		}
	}
	for _, tt := range st.Tentacles {
		add(tt.Name, tt.MgmtMAC, tt.CoreMAC, tt.RackMAC)
	}

	nets := st.Networks()
	if len(nets) != 4 || len(nets[NetCore]) != 3 || len(nets["r1"]) != 4 || len(nets["r2"]) != 3 || len(nets[NetCluster]) != 6 {
		t.Errorf("networks = %v", nets)
	}
	// A rack's network holds its tentacle and its own nodes only.
	for _, p := range nets["r2"] {
		if !strings.Contains(p, "r2") {
			t.Errorf("r2 network has port %s", p)
		}
	}
	if v := st.VM(st.Nodes[2]); len(v.NICs) != 2 || v.NICs[0].Switch != st.switchSock("r2") || v.NICs[1].Switch != st.switchSock(NetCluster) {
		t.Errorf("r2n01 NICs = %+v", v.NICs)
	}

	// The login node: rack 1's network first (iPXE tries it first), then
	// the cluster network, then NAT with SSH from the Mac.
	login := st.loginNodes()[0]
	if v := st.VM(login); len(v.NICs) != 3 || v.NICs[0].Switch != st.switchSock("r1") || v.NICs[2].Switch != "" ||
		v.NICs[2].HostFwd[0] != "tcp:127.0.0.1:2232-:22" {
		t.Errorf("login01 NICs = %+v", v.NICs)
	}

	c := st.Cluster()
	if len(c.Classes) != 2 || c.Classes[0].Image != ComputeImage || !slices.Contains(c.Classes[0].Overlays, "slurm") ||
		c.Classes[1].Name != ClassLogin || c.Classes[1].Image != ComputeImage || !slices.Contains(c.Classes[1].Overlays, "login") ||
		slices.Contains(c.Classes[0].Overlays, "login") {
		t.Errorf("classes = %+v", c.Classes)
	}
	if l := c.Nodes[4]; l.Name != "login01" || l.Class != ClassLogin || l.Labels["role"] != "login" || l.Interfaces[1].IP != "10.100.1.101" {
		t.Errorf("login01 = %+v", l)
	}
	n := c.Nodes[3]
	if n.Name != "r2n02" || n.Interfaces[0].IP != "10.1.2.12" || n.Interfaces[1].IP != "10.100.2.12" || n.Labels["tentacle"] != "10.1.2.1" {
		t.Errorf("r2n02 = %+v", n)
	}

	// The head's server.json passes the server's own validation.
	b, _ := json.Marshal(st.ServerConfig())
	p := filepath.Join(t.TempDir(), "server.json")
	os.WriteFile(p, b, 0o644)
	cfg, err := server.LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Tentacles["r1"] != "https://10.1.1.1:8443" || cfg.TentacleBoot["r2"] != "https://10.1.2.1" || len(cfg.TentacleDHCP) != 2 {
		t.Errorf("server.json = %s", b)
	}

	conf := st.SlurmConf()
	for _, want := range []string{"SlurmctldHost=fj-head(10.100.0.1)", "enable_configless", "AuthAltTypes=auth/jwt",
		"NodeName=r1n02 NodeAddr=10.100.1.12 CPUs=2", "PartitionName=compute Nodes=r1n[01-02],r2n[01-02] Default=YES",
		"PartitionName=r2 Nodes=r2n[01-02]"} {
		if !strings.Contains(conf, want) {
			t.Errorf("slurm.conf lacks %q:\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "login01") {
		t.Errorf("a login node is a Slurm node:\n%s", conf)
	}
	if h := st.hosts(); !strings.Contains(h, "10.100.0.1  fj-head.cluster fj-head head\n") || !strings.Contains(h, "10.100.2.11  r2n01.cluster r2n01\n") {
		t.Errorf("hosts:\n%s", h)
	}
}

func TestSeedServerTentacles(t *testing.T) {
	dir := shortDir(t)
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(dir, "id_ed25519")).CombinedOutput(); err != nil {
		t.Skipf("ssh-keygen: %v %s", err, out)
	}
	st := hpcState(dir)
	srv, err := st.seedServer()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	base := "http://127.0.0.1:17401"
	get := func(p string) (string, int) {
		resp, err := http.Get(base + p)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b), resp.StatusCode
	}
	contains := func(what, body string, wants ...string) {
		t.Helper()
		for _, w := range wants {
			if !strings.Contains(body, w) {
				t.Errorf("%s lacks %q", what, w)
			}
		}
		if strings.Contains(body, "%!") || strings.Contains(body, "<no value>") {
			t.Errorf("%s has a formatting error:\n%s", what, body)
		}
	}
	ud, _ := get("/user-data")
	contains("head user-data", ud, "ipv4.addresses 10.98.0.1/24", "ipv4.addresses 10.100.0.1/16", "/52:54:00:00:00:03/")
	setup, _ := get("/head-setup.sh")
	contains("head-setup.sh", setup, "server install --address 10.98.0.1/24", "get server.json", "slurm-slurmrestd",
		"pki issue tentacle r2 --out $d --boot-address 10.1.2.1", "ssh 10.98.0.12 install-certs", "rest_auth/jwt", "image build -q rocky9-aarch64",
		"useradd -u 2003 -g carol -d /c/home/carol", "/c/home 10.100.0.0/16(rw,sync,root_squash", "/etc/flapjack/files/slurm/slurm.conf", "nfs-server.service")
	tud, _ := get("/tentacle/r2/user-data")
	contains("tentacle user-data", tud, "hostname: tentacle-r2", "ipv4.addresses 10.1.2.1/24", "ipv4.addresses 10.98.0.12/24",
		"tentacle/r2/setup.sh", "Before=flapjack-tentacle.service")
	if md, _ := get("/tentacle/r2/meta-data"); !strings.HasPrefix(md, "instance-id: tentacle-r2-") {
		t.Errorf("meta-data = %q", md)
	}
	ts, _ := get("/tentacle/r1/setup.sh")
	contains("tentacle setup.sh", ts, `"rack": "r1"`, `"head": "https://10.98.0.1:7444"`, `"bootListen": "10.1.1.1:443"`,
		`"address": "10.1.1.1/24"`, `from=\"10.98.0.1\",command=\"/usr/local/sbin/fj-head-command\"`)
	wel, _ := get("/welcome.sh")
	contains("welcome.sh", wel, "tentacle-r1", "r2n02", "fj-slurm-api ping", "srun -N4 hostname", "ssh r2n01 sysctl vm.swappiness",
		"ssh alice@login01", "login · submit host · Mac ssh 127.0.0.1:", `"$D" 2 4 1 "$R"`)
	if k, _ := get("/lab-key.pub"); !strings.HasPrefix(k, "ssh-ed25519 ") {
		t.Errorf("lab-key.pub = %q", k)
	}
	if out, err := exec.Command("bash", "-n", "-c", wel).CombinedOutput(); err != nil {
		t.Errorf("welcome.sh: %v %s", err, out)
	}
	for name, script := range map[string]string{"head-setup.sh": setup, "tentacle setup.sh": ts} {
		if out, err := exec.Command("sh", "-n", "-c", script).CombinedOutput(); err != nil {
			t.Errorf("%s: %v %s", name, err, out)
		}
	}
	if s, _ := get("/slurm.conf"); !strings.Contains(s, "NodeName=r1n01") {
		t.Errorf("slurm.conf = %s", s)
	}

	// The head's key: missing until sent, then write-once.
	if _, code := get("/head-key"); code != http.StatusNotFound {
		t.Errorf("head-key before PUT: %d", code)
	}
	put := func(body string) int {
		req, _ := http.NewRequest(http.MethodPut, base+"/head-key", strings.NewReader(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := put("ssh-ed25519 AAAA head\n"); c != http.StatusNoContent {
		t.Errorf("PUT: %d", c)
	}
	if c := put("ssh-ed25519 BBBB tentacle\n"); c != http.StatusConflict {
		t.Errorf("second key: %d, want 409", c)
	}
	if c := put("ssh-rsa AAAA\nssh-ed25519 x"); c != http.StatusBadRequest {
		t.Errorf("bad key: %d, want 400", c)
	}
	if k, _ := get("/head-key"); k != "ssh-ed25519 AAAA head\n" {
		t.Errorf("head-key = %q", k)
	}
}

func TestWelcomeFlat(t *testing.T) {
	st := State{Spec: Spec{Racks: 1, NodesPerRack: 2}}
	st.Spec.defaults()
	st.Nodes = Layout(st.Spec)
	b, err := execTemplate(welcome, st.setupData())
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("bash", "-n", "-c", string(b)).CombinedOutput(); err != nil {
		t.Errorf("welcome.sh: %v %s", err, out)
	}
	if strings.Contains(string(b), "slurm") || !strings.Contains(string(b), "r1n02") {
		t.Errorf("flat welcome:\n%s", b)
	}
}

func TestFindChecksum(t *testing.T) {
	for _, in := range []string{
		"# Rocky-9-x.qcow2: 1 bytes\nSHA256 (Rocky-9-x.qcow2) = ABCDEF\n",
		"abcdef  Rocky-9-x.qcow2\n",
		"abcdef *Rocky-9-x.qcow2\n",
	} {
		if sum, ok := findChecksum(strings.NewReader(in), "Rocky-9-x.qcow2"); !ok || sum != "abcdef" {
			t.Errorf("%q: %q %v", in, sum, ok)
		}
	}
	if _, ok := findChecksum(strings.NewReader("SHA256 (other.qcow2) = abc\n"), "Rocky-9-x.qcow2"); ok {
		t.Error("matched another file")
	}
}

// TestHPCOverlaysRender renders the compute class's overlays as the head
// would. The nix modules need nix and nixpkgs' lib (FLAPJACK_NIX,
// FLAPJACK_NIXPKGS); without them only the templates are checked.
func TestHPCOverlaysRender(t *testing.T) {
	dir := t.TempDir()
	if err := os.CopyFS(dir, mustSub(t, "overlays")); err != nil {
		t.Fatal(err)
	}
	files := filepath.Join(t.TempDir(), "files")
	os.MkdirAll(filepath.Join(files, "ssh"), 0o755)
	os.WriteFile(filepath.Join(files, "ssh", "authorized_keys"), []byte("ssh-ed25519 KEY\n"), 0o644)
	os.MkdirAll(filepath.Join(files, "slurm"), 0o755)
	os.WriteFile(filepath.Join(files, "slurm", "slurm.conf"), []byte("SLURM CONF\n"), 0o644)
	secrets := t.TempDir()
	os.WriteFile(filepath.Join(secrets, "munge.key"), []byte("MUNGE"), 0o600)
	st := hpcState(t.TempDir())
	c := st.Cluster()
	cl := render.Cluster{Server: "10.98.0.1", Domain: "cluster"}
	var nodes []render.Node
	for _, n := range c.Nodes {
		nodes = append(nodes, render.NodeOf(n))
	}
	cl.Nodes = nodes
	r := &render.Renderer{Dir: dir, FilesDir: files, SecretsDir: secrets}
	nixBin, nixpkgs := os.Getenv("FLAPJACK_NIX"), os.Getenv("FLAPJACK_NIXPKGS")
	if nixBin != "" && nixpkgs != "" {
		r.Nix = render.Nix{Bin: nixBin, Nixpkgs: nixpkgs, WorkDir: t.TempDir()}
	}
	out := map[string]*render.Output{}
	for _, class := range c.Classes {
		var members []render.Node
		for _, n := range nodes {
			if n.Class == class.Name {
				members = append(members, n)
			}
		}
		if r.Nix.Bin == "" {
			class.Overlays = slices.DeleteFunc(slices.Clone(class.Overlays), func(o string) bool { return o != "base" && o != "login" })
		}
		got, err := r.Render(class, members, cl)
		if err != nil {
			t.Fatal(err)
		}
		maps.Copy(out, got)
	}
	o := out["r2n01"]
	file := func(p string) string {
		e, ok := o.Manifest.Entries[p]
		if !ok {
			t.Errorf("no %s", p)
		}
		return string(o.Content[e.Digest])
	}
	if h := file("/etc/hosts"); !strings.Contains(h, "10.100.0.1  head.cluster head\n") || !strings.Contains(h, "10.100.1.12  r1n02.cluster r1n02\n") {
		t.Errorf("hosts:\n%s", h)
	}
	if ch := file("/etc/chrony.conf"); !strings.Contains(ch, "server 10.1.2.1 iburst") {
		t.Errorf("chrony.conf:\n%s", ch)
	}
	if r.Nix.Bin == "" {
		if conf := string(out["login01"].Content[out["login01"].Manifest.Entries["/etc/slurm/slurm.conf"].Digest]); conf != "SLURM CONF\n" {
			t.Errorf("login slurm.conf = %q", conf)
		}
		t.Log("nix modules not rendered: set FLAPJACK_NIX and FLAPJACK_NIXPKGS")
		return
	}
	nm := file("/etc/NetworkManager/system-connections/cluster.nmconnection")
	if !strings.Contains(nm, "mac-address=52:54:00:02:01:11") || !strings.Contains(nm, "address1=10.100.2.11/16") ||
		o.Manifest.Entries["/etc/NetworkManager/system-connections/cluster.nmconnection"].Mode != 0o600 {
		t.Errorf("cluster.nmconnection:\n%s", nm)
	}
	if s := file("/etc/sysconfig/slurmd"); !strings.Contains(s, `SLURMD_OPTIONS="--conf-server 10.100.0.1:6817"`) {
		t.Errorf("sysconfig/slurmd:\n%s", s)
	}
	if u := file("/etc/sysusers.d/flapjack-accounts.conf"); !strings.Contains(u, "u flapjack 1000 \"Lab admin\" /home/flapjack /bin/bash") ||
		!strings.Contains(u, "u alice 2001 \"Alice (user)\" /c/home/alice /bin/bash") {
		t.Errorf("sysusers:\n%s", u)
	}
	if tf := file("/etc/tmpfiles.d/flapjack-accounts.conf"); !strings.Contains(tf, "d /home/flapjack 0700") || strings.Contains(tf, "/c/home") {
		t.Errorf("tmpfiles (shared homes are the server's):\n%s", tf)
	}
	if m := file("/etc/systemd/system/c-home.mount"); !strings.Contains(m, "What=10.100.0.1:/c/home") || !strings.Contains(m, "Options=vers=4.2,hard,noatime,_netdev") {
		t.Errorf("c-home.mount:\n%s", m)
	}
	if e := o.Manifest.Entries["/etc/systemd/system/remote-fs.target.wants/c-home.automount"]; e.Target != "/etc/systemd/system/c-home.automount" {
		t.Errorf("automount symlink = %+v", e)
	}

	// The login node: the munge key and slurm.conf, but no slurmd.
	l := out["login01"]
	lf := func(p string) (string, bool) {
		e, ok := l.Manifest.Entries[p]
		return string(l.Content[e.Digest]), ok
	}
	if conf, ok := lf("/etc/slurm/slurm.conf"); !ok || conf != "SLURM CONF\n" {
		t.Errorf("login slurm.conf = %q %v", conf, ok)
	}
	if _, ok := lf("/etc/munge/munge.key"); !ok {
		t.Error("login node has no munge key")
	}
	if _, ok := lf("/etc/sysconfig/slurmd"); ok {
		t.Error("login node runs slurmd")
	}
	if d, _ := lf("/etc/systemd/system/slurmd.service.d/50-login.conf"); !strings.Contains(d, "ConditionPathExists=/nonexistent") {
		t.Errorf("login slurmd drop-in = %q", d)
	}
	if e := o.Manifest.Entries["/etc/munge/munge.key"]; e.Owner != "munge" || e.Mode != 0o400 {
		t.Errorf("munge.key = %+v", e)
	}
	if s := file("/etc/sysctl.d/90-flapjack.conf"); !strings.Contains(s, "vm.swappiness = 1") {
		t.Errorf("r2 sysctl:\n%s", s)
	}
}

// TestLabUsersMatchAccounts: the head creates LabUsers; the accounts
// overlay creates the same users on the nodes. Their UIDs must agree.
func TestLabUsersMatchAccounts(t *testing.T) {
	b, err := fs.ReadFile(exampleOverlays, "overlays/accounts/default.nix")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?m)^\s+(\w+) = lib.mkDefault \{ uid = (\d+);`)
	nix := map[string]int{}
	for _, m := range re.FindAllStringSubmatch(string(b), -1) {
		nix[m[1]], _ = strconv.Atoi(m[2])
	}
	for _, u := range LabUsers {
		if nix[u.Name] != u.UID {
			t.Errorf("%s: head uid %d, accounts overlay %d", u.Name, u.UID, nix[u.Name])
		}
	}
	if len(nix) != len(LabUsers)+1 { // + flapjack
		t.Errorf("accounts overlay users %v, LabUsers %v", nix, LabUsers)
	}
}
