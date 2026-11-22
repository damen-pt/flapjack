package tentacle_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/agent"
	"github.com/damen-pt/flapjack/internal/apiserver"
	"github.com/damen-pt/flapjack/internal/attest"
	"github.com/damen-pt/flapjack/internal/events"
	"github.com/damen-pt/flapjack/internal/gens"
	"github.com/damen-pt/flapjack/internal/overlay"
	"github.com/damen-pt/flapjack/internal/pki"
	"github.com/damen-pt/flapjack/internal/render"
	"github.com/damen-pt/flapjack/internal/server"
	"github.com/damen-pt/flapjack/internal/staging"
	"github.com/damen-pt/flapjack/internal/store"
	"github.com/damen-pt/flapjack/internal/tentacle"
)

func freeAddr(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// TestServeFromFiles runs a tentacle the way `flapjack tentacle` does,
// over real TCP, with keys laid out by `flapjack pki init` and
// `flapjack pki issue tentacle`, and a node agent the way `flapjack
// agent` runs it: enroll with a ticket, persist the identity, follow.
func TestServeFromFiles(t *testing.T) {
	dir := t.TempDir()
	pkiDir := filepath.Join(dir, "pki")
	if _, err := pki.Init(pki.InitOptions{Dir: pkiDir}); err != nil {
		t.Fatal(err)
	}
	p := func(f string) string { return filepath.Join(pkiDir, f) }
	ca, _ := pki.LoadCA(p(pki.CACertFile), p(pki.CAKeyFile))
	signKey, _ := pki.LoadSigningKey(p(pki.GenKeyFile))
	trust, _ := pki.LoadTrustKey(p(pki.GenPubFile))
	ticketKey, _ := os.ReadFile(p(pki.TicketKeyFile))

	// The head.
	evlog, _ := events.Open(filepath.Join(dir, "events.jsonl"))
	defer evlog.Close()
	st, _ := store.Open(filepath.Join(dir, "state.json"), evlog)
	st.PutClass(v1.NodeClass{Name: "c", Overlays: []string{"base"}})
	// The agent runs on loopback here, so that is its reserved address: a
	// tentacle takes a ticket only from the node's own address.
	st.PutNode(v1.Node{Name: "r7n01", Class: "c", Rack: "r7", Interfaces: []v1.Interface{{MAC: "52:54:00:07:00:01", IP: "127.0.0.1"}}})
	os.MkdirAll(filepath.Join(dir, "overlays/base/rootfs/etc"), 0o755)
	os.WriteFile(filepath.Join(dir, "overlays/base/rootfs/etc/motd.ww"), []byte("hello {{.Node.Name}}\n"), 0o644)
	ov := &server.Overlays{Store: st, Gens: &gens.Store{Dir: filepath.Join(dir, "gens")}, Content: staging.Store{Dir: filepath.Join(dir, "content")},
		Renderer: &render.Renderer{Dir: filepath.Join(dir, "overlays")}, Signer: &pki.Signer{Key: signKey}}
	tickets := &attest.Tickets{Key: ticketKey, TTL: time.Minute, Armed: true}
	api := &server.Tentacles{Overlays: ov, CA: ca, Tickets: tickets, Racks: []string{"r7"}, Windows: &server.Windows{Store: st, Tickets: tickets}}
	headCert, _ := pki.FileCert(p(pki.HeadCertFile), p(pki.HeadKeyFile))
	headAddr := freeAddr(t)
	hln, _ := net.Listen("tcp", headAddr)
	hsrv := &http.Server{Handler: api.Handler(), ErrorLog: log.New(io.Discard, "", 0)}
	go hsrv.Serve(tls.NewListener(hln, pki.ServerConfig(headCert, ca.Pool, api.Allow, false)))
	defer hsrv.Close()

	// The tentacle, from files.
	tdir := filepath.Join(dir, "tentacle")
	os.MkdirAll(tdir, 0o755)
	tc, _ := ca.Issue(pki.Identity{Role: pki.Tentacle, Name: "r7"}, time.Hour)
	if err := pki.WriteIdentity(filepath.Join(tdir, "tentacle.pem"), filepath.Join(tdir, "tentacle.key"), tc); err != nil {
		t.Fatal(err)
	}
	caPEM, _ := os.ReadFile(p(pki.CACertFile))
	os.WriteFile(filepath.Join(tdir, "ca.pem"), caPEM, 0o644)
	agentAddr := freeAddr(t)
	cfg := tentacle.Config{Rack: "r7", Head: "https://" + headAddr, Cert: filepath.Join(tdir, "tentacle.pem"), Key: filepath.Join(tdir, "tentacle.key"),
		CA: filepath.Join(tdir, "ca.pem"), AgentListen: agentAddr, DataDir: filepath.Join(dir, "tentacle-data")}
	b, _ := json.Marshal(cfg)
	os.WriteFile(filepath.Join(tdir, "tentacle.json"), b, 0o644)
	loaded, err := tentacle.LoadConfig(filepath.Join(tdir, "tentacle.json"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- tentacle.Serve(ctx, loaded, io.Discard) }()

	// A tentacle must refuse to start with another rack's certificate.
	wrong := loaded
	wrong.Rack, wrong.AgentListen = "r8", freeAddr(t)
	if err := tentacle.Serve(ctx, wrong, io.Discard); err == nil || !strings.Contains(err.Error(), "not flapjack://tentacle/r8") {
		t.Fatalf("started with r7's certificate as r8: %v", err)
	}

	// The node.
	pool, _ := pki.LoadPool(p(pki.CACertFile))
	state := filepath.Join(dir, "node-state")
	creds := &agent.Credentials{Node: "r7n01", Server: "https://" + agentAddr, Dir: state}
	client := &http.Client{Timeout: time.Minute, Transport: &http.Transport{
		TLSClientConfig: pki.ClientConfig(creds.Certificate, pool, pki.Only(pki.Identity{Role: pki.Tentacle, Name: "r7"}))}}
	creds.Client = client
	tickets.Arm("52:54:00:07:00:01")
	tk, _ := tickets.Issue("52:54:00:07:00:01")
	ectx, ecancel := context.WithTimeout(ctx, 20*time.Second)
	defer ecancel()
	if err := creds.Ensure(ectx, "52:54:00:07:00:01", tk); err != nil {
		t.Fatal(err)
	}
	// A restarted agent reuses its saved identity; the ticket is spent.
	again := &agent.Credentials{Node: "r7n01", Dir: state}
	if err := again.Ensure(ctx, "52:54:00:07:00:01", ""); err != nil || again.Certificate().Leaf.SerialNumber.Cmp(creds.Certificate().Leaf.SerialNumber) != 0 {
		t.Fatalf("saved identity not reused: %v", err)
	}
	if fi, _ := os.Stat(filepath.Join(state, "identity.pem")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("identity mode %v", fi.Mode())
	}
	if (&agent.Credentials{Node: "r7n02", Dir: state}).Load() {
		t.Fatal("another node's name loaded this identity")
	}

	nodeRoot := filepath.Join(dir, "node")
	os.MkdirAll(filepath.Join(nodeRoot, "etc"), 0o755)
	os.WriteFile(filepath.Join(nodeRoot, "etc/passwd"), []byte("root:x:0:0::/root:/bin/sh\n"), 0o644)
	os.WriteFile(filepath.Join(nodeRoot, "etc/group"), []byte("root:x:0:\n"), 0o644)
	root, _ := os.OpenRoot(nodeRoot)
	defer root.Close()
	a := &agent.Agent{Server: "https://" + agentAddr, Node: "r7n01", TrustKey: trust, Root: root, Client: client,
		State: overlay.State{Dir: state}, Verify: 300 * time.Millisecond, ReadyAfter: time.Hour, Logf: t.Logf, Unseal: creds.Unseal}
	go a.Run(ctx)
	if _, err := ov.Build(apiserver.BuildRequest{All: true, Switch: true}, "test"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the node applying its generation over real TCP", 15*time.Second, func() bool {
		b, _ := os.ReadFile(filepath.Join(nodeRoot, "etc/motd"))
		return string(b) == "hello r7n01\n"
	})
	if b, _ := os.ReadFile(filepath.Join(state, "envelope-issued")); len(b) == 0 {
		t.Fatal("the agent did not record the newest envelope")
	}
	// Its reboot announcement, relayed by the tentacle, opens its window
	// on the head.
	if err := creds.AnnounceReboot(ctx); err != nil {
		t.Fatalf("announcing a reboot: %v", err)
	}
	if _, err := tickets.Issue("52:54:00:07:00:01"); err != nil {
		t.Fatalf("no boot window after the relayed announcement: %v", err)
	}
	select {
	case err := <-served:
		t.Fatalf("tentacle stopped: %v", err)
	default:
	}
}

func TestDHCPConfigValidation(t *testing.T) {
	base := func() tentacle.Config {
		return tentacle.Config{Rack: "r1", Head: "https://10.98.0.1:7444", AgentListen: "10.1.1.1:8443", BootListen: "10.1.1.1:443",
			DHCP: &tentacle.DHCPConfig{Interface: "eth1", Address: "10.1.1.1/24"}}
	}
	c := base()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if !*c.DHCP.TFTP || c.DHCP.PlainHTTP {
		t.Fatalf("defaults: tftp=%v plainHTTP=%v", *c.DHCP.TFTP, c.DHCP.PlainHTTP)
	}
	for name, mut := range map[string]func(*tentacle.Config){
		"no bootListen":        func(c *tentacle.Config) { c.BootListen = "" },
		"bootListen elsewhere": func(c *tentacle.Config) { c.BootListen = "10.2.1.1:443" },
		"no interface":         func(c *tentacle.Config) { c.DHCP.Interface = "" },
		"no prefix":            func(c *tentacle.Config) { c.DHCP.Address = "10.1.1.1" },
		"IPv6":                 func(c *tentacle.Config) { c.DHCP.Address = "fd00::1/64" },
		"bad router":           func(c *tentacle.Config) { c.DHCP.Router = "gateway" },
		"bad lease":            func(c *tentacle.Config) { c.DHCP.LeaseTime = "5s" },
	} {
		c := base()
		mut(&c)
		if c.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
