package tentacle_test

// This file builds the test cluster from docs/design/tentacles.md: one
// head, two racks each with a tentacle, three nodes per rack, a
// management network (50G) and a cluster network (100G), all on netsim.
//
//	                    core-mgmt (mgmt speed)
//	               ┌────────┼──────────┐
//	             head   tentacle r1   tentacle r2
//	                      │    │        │    │
//	      r1-mgmt ────────┘    │        │    └──────── r2-mgmt
//	      r1n01..03            │        │              r2n01..03
//	      r1-cluster ──────────┘        └──────────── r2-cluster
//	      r1n01..03 ──────── spine (cluster speed) ── r2n01..03

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/agent"
	"github.com/damen-pt/flapjack/internal/apiserver"
	"github.com/damen-pt/flapjack/internal/attest"
	"github.com/damen-pt/flapjack/internal/events"
	"github.com/damen-pt/flapjack/internal/gens"
	"github.com/damen-pt/flapjack/internal/netsim"
	"github.com/damen-pt/flapjack/internal/overlay"
	"github.com/damen-pt/flapjack/internal/pki"
	"github.com/damen-pt/flapjack/internal/render"
	"github.com/damen-pt/flapjack/internal/server"
	"github.com/damen-pt/flapjack/internal/staging"
	"github.com/damen-pt/flapjack/internal/store"
	"github.com/damen-pt/flapjack/internal/tentacle"
)

const (
	racks        = 2
	nodesPerRack = 3
	headAddr     = "10.0.0.1:7444"
)

type cluster struct {
	t       *testing.T
	ctx     context.Context
	dir     string
	fabric  *netsim.Fabric
	ca      *pki.CA
	signPub ed25519.PublicKey
	head    *headNode
	tents   map[string]*tentNode
	nodes   []*clusterNode
	secret  string
	art     []byte              // the staged artifact, once staged
	old     server.RackSnapshot // rack r1 as signed at generation 1, for replaying

	mu      sync.Mutex
	tickets []string // every ticket issued, to look for on the wire
}

type headNode struct {
	host *netsim.Host
	ov   *server.Overlays
	api  *server.Tentacles
	st   *store.Store
	log  *events.Log

	mu   sync.Mutex
	hits map[string]int // "<peer> <path>" → requests
}

func (h *headNode) count(peer, path string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hits[peer+" "+path]
}

func (h *headNode) countPrefix(peer, prefix string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for k, v := range h.hits {
		if strings.HasPrefix(k, peer+" "+prefix) {
			n += v
		}
	}
	return n
}

type tentNode struct {
	rack string
	host *netsim.Host
	cert tls.Certificate
	t    *tentacle.Tentacle
	mgmt string // agent URL on the rack management network
	data string // artifact URL on the cluster network
}

type clusterNode struct {
	name, rack     string
	mac            string
	mgmtIP, dataIP string
	host           *netsim.Host
	creds          *agent.Credentials
	client         *http.Client // mTLS to its own tentacle
	dir            string

	mu   sync.Mutex
	logs []string
}

func (n *clusterNode) logf(format string, args ...any) {
	n.mu.Lock()
	n.logs = append(n.logs, fmt.Sprintf(format, args...))
	n.mu.Unlock()
}

func (n *clusterNode) logged(s string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, l := range n.logs {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

func (n *clusterNode) read(p string) string {
	b, err := os.ReadFile(filepath.Join(n.dir, "root", p))
	if err != nil {
		return "<missing>"
	}
	return string(b)
}

// httpClient is an mTLS client dialing from host.
func httpClient(host *netsim.Host, cfg *tls.Config, timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &http.Transport{DialContext: host.DialContext, TLSClientConfig: cfg, MaxIdleConnsPerHost: 16}}
}

func serveTLS(t *testing.T, host *netsim.Host, addr string, cfg *tls.Config, h http.Handler) {
	ln, err := host.Listen(addr)
	if err != nil {
		t.Fatal(err)
	}
	// Refused handshakes are the point of several tests; keep them quiet.
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	go srv.Serve(tls.NewListener(ln, cfg))
	t.Cleanup(func() { srv.Close() })
}

func eventually(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// newCluster builds and starts the head and both tentacles; nodes are
// created but not enrolled.
func newCluster(t *testing.T, mgmtBps, clusterBps float64, nodeTTL time.Duration) *cluster {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c := &cluster{t: t, ctx: ctx, dir: t.TempDir(), fabric: netsim.New(), tents: map[string]*tentNode{}}
	c.fabric.CaptureLimit = 8 << 20
	var err error
	if c.ca, err = pki.NewCA("flapjack test cluster"); err != nil {
		t.Fatal(err)
	}
	pub, signKey, _ := ed25519.GenerateKey(rand.Reader)
	c.signPub = pub
	c.secret = "MUNGE-" + rand.Text()

	// Overlay sources: a per-node template, a file every node shares, and
	// a secret.
	write := func(p, s string) {
		p = filepath.Join(c.dir, p)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("overlays/base/rootfs/etc/motd.ww", "hello {{.Node.Name}} in rack {{.Node.Rack}}\n")
	write("overlays/base/rootfs/etc/cluster.conf", strings.Repeat("# shared cluster configuration v1\n", 1000))
	write("overlays/base/overlay.json", `{"secrets": {"/etc/munge/munge.key": {"secret": "munge.key", "mode": "0400"}}}`)
	write("secrets/munge.key", c.secret+"\n")

	// The head.
	evlog, err := events.Open(filepath.Join(c.dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { evlog.Close() })
	st, err := store.Open(filepath.Join(c.dir, "state.json"), evlog)
	if err != nil {
		t.Fatal(err)
	}
	st.PutClass(v1.NodeClass{Name: "compute", Overlays: []string{"base"}})
	for r := 1; r <= racks; r++ {
		for i := 1; i <= nodesPerRack; i++ {
			n := &clusterNode{name: fmt.Sprintf("r%dn%02d", r, i), rack: fmt.Sprintf("r%d", r),
				mac: fmt.Sprintf("52:54:00:01:%02x:%02x", r, i), mgmtIP: fmt.Sprintf("10.1.%d.%d", r, 10+i), dataIP: fmt.Sprintf("10.2.%d.%d", r, 10+i)}
			if err := st.PutNode(v1.Node{Name: n.name, Class: "compute", Rack: n.rack, Interfaces: []v1.Interface{
				{Name: "mgmt0", MAC: n.mac, Network: "mgmt", IP: n.mgmtIP},
				{Name: "ib0", MAC: fmt.Sprintf("52:54:00:02:%02x:%02x", r, i), Network: "cluster", IP: n.dataIP},
			}}); err != nil {
				t.Fatal(err)
			}
			c.nodes = append(c.nodes, n)
		}
	}
	ov := &server.Overlays{Store: st, Gens: &gens.Store{Dir: filepath.Join(c.dir, "gens")}, Content: staging.Store{Dir: filepath.Join(c.dir, "content")},
		Renderer: &render.Renderer{Dir: filepath.Join(c.dir, "overlays"), SecretsDir: filepath.Join(c.dir, "secrets")}, Server: "10.0.0.1", Signer: &pki.Signer{Key: signKey}}
	ticketKey := make([]byte, 32)
	rand.Read(ticketKey)
	tickets := &attest.Tickets{Key: ticketKey, TTL: 5 * time.Minute}
	api := &server.Tentacles{Overlays: ov, CA: c.ca, Tickets: tickets, Windows: &server.Windows{Store: st, Tickets: tickets},
		Racks: []string{"r1", "r2"}, NodeCertTTL: nodeTTL, Artifacts: staging.Store{Dir: filepath.Join(c.dir, "artifacts")}}
	c.head = &headNode{host: c.fabric.Host("head"), ov: ov, api: api, st: st, log: evlog, hits: map[string]int{}}
	c.head.host.Attach("core-mgmt", "10.0.0.1", mgmtBps)
	headCert, err := c.ca.Issue(pki.Identity{Role: pki.Head, Name: "head"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	inner := api.Handler()
	counted := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _ := pki.PeerIdentity(r)
		c.head.mu.Lock()
		c.head.hits[id.Name+" "+r.URL.Path]++
		c.head.mu.Unlock()
		inner.ServeHTTP(w, r)
	})
	serveTLS(t, c.head.host, headAddr, pki.ServerConfig(pki.Static(headCert), c.ca.Pool, api.Allow, false), counted)

	// Tentacles: on the management core, their rack's management switch
	// and their rack's cluster leaf.
	for r := 1; r <= racks; r++ {
		rack := fmt.Sprintf("r%d", r)
		tn := &tentNode{rack: rack, host: c.fabric.Host("tentacle-" + rack),
			mgmt: fmt.Sprintf("https://10.1.%d.1:8443", r), data: fmt.Sprintf("https://10.2.%d.1:8444", r)}
		tn.host.Attach("core-mgmt", fmt.Sprintf("10.0.0.%d", 10+r), mgmtBps)
		tn.host.Attach(rack+"-mgmt", fmt.Sprintf("10.1.%d.1", r), mgmtBps)
		tn.host.Attach(rack+"-cluster", fmt.Sprintf("10.2.%d.1", r), clusterBps)
		c.fabric.Connect(rack+"-cluster", "spine", clusterBps)
		if tn.cert, err = c.ca.Issue(pki.Identity{Role: pki.Tentacle, Name: rack}, time.Hour); err != nil {
			t.Fatal(err)
		}
		up := httpClient(tn.host, pki.ClientConfig(pki.Static(tn.cert), c.ca.Pool, pki.AnyOf(pki.Head)), 2*time.Minute)
		tn.t = &tentacle.Tentacle{Rack: rack, Head: "https://" + headAddr, Up: up,
			Cache:     staging.Store{Dir: filepath.Join(c.dir, "tentacle-"+rack, "cache")},
			Artifacts: staging.Store{Dir: filepath.Join(c.dir, "tentacle-"+rack, "artifacts")},
			Flush:     100 * time.Millisecond, Watch: 30 * time.Second, Logf: t.Logf}
		serveTLS(t, tn.host, strings.TrimPrefix(tn.mgmt, "https://"), pki.ServerConfig(pki.Static(tn.cert), c.ca.Pool, tn.t.AllowNode, true), tn.t.AgentHandler())
		serveTLS(t, tn.host, strings.TrimPrefix(tn.data, "https://"), pki.ServerConfig(pki.Static(tn.cert), c.ca.Pool, tn.t.AllowNode, false), tn.t.ArtifactHandler())
		go tn.t.Run(ctx)
		c.tents[rack] = tn
	}

	// Nodes: one port on their rack's management switch, one on its
	// cluster leaf. Nothing else.
	for _, n := range c.nodes {
		n.host = c.fabric.Host(n.name)
		n.host.Attach(n.rack+"-mgmt", n.mgmtIP, mgmtBps)
		n.host.Attach(n.rack+"-cluster", n.dataIP, clusterBps)
		n.dir = filepath.Join(c.dir, "node-"+n.name)
		n.creds = &agent.Credentials{Node: n.name, Server: c.tents[n.rack].mgmt, Logf: n.logf}
		n.client = httpClient(n.host, pki.ClientConfig(n.creds.Certificate, c.ca.Pool, pki.Only(pki.Identity{Role: pki.Tentacle, Name: n.rack})), time.Minute)
		n.creds.Client = n.client
		for _, p := range []string{"root/etc", "image/etc"} {
			os.MkdirAll(filepath.Join(n.dir, p), 0o755)
		}
		os.WriteFile(filepath.Join(n.dir, "root/etc/passwd"), []byte("root:x:0:0::/root:/bin/sh\n"), 0o644)
		os.WriteFile(filepath.Join(n.dir, "root/etc/group"), []byte("root:x:0:\n"), 0o644)
	}
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		for _, n := range c.nodes {
			n.mu.Lock()
			logs := n.logs[max(0, len(n.logs)-8):]
			n.mu.Unlock()
			for _, l := range logs {
				t.Logf("%s: %s", n.name, l)
			}
		}
	})
	t.Cleanup(cancel) // runs first: stop agents and tentacles before servers close
	for _, tn := range c.tents {
		select {
		case <-tn.t.Ready():
		case <-time.After(10 * time.Second):
			t.Fatalf("tentacle %s never synced", tn.rack)
		}
	}
	return c
}

// ticket is what the head would put on the node's iPXE command line when
// it power-cycles it.
func (c *cluster) ticket(mac string) string {
	tk, err := c.head.api.Tickets.Issue(mac)
	if err != nil {
		c.t.Fatal(err)
	}
	c.mu.Lock()
	c.tickets = append(c.tickets, tk)
	c.mu.Unlock()
	return tk
}

func (c *cluster) enrollAll() {
	var wg sync.WaitGroup
	errs := make(chan error, len(c.nodes))
	for _, n := range c.nodes {
		wg.Go(func() {
			if err := n.creds.Enroll(c.ctx, n.mac, c.ticket(n.mac)); err != nil {
				errs <- fmt.Errorf("%s: %w", n.name, err)
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		c.t.Fatal(err)
	}
}

// runAgent starts n's agent against server (its tentacle by default).
func (c *cluster) runAgent(n *clusterNode, root, serverURL string, client *http.Client) {
	r, err := os.OpenRoot(root)
	if err != nil {
		c.t.Fatal(err)
	}
	c.t.Cleanup(func() { r.Close() })
	a := &agent.Agent{Server: serverURL, Node: n.name, TrustKey: c.signPub, Root: r,
		Pristine: os.DirFS(filepath.Join(n.dir, "image")), State: overlay.State{Dir: root + ".state"},
		Verify: 500 * time.Millisecond, ReadyAfter: time.Hour, Client: client, Logf: n.logf,
		Hook: func(context.Context, string) (string, error) { return "", nil }, Unseal: n.creds.Unseal}
	ctx, cancel := context.WithCancel(c.ctx)
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	c.t.Cleanup(func() { cancel(); <-done })
}

func (c *cluster) switchAll(msg string) {
	if _, err := c.head.ov.Build(apiserver.BuildRequest{All: true, Switch: true, Message: msg}, "test"); err != nil {
		c.t.Fatal(err)
	}
}

// --- helpers for reaching around the intended paths ---

func dialErr(h *netsim.Host, addr string) error {
	conn, err := h.DialContext(context.Background(), "tcp", addr)
	if err == nil {
		conn.Close()
	}
	return err
}

func isNoRoute(err error) bool { return errors.Is(err, netsim.ErrNoRoute) }
