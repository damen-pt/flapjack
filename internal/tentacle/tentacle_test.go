package tentacle_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/damen-pt/flapjack/internal/events"
	"github.com/damen-pt/flapjack/internal/netsim"
	"github.com/damen-pt/flapjack/internal/overlay"
	"github.com/damen-pt/flapjack/internal/pki"
	"github.com/damen-pt/flapjack/internal/server"
	"github.com/damen-pt/flapjack/internal/staging"
)

// TestTwoRacks runs the design's test topology at its real speeds (50G
// management, 100G cluster) and checks that configuration flows head →
// tentacle → node, once per rack, encrypted end to end, and that nothing
// can step outside its rack.
func TestTwoRacks(t *testing.T) {
	c := newCluster(t, 50*netsim.Gbps, 100*netsim.Gbps, 6*time.Second)
	c.enrollAll()
	for _, n := range c.nodes {
		id, err := pki.IdentityOf(n.creds.Certificate().Leaf)
		if err != nil || id != (pki.Identity{Role: pki.Node, Name: n.name}) {
			t.Fatalf("%s enrolled as %v %v", n.name, id, err)
		}
		c.runAgent(n, filepath.Join(n.dir, "root"), c.tents[n.rack].mgmt, n.client)
		go n.creds.Run(c.ctx)
	}

	t.Run("switch reaches every node through its tentacle", func(t *testing.T) {
		c.switchAll("first")
		for _, n := range c.nodes {
			eventually(t, n.name+" applying generation 1", 15*time.Second, func() bool {
				return n.read("etc/motd") == fmt.Sprintf("hello %s in rack %s\n", n.name, n.rack) &&
					strings.HasPrefix(n.read("etc/cluster.conf"), "# shared cluster configuration v1") &&
					n.read("etc/munge/munge.key") == c.secret+"\n"
			})
		}
		// Status reports reach the head in batches through the tentacles.
		eventually(t, "every node's status on the head", 10*time.Second, func() bool {
			for _, n := range c.nodes {
				st, _ := c.head.st.Node(n.name)
				if st.Status.Agent == nil || st.Status.Agent.Applied != 1 {
					return false
				}
			}
			return true
		})
		c.old, _ = c.head.api.Snapshot("r1") // genuinely signed, soon stale
		for rack := range c.tents {
			if got := c.head.count(rack, "/tentacle/v1/status"); got >= nodesPerRack*2 {
				t.Errorf("tentacle %s sent %d status requests; reports were not batched", rack, got)
			}
		}
	})

	t.Run("each tentacle fetches each file once", func(t *testing.T) {
		// Per rack: three motd files and one shared file in the clear; the
		// secret once per node, sealed to it, and never in the clear.
		g, _ := c.head.ov.Gens.Current("r1n01")
		shared, munge := g.Manifest.Entries["/etc/cluster.conf"].Digest, g.Manifest.Entries["/etc/munge/munge.key"].Digest
		for rack := range c.tents {
			if got := c.head.countPrefix(rack, "/tentacle/v1/content/"); got != nodesPerRack+1 {
				t.Errorf("tentacle %s fetched %d files from the head, want %d", rack, got, nodesPerRack+1)
			}
			if got := c.head.countPrefix(rack, "/tentacle/v1/sealed/"); got != nodesPerRack {
				t.Errorf("tentacle %s fetched %d sealed secrets, want %d", rack, got, nodesPerRack)
			}
			if c.tents[rack].t.Cache.Has(munge) {
				t.Errorf("tentacle %s holds the secret in the clear", rack)
			}
			up := c.tents[rack].t.Up
			if code := status(t, up, http.MethodGet, "https://"+headAddr+"/tentacle/v1/content/"+munge, nil); code != http.StatusNotFound {
				t.Errorf("tentacle %s read the secret in the clear: %d", rack, code)
			}
		}
		for rack := range c.tents {
			if got := c.head.count(rack, "/tentacle/v1/content/"+shared); got != 1 {
				t.Errorf("tentacle %s fetched the shared file %d times", rack, got)
			}
		}

		// A tentacle that cached the secret in the clear (before an
		// upgrade) deletes it on its next snapshot.
		key, _ := os.ReadFile(filepath.Join(c.dir, "secrets/munge.key"))
		if err := c.tents["r1"].t.Cache.Put(munge, key); err != nil {
			t.Fatal(err)
		}

		// Changing only the shared file costs each tentacle one fetch.
		before := map[string]int{}
		for rack := range c.tents {
			before[rack] = c.head.countPrefix(rack, "/tentacle/v1/content/")
		}
		os.WriteFile(filepath.Join(c.dir, "overlays/base/rootfs/etc/cluster.conf"), []byte(strings.Repeat("# shared cluster configuration v2\n", 1000)), 0o644)
		c.switchAll("second")
		for _, n := range c.nodes {
			eventually(t, n.name+" applying generation 2", 15*time.Second, func() bool {
				return strings.HasPrefix(n.read("etc/cluster.conf"), "# shared cluster configuration v2")
			})
		}
		if c.tents["r1"].t.Cache.Has(munge) {
			t.Error("a secret cached in the clear survived a snapshot")
		}
		for rack := range c.tents {
			if got := c.head.countPrefix(rack, "/tentacle/v1/content/") - before[rack]; got != 1 {
				t.Errorf("tentacle %s fetched %d files for a one-file change", rack, got)
			}
		}
	})

	t.Run("a node that enrolls again gets secrets sealed to its new key", func(t *testing.T) {
		// A reboot: the node enrolls with a new seal key and asks for its
		// secret at once, before the tentacle's next snapshot. The tentacle
		// must not serve the blob it holds for the old key.
		n := c.nodes[0]
		g, _ := c.head.ov.Gens.Current(n.name)
		munge := g.Manifest.Entries["/etc/munge/munge.key"].Digest
		if err := n.creds.Enroll(c.ctx, n.mac, c.ticket(n.mac)); err != nil {
			t.Fatal(err)
		}
		resp, err := n.client.Get(c.tents[n.rack].mgmt + "/agent/v1/content/" + munge)
		if err != nil {
			t.Fatal(err)
		}
		blob, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("content: %d %s", resp.StatusCode, blob)
		}
		plain, err := n.creds.Unseal(munge, blob)
		if err != nil || string(plain) != c.secret+"\n" {
			t.Fatalf("secret after re-enrolling: %q %v", plain, err)
		}
	})

	t.Run("nodes reach only their own tentacle", func(t *testing.T) {
		r1, r2 := c.nodes[0], c.nodes[nodesPerRack]
		if err := dialErr(r1.host, headAddr); !isNoRoute(err) {
			t.Errorf("r1 node reached the head: %v", err)
		}
		if err := dialErr(r1.host, "10.1.2.1:8443"); !isNoRoute(err) {
			t.Errorf("r1 node reached r2's management network: %v", err)
		}
		if err := dialErr(r2.host, "10.0.0.11:0"); !isNoRoute(err) {
			t.Errorf("r2 node reached the management core: %v", err)
		}
		// The cluster spine joins the racks, so r1 can reach r2's tentacle
		// cache, but r2's tentacle refuses it at the TLS handshake.
		if err := dialErr(r1.host, "10.2.2.1:8444"); err != nil {
			t.Fatalf("cluster spine: %v", err)
		}
		cl := httpClient(r1.host, pki.ClientConfig(r1.creds.Certificate, c.ca.Pool, pki.Only(pki.Identity{Role: pki.Tentacle, Name: "r2"})), 5*time.Second)
		if resp, err := cl.Get("https://10.2.2.1:8444/chunks/sha256:" + strings.Repeat("0", 64)); err == nil {
			resp.Body.Close()
			t.Fatalf("r2's tentacle served an r1 node: %s", resp.Status)
		}
		// A node can't pass itself off as another: its client refuses
		// any tentacle but its own, and tentacles name nodes from their
		// certificates, never from the request.
		cl = httpClient(r1.host, pki.ClientConfig(r1.creds.Certificate, c.ca.Pool, pki.Only(pki.Identity{Role: pki.Tentacle, Name: "r1"})), 5*time.Second)
		resp, err := cl.Get(c.tents["r1"].mgmt + "/agent/v1/manifest?have=-1")
		if err != nil {
			t.Fatal(err)
		}
		var m server.AgentManifest
		json.NewDecoder(resp.Body).Decode(&m)
		resp.Body.Close()
		if m.Node != r1.name {
			t.Fatalf("tentacle answered for %q", m.Node)
		}
	})

	t.Run("a tentacle cannot act outside its rack", func(t *testing.T) {
		up := c.tents["r1"].t.Up
		r2n01 := c.nodes[nodesPerRack]
		g, _ := c.head.ov.Gens.Current(r2n01.name)
		motd := g.Manifest.Entries["/etc/motd"].Digest
		if code := status(t, up, http.MethodGet, "https://"+headAddr+"/tentacle/v1/content/"+motd, nil); code != http.StatusNotFound {
			t.Errorf("r1 read r2's content: %d", code)
		}
		munge := g.Manifest.Entries["/etc/munge/munge.key"].Digest
		if code := status(t, up, http.MethodGet, "https://"+headAddr+"/tentacle/v1/sealed/"+r2n01.name+"/"+munge, nil); code != http.StatusNotFound {
			t.Errorf("r1 fetched r2's sealed secret: %d", code)
		}
		_, csr, _ := pki.NewKey()
		req := server.EnrollRequest{Node: r2n01.name, MAC: r2n01.mac, Ticket: c.ticket(r2n01.mac), CSR: csr}
		if code := status(t, up, http.MethodPost, "https://"+headAddr+"/tentacle/v1/enroll", req); code != http.StatusForbidden {
			t.Errorf("r1 enrolled an r2 node: %d", code)
		}
		// Nor can it open its own nodes' boot windows (and so get their
		// tickets) without a notice the node signed.
		r1n01 := c.nodes[0]
		if code := status(t, up, http.MethodPost, "https://"+headAddr+"/tentacle/v1/rebooting", server.RebootRelay{Node: r1n01.name}); code != http.StatusForbidden {
			t.Errorf("r1 opened %s's window on its own say-so: %d", r1n01.name, code)
		}
		batch := []server.NodeReport{{Node: r2n01.name, Report: server.AgentReport{Generation: 99}}}
		if code := status(t, up, http.MethodPost, "https://"+headAddr+"/tentacle/v1/status", batch); code != http.StatusUnprocessableEntity {
			t.Errorf("r1 reported for an r2 node: %d", code)
		}
		if st, _ := c.head.st.Node(r2n01.name); st.Status.Agent.Applied == 99 {
			t.Error("r1's report for r2 landed")
		}
		// A tentacle the head no longer lists is cut off: refused at the
		// handshake on a new connection, and per request on an open one.
		c.head.api.SetRacks([]string{"r2"})
		if resp, err := up.Get("https://" + headAddr + "/tentacle/v1/watch?wait=0s"); err == nil {
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("a delisted tentacle on an open connection got %s", resp.Status)
			}
		}
		tn := c.tents["r1"]
		fresh := httpClient(tn.host, pki.ClientConfig(pki.Static(tn.cert), c.ca.Pool, pki.AnyOf(pki.Head)), 5*time.Second)
		if resp, err := fresh.Get("https://" + headAddr + "/tentacle/v1/watch?wait=0s"); err == nil {
			resp.Body.Close()
			t.Error("a delisted tentacle completed a new handshake")
		}
		c.head.api.SetRacks([]string{"r1", "r2"})
	})

	t.Run("enrollment needs a fresh ticket for the node's own MAC", func(t *testing.T) {
		n := c.nodes[1]
		up := c.tents[n.rack].t.Up
		_, csr, _ := pki.NewKey()
		old := *n.creds.Certificate()
		used := c.ticket(n.mac)
		ectx, ecancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer ecancel()
		// Through its tentacle, from its own address, as its agent does.
		if err := n.creds.Enroll(ectx, n.mac, used); err != nil {
			t.Fatalf("valid enrollment: %v", err)
		}
		ok := server.EnrollRequest{Node: n.name, MAC: n.mac, Ticket: used, CSR: csr}
		if code := status(t, up, http.MethodPost, "https://"+headAddr+"/tentacle/v1/enroll", ok); code != http.StatusForbidden {
			t.Errorf("ticket reused: %d", code)
		}
		// The new identity revoked the node's earlier certificate: its
		// tentacle refuses it once the head's snapshot says so.
		stale := httpClient(n.host, pki.ClientConfig(pki.Static(old), c.ca.Pool, pki.AnyOf(pki.Tentacle)), 5*time.Second)
		eventually(t, "the tentacle refusing the superseded certificate", 5*time.Second, func() bool {
			return status(t, stale, http.MethodGet, c.tents[n.rack].mgmt+"/agent/v1/manifest?have=-1&wait=0s", nil) == http.StatusForbidden
		})
		// So does the head, for a renewal.
		oldKey := old.PrivateKey.(ed25519.PrivateKey)
		renew := server.EnrollRequest{Node: n.name, CSR: csr, Cert: old.Leaf.Raw, Proof: ed25519.Sign(oldKey, server.RenewMessage(csr))}
		if code := status(t, up, http.MethodPost, "https://"+headAddr+"/tentacle/v1/enroll", renew); code != http.StatusForbidden {
			t.Errorf("renewed a superseded certificate: %d", code)
		}
		other := c.nodes[2]
		stolen := server.EnrollRequest{Node: n.name, MAC: other.mac, Ticket: c.ticket(other.mac), CSR: csr}
		if code := status(t, up, http.MethodPost, "https://"+headAddr+"/tentacle/v1/enroll", stolen); code != http.StatusForbidden {
			t.Errorf("enrolled with another node's MAC and ticket: %d", code)
		}
		// Renewal: only with the node's current key, never another's.
		victim, thief := c.nodes[0], c.nodes[1]
		thiefKey := thief.creds.Certificate().PrivateKey.(ed25519.PrivateKey)
		forged := server.EnrollRequest{Node: victim.name, CSR: csr, Cert: victim.creds.Certificate().Leaf.Raw, Proof: ed25519.Sign(thiefKey, server.RenewMessage(csr))}
		if code := status(t, up, http.MethodPost, "https://"+headAddr+"/tentacle/v1/enroll", forged); code != http.StatusForbidden {
			t.Errorf("renewed %s with %s's key: %d", victim.name, thief.name, code)
		}
		// And the tentacle refuses a node renewing as someone else.
		forged.Cert, forged.Proof = nil, nil
		if code := status(t, thief.client, http.MethodPost, c.tents[thief.rack].mgmt+"/agent/v1/enroll", forged); code != http.StatusForbidden {
			t.Errorf("tentacle relayed %s enrolling as %s: %d", thief.name, victim.name, code)
		}
	})

	t.Run("a compromised tentacle cannot alter a generation", func(t *testing.T) {
		victim := c.nodes[0]
		snap, _ := c.head.api.Snapshot(victim.rack)
		var mine, neighbour server.RackNode
		for _, rn := range snap.Nodes {
			switch rn.Name {
			case victim.name:
				mine = rn
			case c.nodes[1].name:
				neighbour = rn
			}
		}
		evil := []byte("pwned\n")
		evilDigest := overlay.Digest(evil)
		tampered := func() overlay.Manifest {
			entries := map[string]overlay.Entry{}
			for p, e := range mine.Manifest.Entries {
				entries[p] = e
			}
			e := entries["/etc/motd"]
			e.Digest = evilDigest
			entries["/etc/motd"] = e
			return overlay.Manifest{Entries: entries}
		}
		_, attackerKey, _ := ed25519.GenerateKey(rand.Reader)
		var mode sync.Map
		rogue := http.NewServeMux()
		rogue.HandleFunc("GET /agent/v1/manifest", func(w http.ResponseWriter, r *http.Request) {
			out := server.AgentManifest{Node: mine.Name, Generation: mine.Generation, Manifest: mine.Manifest, Envelope: mine.Envelope}
			switch m, _ := mode.Load("mode"); m {
			case "tamper": // change a file, keep the head's signature
				out.Manifest = tampered()
			case "forge": // change a file and sign it with another key
				out.Manifest = tampered()
				e := pki.SignGeneration(attackerKey, mine.Name, mine.Generation, overlay.ManifestDigest(out.Manifest), time.Now().UnixNano())
				out.Envelope = &e
			case "swap": // a genuine signed generation, but another node's
				out.Manifest, out.Envelope = neighbour.Manifest, neighbour.Envelope
			case "unsigned":
				out.Manifest, out.Envelope = tampered(), nil
			case "replay": // the head's own signature, from generation 1
				for _, rn := range c.old.Nodes {
					if rn.Name == mine.Name {
						out.Generation, out.Manifest, out.Envelope = rn.Generation, rn.Manifest, rn.Envelope
					}
				}
			}
			json.NewEncoder(w).Encode(out)
		})
		rogue.HandleFunc("GET /agent/v1/content/{digest}", func(w http.ResponseWriter, r *http.Request) {
			w.Write(evil)
		})
		// The attacker holds tentacle r1's real key and sits on r1's
		// management switch.
		host := c.fabric.Host("rogue")
		host.Attach("r1-mgmt", "10.1.1.250", 50*netsim.Gbps)
		serveTLS(t, host, "10.1.1.250:8443", pki.ServerConfig(pki.Static(c.tents["r1"].cert), c.ca.Pool, pki.AnyOf(pki.Node), false), rogue)

		for m, want := range map[string]string{
			"tamper":   "envelope is for r1n01 generation",
			"forge":    "generation signature does not verify",
			"swap":     "envelope is for r1n02",
			"unsigned": "generation is not signed",
			"replay":   "replayed",
		} {
			mode.Store("mode", m)
			// A separate node identity for logging, same credentials.
			probe := &clusterNode{name: victim.name, rack: victim.rack, dir: victim.dir}
			root := filepath.Join(victim.dir, "rogue-"+m)
			os.MkdirAll(filepath.Join(root, "etc"), 0o755)
			os.WriteFile(filepath.Join(root, "etc/passwd"), []byte("root:x:0:0::/root:/bin/sh\n"), 0o644)
			if m == "replay" {
				// The victim's agent, restarted: it remembers the newest
				// envelope it accepted.
				b, err := os.ReadFile(filepath.Join(victim.dir, "root.state", "envelope-issued"))
				if err != nil {
					t.Fatal(err)
				}
				os.MkdirAll(root+".state", 0o700)
				os.WriteFile(filepath.Join(root+".state", "envelope-issued"), b, 0o600)
			}
			c.runAgent(probe, root, "https://10.1.1.250:8443", victim.client)
			eventually(t, "the agent refusing the "+m+" generation", 10*time.Second, func() bool { return probe.logged(want) })
			if b, err := os.ReadFile(filepath.Join(root, "etc/motd")); err == nil {
				t.Errorf("%s: agent applied %q", m, b)
			}
		}
	})

	t.Run("certificates renew through the tentacle", func(t *testing.T) {
		first := map[string]string{}
		for _, n := range c.nodes {
			first[n.name] = n.creds.Certificate().Leaf.SerialNumber.String()
		}
		eventually(t, "every node renewing", 15*time.Second, func() bool {
			for _, n := range c.nodes {
				if n.creds.Certificate().Leaf.SerialNumber.String() == first[n.name] {
					return false
				}
			}
			return true
		})
		evs, _ := c.head.log.Query(events.Filter{Types: []string{"pki.enrolled"}})
		renewals := 0
		for _, e := range evs {
			if e.Data["renewal"] == "true" {
				renewals++
			}
		}
		if renewals < len(c.nodes) {
			t.Errorf("%d renewal events", renewals)
		}
		// Agents keep converging on renewed certificates.
		os.WriteFile(filepath.Join(c.dir, "overlays/base/rootfs/etc/issue"), []byte("renewed\n"), 0o644)
		c.switchAll("third")
		for _, n := range c.nodes {
			eventually(t, n.name+" applying generation 3", 15*time.Second, func() bool { return n.read("etc/issue") == "renewed\n" })
		}
	})

	t.Run("a rollback is not a replay", func(t *testing.T) {
		n := c.nodes[0]
		if _, err := c.head.ov.Rollback(n.name, 1, "test", "back to the first generation"); err != nil {
			t.Fatal(err)
		}
		eventually(t, n.name+" rolling back to generation 1", 15*time.Second, func() bool {
			return strings.HasPrefix(n.read("etc/cluster.conf"), "# shared cluster configuration v1") && n.read("etc/issue") == "<missing>"
		})
		if n.logged("replayed") {
			t.Fatal("the head's own rollback was refused as a replay")
		}
	})

	t.Run("artifacts stage once per rack over the cluster network", func(t *testing.T) {
		art := make([]byte, 3<<20)
		rand.Read(art)
		m, err := staging.Split(bytes.NewReader(art), "model.bin", 256<<10, c.head.api.Artifacts)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for _, tn := range c.tents {
			wg.Go(func() {
				if _, err := tn.t.Prewarm(c.ctx, m); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		for _, n := range c.nodes {
			wg.Go(func() {
				tn := c.tents[n.rack]
				f := staging.Fetcher{Store: staging.Store{Dir: filepath.Join(n.dir, "chunks")}, Client: n.client, Parallel: 4,
					Sources: []staging.Source{{Name: "tentacle-" + n.rack, URL: tn.data, Tier: staging.TierRack}}}
				st, err := f.Fetch(c.ctx, m, filepath.Join(n.dir, "model.bin"))
				if err != nil {
					t.Errorf("%s: %v", n.name, err)
					return
				}
				if st.Fetched["tentacle-"+n.rack] != int64(len(art)) {
					t.Errorf("%s: fetched %v", n.name, st.Fetched)
				}
			})
		}
		wg.Wait()
		for _, n := range c.nodes {
			if b, _ := os.ReadFile(filepath.Join(n.dir, "model.bin")); !bytes.Equal(b, art) {
				t.Fatalf("%s: artifact differs", n.name)
			}
		}
		for rack := range c.tents {
			if got := c.head.countPrefix(rack, "/tentacle/v1/chunks/"); got != len(m.Chunks) {
				t.Errorf("tentacle %s fetched %d chunks from the head, want %d", rack, got, len(m.Chunks))
			}
		}
		// The head's port carried the artifact about twice (once per
		// rack), not six times.
		for _, l := range c.fabric.Links() {
			if strings.HasPrefix(l.Name, "head/") {
				out, _ := l.Bytes() // A is the head's interface
				if out > int64(len(art))*5/2 {
					t.Errorf("head sent %d bytes for a %d-byte artifact", out, len(art))
				}
			}
		}
		c.art = art
	})

	t.Run("everything on the wire is encrypted", func(t *testing.T) {
		c.mu.Lock()
		needles := map[string][]byte{"munge secret": []byte(c.secret), "PEM key": []byte("PRIVATE KEY"),
			"PEM certificate": []byte("BEGIN CERTIFICATE"), "identity URI": []byte("flapjack://"),
			"agent API": []byte("/agent/v1/"), "tentacle API": []byte("/tentacle/v1/"), "JSON": []byte(`"generation"`)}
		for i, tk := range c.tickets {
			needles[fmt.Sprintf("ticket %d", i)] = []byte(tk)
		}
		c.mu.Unlock()
		for _, n := range c.nodes {
			needles["motd of "+n.name] = []byte("hello " + n.name)
		}
		if c.art != nil {
			needles["artifact"] = c.art[1000:1064]
		}
		flows := c.fabric.Flows()
		if len(flows) < 20 {
			t.Fatalf("only %d flows captured", len(flows))
		}
		for _, fl := range flows {
			fwd, rev, nf, _ := fl.Captured()
			if nf == 0 {
				continue // a reachability probe that never sent
			}
			// TLS records: 0x16 handshake, 0x03 0x01 legacy version.
			if !bytes.HasPrefix(fwd, []byte{0x16, 0x03, 0x01}) {
				t.Errorf("flow %s → %s does not start with a TLS ClientHello: % x", fl.From, fl.To, fwd[:min(8, len(fwd))])
			}
			if len(rev) > 0 && !bytes.HasPrefix(rev, []byte{0x16, 0x03, 0x03}) {
				t.Errorf("flow %s → %s reply is not a TLS ServerHello: % x", fl.From, fl.To, rev[:min(8, len(rev))])
			}
			for what, needle := range needles {
				if bytes.Contains(fwd, needle) || bytes.Contains(rev, needle) {
					t.Errorf("%s visible in plaintext on %s → %s", what, fl.From, fl.To)
				}
			}
		}
		t.Logf("checked %d flows across %d links", len(flows), len(c.fabric.Links()))
	})
}

// TestNetworkSpeeds checks the two networks run at their configured
// speeds, end to end through mTLS. Speeds are scaled down 1000× (50 Mb/s
// and 100 Mb/s) so the link limit, not memory copying, is what's timed.
func TestNetworkSpeeds(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	const mgmt, data = 50 * netsim.Mbps, 100 * netsim.Mbps
	c := newCluster(t, mgmt, data, time.Hour)
	n := c.nodes[0]
	if err := n.creds.Enroll(c.ctx, n.mac, c.ticket(n.mac)); err != nil {
		t.Fatal(err)
	}
	tn := c.tents[n.rack]
	blob := make([]byte, 2<<20)
	rand.Read(blob)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(blob) })
	cfg := pki.ServerConfig(pki.Static(tn.cert), c.ca.Pool, pki.AnyOf(pki.Node), false)
	serveTLS(t, tn.host, "10.1.1.1:9000", cfg, h)
	serveTLS(t, tn.host, "10.2.1.1:9000", cfg, h)

	// Best of three, after a warm-up that opens the TLS connection: a
	// busy machine can only make a transfer slower than the link allows,
	// never faster, so the fastest run is the one that measures the link.
	timeGet := func(url string) time.Duration {
		best := time.Duration(1<<63 - 1)
		for i := range 4 {
			start := time.Now()
			resp, err := n.client.Get(url)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if !bytes.Equal(b, blob) {
				t.Fatal("blob differs")
			}
			if i > 0 {
				best = min(best, time.Since(start))
			}
		}
		return best
	}
	ideal := func(bps float64) time.Duration {
		return time.Duration(float64(len(blob)) * 8 / bps * float64(time.Second))
	}
	tm, tc := timeGet("https://10.1.1.1:9000/"), timeGet("https://10.2.1.1:9000/")
	t.Logf("2 MiB over management: %s (ideal %s); over cluster: %s (ideal %s); ratio %.2f", tm, ideal(mgmt), tc, ideal(data), float64(tm)/float64(tc))
	for _, x := range []struct {
		name      string
		got, want time.Duration
	}{{"management", tm, ideal(mgmt)}, {"cluster", tc, ideal(data)}} {
		// Never faster than the link (the important direction); slower
		// only by protocol overhead and scheduling.
		if x.got < x.want*9/10 || x.got > x.want*5/2 {
			t.Errorf("%s: %s, want about %s", x.name, x.got, x.want)
		}
	}
	if r := float64(tm) / float64(tc); r < 1.4 || r > 2.8 {
		t.Errorf("management/cluster time ratio %.2f, want about 2", r)
	}
}

func status(t *testing.T, c *http.Client, method, url string, body any) int {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, url, r)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}
