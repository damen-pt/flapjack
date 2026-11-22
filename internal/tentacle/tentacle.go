// Package tentacle is a rack's relay between node agents and the head.
//
// A tentacle keeps one long-poll watch open to the head and receives the
// whole desired state of its rack. It fetches the content its nodes need
// once per rack, and only then wakes those nodes, so a switch costs the
// head one request per rack per file instead of one per node. Agents talk
// only to their tentacle: manifests, content, status reports (batched
// upstream) and enrollment (relayed).
//
// A tentacle is a relay, never an authority. Generations carry the head's
// signature, which agents check, so a tentacle can delay a generation but
// not alter it. Enrollment proofs (boot tickets, renewal signatures) are
// checked by the head. The rack a tentacle serves is the name in its
// certificate, and the head refuses anything outside it.
package tentacle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/damen-pt/flapjack/internal/overlay"
	"github.com/damen-pt/flapjack/internal/pki"
	"github.com/damen-pt/flapjack/internal/server"
	"github.com/damen-pt/flapjack/internal/staging"
)

// Tentacle serves one rack.
type Tentacle struct {
	Rack string
	Head string       // "https://10.0.0.1:7444"
	Up   *http.Client // mTLS to the head as flapjack://tentacle/<Rack>
	// Cache holds overlay content for this rack's current generations.
	Cache staging.Store
	// Artifacts is the staged-artifact chunk cache served on the cluster
	// network. It is separate from Cache so that knowing a digest never
	// lets a node read another node's overlay content.
	Artifacts staging.Store
	// Parallel bounds concurrent content fetches from the head (default 8).
	Parallel int
	// Flush is how often batched status reports go upstream (default 1s).
	Flush time.Duration
	// Watch is how long one watch long-poll lasts (default 1m).
	Watch time.Duration
	// Images, when set, is where boot image versions the head lists are
	// staged and served from (BootHandler). Report is how often the
	// staged list is re-sent to the head (default 1m).
	Images string
	Report time.Duration
	// Firmware, when set, is where the iPXE binaries the head lists are
	// staged, for a tentacle that runs its rack's DHCP (DHCPServer).
	Firmware string
	Logf     func(format string, args ...any)

	mu      sync.Mutex
	rev     uint64
	synced  bool
	nodes   map[string]*node
	waiters map[string]chan struct{}
	ready   chan struct{}
	pending []server.NodeReport
	kick    chan struct{}

	wanted         []server.BootImage
	wantedFirmware []staging.Manifest
	haveWanted     bool
	restage        chan struct{}
	windows        map[string]time.Time // MAC → boot window close
	imageKey       []byte               // checks the image tokens in this rack's scripts
}

type node struct {
	server.RackNode
	digests map[string]bool // every file content in its generation
	plain   map[string]bool // ...that some entry holds in the clear
	// sealed holds its secrets as the head sealed them to it: the
	// tentacle never has them in the clear, in memory or in Cache.
	sealed map[string][]byte
}

func (t *Tentacle) logf(format string, args ...any) {
	if t.Logf != nil {
		t.Logf(format, args...)
	}
}

func (t *Tentacle) init() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.nodes == nil {
		t.nodes = map[string]*node{}
		t.waiters = map[string]chan struct{}{}
		t.ready = make(chan struct{})
		t.kick = make(chan struct{}, 1)
		t.restage = make(chan struct{}, 1)
	}
}

// Ready is closed once the first snapshot is cached and served.
func (t *Tentacle) Ready() <-chan struct{} {
	t.init()
	return t.ready
}

// Serves reports whether name is a node of this rack, for the TLS layer.
func (t *Tentacle) Serves(name string) bool {
	t.init()
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.nodes[name]
	return ok
}

// AllowNode is a pki.Allow accepting only this rack's nodes.
func (t *Tentacle) AllowNode(id pki.Identity) bool {
	return id.Role == pki.Node && t.Serves(id.Name)
}

// Run follows the head until ctx ends.
func (t *Tentacle) Run(ctx context.Context) error {
	t.init()
	go t.flushLoop(ctx)
	if t.Images != "" || t.Firmware != "" {
		go t.stageLoop(ctx)
	}
	backoff := time.Second
	for ctx.Err() == nil {
		err := t.sync(ctx)
		if err == nil {
			backoff = time.Second
			continue
		}
		if ctx.Err() != nil {
			break
		}
		d := backoff/2 + rand.N(backoff/2) // tentacles restarting with the head spread out
		t.logf("tentacle %s: %v (retrying in %s)", t.Rack, err, d.Round(time.Millisecond))
		select {
		case <-ctx.Done():
		case <-time.After(d):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
	return nil
}

// sync waits for the next snapshot, caches what it needs and publishes it.
func (t *Tentacle) sync(ctx context.Context) error {
	t.mu.Lock()
	since, synced := t.rev, t.synced
	t.mu.Unlock()
	q := url.Values{"wait": {t.watchFor().String()}}
	if synced {
		q.Set("since", strconv.FormatUint(since, 10))
	}
	var snap server.RackSnapshot
	if err := t.getJSON(ctx, "/tentacle/v1/watch?"+q.Encode(), &snap); err != nil {
		return err
	}
	if snap.Rack != t.Rack {
		return fmt.Errorf("head sent rack %q's snapshot to rack %q", snap.Rack, t.Rack)
	}
	if synced && snap.Revision == since {
		// The long-poll timed out with nothing new for the overlays, but
		// a class's image link may have moved (rebuilds happen outside
		// the head), so the images it lists are still current news.
		t.wantImages(snap.Images, snap.Firmware)
		return nil
	}
	if err := t.prefetch(ctx, snap); err != nil {
		return err
	}
	t.purgeSecrets(snap)
	t.publish(snap, t.prefetchSealed(ctx, snap))
	// Images stage in the background: a root filesystem is gigabytes,
	// and overlay changes must not wait behind it.
	t.wantImages(snap.Images, snap.Firmware)
	return nil
}

func (t *Tentacle) watchFor() time.Duration {
	if t.Watch > 0 {
		return t.Watch
	}
	return time.Minute
}

// prefetch fetches every digest the snapshot needs that the cache lacks,
// each once however many nodes share it.
func (t *Tentacle) prefetch(ctx context.Context, snap server.RackSnapshot) error {
	need := map[string]bool{}
	for _, n := range snap.Nodes {
		for _, e := range n.Manifest.Entries {
			if e.Digest != "" && !e.Secret && !t.Cache.Has(e.Digest) {
				need[e.Digest] = true
			}
		}
	}
	if len(need) == 0 {
		return nil
	}
	par := t.Parallel
	if par <= 0 {
		par = 8
	}
	work := make(chan string)
	errc := make(chan error, len(need))
	var wg sync.WaitGroup
	for range min(par, len(need)) {
		wg.Go(func() {
			for d := range work {
				if err := t.fetch(ctx, d); err != nil {
					errc <- err
				}
			}
		})
	}
	for d := range need {
		work <- d
	}
	close(work)
	wg.Wait()
	close(errc)
	var errs []error
	for err := range errc {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (t *Tentacle) fetch(ctx context.Context, d string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.Head+"/tentacle/v1/content/"+d, nil)
	if err != nil {
		return err
	}
	resp, err := t.Up.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("content %.19s: %s", d, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return err
	}
	return t.Cache.Put(d, b) // verifies b hashes to d
}

// secretDigests are the contents n holds only as secrets.
func secretDigests(rn server.RackNode) []string {
	plain, secret := map[string]bool{}, map[string]bool{}
	for _, e := range rn.Manifest.Entries {
		switch {
		case e.Digest == "":
		case e.Secret:
			secret[e.Digest] = true
		default:
			plain[e.Digest] = true
		}
	}
	var out []string
	for d := range secret {
		if !plain[d] {
			out = append(out, d)
		}
	}
	return out
}

// purgeSecrets deletes from Cache any content the snapshot holds only as
// a secret: a tentacle that ran before secrets were sealed (or before a
// generation marked them) may have it in the clear on disk.
func (t *Tentacle) purgeSecrets(snap server.RackSnapshot) {
	plain := map[string]bool{}
	var secret []string
	for _, rn := range snap.Nodes {
		for _, e := range rn.Manifest.Entries {
			switch {
			case e.Digest == "":
			case e.Secret:
				secret = append(secret, e.Digest)
			default:
				plain[e.Digest] = true
			}
		}
	}
	for _, d := range secret {
		if !plain[d] && t.Cache.Has(d) {
			if err := t.Cache.Remove(d); err != nil {
				t.logf("tentacle %s: removing a secret cached in the clear: %v", t.Rack, err)
			} else {
				t.logf("tentacle %s: removed secret %.19s cached in the clear", t.Rack, d)
			}
		}
	}
}

// rekeyed records that node just enrolled with a new seal key. Blobs
// sealed to its old key are dropped now rather than at the next snapshot,
// so the node's first requests after enrolling never get one it cannot
// open.
func (t *Tentacle) rekeyed(name, keyID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if n, ok := t.nodes[name]; ok && n.SealKeyID != keyID {
		n.SealKeyID = keyID
		n.sealed = map[string][]byte{}
	}
}

// cachedSealed is the blob for node's secret d, if the tentacle holds one
// sealed to the node's current key.
func (t *Tentacle) cachedSealed(name, keyID, d string) []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	if n, ok := t.nodes[name]; ok && n.SealKeyID == keyID {
		return n.sealed[d]
	}
	return nil
}

// prefetchSealed fetches the snapshot's secrets the tentacle lacks, each
// sealed to its node, so nodes woken by publish find them here. It is best
// effort: a node the head cannot seal for (no seal key yet) must not hold
// up the rack, and its agent's request retries.
func (t *Tentacle) prefetchSealed(ctx context.Context, snap server.RackSnapshot) map[string]map[string][]byte {
	got := map[string]map[string][]byte{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(t.Parallel, 8))
	for _, rn := range snap.Nodes {
		for _, d := range secretDigests(rn) {
			if t.cachedSealed(rn.Name, rn.SealKeyID, d) != nil {
				continue
			}
			wg.Go(func() {
				sem <- struct{}{}
				defer func() { <-sem }()
				b, err := t.fetchSealed(ctx, rn.Name, d)
				if err != nil {
					t.logf("tentacle %s: %s: %v", t.Rack, rn.Name, err)
					return
				}
				mu.Lock()
				if got[rn.Name] == nil {
					got[rn.Name] = map[string][]byte{}
				}
				got[rn.Name][d] = b
				mu.Unlock()
			})
		}
	}
	wg.Wait()
	return got
}

func (t *Tentacle) fetchSealed(ctx context.Context, name, d string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.Head+"/tentacle/v1/sealed/"+url.PathEscape(name)+"/"+url.PathEscape(d), nil)
	if err != nil {
		return nil, err
	}
	resp, err := t.Up.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != pki.SealedContentType {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("sealed content %.19s: %s: %s", d, resp.Status, strings.TrimSpace(string(b)))
	}
	return io.ReadAll(io.LimitReader(resp.Body, 80<<20))
}

// publish makes snap what agents see and wakes nodes whose generation
// moved. sealed holds secrets just fetched for it; the rest are carried
// over from the previous snapshot while the node's seal key is the same.
func (t *Tentacle) publish(snap server.RackSnapshot, sealed map[string]map[string][]byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	next := map[string]*node{}
	for _, rn := range snap.Nodes {
		n := &node{RackNode: rn, digests: map[string]bool{}, plain: map[string]bool{}, sealed: map[string][]byte{}}
		for _, e := range rn.Manifest.Entries {
			if e.Digest != "" {
				n.digests[e.Digest] = true
				if !e.Secret {
					n.plain[e.Digest] = true
				}
			}
		}
		old := t.nodes[rn.Name]
		for _, d := range secretDigests(rn) {
			switch {
			case sealed[rn.Name][d] != nil:
				n.sealed[d] = sealed[rn.Name][d]
			case old != nil && old.SealKeyID == rn.SealKeyID && old.sealed[d] != nil:
				n.sealed[d] = old.sealed[d]
			}
		}
		next[rn.Name] = n
		if old, ok := t.nodes[rn.Name]; !ok || old.Generation != rn.Generation || envelopeChanged(old.Envelope, rn.Envelope) {
			t.wakeLocked(rn.Name)
		}
	}
	for name := range t.nodes {
		if _, ok := next[name]; !ok {
			t.wakeLocked(name) // removed from the rack: its long-poll ends
		}
	}
	t.nodes, t.rev = next, snap.Revision
	t.imageKey = snap.ImageKey
	if !t.synced {
		t.synced = true
		close(t.ready)
	}
}

func envelopeChanged(a, b *pki.Envelope) bool {
	if a == nil || b == nil {
		return a != b
	}
	return a.Digest != b.Digest
}

func (t *Tentacle) wakeLocked(name string) {
	if ch, ok := t.waiters[name]; ok {
		close(ch)
		delete(t.waiters, name)
	}
}

func (t *Tentacle) changes(name string) <-chan struct{} {
	t.mu.Lock()
	defer t.mu.Unlock()
	ch, ok := t.waiters[name]
	if !ok {
		ch = make(chan struct{})
		t.waiters[name] = ch
	}
	return ch
}

func (t *Tentacle) lookup(name string) (*node, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n, ok := t.nodes[name]
	return n, ok
}

// callerNode is the request's node certificate, if it is for a node of
// this rack that still accepts it (the head's revocations, in the
// snapshot).
func (t *Tentacle) callerNode(w http.ResponseWriter, r *http.Request) (pki.Identity, bool) {
	id, cert, ok := pki.PeerCert(r)
	if !ok || !t.AllowNode(id) {
		http.Error(w, "a certificate for a node of rack "+t.Rack+" is required", http.StatusForbidden)
		return id, false
	}
	n, ok := t.lookup(id.Name)
	if !ok {
		http.Error(w, "a certificate for a node of rack "+t.Rack+" is required", http.StatusForbidden)
		return id, false
	}
	if err := n.AcceptsCert(pki.IssuedAt(cert)); err != nil {
		http.Error(w, id.Name+": "+err.Error(), http.StatusForbidden)
		return id, false
	}
	return id, true
}

// AgentHandler serves this rack's agents. Every route but enroll needs a
// node certificate for a node of this rack.
func (t *Tentacle) AgentHandler() http.Handler {
	t.init()
	mux := http.NewServeMux()
	caller := func(w http.ResponseWriter, r *http.Request) (string, bool) {
		id, ok := t.callerNode(w, r)
		return id.Name, ok
	}
	mux.HandleFunc("GET /agent/v1/manifest", func(w http.ResponseWriter, r *http.Request) {
		name, ok := caller(w, r)
		if !ok {
			return
		}
		have, _ := strconv.Atoi(r.URL.Query().Get("have"))
		wait, _ := time.ParseDuration(r.URL.Query().Get("wait"))
		ctx, cancel := context.WithTimeout(r.Context(), min(max(wait, 0), 5*time.Minute))
		defer cancel()
		for {
			ch := t.changes(name)
			n, ok := t.lookup(name)
			if !ok {
				http.Error(w, "node left the rack", http.StatusGone)
				return
			}
			if n.Generation != have || ctx.Err() != nil {
				m := n.Manifest
				if m.Entries == nil {
					m.Entries = map[string]overlay.Entry{}
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(server.AgentManifest{Node: name, Generation: n.Generation, Manifest: m, Envelope: n.Envelope})
				return
			}
			select {
			case <-ch:
			case <-ctx.Done():
			}
		}
	})
	mux.HandleFunc("GET /agent/v1/content/{digest}", func(w http.ResponseWriter, r *http.Request) {
		name, ok := caller(w, r)
		if !ok {
			return
		}
		d := r.PathValue("digest")
		n, _ := t.lookup(name)
		if n == nil || !n.digests[d] {
			http.Error(w, "not in this node's current generation", http.StatusNotFound)
			return
		}
		if !n.plain[d] {
			// A secret: relayed sealed to this node, fetched now if the
			// prefetch could not get it.
			b := t.cachedSealed(name, n.SealKeyID, d)
			if b == nil {
				var err error
				if b, err = t.fetchSealed(r.Context(), name, d); err != nil {
					http.Error(w, err.Error(), http.StatusServiceUnavailable)
					return
				}
				t.mu.Lock()
				if cur, ok := t.nodes[name]; ok && cur.SealKeyID == n.SealKeyID {
					cur.sealed[d] = b
				}
				t.mu.Unlock()
			}
			w.Header().Set("Content-Type", pki.SealedContentType)
			w.Write(b)
			return
		}
		f, err := t.Cache.Open(d)
		if err != nil {
			http.Error(w, "content missing", http.StatusNotFound)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		io.Copy(w, f)
	})
	mux.HandleFunc("POST /agent/v1/status", func(w http.ResponseWriter, r *http.Request) {
		name, ok := caller(w, r)
		if !ok {
			return
		}
		var rep server.AgentReport
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&rep); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		t.mu.Lock()
		t.pending = append(t.pending, server.NodeReport{Node: name, Report: rep})
		t.mu.Unlock()
		select {
		case t.kick <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusAccepted)
	})
	mux.HandleFunc("POST /agent/v1/enroll", func(w http.ResponseWriter, r *http.Request) {
		var req server.EnrollRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// A node already holding a certificate may only renew as itself.
		if id, ok := pki.PeerIdentity(r); ok && (id.Role != pki.Node || id.Name != req.Node) {
			http.Error(w, id.String()+" may not enroll "+req.Node, http.StatusForbidden)
			return
		}
		// A boot ticket is only good from one of the node's own addresses,
		// as on the head (which cannot see the agent's address here).
		if req.Ticket != "" {
			if code, msg := t.fromNode(r, req.Node); code != http.StatusOK {
				http.Error(w, msg, code)
				return
			}
		}
		body, _ := json.Marshal(req)
		up, err := http.NewRequestWithContext(r.Context(), http.MethodPost, t.Head+"/tentacle/v1/enroll", bytes.NewReader(body))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		up.Header.Set("Content-Type", "application/json")
		resp, err := t.Up.Do(up)
		if err != nil {
			http.Error(w, "head unreachable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK && req.Ticket != "" {
			t.rekeyed(req.Node, pki.SealKeyID(req.SealKey))
		}
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, io.LimitReader(resp.Body, 64<<10))
	})
	// An agent shutting its node down for a reboot: the head opens the
	// node's boot window (it matters for bootWindow "armed").
	mux.HandleFunc("POST /agent/v1/rebooting", func(w http.ResponseWriter, r *http.Request) {
		name, ok := caller(w, r)
		if !ok {
			return
		}
		// The head opens the window only for the node's own signed notice.
		var notice server.RebootNotice
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&notice); err != nil {
			http.Error(w, "a signed reboot notice is required: "+err.Error(), http.StatusBadRequest)
			return
		}
		if notice.Node != name {
			http.Error(w, "the notice is for "+notice.Node+", not "+name, http.StatusForbidden)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		if err := t.postJSON(ctx, "/tentacle/v1/rebooting", server.RebootRelay{Node: name, Notice: &notice}); err != nil {
			http.Error(w, "head: "+err.Error(), http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

// ArtifactHandler serves staged-artifact chunks to this rack's nodes.
func (t *Tentacle) ArtifactHandler() http.Handler {
	h := staging.Handler(t.Artifacts)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := t.callerNode(w, r); !ok {
			return
		}
		h.ServeHTTP(w, r)
	})
}

// Prewarm stages an artifact's chunks from the head into the rack cache.
func (t *Tentacle) Prewarm(ctx context.Context, m staging.Manifest) (staging.Stats, error) {
	f := staging.Fetcher{Store: t.Artifacts, Client: t.Up, Parallel: t.Parallel,
		Sources: []staging.Source{{Name: "head", URL: t.Head + "/tentacle/v1", Tier: staging.TierOrigin}}}
	return f.Fetch(ctx, m, "")
}

// flushLoop sends batched status reports upstream.
func (t *Tentacle) flushLoop(ctx context.Context) {
	every := t.Flush
	if every <= 0 {
		every = time.Second
	}
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-t.kick:
			// Coalesce reports arriving together (a switch wakes the
			// whole rack at once) into one upstream request.
			select {
			case <-ctx.Done():
				return
			case <-time.After(min(every, 50*time.Millisecond)):
			}
		}
		t.mu.Lock()
		batch := t.pending
		t.pending = nil
		t.mu.Unlock()
		if len(batch) == 0 {
			continue
		}
		if err := t.postJSON(ctx, "/tentacle/v1/status", batch); err != nil {
			t.logf("tentacle %s: status: %v", t.Rack, err)
			if !strings.Contains(err.Error(), "422") {
				t.mu.Lock()
				t.pending = append(batch, t.pending...) // retry next tick
				t.mu.Unlock()
			}
		}
	}
}

func (t *Tentacle) getJSON(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.Head+path, nil)
	if err != nil {
		return err
	}
	resp, err := t.Up.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func (t *Tentacle) postJSON(ctx context.Context, path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.Head+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.Up.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}
