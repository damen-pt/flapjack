package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/apiserver"
	"github.com/damen-pt/flapjack/internal/events"
	"github.com/damen-pt/flapjack/internal/gens"
	"github.com/damen-pt/flapjack/internal/overlay"
	"github.com/damen-pt/flapjack/internal/pki"
	"github.com/damen-pt/flapjack/internal/render"
	"github.com/damen-pt/flapjack/internal/staging"
	"github.com/damen-pt/flapjack/internal/store"
)

// Overlays renders overlays into node generations and serves them to node
// agents. It implements apiserver.Overlays.
type Overlays struct {
	Store    *store.Store
	Gens     *gens.Store
	Content  staging.Store
	Renderer *render.Renderer
	Server   string // provisioning address, as templates see it
	Domain   string
	// Signer, if set, signs every generation served (pki.Envelope), so
	// agents can verify what a relay hands them.
	Signer *pki.Signer

	buildMu sync.Mutex // one build at a time keeps generation numbers sane
	mu      sync.Mutex
	changed map[string]chan struct{} // closed when a node's generation moves
	rev     uint64                   // bumped on every generation move
	revCh   chan struct{}            // closed and replaced when rev moves
}

// NodeResult is what build or switch did for one node.
type NodeResult struct {
	Node     string           `json:"node"`
	Class    string           `json:"class"`
	From     int              `json:"from"`         // current generation before
	To       int              `json:"to,omitempty"` // new current generation (switch only)
	Changes  []overlay.Change `json:"changes,omitempty"`
	Warnings []string         `json:"warnings,omitempty"`
	Error    string           `json:"error,omitempty"`
}

// Sources lists overlay sources and which classes use them.
func (o *Overlays) Sources() (any, error) {
	srcs, err := o.Renderer.Sources()
	if err != nil {
		return nil, err
	}
	type row struct {
		render.Source
		Classes []string `json:"classes,omitempty"`
	}
	var out []row
	for _, s := range srcs {
		r := row{Source: s}
		for _, c := range o.Store.Classes() {
			if slices.Contains(c.Overlays, s.Name) {
				r.Classes = append(r.Classes, c.Name)
			}
		}
		out = append(out, r)
	}
	return out, nil
}

// Build renders overlays for the selected nodes and reports what would
// change on each. With Switch set, nodes whose result differs get a new
// generation, which their agents apply right away.
func (o *Overlays) Build(req apiserver.BuildRequest, actor string) (any, error) {
	o.buildMu.Lock()
	defer o.buildMu.Unlock()
	all := o.Store.Nodes("")
	var selected []v1.Node
	for _, n := range all {
		if req.All || slices.Contains(req.Nodes, n.Name) || slices.Contains(req.Classes, n.Class) {
			selected = append(selected, n)
		}
	}
	for _, name := range req.Nodes {
		if !slices.ContainsFunc(selected, func(n v1.Node) bool { return n.Name == name }) {
			return nil, fmt.Errorf("node %s: %w", name, store.ErrNotFound)
		}
	}
	if len(selected) == 0 {
		return nil, errors.New("no nodes selected: pass node names, --class or --all")
	}
	cl := render.Cluster{Server: o.Server, Domain: o.Domain}
	for _, n := range all {
		cl.Nodes = append(cl.Nodes, render.NodeOf(n))
	}

	byClass := map[string][]v1.Node{}
	for _, n := range selected {
		byClass[n.Class] = append(byClass[n.Class], n)
	}
	results := map[string]*NodeResult{}
	for className, nodes := range byClass {
		var rn []render.Node
		for _, n := range nodes {
			rn = append(rn, render.NodeOf(n))
			results[n.Name] = &NodeResult{Node: n.Name, Class: className}
		}
		class, err := o.Store.Class(className)
		var outs map[string]*render.Output
		if err == nil {
			outs, err = o.Renderer.Render(class, rn, cl)
		}
		for _, n := range nodes {
			r := results[n.Name]
			if err != nil {
				r.Error = err.Error()
				continue
			}
			out := outs[n.Name]
			r.Warnings = out.Warnings
			cur, cerr := o.Gens.Current(n.Name)
			if cerr != nil && !errors.Is(cerr, gens.ErrNone) {
				r.Error = cerr.Error()
				continue
			}
			if cur.Manifest.Entries == nil {
				cur.Manifest.Entries = map[string]overlay.Entry{}
			}
			r.From = cur.Number
			r.Changes = summarize(overlay.Diff(cur.Manifest, out.Manifest))
			if !req.Switch {
				continue
			}
			if cur.Number > 0 && overlay.ManifestDigest(cur.Manifest) == overlay.ManifestDigest(out.Manifest) {
				r.To = cur.Number // already current
				continue
			}
			if err := o.publish(n.Name, class, out, actor, req.Message, r); err != nil {
				r.Error = err.Error()
			}
		}
	}
	var out []NodeResult
	for _, n := range selected {
		out = append(out, *results[n.Name])
	}
	return out, nil
}

func (o *Overlays) publish(node string, class v1.NodeClass, out *render.Output, actor, msg string, r *NodeResult) error {
	for d, b := range out.Content {
		if !o.Content.Has(d) {
			if err := o.Content.Put(d, b); err != nil {
				return err
			}
		}
	}
	g, changed, err := o.Gens.Add(node, out.Manifest, actor, msg, class.Overlays)
	if err != nil {
		return err
	}
	r.To = g.Number
	if !changed {
		return nil
	}
	o.notify(node)
	return o.event(node, "overlay.switch", actor, msg, map[string]string{"generation": strconv.Itoa(g.Number), "from": strconv.Itoa(r.From)})
}

// summarize keeps a change's path, action and overlay, not whole entries.
func summarize(cs []overlay.Change) []overlay.Change {
	out := make([]overlay.Change, len(cs))
	for i, c := range cs {
		out[i] = overlay.Change{Action: c.Action, Path: c.Path}
		for _, e := range []*overlay.Entry{c.New, c.Old} {
			if e != nil {
				out[i].New = &overlay.Entry{Kind: e.Kind, Overlay: e.Overlay, Mode: e.Mode, Policy: e.Policy}
				break
			}
		}
	}
	return out
}

// Generations lists a node's generations.
func (o *Overlays) Generations(node string) (any, error) {
	if _, err := o.Store.Node(node); err != nil {
		return nil, err
	}
	return o.Gens.List(node)
}

// Generation returns one generation with its manifest.
func (o *Overlays) Generation(node string, n int) (any, error) {
	if _, err := o.Store.Node(node); err != nil {
		return nil, err
	}
	return o.Gens.Get(node, n)
}

// Diff compares two of a node's generations; to == 0 means current, from
// == 0 the one before to.
func (o *Overlays) Diff(node string, from, to int) (any, error) {
	if _, err := o.Store.Node(node); err != nil {
		return nil, err
	}
	var b gens.Generation
	var err error
	if to == 0 {
		b, err = o.Gens.Current(node)
	} else {
		b, err = o.Gens.Get(node, to)
	}
	if err != nil {
		return nil, err
	}
	a := gens.Generation{Manifest: overlay.Manifest{Entries: map[string]overlay.Entry{}}}
	if from == 0 {
		from = b.Number - 1
	}
	if from > 0 {
		if a, err = o.Gens.Get(node, from); err != nil {
			return nil, err
		}
	}
	return map[string]any{"from": from, "to": b.Number, "changes": summarize(overlay.Diff(a.Manifest, b.Manifest))}, nil
}

// Rollback points a node at an earlier generation (to == 0: the previous
// one). Nothing is re-rendered: the node gets exactly what it had.
func (o *Overlays) Rollback(node string, to int, actor, reason string) (any, error) {
	if _, err := o.Store.Node(node); err != nil {
		return nil, err
	}
	o.buildMu.Lock()
	defer o.buildMu.Unlock()
	before, _ := o.Gens.Current(node)
	g, err := o.Gens.SetCurrent(node, to)
	if err != nil {
		return nil, err
	}
	o.notify(node)
	err = o.event(node, "overlay.rollback", actor, reason, map[string]string{"generation": strconv.Itoa(g.Number), "from": strconv.Itoa(before.Number)})
	return map[string]any{"node": node, "from": before.Number, "to": g.Number}, err
}

func (o *Overlays) event(node, typ, actor, msg string, data map[string]string) error {
	if o.Store.Events == nil {
		return nil
	}
	return o.Store.Events.Append(events.Event{Node: node, Category: events.Change, Type: typ, Actor: actor, Message: msg, Data: data})
}

func (o *Overlays) notify(node string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if ch, ok := o.changed[node]; ok {
		close(ch)
		delete(o.changed, node)
	}
	o.rev++
	if o.revCh != nil {
		close(o.revCh)
		o.revCh = nil
	}
}

// Bump moves the revision without changing any node, so tentacles fetch
// a fresh snapshot (a boot image became ready, or a class's image moved).
func (o *Overlays) Bump() { o.notify("") }

// revision returns the current revision and a channel closed when it
// moves past it.
func (o *Overlays) revision() (uint64, <-chan struct{}) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.revCh == nil {
		o.revCh = make(chan struct{})
	}
	return o.rev, o.revCh
}

// current is the node's current generation, empty generation 0 if none.
func (o *Overlays) current(node string) (gens.Generation, error) {
	g, err := o.Gens.Current(node)
	if errors.Is(err, gens.ErrNone) {
		return gens.Generation{Manifest: overlay.Manifest{Entries: map[string]overlay.Entry{}}}, nil
	}
	return g, err
}

// envelope signs g for node, or returns nil without a signer.
func (o *Overlays) envelope(node string, g gens.Generation) *pki.Envelope {
	if o.Signer == nil {
		return nil
	}
	e := o.Signer.Sign(node, g.Number, overlay.ManifestDigest(g.Manifest))
	return &e
}

// AgentManifest is what an agent receives: its current generation and,
// when the head signs generations, the head's signature over it.
type AgentManifest struct {
	Node       string           `json:"node"`
	Generation int              `json:"generation"`
	Manifest   overlay.Manifest `json:"manifest"`
	Envelope   *pki.Envelope    `json:"envelope,omitempty"`
}

func (o *Overlays) changes(node string) <-chan struct{} {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.changed == nil {
		o.changed = map[string]chan struct{}{}
	}
	ch, ok := o.changed[node]
	if !ok {
		ch = make(chan struct{})
		o.changed[node] = ch
	}
	return ch
}

// wait returns the node's current generation once it differs from have,
// or when ctx ends.
func (o *Overlays) wait(ctx context.Context, node string, have int) (gens.Generation, error) {
	for {
		ch := o.changes(node)
		g, err := o.current(node)
		if err != nil || g.Number != have {
			return g, err
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return g, nil
		}
	}
}

// AgentReport is what a node agent posts after each apply or check.
type AgentReport struct {
	Generation int              `json:"generation"`
	Changes    []overlay.Change `json:"changes,omitempty"`
	Drift      []overlay.Drift  `json:"drift,omitempty"`
	Repaired   int              `json:"repaired,omitempty"`
	Hooks      []HookResult     `json:"hooks,omitempty"`
	Error      string           `json:"error,omitempty"`
}

// HookResult is one onChange/onRemove command the agent ran.
type HookResult struct {
	Command string `json:"command"`
	Error   string `json:"error,omitempty"`
	Output  string `json:"output,omitempty"`
}

// AgentHandler serves node agents, over mTLS only: a node is identified by
// its certificate, and the routes only hand a node its own manifest and
// content. There is no address-based fallback.
func (o *Overlays) AgentHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /agent/v1/manifest", func(w http.ResponseWriter, r *http.Request) {
		n, ok := o.caller(w, r)
		if !ok {
			return
		}
		have, _ := strconv.Atoi(r.URL.Query().Get("have"))
		wait, _ := time.ParseDuration(r.URL.Query().Get("wait"))
		ctx, cancel := context.WithTimeout(r.Context(), min(max(wait, 0), 5*time.Minute))
		defer cancel()
		g, err := o.wait(ctx, n.Name, have)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(AgentManifest{Node: n.Name, Generation: g.Number, Manifest: g.Manifest, Envelope: o.envelope(n.Name, g)})
	})
	mux.HandleFunc("GET /agent/v1/content/{digest}", func(w http.ResponseWriter, r *http.Request) {
		n, ok := o.caller(w, r)
		if !ok {
			return
		}
		d := r.PathValue("digest")
		g, err := o.Gens.Current(n.Name)
		var found, plain bool
		if err == nil {
			found, plain = digestUse(g.Manifest, d)
		}
		if !found {
			http.Error(w, "not in this node's current generation", http.StatusNotFound)
			return
		}
		if !plain {
			o.serveSealed(w, n, d)
			return
		}
		f, err := o.Content.Open(d)
		if err != nil {
			http.Error(w, "content missing", http.StatusNotFound)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		io.Copy(w, f)
	})
	mux.HandleFunc("POST /agent/v1/status", func(w http.ResponseWriter, r *http.Request) {
		n, ok := o.caller(w, r)
		if !ok {
			return
		}
		var rep AgentReport
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&rep); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := o.report(n.Name, rep); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

// digestUse reports whether m has content d, and whether any entry with
// it is not a secret (so the bytes are served in the clear anyway).
func digestUse(m overlay.Manifest, d string) (found, plain bool) {
	for _, e := range m.Entries {
		if e.Kind == overlay.KindFile && e.Digest == d {
			found = true
			plain = plain || !e.Secret
		}
	}
	return found, plain
}

// maxSecret bounds one secret file, which is sealed in memory.
const maxSecret = 64 << 20

// sealed is content d sealed to node n's seal key.
func (o *Overlays) sealed(n v1.Node, d string) ([]byte, error) {
	if len(n.Status.SealKey) == 0 {
		return nil, fmt.Errorf("%w: node %s enrolled without a seal key; reboot it with a current agent", errNoSealKey, n.Name)
	}
	f, err := o.Content.Open(d)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxSecret+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxSecret {
		return nil, fmt.Errorf("secret %.19s is over %d MiB", d, maxSecret>>20)
	}
	return pki.Seal(n.Status.SealKey, n.Name, d, b)
}

var errNoSealKey = errors.New("no seal key")

func (o *Overlays) serveSealed(w http.ResponseWriter, n v1.Node, d string) {
	b, err := o.sealed(n, d)
	switch {
	case errors.Is(err, errNoSealKey):
		http.Error(w, err.Error(), http.StatusConflict)
		return
	case err != nil:
		http.Error(w, "content missing", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", pki.SealedContentType)
	w.Write(b)
}

func (o *Overlays) caller(w http.ResponseWriter, r *http.Request) (v1.Node, bool) {
	return o.callerCert(w, r)
}

func (o *Overlays) report(node string, rep AgentReport) error {
	st := v1.AgentStatus{Applied: rep.Generation, Error: rep.Error, Seen: time.Now().UTC()}
	for _, d := range rep.Drift {
		st.Drift = append(st.Drift, d.Path)
	}
	prev, err := o.Store.ReportAgent(node, st)
	if err != nil {
		return err
	}
	ev := func(typ, msg string, data map[string]string) error {
		if o.Store.Events == nil {
			return nil
		}
		return o.Store.Events.Append(events.Event{Node: node, Category: events.Change, Type: typ, Actor: "agent", Message: msg, Data: data})
	}
	gen := strconv.Itoa(rep.Generation)
	var errs []error
	if len(rep.Changes) > 0 || prev == nil || prev.Applied != rep.Generation {
		errs = append(errs, ev("overlay.applied", fmt.Sprintf("generation %d: %d changes", rep.Generation, len(rep.Changes)),
			map[string]string{"generation": gen}))
	}
	if rep.Repaired > 0 {
		errs = append(errs, ev("overlay.repaired", fmt.Sprintf("repaired %d drifted paths", rep.Repaired), map[string]string{"generation": gen}))
	}
	if len(st.Drift) > 0 && (prev == nil || !slices.Equal(prev.Drift, st.Drift)) {
		errs = append(errs, ev("overlay.drift", fmt.Sprintf("%d paths drifted", len(st.Drift)), map[string]string{"generation": gen}))
	}
	if rep.Error != "" && (prev == nil || prev.Error != rep.Error) {
		errs = append(errs, ev("overlay.error", rep.Error, map[string]string{"generation": gen}))
	}
	for _, h := range rep.Hooks {
		if h.Error != "" {
			errs = append(errs, ev("overlay.hook_failed", h.Command+": "+h.Error, map[string]string{"generation": gen}))
		}
	}
	return errors.Join(errs...)
}

var _ apiserver.Overlays = (*Overlays)(nil)
