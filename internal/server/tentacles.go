package server

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/attest"
	"github.com/damen-pt/flapjack/internal/overlay"
	"github.com/damen-pt/flapjack/internal/pki"
	"github.com/damen-pt/flapjack/internal/staging"
)

// RackNode is one node's desired state as a tentacle receives it.
type RackNode struct {
	Name       string           `json:"name"`
	MACs       []string         `json:"macs,omitempty"`
	Interfaces []RackInterface  `json:"interfaces,omitempty"`
	Generation int              `json:"generation"`
	Manifest   overlay.Manifest `json:"manifest"`
	Envelope   *pki.Envelope    `json:"envelope,omitempty"`
	// CertsFrom and Retired are the node's certificate rules
	// (NodeStatus.AcceptsCert), which the tentacle applies to its agents.
	CertsFrom time.Time `json:"certsFrom,omitzero"`
	Retired   bool      `json:"retired,omitempty"`
	// SealKeyID names the key the node's secrets are sealed to; when it
	// changes (the node enrolled again) cached sealed blobs are stale.
	SealKeyID string `json:"sealKeyID,omitempty"`
}

// AcceptsCert applies the node's certificate rules.
func (n RackNode) AcceptsCert(issued time.Time) error {
	st := v1.NodeStatus{CertsFrom: n.CertsFrom}
	if n.Retired {
		st.Phase = v1.PhaseRetired
	}
	return st.AcceptsCert(issued)
}

// RackInterface is a node's reserved address, for a tentacle that runs
// its rack's DHCP.
type RackInterface struct {
	MAC string `json:"mac"`
	IP  string `json:"ip,omitempty"`
}

// RackSnapshot is the whole desired state of one rack at a revision. A
// full snapshot per change keeps tentacles stateless.
type RackSnapshot struct {
	Rack     string     `json:"rack"`
	Revision uint64     `json:"revision"`
	Nodes    []RackNode `json:"nodes"`
	// Images are the boot image versions the rack's nodes boot now, once
	// the head has indexed them; the tentacle stages and serves them.
	Images []BootImage `json:"images,omitempty"`
	// Firmware is the iPXE binaries, for a tentacle that runs its rack's
	// DHCP and so is where the rack's firmware loads iPXE from.
	Firmware []staging.Manifest `json:"firmware,omitempty"`
	// ImageKey checks the image tokens in this rack's boot scripts. It
	// is the rack's own key: it cannot mint tokens for another rack or
	// for the head. Only sent when the rack boots from its tentacle.
	ImageKey []byte `json:"imageKey,omitempty"`
}

// NodeReport is one agent report relayed by a tentacle.
type NodeReport struct {
	Node   string      `json:"node"`
	Report AgentReport `json:"report"`
}

// EnrollRequest asks for a node certificate. A first enrollment proves
// the boot with a ticket bound to one of the node's MACs; a renewal
// proves possession of the node's current certificate by signing the new
// CSR with its key. A tentacle relaying a renewal cannot forge it. A
// ticket is only as good as the boot window that produced it: a tentacle
// running its rack's DHCP opens windows for its rack (bootWindow dhcp),
// so there it is trusted with its rack's identities; with bootWindow
// armed it cannot open one (reboot notices are node-signed).
type EnrollRequest struct {
	Node   string `json:"node"`
	MAC    string `json:"mac,omitempty"`
	Ticket string `json:"ticket,omitempty"`
	CSR    []byte `json:"csr"` // DER
	// SealKey is the node's new seal public key (pki.NewSealKey), required
	// with a ticket: the head seals the node's secrets to it. A renewal
	// keeps the key the node enrolled with.
	SealKey []byte `json:"sealKey,omitempty"`
	Cert    []byte `json:"cert,omitempty"`  // renewal: current certificate, DER
	Proof   []byte `json:"proof,omitempty"` // renewal: RenewProof by the current key
}

// EnrollResponse carries the new certificate.
type EnrollResponse struct {
	Cert []byte `json:"cert"` // PEM
}

// RenewMessage is what a renewing node signs with its current key.
func RenewMessage(csr []byte) []byte {
	h := sha256.Sum256(csr)
	return append([]byte("flapjack-renew-v1\x00"), h[:]...)
}

// Tentacles serves the head's side of the tentacle protocol. Callers are
// identified by their certificate, and a tentacle only ever sees and acts
// for the nodes in the rack its certificate names.
type Tentacles struct {
	Overlays *Overlays
	CA       *pki.CA
	Tickets  *attest.Tickets
	// Tokens is the head's image-token key; each rack's tentacle gets its
	// derived key in the snapshot.
	Tokens *attest.ImageTokens
	// Windows opens boot windows for reboots agents announce through
	// their tentacle.
	Windows *Windows
	// Racks lists the tentacles allowed to connect; a tentacle removed
	// from it (SetRacks) is cut off even while its certificate is valid.
	Racks   []string
	racksMu sync.RWMutex
	// NodeCertTTL is how long node certificates last (default 24h).
	NodeCertTTL time.Duration
	// Artifacts is the staging origin tentacles pre-warm from.
	Artifacts staging.Store
	// Boot, when set, offers racks' boot images to their tentacles
	// (chunked into Artifacts) and tracks which each has staged.
	Boot *BootImages
	// Scripts writes iPXE scripts for racks whose tentacle runs their
	// DHCP and asks the head for each script (GET /tentacle/v1/boot/).
	Scripts *Boot
	// Watch caps one long-poll (default 5m).
	Watch time.Duration

	notices notices
}

// RebootRelay is what a tentacle posts when one of its agents announces a
// reboot: the node, and the notice the node signed.
type RebootRelay struct {
	Node   string        `json:"node"`
	Notice *RebootNotice `json:"notice,omitempty"`
}

// SetRacks replaces the allowed tentacles. Requests on connections
// already open are checked against the new list too.
func (t *Tentacles) SetRacks(racks []string) {
	t.racksMu.Lock()
	old := t.Racks
	t.Racks = slices.Clone(racks)
	t.racksMu.Unlock()
	for _, r := range old {
		if !slices.Contains(racks, r) {
			t.Boot.clearStaged(r)
		}
	}
}

// ServesImage reports whether rack's tentacle is allowed and has recently
// reported holding image version, so its nodes can boot from it.
func (t *Tentacles) ServesImage(rack, version string) bool {
	return t != nil && t.Allow(pki.Identity{Role: pki.Tentacle, Name: rack}) && t.Boot.Staged(rack, version)
}

// Allow is the TLS-level check for the tentacle listener, repeated on
// every request.
func (t *Tentacles) Allow(id pki.Identity) bool {
	t.racksMu.RLock()
	defer t.racksMu.RUnlock()
	return id.Role == pki.Tentacle && slices.Contains(t.Racks, id.Name)
}

func (t *Tentacles) rack(w http.ResponseWriter, r *http.Request) (string, bool) {
	id, ok := pki.PeerIdentity(r)
	if !ok || !t.Allow(id) {
		http.Error(w, "tentacle certificate required", http.StatusForbidden)
		return "", false
	}
	return id.Name, true
}

func (t *Tentacles) rackNodes(rack string) []v1.Node {
	var out []v1.Node
	for _, n := range t.Overlays.Store.Nodes("") {
		if n.Rack == rack {
			out = append(out, n)
		}
	}
	return out
}

// Snapshot is the desired state of rack now.
func (t *Tentacles) Snapshot(rack string) (RackSnapshot, error) {
	rev, _ := t.Overlays.revision()
	s := RackSnapshot{Rack: rack, Revision: rev, Nodes: []RackNode{}}
	versions := map[string]bool{}
	for _, n := range t.rackNodes(rack) {
		if c, err := t.Overlays.Store.Class(n.Class); err == nil && c.Image != "" && t.Boot != nil && t.Boot.Images != nil {
			versions[ResolveImage(t.Boot.Images, c.Image)] = true
		}
		g, err := t.Overlays.current(n.Name)
		if err != nil {
			return s, err
		}
		rn := RackNode{Name: n.Name, Generation: g.Number, Manifest: g.Manifest, Envelope: t.Overlays.envelope(n.Name, g),
			CertsFrom: n.Status.CertsFrom, Retired: n.Status.Phase == v1.PhaseRetired, SealKeyID: pki.SealKeyID(n.Status.SealKey)}
		for _, i := range n.Interfaces {
			rn.MACs = append(rn.MACs, strings.ToLower(i.MAC))
			rn.Interfaces = append(rn.Interfaces, RackInterface{MAC: strings.ToLower(i.MAC), IP: i.IP})
		}
		s.Nodes = append(s.Nodes, rn)
	}
	for _, v := range slices.Sorted(maps.Keys(versions)) {
		if img, ok := t.Boot.Image(v); ok {
			s.Images = append(s.Images, img)
		}
	}
	s.Firmware = t.Boot.Firmware()
	if t.Boot != nil && t.Tokens != nil {
		s.ImageKey = t.Tokens.For(rack).Key
	}
	return s, nil
}

func (t *Tentacles) watch(ctx context.Context, rack string, since uint64) (RackSnapshot, error) {
	for {
		rev, ch := t.Overlays.revision()
		if rev != since {
			return t.Snapshot(rack)
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return t.Snapshot(rack)
		}
	}
}

// Handler serves /tentacle/v1/*.
func (t *Tentacles) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /tentacle/v1/watch", func(w http.ResponseWriter, r *http.Request) {
		rack, ok := t.rack(w, r)
		if !ok {
			return
		}
		// since is absent on a tentacle's first call: answer at once.
		since, err := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
		if err != nil {
			since = ^uint64(0)
		}
		wait, _ := time.ParseDuration(r.URL.Query().Get("wait"))
		limit := t.Watch
		if limit == 0 {
			limit = 5 * time.Minute
		}
		ctx, cancel := context.WithTimeout(r.Context(), min(max(wait, 0), limit))
		defer cancel()
		s, err := t.watch(ctx, rack, since)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, s)
	})
	mux.HandleFunc("GET /tentacle/v1/content/{digest}", func(w http.ResponseWriter, r *http.Request) {
		rack, ok := t.rack(w, r)
		if !ok {
			return
		}
		d := r.PathValue("digest")
		if !t.rackNeeds(rack, d) {
			http.Error(w, "not in any current generation in this rack", http.StatusNotFound)
			return
		}
		f, err := t.Overlays.Content.Open(d)
		if err != nil {
			http.Error(w, "content missing", http.StatusNotFound)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		io.Copy(w, f)
	})
	// A node's secret, sealed to the node: the tentacle caches and relays
	// it but cannot open it.
	mux.HandleFunc("GET /tentacle/v1/sealed/{node}/{digest}", func(w http.ResponseWriter, r *http.Request) {
		rack, ok := t.rack(w, r)
		if !ok {
			return
		}
		n, err := t.Overlays.Store.Node(r.PathValue("node"))
		if err != nil || n.Rack != rack {
			http.Error(w, "no such node in rack "+rack, http.StatusNotFound)
			return
		}
		d := r.PathValue("digest")
		g, err := t.Overlays.current(n.Name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if found, _ := digestUse(g.Manifest, d); !found {
			http.Error(w, "not in the node's current generation", http.StatusNotFound)
			return
		}
		t.Overlays.serveSealed(w, n, d)
	})
	mux.HandleFunc("GET /tentacle/v1/chunks/{digest}", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := t.rack(w, r); !ok {
			return
		}
		http.StripPrefix("/tentacle/v1", staging.Handler(t.Artifacts)).ServeHTTP(w, r)
	})
	mux.HandleFunc("POST /tentacle/v1/status", func(w http.ResponseWriter, r *http.Request) {
		rack, ok := t.rack(w, r)
		if !ok {
			return
		}
		var batch []NodeReport
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<20)).Decode(&batch); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var errs []error
		for _, nr := range batch {
			n, err := t.Overlays.Store.Node(nr.Node)
			if err != nil || n.Rack != rack {
				errs = append(errs, fmt.Errorf("%s: not in rack %s", nr.Node, rack))
				continue
			}
			if err := t.Overlays.report(nr.Node, nr.Report); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", nr.Node, err))
			}
		}
		if err := errors.Join(errs...); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /tentacle/v1/boot/{mac}", func(w http.ResponseWriter, r *http.Request) {
		rack, ok := t.rack(w, r)
		if !ok {
			return
		}
		if t.Scripts == nil {
			http.Error(w, "this head does not serve boot scripts to tentacles", http.StatusNotFound)
			return
		}
		// The tentacle checked that the request came from the address its
		// DHCP gave this MAC; the head checks the MAC is in its rack.
		mac, sig := strings.CutSuffix(r.PathValue("mac"), ".sig")
		hw, err := net.ParseMAC(mac)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		n, _, ok := t.Overlays.Store.NodeByMAC(hw.String())
		if !ok || n.Rack != rack {
			http.Error(w, "no node of rack "+rack+" has that MAC", http.StatusNotFound)
			return
		}
		if sig {
			if t.Scripts.Signing == nil {
				http.NotFound(w, r)
				return
			}
			t.Scripts.writeScriptSig(w, r, hw)
			return
		}
		t.Scripts.RackScript(w, n, hw, r.URL.Query().Get("window") == "1")
	})
	mux.HandleFunc("POST /tentacle/v1/rebooting", func(w http.ResponseWriter, r *http.Request) {
		rack, ok := t.rack(w, r)
		if !ok {
			return
		}
		var req RebootRelay
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		n, err := t.Overlays.Store.Node(req.Node)
		if err != nil || n.Rack != rack || t.Windows == nil {
			http.Error(w, "no node "+req.Node+" in rack "+rack, http.StatusNotFound)
			return
		}
		// The tentacle cannot vouch for this itself: only the node's own
		// signature opens its window.
		if err := t.notices.check(t.CA, n, req.Notice, time.Now()); err != nil {
			t.Overlays.event(n.Name, "boot.reboot_refused", "tentacle/"+rack, err.Error(), nil)
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		if err := t.Windows.Arm(n.Name, "the node's agent announced a reboot (via tentacle "+rack+")", "agent"); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /tentacle/v1/images", func(w http.ResponseWriter, r *http.Request) {
		rack, ok := t.rack(w, r)
		if !ok {
			return
		}
		if t.Boot == nil {
			http.Error(w, "this head does not offer boot images to tentacles", http.StatusNotFound)
			return
		}
		var rep StagedImages
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&rep); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		t.Boot.SetStaged(rack, rep.Versions)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /tentacle/v1/enroll", func(w http.ResponseWriter, r *http.Request) {
		rack, ok := t.rack(w, r)
		if !ok {
			return
		}
		var req EnrollRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cert, err := t.enroll(rack, req)
		if err != nil {
			t.Overlays.event(req.Node, "pki.enroll_refused", "tentacle/"+rack, err.Error(), nil)
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		t.Overlays.event(req.Node, "pki.enrolled", "tentacle/"+rack, "certificate issued",
			map[string]string{"serial": cert.SerialNumber.Text(16), "expires": cert.NotAfter.UTC().Format(time.RFC3339), "renewal": strconv.FormatBool(req.Cert != nil)})
		writeJSON(w, EnrollResponse{Cert: pki.CertPEM(cert)})
	})
	return mux
}

// rackNeeds reports whether some node of rack has content d in the
// clear. Secrets are never served to a tentacle in the clear: only sealed
// to their node (/tentacle/v1/sealed/).
func (t *Tentacles) rackNeeds(rack, d string) bool {
	for _, n := range t.rackNodes(rack) {
		g, err := t.Overlays.current(n.Name)
		if err != nil {
			continue
		}
		if _, plain := digestUse(g.Manifest, d); plain {
			return true
		}
	}
	return false
}

// enroll authenticates a relayed enrollment and signs the node's CSR.
func (t *Tentacles) enroll(rack string, req EnrollRequest) (*x509.Certificate, error) {
	n, err := t.Overlays.Store.Node(req.Node)
	if err != nil {
		return nil, fmt.Errorf("node %q unknown", req.Node)
	}
	if n.Rack != rack {
		return nil, fmt.Errorf("node %s is in rack %q, not %q", n.Name, n.Rack, rack)
	}
	// The tentacle checked the ticket came from the node's address.
	return t.Overlays.enroll(t.CA, t.Tickets, t.NodeCertTTL, n, req, nil)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
