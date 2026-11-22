package server

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/attest"
	"github.com/damen-pt/flapjack/internal/events"
	"github.com/damen-pt/flapjack/internal/pki"
	"github.com/damen-pt/flapjack/internal/store"
)

// Windows opens nodes' boot windows: the only time a node's script
// carries an enrollment ticket and image tokens. Every window opened is
// logged with what opened it.
type Windows struct {
	Store   *store.Store
	Tickets *attest.Tickets
	// DHCP says DHCP answers open windows (bootWindow "dhcp"). Callers of
	// Arm open them either way.
	DHCP bool
}

// Arm opens a boot window on every interface of node.
func (w *Windows) Arm(node, reason, actor string) error {
	n, err := w.Store.Node(node)
	if err != nil {
		return err
	}
	if len(n.Interfaces) == 0 {
		return fmt.Errorf("node %s has no interfaces", node)
	}
	var macs []string
	for _, i := range n.Interfaces {
		w.Tickets.Arm(i.MAC)
		macs = append(macs, strings.ToLower(i.MAC))
	}
	if w.Store.Events != nil {
		w.Store.Events.Append(events.Event{Node: node, Category: events.Boot, Type: "boot.window_opened", Actor: actor,
			Message: reason, Data: map[string]string{"macs": strings.Join(macs, " ")}})
	}
	return nil
}

// HeadAgents serves the agents of racks without a tentacle over mTLS on
// the provisioning network: enrollment with a boot ticket, then overlays
// for the node certificate's own node only.
type HeadAgents struct {
	Overlays    *Overlays
	CA          *pki.CA
	Tickets     *attest.Tickets
	Windows     *Windows
	NodeCertTTL time.Duration
	// Tentacles lists racks whose agents go through their tentacle.
	Tentacles map[string]string
}

// Allow is the TLS check: a node certificate (or none, to enroll).
func (h *HeadAgents) Allow(id pki.Identity) bool { return id.Role == pki.Node }

// Handler returns the agent routes.
func (h *HeadAgents) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/agent/", h.Overlays.AgentHandler())
	mux.HandleFunc("POST /agent/v1/enroll", func(w http.ResponseWriter, r *http.Request) {
		var req EnrollRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// A node already holding a certificate may only renew as itself.
		if id, ok := pki.PeerIdentity(r); ok && (id.Role != pki.Node || id.Name != req.Node) {
			http.Error(w, id.String()+" may not enroll "+req.Node, http.StatusForbidden)
			return
		}
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		cert, err := h.enroll(req, net.ParseIP(host))
		if err != nil {
			h.Overlays.event(req.Node, "pki.enroll_refused", "head", err.Error(), nil)
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		h.Overlays.event(req.Node, "pki.enrolled", "head", "certificate issued",
			map[string]string{"serial": cert.SerialNumber.Text(16), "expires": cert.NotAfter.UTC().Format(time.RFC3339), "renewal": strconv.FormatBool(req.Cert != nil)})
		writeJSON(w, EnrollResponse{Cert: pki.CertPEM(cert)})
	})
	mux.HandleFunc("POST /agent/v1/rebooting", func(w http.ResponseWriter, r *http.Request) {
		n, ok := h.Overlays.caller(w, r)
		if !ok {
			return
		}
		if err := h.Windows.Arm(n.Name, "the node's agent announced a reboot", "agent"); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func (h *HeadAgents) enroll(req EnrollRequest, from net.IP) (*x509.Certificate, error) {
	n, err := h.Overlays.Store.Node(req.Node)
	if err != nil {
		return nil, fmt.Errorf("node %q unknown", req.Node)
	}
	if _, ok := h.Tentacles[n.Rack]; ok {
		return nil, fmt.Errorf("node %s enrolls through rack %s's tentacle", n.Name, n.Rack)
	}
	if from == nil {
		return nil, fmt.Errorf("enrollment for %s from an unknown address", n.Name)
	}
	return h.Overlays.enroll(h.CA, h.Tickets, h.NodeCertTTL, n, req, from)
}

// agentSilent reports whether n's agent has not reported for over d.
func agentSilent(n v1.Node, now time.Time, d time.Duration) bool {
	return n.Status.Agent == nil || now.Sub(n.Status.Agent.Seen) > d
}
