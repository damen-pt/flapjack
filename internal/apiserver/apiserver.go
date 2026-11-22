// Package apiserver is Flapjack's HTTP API. Reads need the viewer role;
// mutations need operator and are recorded on the event log with the
// caller's identity. Bearer tokens are stored only as SHA-256 hashes.
// Node agents get node-scoped tokens that can only submit their own
// node's health reports.
package apiserver

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/events"
	"github.com/damen-pt/flapjack/internal/health"
	"github.com/damen-pt/flapjack/internal/pki"
	"github.com/damen-pt/flapjack/internal/store"
)

// Role is an access level. Higher includes lower.
type Role int

const (
	Viewer Role = iota + 1
	Operator
	Admin
)

// Principal is an authenticated caller.
type Principal struct {
	Name string `json:"name"`
	Role Role   `json:"role"`
	// Node scopes the token to one node's agent. A scoped token can only
	// post that node's health reports, whatever its role.
	Node string `json:"node,omitempty"`
	// Cert, for an admin token, is the admin certificate name it must be
	// presented with (flapjack://admin/<Cert>), so a stolen token is no
	// use with another admin's certificate, and the audit trail's actor
	// is the certificate's holder.
	Cert string `json:"cert,omitempty"`
}

// HashToken returns the form tokens are stored in.
func HashToken(token string) string {
	s := sha256.Sum256([]byte(token))
	return hex.EncodeToString(s[:])
}

// BuildRequest selects nodes for an overlay build or switch.
type BuildRequest struct {
	Nodes   []string `json:"nodes,omitempty"`
	Classes []string `json:"classes,omitempty"`
	All     bool     `json:"all,omitempty"`
	// Switch publishes a new generation to nodes whose result changed;
	// without it the build is a dry run.
	Switch  bool   `json:"switch,omitempty"`
	Message string `json:"message,omitempty"`
}

// Overlays is the overlay and generation service behind /v1/overlays and
// /v1/nodes/{name}/generations.
type Overlays interface {
	Sources() (any, error)
	Build(req BuildRequest, actor string) (any, error)
	Generations(node string) (any, error)
	Generation(node string, n int) (any, error)
	Diff(node string, from, to int) (any, error)
	Rollback(node string, to int, actor, reason string) (any, error)
}

// Server serves the API.
type Server struct {
	Store    *store.Store
	Overlays Overlays // optional
	// Tokens maps HashToken(token) → principal.
	Tokens map[string]Principal
	Now    func() time.Time
	// RequireCert also demands a verified cluster certificate on every
	// request: an admin's for admin tokens, the node's own for a
	// node-scoped token. A stolen token alone is then useless.
	RequireCert bool
	// ArmBoot opens a node's boot window (POST /v1/nodes/{name}/boot).
	ArmBoot func(node, actor string) error
	// Revoked is told a node's certificates were revoked, so relays
	// (tentacles) can be told too.
	Revoked func(node string)
}

func (s *Server) auth(r *http.Request) (Principal, bool) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || tok == "" {
		return Principal{}, false
	}
	h := HashToken(tok)
	for k, p := range s.Tokens {
		if subtle.ConstantTimeCompare([]byte(k), []byte(h)) == 1 {
			return p, true
		}
	}
	return Principal{}, false
}

type handler func(p Principal, w http.ResponseWriter, r *http.Request) (any, error)

func (s *Server) route(need Role, h handler) http.HandlerFunc {
	return s.authorize(func(p Principal, _ *http.Request) bool { return p.Node == "" && p.Role >= need }, h)
}

func (s *Server) authorize(allowed func(Principal, *http.Request) bool, h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := s.auth(r)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "missing or invalid bearer token")
			return
		}
		if s.RequireCert {
			if err := s.certMatches(r, p); err != nil {
				writeErr(w, http.StatusForbidden, err.Error())
				return
			}
		}
		if !allowed(p, r) {
			writeErr(w, http.StatusForbidden, p.Name+" is not allowed to do this")
			return
		}
		out, err := h(p, w, r)
		switch {
		case errors.Is(err, store.ErrNotFound), errors.Is(err, fs.ErrNotExist):
			writeErr(w, http.StatusNotFound, err.Error())
		case errors.Is(err, errBadRequest):
			writeErr(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, store.ErrReadOnly):
			writeErr(w, http.StatusServiceUnavailable, err.Error())
		case err != nil:
			writeErr(w, http.StatusConflict, err.Error())
		default:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(out)
		}
	}
}

var errBadRequest = errors.New("bad request")

// externalEvents are the event types a client may record on a node.
var externalEvents = []string{"firmware.flashed", "bios.configured", "bmc.insecure_protocol"}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) parseSince(r *http.Request, def time.Duration) (time.Time, error) {
	v := r.URL.Query().Get("since")
	if v == "" {
		return s.now().Add(-def), nil
	}
	if d, err := time.ParseDuration(v); err == nil {
		return s.now().Add(-d), nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return t, errors.Join(errBadRequest, errors.New("since must be RFC3339 or a duration like 6h"))
	}
	return t, nil
}

// Handler returns the API routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /v1/nodes", s.route(Viewer, func(_ Principal, _ http.ResponseWriter, r *http.Request) (any, error) {
		return s.Store.Nodes(v1.Phase(r.URL.Query().Get("phase"))), nil
	}))
	mux.Handle("GET /v1/nodes/{name}", s.route(Viewer, func(_ Principal, _ http.ResponseWriter, r *http.Request) (any, error) {
		return s.Store.Node(r.PathValue("name"))
	}))
	mux.Handle("GET /v1/nodes/{name}/explain", s.route(Viewer, func(_ Principal, _ http.ResponseWriter, r *http.Request) (any, error) {
		since, err := s.parseSince(r, 24*time.Hour)
		if err != nil {
			return nil, err
		}
		return s.Store.Explain(r.PathValue("name"), since)
	}))
	mux.Handle("GET /v1/events", s.route(Viewer, func(_ Principal, _ http.ResponseWriter, r *http.Request) (any, error) {
		since, err := s.parseSince(r, 24*time.Hour)
		if err != nil {
			return nil, err
		}
		f := events.Filter{Since: since}
		q := r.URL.Query()
		if n := q.Get("node"); n != "" {
			f.Nodes = strings.Split(n, ",")
		}
		if t := q.Get("type"); t != "" {
			f.Types = strings.Split(t, ",")
		}
		return s.Store.Events.Query(f)
	}))
	transition := func(to v1.Phase) handler {
		return func(p Principal, w http.ResponseWriter, r *http.Request) (any, error) {
			var body struct {
				Reason string `json:"reason"`
			}
			if r.ContentLength != 0 {
				if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
					return nil, errors.Join(errBadRequest, err)
				}
			}
			if body.Reason == "" {
				return nil, errors.Join(errBadRequest, errors.New("a reason is required"))
			}
			return s.Store.SetPhase(r.PathValue("name"), to, body.Reason, p.Name)
		}
	}
	// Release sends a quarantined node back through burn-in; it cannot go
	// straight to Ready.
	mux.Handle("POST /v1/nodes/{name}/boot", s.route(Operator, func(p Principal, w http.ResponseWriter, r *http.Request) (any, error) {
		if s.ArmBoot == nil {
			return nil, errors.New("this server does not manage boot windows")
		}
		name := r.PathValue("name")
		if _, err := s.Store.Node(name); err != nil {
			return nil, err
		}
		if err := s.ArmBoot(name, "api/"+p.Name); err != nil {
			return nil, err
		}
		return map[string]string{"node": name, "status": "boot window open"}, nil
	}))
	// Revoke refuses every certificate the node holds now, renewal
	// included. The node gets a new one only by booting again with a fresh
	// ticket, inside a boot window.
	mux.Handle("POST /v1/nodes/{name}/revoke", s.route(Admin, func(p Principal, w http.ResponseWriter, r *http.Request) (any, error) {
		var body struct {
			Reason string `json:"reason"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
			return nil, errors.Join(errBadRequest, err)
		}
		if body.Reason == "" {
			return nil, errors.Join(errBadRequest, errors.New("a reason is required"))
		}
		from := s.now()
		n, err := s.Store.Update(r.PathValue("name"), func(n *v1.Node) ([]events.Event, error) {
			n.Status.CertsFrom = from
			return []events.Event{{Category: events.Admin, Type: "pki.revoked", Actor: p.Name, Message: body.Reason,
				Data: map[string]string{"certsFrom": from.UTC().Format(time.RFC3339Nano)}}}, nil
		})
		if err != nil {
			return nil, err
		}
		if s.Revoked != nil {
			s.Revoked(n.Name)
		}
		return map[string]string{"node": n.Name, "certsFrom": from.UTC().Format(time.RFC3339Nano)}, nil
	}))
	// Events records a change made outside the server (firmware flashed or
	// BIOS set over the BMC by flapjack firmware converge), so the node's
	// timeline and change correlation see it. Only these types are taken:
	// a client can never write boot, PKI or audit history.
	mux.Handle("POST /v1/nodes/{name}/events", s.route(Admin, func(p Principal, w http.ResponseWriter, r *http.Request) (any, error) {
		var e events.Event
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&e); err != nil {
			return nil, errors.Join(errBadRequest, err)
		}
		if !slices.Contains(externalEvents, e.Type) {
			return nil, errors.Join(errBadRequest, fmt.Errorf("event type %q is not one a client may record (%s)", e.Type, strings.Join(externalEvents, ", ")))
		}
		name := r.PathValue("name")
		if _, err := s.Store.Node(name); err != nil {
			return nil, err
		}
		if s.Store.Events == nil {
			return nil, errors.New("this server keeps no event log")
		}
		e = events.Event{Node: name, Category: events.Change, Type: e.Type, Actor: p.Name, Message: e.Message, Data: e.Data}
		return map[string]string{"node": name, "type": e.Type}, s.Store.Events.Append(e)
	}))
	mux.Handle("POST /v1/nodes/{name}/release", s.route(Operator, transition(v1.PhaseBurnIn)))
	mux.Handle("POST /v1/nodes/{name}/drain", s.route(Operator, transition(v1.PhaseDraining)))
	mux.Handle("POST /v1/nodes/{name}/quarantine", s.route(Operator, transition(v1.PhaseQuarantined)))

	mux.Handle("GET /v1/classes", s.route(Viewer, func(Principal, http.ResponseWriter, *http.Request) (any, error) {
		return s.Store.Classes(), nil
	}))
	mux.Handle("GET /v1/classes/{name}", s.route(Viewer, func(_ Principal, _ http.ResponseWriter, r *http.Request) (any, error) {
		return s.Store.Class(r.PathValue("name"))
	}))
	mux.Handle("PUT /v1/classes/{name}", s.route(Admin, func(p Principal, w http.ResponseWriter, r *http.Request) (any, error) {
		var c v1.NodeClass
		if err := decodeNamed(w, r, &c, &c.Name); err != nil {
			return nil, err
		}
		if err := validateClass(c); err != nil {
			return nil, errors.Join(errBadRequest, err)
		}
		if err := s.Store.PutClass(c); err != nil {
			return nil, err
		}
		return c, s.audit(p, "", "class.put", c.Name)
	}))
	mux.Handle("PUT /v1/nodes/{name}", s.route(Admin, func(p Principal, w http.ResponseWriter, r *http.Request) (any, error) {
		var n v1.Node
		if err := decodeNamed(w, r, &n, &n.Name); err != nil {
			return nil, err
		}
		if err := validateNode(n); err != nil {
			return nil, errors.Join(errBadRequest, err)
		}
		if err := s.Store.PutNode(n); err != nil {
			return nil, err
		}
		if err := s.audit(p, n.Name, "node.put", n.Name); err != nil {
			return nil, err
		}
		return s.Store.Node(n.Name)
	}))
	if s.Overlays != nil {
		s.overlayRoutes(mux)
	}

	// Health reports come from the node's own agent (node-scoped token) or
	// an operator replaying one. The verdict, not the caller, decides the
	// phase, so an agent can quarantine its node but never release it.
	ownNodeOrOperator := func(p Principal, r *http.Request) bool {
		if p.Node != "" {
			return p.Node == r.PathValue("name")
		}
		return p.Role >= Operator
	}
	mux.Handle("POST /v1/nodes/{name}/health", s.authorize(ownNodeOrOperator, func(p Principal, w http.ResponseWriter, r *http.Request) (any, error) {
		var rep health.Report
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&rep); err != nil {
			return nil, errors.Join(errBadRequest, err)
		}
		if rep.Node != r.PathValue("name") {
			return nil, errors.Join(errBadRequest, errors.New("report is for node "+rep.Node))
		}
		if rep.Time.After(s.now().Add(5 * time.Minute)) {
			// A report from the future would make every later report stale.
			return nil, errors.Join(errBadRequest, errors.New("report time is in the future; check the node clock"))
		}
		return health.Admit(s.Store, rep, p.Name)
	}))
	return mux
}

func (s *Server) overlayRoutes(mux *http.ServeMux) {
	num := func(r *http.Request, key string) (int, error) {
		v := r.PathValue(key)
		if v == "" {
			v = r.URL.Query().Get(key)
		}
		if v == "" {
			return 0, nil
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return 0, errors.Join(errBadRequest, fmt.Errorf("%s must be a generation number", key))
		}
		return n, nil
	}
	mux.Handle("GET /v1/overlays", s.route(Viewer, func(Principal, http.ResponseWriter, *http.Request) (any, error) {
		return s.Overlays.Sources()
	}))
	mux.Handle("POST /v1/overlays/build", s.route(Operator, func(p Principal, w http.ResponseWriter, r *http.Request) (any, error) {
		var req BuildRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			return nil, errors.Join(errBadRequest, err)
		}
		if req.Switch && req.Message == "" {
			req.Message = "switch"
		}
		return s.Overlays.Build(req, p.Name)
	}))
	mux.Handle("GET /v1/nodes/{name}/generations", s.route(Viewer, func(_ Principal, _ http.ResponseWriter, r *http.Request) (any, error) {
		return s.Overlays.Generations(r.PathValue("name"))
	}))
	mux.Handle("GET /v1/nodes/{name}/generations/{n}", s.route(Viewer, func(_ Principal, _ http.ResponseWriter, r *http.Request) (any, error) {
		n, err := num(r, "n")
		if err != nil {
			return nil, err
		}
		return s.Overlays.Generation(r.PathValue("name"), n)
	}))
	mux.Handle("GET /v1/nodes/{name}/diff", s.route(Viewer, func(_ Principal, _ http.ResponseWriter, r *http.Request) (any, error) {
		from, err := num(r, "from")
		if err != nil {
			return nil, err
		}
		to, err := num(r, "to")
		if err != nil {
			return nil, err
		}
		return s.Overlays.Diff(r.PathValue("name"), from, to)
	}))
	mux.Handle("POST /v1/nodes/{name}/rollback", s.route(Operator, func(p Principal, w http.ResponseWriter, r *http.Request) (any, error) {
		var body struct {
			To     int    `json:"to"`
			Reason string `json:"reason"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
			return nil, errors.Join(errBadRequest, err)
		}
		if body.Reason == "" {
			return nil, errors.Join(errBadRequest, errors.New("a reason is required"))
		}
		return s.Overlays.Rollback(r.PathValue("name"), body.To, p.Name, body.Reason)
	}))
}

// decodeNamed decodes a PUT body whose name must match the URL.
func decodeNamed(w http.ResponseWriter, r *http.Request, v any, name *string) error {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		return errors.Join(errBadRequest, err)
	}
	if *name == "" {
		*name = r.PathValue("name")
	}
	if *name != r.PathValue("name") {
		return errors.Join(errBadRequest, fmt.Errorf("body names %q but the URL names %q", *name, r.PathValue("name")))
	}
	return nil
}

// Names reach iPXE scripts, kernel command lines, file paths and
// certificates, so they are held to the certificate name rules. An image
// may also be a version (name@hash) or an OCI reference. Nothing may hold
// whitespace, control characters or iPXE's "${" expansion.
var imageRef = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@:/+-]{0,254}$`)

func validateClass(c v1.NodeClass) error {
	if !pki.ValidName(c.Name) {
		return fmt.Errorf("invalid class name %q", c.Name)
	}
	if c.Image != "" && !imageRef.MatchString(c.Image) {
		return fmt.Errorf("invalid image %q", c.Image)
	}
	for _, a := range c.BootArgs {
		switch {
		case a == "" || strings.ContainsFunc(a, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) || strings.Contains(a, "$"):
			return fmt.Errorf("boot argument %q: no spaces, control characters or $", a)
		case strings.HasPrefix(a, "flapjack."):
			return fmt.Errorf("boot argument %q: flapjack.* arguments are set by the head", a)
		}
	}
	return nil
}

func validateNode(n v1.Node) error {
	if !pki.ValidName(n.Name) {
		return fmt.Errorf("invalid node name %q", n.Name)
	}
	if n.Rack != "" && !pki.ValidName(n.Rack) {
		return fmt.Errorf("invalid rack name %q", n.Rack)
	}
	if n.Class != "" && !pki.ValidName(n.Class) {
		return fmt.Errorf("invalid class name %q", n.Class)
	}
	for _, i := range n.Interfaces {
		if _, err := net.ParseMAC(i.MAC); err != nil {
			return fmt.Errorf("interface %s: %w", i.Name, err)
		}
		if i.IP != "" && net.ParseIP(i.IP).To4() == nil {
			return fmt.Errorf("interface %s: %q is not an IPv4 address", i.Name, i.IP)
		}
	}
	return nil
}

func (s *Server) audit(p Principal, node, typ, msg string) error {
	if s.Store.Events == nil {
		return nil
	}
	return s.Store.Events.Append(events.Event{Node: node, Category: events.Admin, Type: typ, Actor: p.Name, Message: msg})
}

// certMatches checks the request's client certificate against the token's
// principal: admin tokens need an admin certificate, of the principal's
// cert identity if it names one; node-scoped tokens need that node's
// certificate, one the node still accepts (not revoked, not retired).
func (s *Server) certMatches(r *http.Request, p Principal) error {
	id, cert, ok := pki.PeerCert(r)
	if !ok {
		return errors.New("a cluster client certificate is required")
	}
	switch {
	case p.Node != "" && (id.Role != pki.Node || id.Name != p.Node):
		return fmt.Errorf("this token belongs to node %s; the certificate is %s", p.Node, id)
	case p.Node != "":
		n, err := s.Store.Node(p.Node)
		if err != nil {
			return err
		}
		return n.Status.AcceptsCert(pki.IssuedAt(cert))
	case id.Role != pki.Admin:
		return fmt.Errorf("%s may not use an admin token", id)
	case p.Cert != "" && id.Name != p.Cert:
		return fmt.Errorf("this token belongs to admin certificate %s, not %s", p.Cert, id.Name)
	}
	return nil
}
