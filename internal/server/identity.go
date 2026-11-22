package server

import (
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/attest"
	"github.com/damen-pt/flapjack/internal/events"
	"github.com/damen-pt/flapjack/internal/pki"
)

// A node's identity is its certificate, and three rules decide whether a
// certificate still counts, wherever it is presented (agent routes,
// renewal, the API, a tentacle):
//
//   - a retired node's certificates are refused;
//   - certificates issued before the node's CertsFrom are refused. Each
//     ticket enrollment moves CertsFrom to the new certificate, so a node
//     has one live identity: an impostor that enrolls with a stolen or
//     raced ticket cuts the real node off (loudly) rather than sharing
//     its identity, and a stolen certificate dies at the node's next
//     boot. An admin can move it too (flapjack node revoke).

// callerCert is the request's verified node certificate, refused unless
// the node still accepts it.
func (o *Overlays) callerCert(w http.ResponseWriter, r *http.Request) (v1.Node, bool) {
	id, cert, ok := pki.PeerCert(r)
	if !ok {
		http.Error(w, "a node certificate is required", http.StatusUnauthorized)
		return v1.Node{}, false
	}
	n, err := o.Store.Node(id.Name)
	if id.Role != pki.Node || err != nil {
		http.Error(w, id.String()+" is not a node of this cluster", http.StatusForbidden)
		return v1.Node{}, false
	}
	if err := n.Status.AcceptsCert(pki.IssuedAt(cert)); err != nil {
		http.Error(w, n.Name+": "+err.Error(), http.StatusForbidden)
		return v1.Node{}, false
	}
	return n, true
}

// enroll signs n's CSR if req proves it is n: with its current, still
// accepted certificate (renewal), or with the boot ticket its script
// carried. from, when known, is the address the request came from; a
// ticket is only good from one of the node's reserved addresses.
func (o *Overlays) enroll(ca *pki.CA, tickets *attest.Tickets, ttl time.Duration, n v1.Node, req EnrollRequest, from net.IP) (*x509.Certificate, error) {
	if n.Status.Phase == v1.PhaseRetired {
		return nil, fmt.Errorf("node %s is retired", n.Name)
	}
	id := pki.Identity{Role: pki.Node, Name: n.Name}
	switch {
	case req.Cert != nil:
		cur, err := x509.ParseCertificate(req.Cert)
		if err != nil {
			return nil, err
		}
		got, err := pki.Verify(ca.Pool, []*x509.Certificate{cur}, x509.ExtKeyUsageClientAuth)
		if err != nil {
			return nil, fmt.Errorf("current certificate: %w", err)
		}
		if got != id {
			return nil, fmt.Errorf("current certificate is %s, not %s", got, id)
		}
		if err := n.Status.AcceptsCert(pki.IssuedAt(cur)); err != nil {
			return nil, fmt.Errorf("current certificate: %w", err)
		}
		pub, ok := cur.PublicKey.(ed25519.PublicKey)
		if !ok || !ed25519.Verify(pub, RenewMessage(req.CSR), req.Proof) {
			return nil, errors.New("renewal proof does not verify with the current key")
		}
	case req.Ticket != "":
		if tickets == nil {
			return nil, errors.New("boot tickets are not enabled")
		}
		if !slices.ContainsFunc(n.Interfaces, func(i v1.Interface) bool { return strings.EqualFold(i.MAC, req.MAC) }) {
			return nil, fmt.Errorf("MAC %s is not one of %s's", req.MAC, n.Name)
		}
		if from != nil && !slices.ContainsFunc(n.Interfaces, func(i v1.Interface) bool { return net.ParseIP(i.IP).Equal(from) }) {
			return nil, fmt.Errorf("a boot ticket for %s is only good from its own address, not %s", n.Name, from)
		}
		if err := pki.CheckSealPublicKey(req.SealKey); err != nil {
			return nil, fmt.Errorf("enrollment needs the node's seal key (is its agent current?): %w", err)
		}
		if err := tickets.Redeem(req.Ticket, strings.ToLower(req.MAC)); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("enrollment needs a boot ticket or the current certificate")
	}
	if ttl == 0 {
		ttl = 24 * time.Hour
	}
	cert, err := ca.SignCSR(req.CSR, id, ttl)
	if err != nil || req.Cert != nil {
		return cert, err
	}
	// A ticket enrollment starts a new identity: every earlier certificate
	// of this node is revoked, and its secrets are sealed to its new key
	// from now on.
	issued := pki.IssuedAt(cert)
	if _, err := o.Store.Update(n.Name, func(n *v1.Node) ([]events.Event, error) {
		prev := n.Status.CertsFrom
		if !issued.Before(prev) {
			n.Status.SealKey = req.SealKey
		}
		// Only ever forward: of two enrollments racing here, the later
		// certificate wins whichever saves first, and an admin's revocation
		// at a later time stands (this certificate is then refused too).
		if !issued.After(prev) {
			return nil, nil
		}
		n.Status.CertsFrom = issued
		if prev.IsZero() {
			return nil, nil
		}
		return []events.Event{{Category: events.Change, Type: "pki.superseded", Actor: "head",
			Message: "a new enrollment revoked the node's earlier certificates",
			Data:    map[string]string{"certsFrom": issued.UTC().Format(time.RFC3339Nano)}}}, nil
	}); err != nil {
		return nil, fmt.Errorf("recording the enrollment: %w", err)
	}
	o.Bump() // tentacles learn the new CertsFrom
	return cert, nil
}

// RebootNotice is an agent's signed announcement that its node is about to
// reboot. A tentacle relays it to the head, which opens the node's boot
// window only for a notice the node's own, still accepted key signed, so
// a tentacle cannot open windows (and so obtain boot tickets) by itself.
type RebootNotice struct {
	Node  string `json:"node"`
	Cert  []byte `json:"cert"` // DER
	Time  int64  `json:"time"` // Unix nanoseconds, node clock
	Nonce string `json:"nonce"`
	Proof []byte `json:"proof"`
}

func (n RebootNotice) message() []byte {
	return []byte("flapjack-reboot-v1\x00" + n.Node + "\x00" + strconv.FormatInt(n.Time, 10) + "\x00" + n.Nonce)
}

// SignRebootNotice signs a notice for node with its current certificate
// and key.
func SignRebootNotice(node string, cert []byte, key ed25519.PrivateKey, now time.Time, nonce string) RebootNotice {
	n := RebootNotice{Node: node, Cert: cert, Time: now.UnixNano(), Nonce: nonce}
	n.Proof = ed25519.Sign(key, n.message())
	return n
}

// rebootNoticeSkew is how far a notice's time may be from the head's.
const rebootNoticeSkew = 2 * time.Minute

// notices remembers the reboot notices accepted recently, so a relay
// cannot replay one to reopen a window.
type notices struct {
	mu   sync.Mutex
	seen map[string]time.Time // node|nonce → forget after
}

// check verifies a relayed notice for node n.
func (s *notices) check(ca *pki.CA, n v1.Node, rn *RebootNotice, now time.Time) error {
	if rn == nil {
		return errors.New("a reboot notice signed by the node is required (is its agent current?)")
	}
	if rn.Node != n.Name {
		return fmt.Errorf("notice is for %s, not %s", rn.Node, n.Name)
	}
	if rn.Nonce == "" || len(rn.Nonce) > 64 {
		return errors.New("notice needs a nonce")
	}
	if d := now.Sub(time.Unix(0, rn.Time)); d > rebootNoticeSkew || d < -rebootNoticeSkew {
		return fmt.Errorf("notice time is %s from the head's clock", d.Round(time.Second))
	}
	cert, err := x509.ParseCertificate(rn.Cert)
	if err != nil {
		return fmt.Errorf("notice certificate: %w", err)
	}
	id, err := pki.Verify(ca.Pool, []*x509.Certificate{cert}, x509.ExtKeyUsageClientAuth)
	if err != nil {
		return fmt.Errorf("notice certificate: %w", err)
	}
	if id != (pki.Identity{Role: pki.Node, Name: n.Name}) {
		return fmt.Errorf("notice certificate is %s", id)
	}
	if err := n.Status.AcceptsCert(pki.IssuedAt(cert)); err != nil {
		return err
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || !ed25519.Verify(pub, rn.message(), rn.Proof) {
		return errors.New("notice signature does not verify")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen == nil {
		s.seen = map[string]time.Time{}
	}
	for k, e := range s.seen {
		if now.After(e) {
			delete(s.seen, k)
		}
	}
	k := n.Name + "|" + rn.Nonce
	if _, dup := s.seen[k]; dup {
		return errors.New("notice already used")
	}
	s.seen[k] = now.Add(2 * rebootNoticeSkew)
	return nil
}
