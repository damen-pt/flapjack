// Package pki is Flapjack's cluster CA and the mutual TLS built on it.
//
// Every party has an identity carried as a URI SAN:
//
//	flapjack://head/<name>      a head node
//	flapjack://tentacle/<rack>  the tentacle serving a rack
//	flapjack://node/<name>      a node, issued at enrollment
//
// Peers verify the certificate chain against the cluster CA and then check
// the identity they expect, instead of matching hostnames: addresses
// change, identities do not.
package pki

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"time"
)

// Role is what kind of party an identity names.
type Role string

const (
	Head     Role = "head"
	Tentacle Role = "tentacle"
	Node     Role = "node"
	// Admin is a person or automation using the control-plane API.
	Admin Role = "admin"
)

// Identity is who a certificate was issued to.
type Identity struct {
	Role Role
	Name string
}

func (id Identity) String() string { return id.URI().String() }

// URI is the identity's SAN.
func (id Identity) URI() *url.URL {
	return &url.URL{Scheme: "flapjack", Host: string(id.Role), Path: "/" + id.Name}
}

var validName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$`)

// ValidName reports whether s can name a node, rack, head or admin in a
// certificate.
func ValidName(s string) bool { return validName.MatchString(s) }

// Valid reports whether id can be put in a certificate.
func (id Identity) Valid() error {
	switch id.Role {
	case Head, Tentacle, Node, Admin:
	default:
		return fmt.Errorf("unknown role %q", id.Role)
	}
	if !validName.MatchString(id.Name) {
		return fmt.Errorf("invalid %s name %q", id.Role, id.Name)
	}
	return nil
}

// IdentityOf reads the single Flapjack identity in cert.
func IdentityOf(cert *x509.Certificate) (Identity, error) {
	var found []Identity
	for _, u := range cert.URIs {
		if u.Scheme != "flapjack" {
			continue
		}
		id := Identity{Role: Role(u.Host), Name: u.Path[min(1, len(u.Path)):]}
		if err := id.Valid(); err != nil {
			return Identity{}, err
		}
		found = append(found, id)
	}
	if len(found) != 1 {
		return Identity{}, fmt.Errorf("certificate has %d flapjack identities, want 1", len(found))
	}
	return found[0], nil
}

// CA is the cluster certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
	Pool *x509.CertPool
}

// NewCA creates a self-signed Ed25519 CA valid for ten years.
func NewCA(name string) (*CA, error) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return newCA(cert, key), nil
}

func newCA(cert *x509.Certificate, key crypto.Signer) *CA {
	p := x509.NewCertPool()
	p.AddCert(cert)
	return &CA{Cert: cert, Key: key, Pool: p}
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err)
	}
	return n
}

// Sign issues a certificate for id over pub, valid for ttl.
func (ca *CA) Sign(id Identity, pub crypto.PublicKey, ttl time.Duration) (*x509.Certificate, error) {
	if err := id.Valid(); err != nil {
		return nil, err
	}
	now := time.Now()
	skew := backdate(ttl)
	tmpl := &x509.Certificate{
		SerialNumber: serialAt(now),
		Subject:      pkix.Name{CommonName: id.String()},
		URIs:         []*url.URL{id.URI()},
		NotBefore:    now.Add(-skew),
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	if id.Role == Head {
		// The head also serves the API on loopback: tools that check
		// host names (curl) can then verify it there.
		tmpl.DNSNames, tmpl.IPAddresses = []string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.Key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// backdate is how far before its issue a certificate valid for ttl starts:
// enough for clock skew, but not so far that a short-lived certificate's
// renewal point (half its validity) moves much.
func backdate(ttl time.Duration) time.Duration {
	if ttl > 0 && ttl < 10*time.Minute {
		return ttl / 10
	}
	return time.Minute
}

// serialAt is a serial number carrying its issue time: Unix nanoseconds
// in the high bits, 64 random bits below.
func serialAt(t time.Time) *big.Int {
	r, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		panic(err)
	}
	return new(big.Int).Or(new(big.Int).Lsh(big.NewInt(t.UnixNano()), 64), r)
}

// IssuedAt is when Sign issued cert, to the nanosecond: the time in its
// serial number. Certificates whose serial holds no plausible issue time
// (issued before serials carried one) fall back to their start of
// validity plus the backdating Sign applied, to the second. Revoking
// "every certificate issued before T" compares these.
func IssuedAt(cert *x509.Certificate) time.Time {
	life := cert.NotAfter.Sub(cert.NotBefore) // ttl + backdate(ttl)
	skew := time.Minute
	if life < 11*time.Minute-time.Second { // ttl under 10m: life is 1.1×ttl
		skew = (life / 11).Round(time.Second)
	}
	approx := cert.NotBefore.Add(skew)
	if cert.SerialNumber != nil && cert.SerialNumber.Sign() > 0 {
		if hi := new(big.Int).Rsh(cert.SerialNumber, 64); hi.IsInt64() {
			t := time.Unix(0, hi.Int64())
			// NotBefore is truncated to the second; the serial's time must
			// sit within that second of approx.
			if !t.Before(approx.Add(-2*time.Second)) && !t.After(approx.Add(2*time.Second)) {
				return t
			}
		}
	}
	return approx
}

// Issue generates a key and certificate for id: how an admin provisions
// heads and tentacles.
func (ca *CA) Issue(id Identity, ttl time.Duration) (tls.Certificate, error) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert, err := ca.Sign(id, pub, ttl)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}, nil
}

// SignCSR issues a certificate for id over the key in a CSR. Whatever
// subject the CSR asks for is ignored: the caller decides the identity
// after authenticating the request.
func (ca *CA) SignCSR(csrDER []byte, id Identity, ttl time.Duration) (*x509.Certificate, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("csr: %w", err)
	}
	return ca.Sign(id, csr.PublicKey, ttl)
}

// NewKey returns a fresh Ed25519 key and a CSR for it.
func NewKey() (ed25519.PrivateKey, []byte, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	return key, csr, err
}

// Verify checks cert chains to roots, is valid now and usable for usage,
// and returns its identity.
func Verify(roots *x509.CertPool, chain []*x509.Certificate, usage x509.ExtKeyUsage) (Identity, error) {
	if len(chain) == 0 {
		return Identity{}, errors.New("no certificate")
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
		return Identity{}, err
	}
	return IdentityOf(chain[0])
}

// Allow decides whether a verified peer identity may connect.
type Allow func(Identity) bool

// Only allows exactly one identity.
func Only(id Identity) Allow { return func(p Identity) bool { return p == id } }

// AnyOf allows any identity with one of roles.
func AnyOf(roles ...Role) Allow {
	return func(p Identity) bool {
		for _, r := range roles {
			if p.Role == r {
				return true
			}
		}
		return false
	}
}

// ServerConfig is a TLS 1.3 server presenting cert. With allow set, every
// client must present a certificate from roots whose identity allow
// accepts. With optional also set, clients without a certificate get
// through the handshake (for enrollment) and handlers must check
// PeerIdentity themselves.
func ServerConfig(cert func() *tls.Certificate, roots *x509.CertPool, allow Allow, optional bool) *tls.Config {
	c := &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert(), nil },
		ClientCAs:      roots,
		ClientAuth:     tls.RequireAndVerifyClientCert,
	}
	if optional {
		c.ClientAuth = tls.VerifyClientCertIfGiven
	}
	c.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			if optional {
				return nil
			}
			return errors.New("client certificate required")
		}
		id, err := IdentityOf(cs.PeerCertificates[0])
		if err != nil {
			return err
		}
		if allow != nil && !allow(id) {
			return fmt.Errorf("%s may not connect here", id)
		}
		return nil
	}
	return c
}

// ClientConfig is a TLS 1.3 client that trusts only roots, accepts only a
// server whose identity allow accepts, and presents cert (which may
// return nil before enrollment).
func ClientConfig(cert func() *tls.Certificate, roots *x509.CertPool, allow Allow) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		// Hostname checks are replaced, not dropped: VerifyConnection
		// verifies the chain against roots and checks the identity.
		InsecureSkipVerify: true,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if c := cert(); c != nil {
				return c, nil
			}
			return &tls.Certificate{}, nil
		},
		VerifyConnection: func(cs tls.ConnectionState) error {
			id, err := Verify(roots, cs.PeerCertificates, x509.ExtKeyUsageServerAuth)
			if err != nil {
				return err
			}
			if allow != nil && !allow(id) {
				return fmt.Errorf("server is %s, which is not who this client expects", id)
			}
			return nil
		},
	}
}

// Static wraps a fixed certificate for ServerConfig and ClientConfig.
func Static(c tls.Certificate) func() *tls.Certificate { return func() *tls.Certificate { return &c } }

// PeerIdentity is the verified identity of an HTTPS request's client.
func PeerIdentity(r *http.Request) (Identity, bool) {
	id, _, ok := PeerCert(r)
	return id, ok
}

// PeerCert is the verified identity and leaf certificate of an HTTPS
// request's client.
func PeerCert(r *http.Request) (Identity, *x509.Certificate, bool) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		return Identity{}, nil, false
	}
	leaf := r.TLS.VerifiedChains[0][0]
	id, err := IdentityOf(leaf)
	return id, leaf, err == nil
}

// PEM helpers.

func CertPEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func KeyPEM(k crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParseCert reads the first certificate in PEM.
func ParseCert(b []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, errors.New("no PEM certificate")
	}
	return x509.ParseCertificate(blk.Bytes)
}

// LoadCA reads a CA certificate and its key.
func LoadCA(certFile, keyFile string) (*CA, error) {
	cb, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	cert, err := ParseCert(cb)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", certFile, err)
	}
	kb, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(kb)
	if blk == nil {
		return nil, fmt.Errorf("%s: no PEM key", keyFile)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", keyFile, err)
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%s: not a signing key", keyFile)
	}
	return newCA(cert, s), nil
}

// LoadPool reads a CA bundle.
func LoadPool(file string) (*x509.CertPool, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("%s: no PEM certificates", file)
	}
	return p, nil
}

// ParseCertFile reads the first certificate in a PEM file.
func ParseCertFile(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c, err := ParseCert(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}
