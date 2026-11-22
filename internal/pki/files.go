package pki

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

// Files in a PKI directory (/etc/flapjack/pki on the head).
const (
	CACertFile    = "ca.pem"         // cluster CA (Ed25519): mTLS for heads, tentacles, nodes
	CAKeyFile     = "ca.key"         // its key; the head signs node certificates with it
	GenKeyFile    = "generation.key" // signs generations (Ed25519)
	GenPubFile    = "generation.pub" // shipped in images: agents verify generations with it
	TicketKeyFile = "ticket.key"     // HMAC key for boot tickets
	HeadCertFile  = "head.pem"       // the head's identity towards tentacles
	HeadKeyFile   = "head.key"
	// AdminCertFile is the head's first admin identity (admin/root), for
	// the CLI on the head: the API requires a cluster certificate.
	AdminCertFile = "admin.pem"
	AdminKeyFile  = "admin.key"
	// The boot path has its own RSA CA because iPXE verifies RSA
	// signatures and speaks TLS 1.2, not Ed25519 and TLS 1.3. Build iPXE
	// with TRUST=boot-ca.pem; images trust it too, for dracut's download.
	BootCACertFile = "boot-ca.pem"
	BootCAKeyFile  = "boot-ca.key"
	BootCertFile   = "boot.pem" // HTTPS boot server, with the head's addresses as SANs
	BootKeyFile    = "boot.key"
	// The head signs kernels, initrds and boot scripts with a code-signing
	// certificate from the boot CA; iPXE checks them with imgverify, so a
	// tentacle serving a rack's boot cannot alter them.
	CodeSignCertFile = "codesign.pem"
	CodeSignKeyFile  = "codesign.key"
	// IPXEEmbedFile is the script to build into iPXE (EMBED=) so that it
	// only runs boot scripts the head signed.
	IPXEEmbedFile = "ipxe-embed.ipxe"
)

// IPXEEmbed makes iPXE refuse any image it has not verified
// (imgtrust --permanent), then fetch its boot script and run it only if
// the head's signature over it verifies. Build iPXE with
// TRUST=boot-ca.pem EMBED=ipxe-embed.ipxe and IMAGE_TRUST_CMD enabled.
const IPXEEmbed = `#!ipxe
imgtrust --permanent
dhcp || reboot
imgfetch --name script ${filename} || reboot
imgverify script ${filename}.sig || reboot
chain --replace --autofree script || reboot
`

// InitOptions describes a head's PKI.
type InitOptions struct {
	Dir       string
	HeadName  string   // the head's identity name (default "head")
	BootHosts []string // addresses and names nodes use for HTTPS boot
	// Group, if set, is given read access to the keys the service needs.
	GID int
}

// Init creates whatever of the head's PKI is missing in o.Dir and
// returns the files it wrote. Existing files are never replaced, so it is
// safe to rerun.
func Init(o InitOptions) ([]string, error) {
	if o.HeadName == "" {
		o.HeadName = "head"
	}
	if err := os.MkdirAll(o.Dir, 0o750); err != nil {
		return nil, err
	}
	p := func(f string) string { return filepath.Join(o.Dir, f) }
	var wrote []string
	write := func(name string, b []byte, mode os.FileMode) error {
		if err := writeNew(p(name), b, mode, o.GID); err != nil {
			return err
		}
		wrote = append(wrote, p(name))
		return nil
	}
	exists := func(f string) bool { _, err := os.Stat(p(f)); return err == nil }

	// Cluster CA.
	if !exists(CACertFile) {
		ca, err := NewCA("flapjack cluster CA")
		if err != nil {
			return wrote, err
		}
		if err := writeCA(ca, write, CACertFile, CAKeyFile); err != nil {
			return wrote, err
		}
	}
	ca, err := LoadCA(p(CACertFile), p(CAKeyFile))
	if err != nil {
		return wrote, err
	}
	// Generation signing key.
	if !exists(GenKeyFile) {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return wrote, err
		}
		kp, _ := KeyPEM(key)
		pubDER, _ := x509.MarshalPKIXPublicKey(pub)
		if err := write(GenKeyFile, kp, 0o640); err != nil {
			return wrote, err
		}
		if err := write(GenPubFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil {
			return wrote, err
		}
	}
	if !exists(TicketKeyFile) {
		k := make([]byte, 32)
		rand.Read(k)
		if err := write(TicketKeyFile, k, 0o640); err != nil {
			return wrote, err
		}
	}
	// The head's identity towards tentacles.
	if !exists(HeadCertFile) {
		c, err := ca.Issue(Identity{Role: Head, Name: o.HeadName}, 365*24*time.Hour)
		if err != nil {
			return wrote, err
		}
		if err := writePair(c, write, HeadCertFile, HeadKeyFile); err != nil {
			return wrote, err
		}
	}
	// The first admin, for the CLI on the head. Root only: it is not
	// shared with the service's group.
	if !exists(AdminCertFile) {
		c, err := ca.Issue(Identity{Role: Admin, Name: "root"}, 365*24*time.Hour)
		if err != nil {
			return wrote, err
		}
		kp, err := KeyPEM(c.PrivateKey.(crypto.Signer))
		if err != nil {
			return wrote, err
		}
		if err := writeNew(p(AdminKeyFile), kp, 0o600, 0); err != nil {
			return wrote, err
		}
		wrote = append(wrote, p(AdminKeyFile))
		if err := write(AdminCertFile, chainPEM(c), 0o644); err != nil {
			return wrote, err
		}
	}
	// The boot CA and HTTPS boot certificate.
	if !exists(BootCACertFile) {
		key, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			return wrote, err
		}
		bca, err := NewCAWithKey("flapjack boot CA", key)
		if err != nil {
			return wrote, err
		}
		if err := writeCA(bca, write, BootCACertFile, BootCAKeyFile); err != nil {
			return wrote, err
		}
	}
	if !exists(BootCertFile) && len(o.BootHosts) > 0 {
		bca, err := LoadCA(p(BootCACertFile), p(BootCAKeyFile))
		if err != nil {
			return wrote, err
		}
		c, err := bca.IssueServer(o.BootHosts, 365*24*time.Hour)
		if err != nil {
			return wrote, err
		}
		if err := writePair(c, write, BootCertFile, BootKeyFile); err != nil {
			return wrote, err
		}
	}
	if !exists(CodeSignCertFile) {
		bca, err := LoadCA(p(BootCACertFile), p(BootCAKeyFile))
		if err != nil {
			return wrote, err
		}
		c, err := bca.IssueCodeSigning("flapjack boot signing", 5*365*24*time.Hour)
		if err != nil {
			return wrote, err
		}
		if err := writePair(c, write, CodeSignCertFile, CodeSignKeyFile); err != nil {
			return wrote, err
		}
	}
	if !exists(IPXEEmbedFile) {
		if err := write(IPXEEmbedFile, []byte(IPXEEmbed), 0o644); err != nil {
			return wrote, err
		}
	}
	return wrote, nil
}

// IssueCodeSigning issues an RSA code-signing certificate (what iPXE's
// imgverify requires of a signer).
func (ca *CA) IssueCodeSigning(name string, ttl time.Duration) (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(ttl),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, key.Public(), ca.Key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// LoadCodeSigner reads the head's boot code-signing certificate and key.
func LoadCodeSigner(dir string) (*CodeSigner, error) {
	c, err := LoadCA(filepath.Join(dir, CodeSignCertFile), filepath.Join(dir, CodeSignKeyFile))
	if err != nil {
		return nil, fmt.Errorf("boot signing key: %w (run flapjack pki init)", err)
	}
	return &CodeSigner{Cert: c.Cert, Key: c.Key}, nil
}

func writeCA(ca *CA, write func(string, []byte, os.FileMode) error, certFile, keyFile string) error {
	kp, err := KeyPEM(ca.Key)
	if err != nil {
		return err
	}
	if err := write(keyFile, kp, 0o640); err != nil {
		return err
	}
	return write(certFile, CertPEM(ca.Cert), 0o644)
}

func writePair(c tls.Certificate, write func(string, []byte, os.FileMode) error, certFile, keyFile string) error {
	kp, err := KeyPEM(c.PrivateKey.(crypto.Signer))
	if err != nil {
		return err
	}
	if err := write(keyFile, kp, 0o640); err != nil {
		return err
	}
	return write(certFile, chainPEM(c), 0o644)
}

// writeNew writes a file that must not exist yet.
func writeNew(path string, b []byte, mode os.FileMode, gid int) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if gid > 0 {
		if err := f.Chown(-1, gid); err != nil {
			f.Close()
			return err
		}
	}
	return f.Close()
}

// WriteIdentity writes a certificate and key (0600) for a tentacle or a
// head, refusing to overwrite either.
func WriteIdentity(certPath, keyPath string, c tls.Certificate) error {
	kp, err := KeyPEM(c.PrivateKey.(crypto.Signer))
	if err != nil {
		return err
	}
	if err := writeNew(keyPath, kp, 0o600, 0); err != nil {
		return err
	}
	return writeNew(certPath, chainPEM(c), 0o644, 0)
}

// NewCAWithKey creates a self-signed CA over key (for the RSA boot CA).
func NewCAWithKey(name string, key crypto.Signer) (*CA, error) {
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return newCA(cert, key), nil
}

// IssueServer issues a plain HTTPS server certificate (RSA-2048, which
// iPXE and every curl can verify) for hosts: IP addresses or DNS names.
func (ca *CA) IssueServer(hosts []string, ttl time.Duration) (tls.Certificate, error) {
	if len(hosts) == 0 {
		return tls.Certificate{}, errors.New("a server certificate needs at least one address or name")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: hosts[0]},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(ttl),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, key.Public(), ca.Key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	// The CA goes in the chain: iPXE's TRUST= holds only fingerprints of
	// trusted roots, so it can verify a server only if the server sends
	// the root too.
	return tls.Certificate{Certificate: [][]byte{der, ca.Cert.Raw}, PrivateKey: key, Leaf: leaf}, nil
}

// WithIssuer serves cert with issuer appended to its chain when the
// chain lacks it, for boot certificates written before chains were
// included.
func WithIssuer(cert func() *tls.Certificate, issuer *x509.Certificate) func() *tls.Certificate {
	var mu sync.Mutex
	var src, out *tls.Certificate
	return func() *tls.Certificate {
		c := cert()
		mu.Lock()
		defer mu.Unlock()
		if c != src {
			src, out = c, c
			if n := len(c.Certificate); n > 0 && !bytes.Equal(c.Certificate[n-1], issuer.Raw) {
				cc := *c
				cc.Certificate = append(slices.Clone(c.Certificate), issuer.Raw)
				out = &cc
			}
		}
		return out
	}
}

// chainPEM is every certificate of c, leaf first.
func chainPEM(c tls.Certificate) []byte {
	var b []byte
	for _, der := range c.Certificate {
		b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return b
}

// BootServerConfig is the TLS config for HTTPS boot. iPXE speaks TLS 1.2,
// so this listener (and only this one) allows it, with forward-secret
// AEAD suites only.
//
// It is also capped at TLS 1.2. iPXE master (2.0) offers TLS 1.3 too, and
// a TLS 1.3 handshake between it and Go fails at the Finished message
// (found in the lab with iPXE e6555a5); TLS 1.2 works with every iPXE
// that speaks HTTPS.
func BootServerConfig(cert func() *tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		MaxVersion:     tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert(), nil },
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}
}

// LoadSigningKey reads the generation signing key.
func LoadSigningKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s: no PEM key", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	ek, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an Ed25519 key", path)
	}
	return ek, nil
}

// LoadTrustKey reads the generation verification key agents use.
func LoadTrustKey(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s: no PEM public key", path)
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	ek, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an Ed25519 public key", path)
	}
	return ek, nil
}

// FileCert serves a certificate and key from files, re-reading them when
// either changes, so a re-issued certificate takes effect on the next
// handshake without a restart. A broken replacement keeps the old one.
func FileCert(certPath, keyPath string) (func() *tls.Certificate, error) {
	var mu sync.Mutex
	var cur *tls.Certificate
	var stamp [2]time.Time
	load := func() error {
		var st [2]time.Time
		for i, p := range []string{certPath, keyPath} {
			fi, err := os.Stat(p)
			if err != nil {
				return err
			}
			st[i] = fi.ModTime()
		}
		if cur != nil && st == stamp {
			return nil
		}
		c, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return err
		}
		cur, stamp = &c, st
		return nil
	}
	if err := load(); err != nil {
		return nil, err
	}
	return func() *tls.Certificate {
		mu.Lock()
		defer mu.Unlock()
		load() // on error keep serving the last good pair
		return cur
	}, nil
}

// Exists reports whether a PKI directory has been initialised.
func Exists(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, CACertFile))
	return !errors.Is(err, fs.ErrNotExist)
}
