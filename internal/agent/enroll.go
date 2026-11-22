package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/damen-pt/flapjack/internal/pki"
	"github.com/damen-pt/flapjack/internal/server"
)

// Credentials is a node's mTLS identity: a key generated on the node and
// a short-lived certificate the head issues for it. The key never leaves
// the node; only CSRs do.
type Credentials struct {
	Node   string
	Server string       // the tentacle, "https://10.1.1.1:8443"
	Client *http.Client // TLS to the tentacle, presenting Certificate
	Logf   func(format string, args ...any)
	// Dir, if set, keeps the key and certificate (identity.pem, mode
	// 0600) so a restarted agent needs no new boot ticket. Nodes are
	// stateless, so this is in RAM and gone at reboot, as it should be.
	Dir string

	mu   sync.RWMutex
	cert *tls.Certificate
	// seal opens the secrets the head sealed to this node (pki.Seal). It is
	// made at each ticket enrollment and kept with the certificate.
	seal hpke.PrivateKey
}

// sealPEM is identity.pem's block for the seal key. tls.X509KeyPair
// skips it.
const sealPEM = "FLAPJACK SEAL KEY"

// Unseal opens content d that the head sealed to this node.
func (c *Credentials) Unseal(d string, blob []byte) ([]byte, error) {
	c.mu.RLock()
	k := c.seal
	c.mu.RUnlock()
	if k == nil {
		return nil, errors.New("no seal key: not enrolled")
	}
	return pki.Unseal(k, c.Node, d, blob)
}

// Certificate is the current certificate, or nil before enrollment. Use
// it as the TLS client certificate source.
func (c *Credentials) Certificate() *tls.Certificate {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cert
}

// Enroll obtains the first certificate with a single-use boot ticket, and
// gives the head a new seal key for this node's secrets.
func (c *Credentials) Enroll(ctx context.Context, mac, ticket string) error {
	seal, err := pki.NewSealKey()
	if err != nil {
		return err
	}
	return c.request(ctx, seal, func(csr []byte) server.EnrollRequest {
		return server.EnrollRequest{Node: c.Node, MAC: mac, Ticket: ticket, CSR: csr, SealKey: seal.PublicKey().Bytes()}
	})
}

// Renew replaces the certificate, proving possession of the current one.
func (c *Credentials) Renew(ctx context.Context) error {
	cur := c.Certificate()
	if cur == nil {
		return errors.New("not enrolled")
	}
	key, ok := cur.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		return errors.New("current key is not Ed25519")
	}
	return c.request(ctx, nil, func(csr []byte) server.EnrollRequest {
		return server.EnrollRequest{Node: c.Node, CSR: csr, Cert: cur.Leaf.Raw, Proof: ed25519.Sign(key, server.RenewMessage(csr))}
	})
}

// request enrolls or renews; seal is the seal key a ticket enrollment
// registered, nil to keep the current one.
func (c *Credentials) request(ctx context.Context, seal hpke.PrivateKey, build func(csr []byte) server.EnrollRequest) error {
	key, csr, err := pki.NewKey()
	if err != nil {
		return err
	}
	body, _ := json.Marshal(build(csr))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Server+"/agent/v1/enroll", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("enroll: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var er server.EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		return err
	}
	leaf, err := pki.ParseCert(er.Cert)
	if err != nil {
		return err
	}
	if id, err := pki.IdentityOf(leaf); err != nil || id != (pki.Identity{Role: pki.Node, Name: c.Node}) {
		return fmt.Errorf("issued certificate is for %v, not node %s", id, c.Node)
	}
	if !key.Public().(ed25519.PublicKey).Equal(leaf.PublicKey) {
		return errors.New("issued certificate is not for this node's key")
	}
	c.mu.Lock()
	c.cert = &tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}
	if seal != nil {
		c.seal = seal
	}
	seal = c.seal
	c.mu.Unlock()
	if err := c.save(key, leaf, seal); err != nil && c.Logf != nil {
		c.Logf("saving identity: %v", err)
	}
	// Pooled connections were authenticated with the old certificate, or
	// none: the tentacle would keep treating requests on them as that.
	c.Client.CloseIdleConnections()
	return nil
}

// Run renews the certificate at half its lifetime until ctx ends,
// retrying failures every tenth of a lifetime.
func (c *Credentials) Run(ctx context.Context) {
	for {
		cur := c.Certificate()
		if cur == nil {
			return
		}
		life := cur.Leaf.NotAfter.Sub(cur.Leaf.NotBefore)
		wait := time.Until(cur.Leaf.NotBefore.Add(life / 2))
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		for ctx.Err() == nil {
			err := c.Renew(ctx)
			if err == nil {
				break
			}
			if c.Logf != nil {
				c.Logf("certificate renewal: %v", err)
			}
			sleep(ctx, max(life/10, time.Second))
		}
	}
}

func (c *Credentials) path() string { return filepath.Join(c.Dir, "identity.pem") }

func (c *Credentials) save(key ed25519.PrivateKey, leaf *x509.Certificate, seal hpke.PrivateKey) error {
	if c.Dir == "" {
		return nil
	}
	kp, err := pki.KeyPEM(key)
	if err != nil {
		return err
	}
	if seal != nil {
		sb, err := seal.Bytes()
		if err != nil {
			return err
		}
		kp = append(kp, pem.EncodeToMemory(&pem.Block{Type: sealPEM, Bytes: sb})...)
	}
	if err := os.MkdirAll(c.Dir, 0o700); err != nil {
		return err
	}
	tmp := c.path() + ".tmp"
	if err := os.WriteFile(tmp, append(pki.CertPEM(leaf), kp...), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path())
}

// Load restores a saved identity if it is this node's and still valid
// for at least a minute; it reports whether it did.
func (c *Credentials) Load() bool {
	if c.Dir == "" {
		return false
	}
	b, err := os.ReadFile(c.path())
	if err != nil {
		return false
	}
	cert, err := tls.X509KeyPair(b, b)
	if err != nil || cert.Leaf == nil {
		return false
	}
	if id, err := pki.IdentityOf(cert.Leaf); err != nil || id != (pki.Identity{Role: pki.Node, Name: c.Node}) {
		return false
	}
	if time.Until(cert.Leaf.NotAfter) < time.Minute {
		return false
	}
	// Without its seal key the node could not open its secrets: enroll
	// again rather than run without them.
	var seal hpke.PrivateKey
	for rest := b; ; {
		var blk *pem.Block
		if blk, rest = pem.Decode(rest); blk == nil {
			break
		}
		if blk.Type == sealPEM {
			seal, err = pki.ParseSealKey(blk.Bytes)
		}
	}
	if seal == nil || err != nil {
		return false
	}
	c.mu.Lock()
	c.cert, c.seal = &cert, seal
	c.mu.Unlock()
	return true
}

// Ensure loads a saved identity or enrolls with the ticket, retrying
// until ctx ends: the tentacle may come up after the node.
func (c *Credentials) Ensure(ctx context.Context, mac, ticket string) error {
	if c.Load() {
		return nil
	}
	if ticket == "" {
		return errors.New("no saved identity and no boot ticket (flapjack.ticket=) to enroll with")
	}
	backoff := time.Second
	for {
		err := c.Enroll(ctx, mac, ticket)
		if err == nil {
			return nil
		}
		// A refused ticket will not get better by retrying.
		if strings.Contains(err.Error(), "403") {
			return err
		}
		d := jitter(backoff)
		if c.Logf != nil {
			c.Logf("enrollment: %v (retrying in %s)", err, d.Round(time.Millisecond))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

// Rebooting reports whether systemd is taking the machine down for a
// reboot (rather than a power-off, or just stopping the agent).
func Rebooting() bool {
	out, err := exec.Command("systemctl", "list-jobs", "--no-legend", "--no-pager").Output()
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && (f[1] == "reboot.target" || f[1] == "kexec.target") {
			return true
		}
	}
	return false
}

// AnnounceReboot tells the head (directly or through the rack's
// tentacle) that this node is about to reboot, with a notice signed by
// the node's key: a tentacle relays it, and the head opens the node's
// boot window only for a notice the node signed.
func (c *Credentials) AnnounceReboot(ctx context.Context) error {
	cur := c.Certificate()
	if cur == nil {
		return errors.New("not enrolled")
	}
	key, ok := cur.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		return errors.New("current key is not Ed25519")
	}
	body, err := json.Marshal(server.SignRebootNotice(c.Node, cur.Leaf.Raw, key, time.Now(), rand.Text()))
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Server+"/agent/v1/rebooting", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}
