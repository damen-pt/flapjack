package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/damen-pt/flapjack/internal/pki"
)

// Signed boot. A tentacle serving a rack's boot (or anything else on the
// path) holds a boot-CA certificate, so HTTPS alone cannot stop it
// serving altered files. The head therefore signs what it means the node
// to run, and the node checks it:
//
//   - kernel and initrd: a detached CMS signature next to each
//     (<file>.sig), checked by iPXE's imgverify before boot;
//   - root filesystem: too big for iPXE, and dracut fetches it, so its
//     sha256 goes on the kernel command line (flapjack.rootfs=) and the
//     initrd's flapjack-verify hook refuses to switch to anything else;
//   - the script itself, which carries those lines and that digest: the
//     head signs each one (<mac>.ipxe.sig), and iPXE built with the
//     embedded script from pki init runs only a verified script.
//
// The chain starts at the iPXE binary. Firmware loads it unverified
// unless UEFI Secure Boot checks it, so a party that can serve the rack
// its own iPXE (a tentacle running the rack's DHCP) is only stopped by
// Secure Boot or, later, by attested enrollment measuring it.

// BootSigner signs image versions (once each: versions are immutable)
// and scripts.
type BootSigner struct {
	Signer *pki.CodeSigner
	Images *os.Root
	// ScriptFor is how long a script's signature stays available after
	// the script was served (default 10 minutes).
	ScriptFor time.Duration

	mu       sync.Mutex
	versions map[string]*signedVersion
	scripts  map[string]signedScript // MAC → its latest script
}

type signedVersion struct {
	done   chan struct{}
	sigs   map[string][]byte // vmlinuz, initrd.img → CMS
	rootfs string            // "sha256:…", or "" without a root filesystem
	err    error
}

type signedScript struct {
	sig []byte
	at  time.Time
}

// SignedFiles are the image files iPXE verifies.
var SignedFiles = []string{"vmlinuz", "initrd.img"}

// Version returns version's kernel and initrd signatures and its root
// filesystem digest, computing them the first time (concurrent callers
// wait for the one computation; a failure is retried on the next call).
func (s *BootSigner) Version(version string) (map[string][]byte, string, error) {
	if version == "" || strings.ContainsAny(version, `/\`) || version == "." || version == ".." {
		return nil, "", fmt.Errorf("image version %q", version)
	}
	s.mu.Lock()
	if s.versions == nil {
		s.versions = map[string]*signedVersion{}
	}
	v, ok := s.versions[version]
	if !ok {
		v = &signedVersion{done: make(chan struct{})}
		s.versions[version] = v
		go func() {
			v.sigs, v.rootfs, v.err = s.sign(version)
			if v.err != nil {
				s.mu.Lock()
				delete(s.versions, version)
				s.mu.Unlock()
			}
			close(v.done)
		}()
	}
	s.mu.Unlock()
	<-v.done
	return v.sigs, v.rootfs, v.err
}

func (s *BootSigner) sign(version string) (map[string][]byte, string, error) {
	sigs := map[string][]byte{}
	for _, f := range SignedFiles {
		fh, err := s.Images.Open(version + "/" + f)
		if err != nil {
			return nil, "", err
		}
		sig, err := s.Signer.SignDetached(fh)
		fh.Close()
		if err != nil {
			return nil, "", fmt.Errorf("signing %s/%s: %w", version, f, err)
		}
		sigs[f] = sig
	}
	fh, err := s.Images.Open(version + "/rootfs.squashfs")
	if os.IsNotExist(err) {
		return sigs, "", nil
	} else if err != nil {
		return nil, "", err
	}
	defer fh.Close()
	h := sha256.New()
	if _, err := io.Copy(h, fh); err != nil {
		return nil, "", err
	}
	return sigs, "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// SignScript signs a script just served for mac and keeps the signature
// for iPXE's next request (<mac>.ipxe.sig).
func (s *BootSigner) SignScript(mac string, body []byte) error {
	sig, err := s.Signer.SignDetached(bytes.NewReader(body))
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.scripts == nil {
		s.scripts = map[string]signedScript{}
	}
	now := time.Now()
	for m, sc := range s.scripts {
		if now.Sub(sc.at) > s.scriptFor() {
			delete(s.scripts, m)
		}
	}
	s.scripts[strings.ToLower(mac)] = signedScript{sig: sig, at: now}
	return nil
}

// ScriptSig is the signature of the script last served for mac.
func (s *BootSigner) ScriptSig(mac string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sc, ok := s.scripts[strings.ToLower(mac)]
	if !ok || time.Since(sc.at) > s.scriptFor() {
		return nil, false
	}
	return sc.sig, true
}

func (s *BootSigner) scriptFor() time.Duration {
	if s.ScriptFor > 0 {
		return s.ScriptFor
	}
	return 10 * time.Minute
}

// scriptSig serves a script's signature, to the same address the script
// itself is served to.
func (b *Boot) scriptSig(w http.ResponseWriter, r *http.Request, mac string) {
	hw, err := net.ParseMAC(mac)
	if err != nil || b.Signing == nil {
		http.NotFound(w, r)
		return
	}
	_, iface, ok := b.Store.NodeByMAC(hw.String())
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !ok || !net.ParseIP(host).Equal(net.ParseIP(iface.IP)) {
		http.Error(w, "this signature belongs to another address", http.StatusForbidden)
		return
	}
	b.writeScriptSig(w, r, hw)
}

func (b *Boot) writeScriptSig(w http.ResponseWriter, r *http.Request, hw net.HardwareAddr) {
	sig, ok := b.Signing.ScriptSig(hw.String())
	if !ok {
		http.Error(w, "no script was served to this MAC recently", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/pkcs7-signature")
	w.Write(sig)
}

// imageSig serves the signature of an image version's kernel or initrd.
func (b *Boot) imageSig(w http.ResponseWriter, r *http.Request, version, file string) {
	if b.Signing == nil || (file != "vmlinuz" && file != "initrd.img") {
		http.NotFound(w, r)
		return
	}
	sigs, _, err := b.Signing.Version(version)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/pkcs7-signature")
	w.Write(sigs[file])
}
