package server

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/damen-pt/flapjack/internal/attest"
	"github.com/damen-pt/flapjack/internal/events"
	"github.com/damen-pt/flapjack/internal/pki"
)

func getTLS(h http.Handler, path, from string, secure bool) (int, string) {
	r := httptest.NewRequest("GET", path, nil)
	r.RemoteAddr = from + ":4000"
	if secure {
		r.TLS = &tls.ConnectionState{Version: tls.VersionTLS12}
	} else {
		r.TLS = nil
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	b, _ := io.ReadAll(w.Result().Body)
	return w.Code, string(b)
}

// TestBootServesImagesOnlyWithTokens: plain HTTP carries the iPXE
// binaries and nothing else; over HTTPS a booting node's script carries
// its ticket and an image token, and an image file is only served with a
// token, from the address it names, for the version it names.
func TestBootServesImagesOnlyWithTokens(t *testing.T) {
	b, dir := bootSetup(t)
	bootFiles(t, dir, "el9", "vmlinuz", "initrd.img", "rootfs.squashfs")
	n, _ := b.Store.Node("r1n01")
	n.Rack = "r1"
	b.Store.PutNode(n)
	b.Tentacles = map[string]string{"r1": "https://10.1.1.1:8443"}
	h := b.Handler()

	plain := b.FirmwareHandler()
	if code, body := getTLS(plain, "/boot/ipxe-arm64.efi", "10.99.1.1", false); code != 200 || body != "ipxe" {
		t.Fatalf("plain iPXE binary = %d", code)
	}
	for _, p := range []string{"/boot/52-54-00-01-01-01.ipxe", "/boot/52-54-00-01-01-01.ipxe.sig", "/images/el9/x/vmlinuz", "/agent/v1/manifest"} {
		if code, _ := getTLS(plain, p, "10.99.1.1", false); code != 404 {
			t.Errorf("plain HTTP %s = %d", p, code)
		}
	}

	b.Tickets.Arm("52:54:00:01:01:01")
	code, body := getTLS(h, "/boot/52-54-00-01-01-01.ipxe", "10.99.1.1", true)
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	for _, want := range []string{"flapjack.tentacle=https://10.1.1.1:8443", "flapjack.rack=r1", "flapjack.mac=52:54:00:01:01:01"} {
		if !strings.Contains(body, want) {
			t.Errorf("script lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "flapjack.server=") {
		t.Errorf("a tentacle rack's node was sent to the head:\n%s", body)
	}
	tk := regexp.MustCompile(`flapjack\.ticket=(\S+)`).FindStringSubmatch(body)
	if tk == nil {
		t.Fatalf("no ticket:\n%s", body)
	}
	if err := b.Tickets.Redeem(tk[1], "52:54:00:01:01:01"); err != nil {
		t.Fatalf("ticket does not redeem for the boot MAC: %v", err)
	}
	v, tok := imageToken(t, body)
	other, _ := b.Tokens.Mint(v, net.ParseIP("10.99.1.2"))
	rack, _ := b.Tokens.For("r1").Mint(v, net.ParseIP("10.99.1.1"))
	for name, c := range map[string]struct {
		path, from string
		want       int
	}{
		"own token":            {"/images/" + v + "/" + tok + "/rootfs.squashfs", "10.99.1.1", 200},
		"signature":            {"/images/" + v + "/" + tok + "/vmlinuz.sig", "10.99.1.1", 200},
		"from another address": {"/images/" + v + "/" + tok + "/rootfs.squashfs", "10.99.1.2", 403},
		"another node's token": {"/images/" + v + "/" + other + "/rootfs.squashfs", "10.99.1.1", 403},
		"a rack's token":       {"/images/" + v + "/" + rack + "/rootfs.squashfs", "10.99.1.1", 403},
		"no token":             {"/images/" + v + "/rootfs.squashfs", "10.99.1.1", 404},
		"garbage token":        {"/images/" + v + "/x.y/rootfs.squashfs", "10.99.1.1", 403},
	} {
		if code, _ := getTLS(h, c.path, c.from, true); code != c.want {
			t.Errorf("%s: %d, want %d", name, code, c.want)
		}
	}
}

// TestBootTLSWorksForIPXE checks the boot listener negotiates what iPXE
// speaks: TLS 1.2, ECDHE with an RSA certificate, AES-GCM, verified
// against the boot CA for the head's IP address.
func TestBootTLSWorksForIPXE(t *testing.T) {
	dir := t.TempDir()
	if _, err := pki.Init(pki.InitOptions{Dir: dir, BootHosts: []string{"127.0.0.1"}}); err != nil {
		t.Fatal(err)
	}
	cert, err := pki.FileCert(filepath.Join(dir, pki.BootCertFile), filepath.Join(dir, pki.BootKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "#!ipxe\n") })}
	go srv.Serve(tls.NewListener(ln, pki.BootServerConfig(cert)))
	defer srv.Close()
	roots, _ := pki.LoadPool(filepath.Join(dir, pki.BootCACertFile))
	for name, cfg := range map[string]*tls.Config{
		"iPXE-like TLS 1.2": {RootCAs: roots, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}},
		"TLS 1.3 client":    {RootCAs: roots},
	} {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
		resp, err := c.Get("https://" + ln.Addr().String() + "/")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		resp.Body.Close()
		// TLS 1.2 even for a client offering 1.3: iPXE 2.0 offers 1.3, and
		// its 1.3 handshake with Go fails (seen in the lab).
		if resp.TLS.Version != tls.VersionTLS12 {
			t.Errorf("%s: negotiated %s", name, tls.VersionName(resp.TLS.Version))
		}
		// The root comes with the chain: iPXE's TRUST= holds only
		// fingerprints, so it cannot verify a leaf on its own.
		if chain := resp.TLS.PeerCertificates; len(chain) != 2 || !chain[1].IsCA {
			t.Errorf("%s: server sent %d certificates, want leaf and boot CA", name, len(chain))
		}
	}
	// An older boot.pem with only the leaf gets the CA added.
	leafOnly, _ := tls.X509KeyPair(pki.CertPEM(cert().Leaf), mustRead(t, filepath.Join(dir, pki.BootKeyFile)))
	bootCA, _ := pki.ParseCertFile(filepath.Join(dir, pki.BootCACertFile))
	if got := pki.WithIssuer(pki.Static(leafOnly), bootCA)(); len(got.Certificate) != 2 {
		t.Fatalf("WithIssuer: %d certificates", len(got.Certificate))
	}
	if got := pki.WithIssuer(cert, bootCA)(); len(got.Certificate) != 2 {
		t.Fatalf("WithIssuer duplicated the CA: %d certificates", len(got.Certificate))
	}
	// Old CBC suites and TLS 1.1 are refused; so is a client that trusts
	// only the cluster CA.
	for name, cfg := range map[string]*tls.Config{
		"CBC suite": {RootCAs: roots, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}},
		"TLS 1.1":   {RootCAs: roots, MaxVersion: tls.VersionTLS11},
	} {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
		if resp, err := c.Get("https://" + ln.Addr().String() + "/"); err == nil {
			resp.Body.Close()
			t.Errorf("%s negotiated", name)
		}
	}
	cluster, _ := pki.LoadPool(filepath.Join(dir, pki.CACertFile))
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: cluster}}, Timeout: 5 * time.Second}
	if resp, err := c.Get("https://" + ln.Addr().String() + "/"); err == nil {
		resp.Body.Close()
		t.Error("boot certificate verified against the cluster CA")
	}
}

func TestTentacleConfigValidation(t *testing.T) {
	base := func() Config {
		return Config{Address: "10.99.0.1/16", TentacleListen: "10.98.0.1:7444",
			Tentacles: map[string]string{"r1": "https://10.1.1.1:8443"}}
	}
	if c := base(); c.validate() != nil {
		t.Fatal(c.validate())
	}
	for name, mut := range map[string]func(*Config){
		"no listen":             func(c *Config) { c.TentacleListen = "" },
		"plain URL":             func(c *Config) { c.Tentacles["r1"] = "http://10.1.1.1:8443" },
		"short certTTL":         func(c *Config) { c.NodeCertTTL = Duration(time.Minute) },
		"boot for unknown rack": func(c *Config) { c.TentacleBoot = map[string]string{"r9": "https://10.1.9.1"} },
		"boot with a path":      func(c *Config) { c.TentacleBoot = map[string]string{"r1": "https://10.1.1.1/images"} },
		"boot over http":        func(c *Config) { c.TentacleBoot = map[string]string{"r1": "http://10.1.1.1"} },
		"dhcp without boot":     func(c *Config) { c.TentacleDHCP = []string{"r1"} },
	} {
		c := base()
		mut(&c)
		if c.validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	c := base()
	c.TentacleBoot = map[string]string{"r1": "https://10.1.1.1:443"}
	if err := c.validate(); err != nil {
		t.Errorf("tentacleBoot refused: %v", err)
	}
	c.TentacleDHCP = []string{"r1"}
	if err := c.validate(); err != nil {
		t.Errorf("tentacleDHCP refused: %v", err)
	}
}

// TestNothingBootsOutsideAWindow: a script fetched from the node's
// address outside its boot window carries no ticket, no image token and
// no kernel: the node waits. With windows on DHCP, it re-runs DHCP to
// open one; armed, it waits for an authorized trigger. A window is good
// for one bootable script.
func TestNothingBootsOutsideAWindow(t *testing.T) {
	b, dir := bootSetup(t)
	bootFiles(t, dir, "el9", "vmlinuz", "initrd.img", "rootfs.squashfs")
	h := b.Handler()
	script := func() string {
		code, body := getTLS(h, "/boot/52-54-00-01-01-01.ipxe", "10.99.1.1", true)
		if code != 200 {
			t.Fatalf("%d %s", code, body)
		}
		return body
	}
	closed := func(body string) bool {
		return strings.Contains(body, "no boot window is open") && !strings.Contains(body, "flapjack.ticket=") &&
			!strings.Contains(body, "/images/") && !strings.Contains(body, "\nkernel ")
	}
	body := script()
	if !closed(body) || !strings.Contains(body, "\ndhcp ||\n") {
		t.Fatalf("outside a window (DHCP mode): want a wait that re-runs DHCP:\n%s", body)
	}
	b.Tickets.Arm("52:54:00:01:01:01")
	if body := script(); !strings.Contains(body, "flapjack.ticket=") || !strings.Contains(body, "/images/") {
		t.Fatalf("no ticket or image inside the window:\n%s", body)
	}
	if !closed(script()) {
		t.Fatal("a second fetch in one window got a bootable script too")
	}

	b.DHCPArms = false // bootWindow armed
	body = script()
	if !closed(body) || strings.Contains(body, "\ndhcp") || !strings.Contains(body, "flapjack node boot r1n01") {
		t.Fatalf("armed, outside a window:\n%s", body)
	}
	evs, _ := b.Store.Events.Query(events.Filter{Nodes: []string{"r1n01"}, Types: []string{"boot.window_closed"}})
	if len(evs) == 0 {
		t.Fatal("no boot.window_closed event")
	}
}

func TestDHCPArmsOnlyIPXEScripts(t *testing.T) {
	tk := &attest.Tickets{Key: make([]byte, 32), TTL: time.Minute, Armed: true}
	mac, _ := net.ParseMAC("52:54:00:01:01:01")
	for _, file := range []string{"", "undionly.kpxe", "http://10.99.0.1/boot/ipxe-x86_64.efi"} {
		armBoot(tk, mac, file)
		if _, err := tk.Issue(mac.String()); err == nil {
			t.Fatalf("DHCP for %q opened a boot window", file)
		}
	}
	armBoot(tk, mac, "https://10.99.0.1/boot/52-54-00-01-01-01.ipxe")
	if _, err := tk.Issue(mac.String()); err != nil {
		t.Fatalf("iPXE script DHCP did not open a window: %v", err)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
