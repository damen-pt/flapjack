package server

import (
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/attest"
	"github.com/damen-pt/flapjack/internal/events"
	"github.com/damen-pt/flapjack/internal/pki"
	"github.com/damen-pt/flapjack/internal/store"
)

// testPKI is one head PKI shared by the package's tests: its RSA keys
// are slow to make.
var testPKI = sync.OnceValues(func() (string, error) {
	dir, err := os.MkdirTemp("", "flapjack-pki-")
	if err != nil {
		return "", err
	}
	_, err = pki.Init(pki.InitOptions{Dir: dir, BootHosts: []string{"10.99.0.1", "127.0.0.1"}})
	return dir, err
})

func TestMain(m *testing.M) {
	code := m.Run()
	if dir, err := testPKI(); err == nil {
		os.RemoveAll(dir)
	}
	os.Exit(code)
}

// bootSetup is a head's boot server as Run builds it: HTTPS base,
// windows on DHCP, image tokens and signing.
func bootSetup(t *testing.T) (*Boot, string) {
	dir := t.TempDir()
	log, _ := events.Open(filepath.Join(dir, "events.jsonl"))
	t.Cleanup(func() { log.Close() })
	st, _ := store.Open(filepath.Join(dir, "state.json"), log)
	st.PutClass(v1.NodeClass{Name: "compute", Image: "el9", BootArgs: []string{"console=ttyAMA0"}})
	st.PutNode(v1.Node{Name: "r1n01", Class: "compute", Interfaces: []v1.Interface{{MAC: "52:54:00:01:01:01", IP: "10.99.1.1"}}})
	st.PutNode(v1.Node{Name: "r1n02", Class: "missing", Interfaces: []v1.Interface{{MAC: "52:54:00:01:02:01", IP: "10.99.1.2"}}})
	for _, d := range []string{"boot", "images/el9"} {
		os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	os.WriteFile(filepath.Join(dir, "boot", "ipxe-arm64.efi"), []byte("ipxe"), 0o644)
	files, _ := os.OpenRoot(filepath.Join(dir, "boot"))
	images, _ := os.OpenRoot(filepath.Join(dir, "images"))
	t.Cleanup(func() { files.Close(); images.Close() })
	pkiDir, err := testPKI()
	if err != nil {
		t.Fatal(err)
	}
	cs, err := pki.LoadCodeSigner(pkiDir)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	rand.Read(key)
	return &Boot{Store: st, Base: "https://10.99.0.1", AgentURL: "https://10.99.0.1:8443", Files: files, Images: images,
		Tickets: &attest.Tickets{Key: key, TTL: time.Minute, Armed: true}, DHCPArms: true,
		Tokens: &attest.ImageTokens{Key: attest.DeriveImageKey(key)}, Signing: &BootSigner{Signer: cs, Images: images}}, dir
}

// bootFiles writes an image version's files.
func bootFiles(t *testing.T, dir, version string, files ...string) {
	t.Helper()
	os.MkdirAll(filepath.Join(dir, "images", version), 0o755)
	for _, f := range files {
		os.WriteFile(filepath.Join(dir, "images", version, f), []byte(f), 0o644)
	}
}

var tokenURL = regexp.MustCompile(`https://10\.99\.0\.1/images/([^/\s]+)/([^/\s]+)/`)

// imageToken returns the image version and token a script points at.
func imageToken(t *testing.T, script string) (string, string) {
	t.Helper()
	m := tokenURL.FindStringSubmatch(script)
	if m == nil {
		t.Fatalf("no image URL in:\n%s", script)
	}
	return m[1], m[2]
}

func get(h http.Handler, path, from string) (int, string) {
	r := httptest.NewRequest("GET", path, nil)
	r.RemoteAddr = from + ":4000"
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS12}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	b, _ := io.ReadAll(w.Result().Body)
	return w.Code, string(b)
}

func TestScriptWaitsUntilImageExists(t *testing.T) {
	b, dir := bootSetup(t)
	h := b.Handler()
	b.Tickets.Arm("52:54:00:01:01:01")
	code, body := get(h, "/boot/52-54-00-01-01-01.ipxe", "10.99.1.1")
	if code != 200 || !strings.HasPrefix(body, "#!ipxe\n") || !strings.Contains(body, `image "el9" is not built (no vmlinuz)`) ||
		!strings.Contains(body, "imgfetch --name next https://10.99.0.1/boot/52-54-00-01-01-01.ipxe && imgverify next https://10.99.0.1/boot/52-54-00-01-01-01.ipxe.sig && chain --replace --autofree next") {
		t.Fatalf("%d\n%s", code, body)
	}
	get(h, "/boot/52-54-00-01-01-01.ipxe", "10.99.1.1") // same reason: not logged again

	// Images are versioned directories behind a symlink. Waiting did not
	// spend the boot window.
	bootFiles(t, dir, "el9@abc", "vmlinuz", "initrd.img", "rootfs.squashfs")
	os.Remove(filepath.Join(dir, "images", "el9"))
	os.Symlink("el9@abc", filepath.Join(dir, "images", "el9"))
	_, body = get(h, "/boot/52-54-00-01-01-01.ipxe", "10.99.1.1")
	version, tok := imageToken(t, body)
	base := "https://10.99.0.1/images/el9@abc/" + tok
	for _, want := range []string{
		"kernel " + base + "/vmlinuz initrd=initrd.img BOOTIF=01-52-54-00-01-01-01 ip=dhcp",
		"root=live:" + base + "/rootfs.squashfs", "flapjack.node=r1n01", "flapjack.server=https://10.99.0.1:8443", "console=ttyAMA0",
		"initrd " + base + "/initrd.img\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("script lacks %q:\n%s", want, body)
		}
	}
	if version != "el9@abc" {
		t.Errorf("pinned version %q", version)
	}
	evs, _ := b.Store.Events.Query(events.Filter{Categories: []events.Category{events.Boot}})
	if len(evs) != 2 || evs[0].Type != "boot.waiting" || evs[1].Type != "boot.script" {
		t.Fatalf("events = %+v", evs)
	}
}

func TestScriptOnlyForTheReservedAddress(t *testing.T) {
	b, _ := bootSetup(t)
	h := b.Handler()
	if code, _ := get(h, "/boot/52-54-00-01-01-01.ipxe", "10.99.1.2"); code != http.StatusForbidden {
		t.Fatalf("another node's script = %d, want 403", code)
	}
	if code, _ := get(h, "/boot/52-54-00-09-09-09.ipxe", "10.99.9.9"); code != 404 {
		t.Fatalf("unknown MAC = %d", code)
	}
	if _, body := get(h, "/boot/52-54-00-01-02-01.ipxe", "10.99.1.2"); !strings.Contains(body, `class "missing" does not exist`) {
		t.Fatalf("missing class:\n%s", body)
	}
}

func TestFilesAreConfined(t *testing.T) {
	b, dir := bootSetup(t)
	bootFiles(t, dir, "el9", "vmlinuz", "initrd.img")
	os.WriteFile(filepath.Join(dir, "images", "el9", "notes.txt"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(dir, "boot", "secret.key"), []byte("x"), 0o644)
	h := b.Handler()
	if code, body := get(h, "/boot/ipxe-arm64.efi", "10.99.1.9"); code != 200 || body != "ipxe" {
		t.Fatalf("boot file = %d %q", code, body)
	}
	tok, _ := b.Tokens.Mint("el9", net.ParseIP("10.99.1.9"))
	for _, p := range []string{"/boot/secret.key", "/images/el9/", "/images/el9/vmlinuz", "/images/../state.json",
		"/images/el9/" + tok + "/..%2f..%2fstate.json", "/boot/..%2fstate.json", "/images/el9/" + tok + "/notes.txt"} {
		if code, _ := get(h, p, "10.99.1.9"); code == 200 {
			t.Errorf("%s served", p)
		}
	}
	if code, _ := get(h, "/images/el9/"+tok+"/vmlinuz", "10.99.1.9"); code != 200 {
		t.Fatalf("image with its token = %d", code)
	}
}

func TestConfigDefaultsAndValidation(t *testing.T) {
	c := Config{Address: "10.99.0.1/16"}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	if c.PlainHTTP || !*c.TFTP || c.API.Listen != DefaultAPI || c.DataDir != DefaultDataDir || c.AgentPort != 8443 ||
		c.BootWindow != BootWindowArmed || c.API.TLSCert == "" || c.API.ClientCA == "" {
		t.Fatalf("defaults = %+v", c)
	}
	off, on := false, true
	for name, bad := range map[string]Config{
		"no prefix":        {Address: "10.99.0.1"},
		"bad router":       {Address: "10.99.0.1/16", Router: "x"},
		"half API TLS":     {Address: "10.99.0.1/16", API: APIConfig{TLSCert: "c"}},
		"bootTLS off":      {Address: "10.99.0.1/16", BootTLS: &off},
		"signedBoot off":   {Address: "10.99.0.1/16", SignedBoot: &off},
		"plaintext ticket": {Address: "10.99.0.1/16", InsecureBootTickets: true},
		"bogus window":     {Address: "10.99.0.1/16", BootWindow: "always"},
		"short armFor":     {Address: "10.99.0.1/16", ArmFor: Duration(time.Second)},
		"bmc without CA":   {Address: "10.99.0.1/16", BMC: &BMCConfig{PasswordFile: "/p"}},
		"port clash":       {Address: "10.99.0.1/16", AgentPort: 443},
		"plain on https":   {Address: "10.99.0.1/16", PlainHTTP: true, HTTPPort: 443},
	} {
		if err := bad.validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Saying they are on is harmless.
	if c := (Config{Address: "10.99.0.1/16", BootTLS: &on, SignedBoot: &on, BootWindow: BootWindowArmed}); c.validate() != nil {
		t.Error(c.validate())
	}
	if !strings.Contains(Unit("/usr/local/bin/flapjack", DefaultConfig), "ExecStart=/usr/local/bin/flapjack server --config /etc/flapjack/server.json") {
		t.Error("unit ExecStart")
	}
}
