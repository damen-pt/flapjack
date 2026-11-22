package tentacle_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
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
	"github.com/damen-pt/flapjack/internal/gens"
	"github.com/damen-pt/flapjack/internal/pki"
	"github.com/damen-pt/flapjack/internal/render"
	"github.com/damen-pt/flapjack/internal/server"
	"github.com/damen-pt/flapjack/internal/staging"
	"github.com/damen-pt/flapjack/internal/store"
	"github.com/damen-pt/flapjack/internal/tentacle"
)

// TestBootImagesFromTentacle: the head indexes the image version a rack
// boots, the rack's tentacle stages it once and serves it over HTTPS with
// a boot-CA certificate, and the head only routes the rack's iPXE to the
// tentacle once it has said the version is staged, with the head as the
// fallback. A rebuild moves the rack to the new version.
func TestBootImagesFromTentacle(t *testing.T) {
	dir := t.TempDir()
	pkiDir := filepath.Join(dir, "pki")
	if _, err := pki.Init(pki.InitOptions{Dir: pkiDir, BootHosts: []string{"10.99.0.1"}}); err != nil {
		t.Fatal(err)
	}
	p := func(f string) string { return filepath.Join(pkiDir, f) }
	ca, _ := pki.LoadCA(p(pki.CACertFile), p(pki.CAKeyFile))
	bootCA, _ := pki.LoadCA(p(pki.BootCACertFile), p(pki.BootCAKeyFile))
	signKey, _ := pki.LoadSigningKey(p(pki.GenKeyFile))

	// Image el9 → version el9-1, with a root filesystem bigger than one
	// chunk.
	imagesDir := filepath.Join(dir, "images")
	files := map[string][]byte{"vmlinuz": []byte("kernel v1"), "initrd.img": []byte("initrd v1"),
		"rootfs.squashfs": bytes.Repeat([]byte("squash v1 "), (5<<20)/10)}
	writeImage := func(version string, f map[string][]byte) {
		os.MkdirAll(filepath.Join(imagesDir, version), 0o755)
		for name, b := range f {
			os.WriteFile(filepath.Join(imagesDir, version, name), b, 0o644)
		}
	}
	writeImage("el9-1", files)
	os.Symlink("el9-1", filepath.Join(imagesDir, "el9"))
	images, err := os.OpenRoot(imagesDir)
	if err != nil {
		t.Fatal(err)
	}
	defer images.Close()

	// The head.
	evlog, _ := events.Open(filepath.Join(dir, "events.jsonl"))
	defer evlog.Close()
	st, _ := store.Open(filepath.Join(dir, "state.json"), evlog)
	st.PutClass(v1.NodeClass{Name: "c", Image: "el9"})
	st.PutNode(v1.Node{Name: "r7n01", Class: "c", Rack: "r7", Interfaces: []v1.Interface{{MAC: "52:54:00:07:00:01", IP: "10.1.7.11"}}})
	ov := &server.Overlays{Store: st, Gens: &gens.Store{Dir: filepath.Join(dir, "gens")}, Content: staging.Store{Dir: filepath.Join(dir, "content")},
		Renderer: &render.Renderer{Dir: filepath.Join(dir, "overlays")}, Signer: &pki.Signer{Key: signKey}}
	ticketKey := make([]byte, 32)
	rand.Read(ticketKey)
	tickets := &attest.Tickets{Key: ticketKey, TTL: time.Minute, Armed: true}
	tokens := &attest.ImageTokens{Key: attest.DeriveImageKey(ticketKey)}
	api := &server.Tentacles{Overlays: ov, CA: ca, Tickets: tickets, Tokens: tokens, Racks: []string{"r7"}, Artifacts: staging.Store{Dir: filepath.Join(dir, "origin")}}
	cs, err := pki.LoadCodeSigner(pkiDir)
	if err != nil {
		t.Fatal(err)
	}
	signing := &server.BootSigner{Signer: cs, Images: images}
	api.Boot = &server.BootImages{Images: images, Store: api.Artifacts, Logf: t.Logf, Notify: ov.Bump, Signing: signing}
	var mu sync.Mutex
	chunkGets := map[string]int{}
	inner := api.Handler()
	counted := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/tentacle/v1/chunks/") {
			mu.Lock()
			chunkGets[r.URL.Path]++
			mu.Unlock()
		}
		inner.ServeHTTP(w, r)
	})
	headCert, _ := pki.FileCert(p(pki.HeadCertFile), p(pki.HeadKeyFile))
	headAddr := freeAddr(t)
	hln, _ := net.Listen("tcp", headAddr)
	hsrv := &http.Server{Handler: counted, ErrorLog: log.New(io.Discard, "", 0)}
	go hsrv.Serve(tls.NewListener(hln, pki.ServerConfig(headCert, ca.Pool, api.Allow, false)))
	defer hsrv.Close()

	// The tentacle, from files, with a boot listener.
	tdir := filepath.Join(dir, "tentacle")
	os.MkdirAll(tdir, 0o755)
	tc, _ := ca.Issue(pki.Identity{Role: pki.Tentacle, Name: "r7"}, time.Hour)
	pki.WriteIdentity(filepath.Join(tdir, "tentacle.pem"), filepath.Join(tdir, "tentacle.key"), tc)
	bc, err := bootCA.IssueServer([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pki.WriteIdentity(filepath.Join(tdir, "boot.pem"), filepath.Join(tdir, "boot.key"), bc)
	caPEM, _ := os.ReadFile(p(pki.CACertFile))
	os.WriteFile(filepath.Join(tdir, "ca.pem"), caPEM, 0o644)
	bootAddr := freeAddr(t)
	cfg := tentacle.Config{Rack: "r7", Head: "https://" + headAddr, Cert: filepath.Join(tdir, "tentacle.pem"), Key: filepath.Join(tdir, "tentacle.key"),
		CA: filepath.Join(tdir, "ca.pem"), AgentListen: freeAddr(t), BootListen: bootAddr,
		BootCert: filepath.Join(tdir, "boot.pem"), BootKey: filepath.Join(tdir, "boot.key"), DataDir: filepath.Join(dir, "tentacle-data")}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tentacle.Serve(ctx, cfg, io.Discard)

	// The boot side of the head: scripts route r7 to its tentacle once
	// staged.
	boot := &server.Boot{Store: st, Base: "https://10.99.0.1", AgentURL: "https://10.99.0.1:8443", Images: images,
		Tickets: tickets, DHCPArms: true, Tokens: tokens, RackBoot: map[string]string{"r7": "https://" + bootAddr}, Staged: api.ServesImage, Signing: signing}
	bh := boot.Handler()
	script := func() string {
		tickets.Arm("52:54:00:07:00:01")
		r := httptest.NewRequest("GET", "/boot/52-54-00-07-00-01.ipxe", nil)
		r.RemoteAddr, r.TLS = "10.1.7.11:4000", &tls.ConnectionState{Version: tls.VersionTLS12}
		w := httptest.NewRecorder()
		bh.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("script: %d %s", w.Code, w.Body)
		}
		return w.Body.String()
	}
	if s := script(); strings.Contains(s, bootAddr) {
		t.Fatalf("routed to the tentacle before it staged anything:\n%s", s)
	}

	eventually(t, "the tentacle staging el9-1", 20*time.Second, func() bool { return api.ServesImage("r7", "el9-1") })
	s := script()
	tok := func(base string) string {
		m := regexp.MustCompile(regexp.QuoteMeta(base) + `/images/el9-1/([^/\s]+)/`).FindStringSubmatch(s)
		if m == nil {
			t.Fatalf("no %s image URL in:\n%s", base, s)
		}
		return base + "/images/el9-1/" + m[1]
	}
	inScript, head := tok("https://"+bootAddr), tok("https://10.99.0.1")
	for _, want := range []string{
		"kernel " + inScript + "/vmlinuz initrd=initrd.img ",
		"root=live:" + inScript + "/rootfs.squashfs",
		// A kernel or initrd that fails verification falls back to the head.
		"&& initrd " + inScript + "/initrd.img && imgverify vmlinuz " + inScript + "/vmlinuz.sig && imgverify initrd.img " + inScript + "/initrd.img.sig && boot ||",
		"imgverify vmlinuz " + head + "/vmlinuz.sig",
		"kernel " + head + "/vmlinuz", // the fallback
		"root=live:" + head + "/rootfs.squashfs",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q:\n%s", want, s)
		}
	}
	tks := regexp.MustCompile(`flapjack\.ticket=(\S+)`).FindAllStringSubmatch(s, -1)
	if len(tks) != 2 || tks[0][1] != tks[1][1] {
		t.Fatalf("both paths must carry the same single ticket: %v", tks)
	}

	// iPXE (TLS 1.2, trusting only the boot CA) downloads from the tentacle,
	// here from 127.0.0.1, so with a token for that address.
	rackTok, _ := tokens.For("r7").Mint("el9-1", net.ParseIP("127.0.0.1"))
	rack := "https://" + bootAddr + "/images/el9-1/" + rackTok
	bootPool, _ := pki.LoadPool(p(pki.BootCACertFile))
	ipxe := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: bootPool, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384}}}}
	get := func(url string) (int, []byte) {
		resp, err := ipxe.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}
	for name, want := range files {
		if code, b := get(rack + "/" + name); code != 200 || !bytes.Equal(b, want) {
			t.Fatalf("%s from the tentacle: %d, %d bytes", name, code, len(b))
		}
	}
	for _, name := range server.SignedFiles {
		_, sig := get(rack + "/" + name + ".sig")
		if err := pki.VerifyDetached(sig, files[name], bootPool); err != nil {
			t.Fatalf("%s.sig from the tentacle: %v", name, err)
		}
	}
	if code, _ := get(rack + "/rootfs.squashfs.sig"); code != 404 {
		t.Fatal("served a signature the head never made")
	}
	if code, _ := get(rack + "/manifest.json"); code != 404 {
		t.Fatalf("served a non-boot file: %d", code)
	}
	if code, _ := get("https://" + bootAddr + "/images/../pki/ca.key"); code == 200 {
		t.Fatal("path escaped the image directory")
	}
	// The tentacle's boot certificate does not verify against the
	// cluster CA, nor its mTLS one against the boot CA: the two trust
	// domains stay apart.
	if _, err := x509.ParseCertificate(bc.Certificate[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := bc.Leaf.Verify(x509.VerifyOptions{Roots: ca.Pool}); err == nil {
		t.Fatal("boot certificate verifies against the cluster CA")
	}

	mu.Lock()
	for path, n := range chunkGets {
		if n != 1 {
			t.Errorf("%s fetched %d times", path, n)
		}
	}
	firstPass := len(chunkGets)
	mu.Unlock()
	if firstPass == 0 {
		t.Fatal("no chunks fetched from the head")
	}

	// A rebuild: el9 now points at el9-2. Shared chunks are not fetched
	// again; el9-1 is pruned and stops being offered.
	v2 := map[string][]byte{"vmlinuz": []byte("kernel v2"), "initrd.img": files["initrd.img"], "rootfs.squashfs": files["rootfs.squashfs"]}
	writeImage("el9-2", v2)
	os.Remove(filepath.Join(imagesDir, "el9"))
	os.Symlink("el9-2", filepath.Join(imagesDir, "el9"))
	ov.Bump() // in production the next watch timeout (≤1m) carries the move
	eventually(t, "the tentacle staging el9-2 and dropping el9-1", 20*time.Second, func() bool {
		return api.ServesImage("r7", "el9-2") && !api.ServesImage("r7", "el9-1")
	})
	v2Tok, _ := tokens.For("r7").Mint("el9-2", net.ParseIP("127.0.0.1"))
	if code, _ := get("https://" + bootAddr + "/images/el9-2/" + rackTok + "/vmlinuz"); code != 403 {
		t.Fatalf("el9-1's token read el9-2: %d", code)
	}
	if code, b := get("https://" + bootAddr + "/images/el9-2/" + v2Tok + "/vmlinuz"); code != 200 || string(b) != "kernel v2" {
		t.Fatalf("el9-2 kernel: %d %q", code, b)
	}
	if code, _ := get(rack + "/vmlinuz"); code != 404 {
		t.Fatalf("pruned version still served: %d", code)
	}
	mu.Lock()
	for path, n := range chunkGets {
		if n != 1 {
			t.Errorf("%s fetched %d times after the rebuild", path, n)
		}
	}
	if len(chunkGets) != firstPass+1 {
		t.Errorf("rebuild fetched %d new chunks, want 1 (only the kernel changed)", len(chunkGets)-firstPass)
	}
	mu.Unlock()

	// A tentacle removed from the head's list stops getting boots at once.
	api.SetRacks(nil)
	if api.ServesImage("r7", "el9-2") || strings.Contains(script(), bootAddr) {
		t.Fatal("a delisted tentacle is still sent boots")
	}
}
