package tentacle_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/attest"
	"github.com/damen-pt/flapjack/internal/dhcp"
	"github.com/damen-pt/flapjack/internal/events"
	"github.com/damen-pt/flapjack/internal/gens"
	"github.com/damen-pt/flapjack/internal/pki"
	"github.com/damen-pt/flapjack/internal/render"
	"github.com/damen-pt/flapjack/internal/server"
	"github.com/damen-pt/flapjack/internal/staging"
	"github.com/damen-pt/flapjack/internal/store"
	"github.com/damen-pt/flapjack/internal/tentacle"
)

func dhcpRequest(t *testing.T, typ byte, mac string, opts map[byte][]byte) *dhcp.Packet {
	hw, _ := net.ParseMAC(mac)
	p := &dhcp.Packet{Op: 1, XID: 0x1234, CHAddr: hw, CIAddr: net.IPv4zero, YIAddr: net.IPv4zero, SIAddr: net.IPv4zero,
		GIAddr: net.IPv4zero, Options: map[byte][]byte{dhcp.OptMessageType: {typ}}}
	for k, v := range opts {
		p.Options[k] = v
	}
	q, err := dhcp.Parse(p.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// TestRackBootFromTentacle: a tentacle running its rack's DHCP carries a
// node's whole boot. Its DHCP answers from the rack snapshot (only the
// rack's nodes, only on its subnet), hands firmware iPXE it staged from
// the head, and points iPXE at its own HTTPS script, which it relays from
// the head with the boot window its DHCP opened. The head writes a script
// that points only at the tentacle and waits while the image is staged.
func TestRackBootFromTentacle(t *testing.T) {
	dir := t.TempDir()
	pkiDir := filepath.Join(dir, "pki")
	if _, err := pki.Init(pki.InitOptions{Dir: pkiDir, BootHosts: []string{"10.99.0.1"}}); err != nil {
		t.Fatal(err)
	}
	p := func(f string) string { return filepath.Join(pkiDir, f) }
	ca, _ := pki.LoadCA(p(pki.CACertFile), p(pki.CAKeyFile))
	bootCA, _ := pki.LoadCA(p(pki.BootCACertFile), p(pki.BootCAKeyFile))
	signKey, _ := pki.LoadSigningKey(p(pki.GenKeyFile))

	imagesDir, filesDir := filepath.Join(dir, "images"), filepath.Join(dir, "boot")
	os.MkdirAll(filepath.Join(imagesDir, "el9-1"), 0o755)
	for _, f := range []string{"vmlinuz", "initrd.img", "rootfs.squashfs"} {
		os.WriteFile(filepath.Join(imagesDir, "el9-1", f), []byte(f+" v1"), 0o644)
	}
	os.Symlink("el9-1", filepath.Join(imagesDir, "el9"))
	os.MkdirAll(filesDir, 0o755)
	firmware := map[string]string{"ipxe-x86_64.efi": "efi built with TRUST=boot-ca.pem", "undionly.kpxe": "kpxe built with TRUST=boot-ca.pem"}
	for f, b := range firmware {
		os.WriteFile(filepath.Join(filesDir, f), []byte(b), 0o644)
	}
	os.WriteFile(filepath.Join(filesDir, "README"), []byte("not firmware"), 0o644)
	images, _ := os.OpenRoot(imagesDir)
	defer images.Close()
	files, _ := os.OpenRoot(filesDir)
	defer files.Close()

	// The head. The node's management NIC is on the rack's subnet (here
	// loopback, so the test can connect from its address); its cluster NIC
	// is not, and the tentacle's DHCP must leave it alone.
	const mac, ibMAC, otherRack = "52:54:00:07:00:01", "52:54:00:07:00:02", "52:54:00:08:00:01"
	evlog, _ := events.Open(filepath.Join(dir, "events.jsonl"))
	defer evlog.Close()
	st, _ := store.Open(filepath.Join(dir, "state.json"), evlog)
	st.PutClass(v1.NodeClass{Name: "c", Image: "el9"})
	st.PutNode(v1.Node{Name: "r7n01", Class: "c", Rack: "r7", Interfaces: []v1.Interface{
		{MAC: mac, IP: "127.0.0.1"}, {MAC: ibMAC, IP: "10.2.7.11"}}})
	st.PutNode(v1.Node{Name: "r8n01", Class: "c", Rack: "r8", Interfaces: []v1.Interface{{MAC: otherRack, IP: "127.0.0.2"}}})
	ov := &server.Overlays{Store: st, Gens: &gens.Store{Dir: filepath.Join(dir, "gens")}, Content: staging.Store{Dir: filepath.Join(dir, "content")},
		Renderer: &render.Renderer{Dir: filepath.Join(dir, "overlays")}, Signer: &pki.Signer{Key: signKey}}
	ticketKey := make([]byte, 32)
	rand.Read(ticketKey)
	tickets := &attest.Tickets{Key: ticketKey, TTL: time.Minute, Armed: true}
	tokens := &attest.ImageTokens{Key: attest.DeriveImageKey(ticketKey)}
	windows := &server.Windows{Store: st, Tickets: tickets, DHCP: true}
	api := &server.Tentacles{Overlays: ov, CA: ca, Tickets: tickets, Tokens: tokens, Windows: windows, Racks: []string{"r7", "r8"}, Artifacts: staging.Store{Dir: filepath.Join(dir, "origin")}}
	cs, err := pki.LoadCodeSigner(pkiDir)
	if err != nil {
		t.Fatal(err)
	}
	signing := &server.BootSigner{Signer: cs, Images: images}
	api.Boot = &server.BootImages{Images: images, Files: files, Store: api.Artifacts, Logf: t.Logf, Notify: ov.Bump, Signing: signing}

	// The tentacle's boot listener: HTTPS with a boot-CA certificate.
	bootLn, _ := net.Listen("tcp", "127.0.0.1:0")
	bootBase := "https://" + bootLn.Addr().String()
	boot := &server.Boot{Store: st, Base: "https://10.99.0.1", AgentURL: "https://10.99.0.1:8443", Images: images, Files: files,
		Tickets: tickets, DHCPArms: true, Tokens: tokens, Tentacles: map[string]string{"r7": "https://10.7.0.1:8443"},
		RackBoot: map[string]string{"r7": bootBase}, Staged: api.ServesImage, Signing: signing}
	api.Scripts = boot

	headCert, _ := pki.FileCert(p(pki.HeadCertFile), p(pki.HeadKeyFile))
	hln, _ := net.Listen("tcp", "127.0.0.1:0")
	hsrv := &http.Server{Handler: api.Handler(), ErrorLog: log.New(io.Discard, "", 0)}
	go hsrv.Serve(tls.NewListener(hln, pki.ServerConfig(headCert, ca.Pool, api.Allow, false)))
	defer hsrv.Close()

	// Before anything is staged, the head makes the node wait, and never
	// points it at itself: the node cannot reach the head.
	hw, _ := net.ParseMAC(mac)
	n, _ := st.Node("r7n01")
	rec := httptest.NewRecorder()
	boot.RackScript(rec, n, hw, false)
	if s := rec.Body.String(); !strings.Contains(s, "being staged to rack r7") || !strings.Contains(s, "imgverify next "+bootBase+"/boot/52-54-00-07-00-01.ipxe.sig && chain --replace --autofree next") || strings.Contains(s, "10.99.0.1") {
		t.Fatalf("unstaged script:\n%s", s)
	}

	tcert, _ := ca.Issue(pki.Identity{Role: pki.Tentacle, Name: "r7"}, time.Hour)
	up := &http.Client{Timeout: time.Minute, Transport: &http.Transport{TLSClientConfig: pki.ClientConfig(pki.Static(tcert), ca.Pool, pki.AnyOf(pki.Head))}}
	tn := &tentacle.Tentacle{Rack: "r7", Head: "https://" + hln.Addr().String(), Up: up,
		Cache: staging.Store{Dir: filepath.Join(dir, "t", "cache")}, Artifacts: staging.Store{Dir: filepath.Join(dir, "t", "artifacts")},
		Images: filepath.Join(dir, "t", "images"), Firmware: filepath.Join(dir, "t", "ipxe"), Watch: 2 * time.Second, Logf: t.Logf}
	bc, _ := bootCA.IssueServer([]string{"127.0.0.1"}, time.Hour)
	bsrv := &http.Server{Handler: tn.BootHandler(), ErrorLog: log.New(io.Discard, "", 0)}
	go bsrv.Serve(tls.NewListener(bootLn, pki.BootServerConfig(pki.Static(bc))))
	defer bsrv.Close()
	plain := httptest.NewServer(tn.FirmwareHandler())
	defer plain.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tn.Run(ctx)
	<-tn.Ready()

	subnet := &net.IPNet{IP: net.IPv4(127, 0, 0, 0), Mask: net.CIDRMask(8, 32)}
	ds := tn.DHCPServer(net.IPv4(127, 0, 0, 1), subnet, plain.URL, bootBase)

	// DHCP: PXE firmware gets iPXE over TFTP; iPXE gets its HTTPS script.
	off := ds.Handle(dhcpRequest(t, dhcp.Discover, mac, map[byte][]byte{dhcp.OptVendorClass: []byte("PXEClient:Arch:00007"),
		dhcp.OptClientArch: binary.BigEndian.AppendUint16(nil, 7)}))
	if off == nil || off.Type() != dhcp.Offer || !off.YIAddr.Equal(net.IPv4(127, 0, 0, 1)) || off.File != "ipxe-x86_64.efi" || string(off.Options[dhcp.OptHostname]) != "r7n01" {
		t.Fatalf("PXE offer: %+v", off)
	}
	for _, m := range []string{ibMAC, otherRack, "52:54:00:99:99:99"} {
		if r := ds.Handle(dhcpRequest(t, dhcp.Discover, m, nil)); r != nil {
			t.Fatalf("answered %s, which is not this rack's node on this subnet", m)
		}
	}

	// iPXE binaries, staged from the head (and only those).
	bootPool, _ := pki.LoadPool(p(pki.BootCACertFile))
	ipxe := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: bootPool, MaxVersion: tls.VersionTLS12}}}
	get := func(c *http.Client, url string) (int, string) {
		resp, err := c.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	eventually(t, "the tentacle staging iPXE and el9-1", 20*time.Second, func() bool {
		code, _ := get(http.DefaultClient, plain.URL+"/boot/undionly.kpxe")
		return code == 200 && api.ServesImage("r7", "el9-1")
	})
	for f, want := range firmware {
		if code, b := get(http.DefaultClient, plain.URL+"/boot/"+f); code != 200 || b != want {
			t.Fatalf("%s over HTTP: %d %q", f, code, b)
		}
	}
	if code, _ := get(http.DefaultClient, plain.URL+"/boot/README"); code != 404 {
		t.Fatal("served a file that is not iPXE")
	}
	if ents, _ := os.ReadDir(filepath.Join(dir, "t", "ipxe")); len(ents) == 0 {
		t.Fatal("no firmware directory")
	} else {
		for _, e := range ents {
			if e.Name() == "README" {
				t.Fatal("README staged")
			}
		}
	}
	if code, _ := get(http.DefaultClient, plain.URL+"/boot/52-54-00-07-00-01.ipxe"); code != 404 {
		t.Fatalf("plain-HTTP script: %d", code)
	}

	// Outside a boot window: nothing to boot, and a wait that re-runs DHCP.
	script := func() (int, string) { return get(ipxe, bootBase+"/boot/52-54-00-07-00-01.ipxe") }
	if code, s := script(); code != 200 || strings.Contains(s, "flapjack.ticket=") || strings.Contains(s, "/images/") || !strings.Contains(s, "no boot window is open") {
		t.Fatalf("script outside a boot window: %d\n%s", code, s)
	}

	// iPXE's DHCP opens the window: one ticket, everything from the rack.
	ack := ds.Handle(dhcpRequest(t, dhcp.Request, mac, map[byte][]byte{dhcp.OptUserClass: []byte("iPXE"), dhcp.OptRequestedIP: net.IPv4(127, 0, 0, 1).To4()}))
	if ack == nil || ack.Type() != dhcp.Ack || ack.File != bootBase+"/boot/52-54-00-07-00-01.ipxe" {
		t.Fatalf("iPXE ack: %+v", ack)
	}
	code, s := script()
	if code != 200 {
		t.Fatalf("%d %s", code, s)
	}
	m := regexp.MustCompile(regexp.QuoteMeta(bootBase) + `/images/el9-1/([^/\s]+)/`).FindStringSubmatch(s)
	if m == nil {
		t.Fatalf("no image token in:\n%s", s)
	}
	img := bootBase + "/images/el9-1/" + m[1]
	for _, want := range []string{"flapjack.ticket=", "flapjack.mac=" + mac, "kernel " + img + "/vmlinuz",
		"initrd " + img + "/initrd.img", "root=live:" + img + "/rootfs.squashfs", "flapjack.tentacle=https://10.7.0.1:8443"} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "10.99.0.1") || strings.Contains(s, "||") {
		t.Fatalf("a tentacle-DHCP rack's script must not fall back to the head:\n%s", s)
	}

	// Signed boot through the tentacle. The script, relayed, verifies
	// against the head's signature, relayed too; so do the kernel and
	// initrd the tentacle serves, and the script pins the root
	// filesystem's digest.
	roots, _ := pki.LoadPool(p(pki.BootCACertFile))
	if code, sig := get(ipxe, bootBase+"/boot/52-54-00-07-00-01.ipxe.sig"); code != 200 || pki.VerifyDetached([]byte(sig), []byte(s), roots) != nil {
		t.Fatalf("relayed script signature: %d", code)
	}
	for _, want := range []string{"imgverify vmlinuz " + img + "/vmlinuz.sig", "imgverify initrd.img " + img + "/initrd.img.sig",
		"flapjack.rootfs=sha256:"} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	served := map[string]string{}
	for _, f := range []string{"vmlinuz", "initrd.img"} {
		_, body := get(ipxe, img+"/"+f)
		code, sig := get(ipxe, img+"/"+f+".sig")
		if code != 200 || pki.VerifyDetached([]byte(sig), []byte(body), roots) != nil {
			t.Fatalf("%s from the tentacle does not verify: %d", f, code)
		}
		served[f] = sig
	}
	// A compromised tentacle swaps the kernel it staged and rewrites a
	// script line. Neither verifies any more, and it has no key to fix that.
	staged := filepath.Join(dir, "t", "images", "el9-1")
	os.WriteFile(filepath.Join(staged, "vmlinuz"), []byte("vmlinuz with a rootkit"), 0o644)
	_, evil := get(ipxe, img+"/vmlinuz")
	if evil != "vmlinuz with a rootkit" || pki.VerifyDetached([]byte(served["vmlinuz"]), []byte(evil), roots) == nil {
		t.Fatal("a swapped kernel verified")
	}
	_, ssig := get(ipxe, bootBase+"/boot/52-54-00-07-00-01.ipxe.sig")
	if pki.VerifyDetached([]byte(ssig), []byte(strings.Replace(s, "imgverify vmlinuz", "echo skipped", 1)), roots) == nil {
		t.Fatal("a script with its kernel check removed verified")
	}
	if _, s := script(); strings.Contains(s, "flapjack.ticket=") || strings.Contains(s, "/images/") {
		t.Fatal("second fetch in one boot got a ticket or image token")
	}
	// Images only with a token: none, another node's, or the head's key.
	headTok, _ := tokens.Mint("el9-1", net.ParseIP("127.0.0.1"))
	other, _ := tokens.For("r7").Mint("el9-1", net.ParseIP("127.0.0.2"))
	for name, u := range map[string]string{"no token": bootBase + "/images/el9-1/rootfs.squashfs",
		"head token": bootBase + "/images/el9-1/" + headTok + "/rootfs.squashfs", "another address's": bootBase + "/images/el9-1/" + other + "/rootfs.squashfs"} {
		if code, _ := get(ipxe, u); code == 200 {
			t.Errorf("%s: served", name)
		}
	}
	if code, _ := get(ipxe, img+"/rootfs.squashfs"); code != 200 {
		t.Fatalf("rootfs with its token: %d", code)
	}

	// Another address cannot read the node's script, and the head refuses
	// r7's tentacle a script for r8's node.
	r8, _ := net.ParseMAC(otherRack)
	req, _ := http.NewRequest("GET", tn.Head+"/tentacle/v1/boot/"+r8.String()+"?window=1", nil)
	if resp, err := up.Do(req); err != nil || resp.StatusCode != 404 {
		t.Fatalf("r7's tentacle got r8's script: %v %v", resp.StatusCode, err)
	}
	rr := httptest.NewRequest("GET", "/boot/52-54-00-07-00-01.ipxe", nil)
	rr.RemoteAddr = "127.0.0.9:5000"
	w := httptest.NewRecorder()
	tn.BootHandler().ServeHTTP(w, rr)
	if w.Code != 403 {
		t.Fatalf("script served to another address: %d", w.Code)
	}

	// With the head gone, DHCP still answers from the snapshot; the script
	// fails (the head issues tickets), so the node retries or falls through.
	hsrv.Close()
	ds.Handle(dhcpRequest(t, dhcp.Request, mac, map[byte][]byte{dhcp.OptUserClass: []byte("iPXE"), dhcp.OptRequestedIP: net.IPv4(127, 0, 0, 1).To4()}))
	if code, _ := script(); code != 503 {
		t.Fatalf("script with the head down: %d", code)
	}
	if r := ds.Handle(dhcpRequest(t, dhcp.Discover, mac, nil)); r == nil || !r.YIAddr.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatal("DHCP stopped answering with the head down")
	}
}
