package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/damen-pt/flapjack/internal/apiserver"
	"github.com/damen-pt/flapjack/internal/attest"
	"github.com/damen-pt/flapjack/internal/dhcp"
	"github.com/damen-pt/flapjack/internal/events"
	"github.com/damen-pt/flapjack/internal/gens"
	"github.com/damen-pt/flapjack/internal/pki"
	"github.com/damen-pt/flapjack/internal/render"
	"github.com/damen-pt/flapjack/internal/staging"
	"github.com/damen-pt/flapjack/internal/store"
	"github.com/damen-pt/flapjack/internal/tftp"
	"github.com/damen-pt/flapjack/internal/tlsutil"
)

// Run serves until ctx is cancelled or a listener fails.
func Run(ctx context.Context, c Config, log io.Writer) error {
	if err := c.validate(); err != nil {
		return err
	}
	logf := func(format string, args ...any) { fmt.Fprintf(log, format+"\n", args...) }

	for _, d := range []string{c.DataDir, c.BootDir(), c.ImageDir()} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	evlog, err := events.Open(c.eventsPath())
	if err != nil {
		return err
	}
	defer evlog.Close()
	st, err := store.Open(c.statePath(), evlog)
	if err != nil {
		return err
	}
	defer func() {
		if err := st.Flush(); err != nil {
			logf("state: writing agent reports: %v", err)
		}
	}()
	var tokens map[string]apiserver.Principal
	if err := readJSON(c.API.Tokens, &tokens); err != nil {
		return fmt.Errorf("api tokens: %w", err)
	}

	sec, err := loadSecurity(c)
	if err != nil {
		return err
	}

	ip, ipnet, _ := net.ParseCIDR(c.Address)
	iface, err := waitForInterface(ctx, c.Interface, ip, logf)
	if err != nil {
		return err
	}
	withPort := func(scheme string, port, def int) string {
		u := scheme + "://" + ip.String()
		if port != def {
			u += ":" + strconv.Itoa(port)
		}
		return u
	}
	secureBase := withPort("https", c.HTTPSPort, 443)
	agentURL := withPort("https", c.AgentPort, 443)
	firmwareBase := secureBase // UEFI HTTPS boot fetches iPXE here
	if c.PlainHTTP {
		firmwareBase = withPort("http", c.HTTPPort, 80)
	}

	files, err := os.OpenRoot(c.BootDir())
	if err != nil {
		return err
	}
	defer files.Close()
	images, err := os.OpenRoot(c.ImageDir())
	if err != nil {
		return err
	}
	defer images.Close()

	errc := make(chan error, 8) // one per listener, so none blocks after Run returns
	var closers []io.Closer
	defer func() {
		for _, c := range closers {
			c.Close()
		}
	}()
	serve := func(name, addr string, h http.Handler, cfg *tls.Config) error {
		srv := &http.Server{Handler: logRequests(h, logf), TLSConfig: cfg}
		Timeouts(srv)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		closers = append(closers, srv)
		go func() {
			if cfg == nil {
				errc <- fmt.Errorf("%s: %w", name, srv.Serve(ln))
			} else {
				errc <- fmt.Errorf("%s: %w", name, srv.ServeTLS(ln, "", ""))
			}
		}()
		return nil
	}

	windows := &Windows{Store: st, Tickets: sec.tickets, DHCP: c.BootWindow == BootWindowDHCP}
	if windows.DHCP {
		sec.tickets.ArmFor = 2 * time.Minute // DHCP to script fetch
	} else {
		sec.tickets.ArmFor = time.Duration(c.ArmFor) // power-on to script fetch, firmware POST included
	}
	logf("boot: windows open on %s", map[bool]string{true: "DHCP", false: "authorized triggers only (armed)"}[windows.DHCP])

	// DHCP
	dconn, err := dhcp.Listen(iface)
	if err != nil {
		return fmt.Errorf("dhcp: %w", err)
	}
	closers = append(closers, dconn)
	ds := &dhcp.Server{
		ServerIP: ip, Mask: ipnet.Mask, Domain: c.Domain, LeaseTime: time.Duration(c.LeaseTime), HTTPBase: firmwareBase, ScriptBase: secureBase,
		Lookup: func(mac net.HardwareAddr) (dhcp.Lease, bool) {
			n, i, ok := st.NodeByMAC(mac.String())
			if ok && slices.Contains(c.TentacleDHCP, n.Rack) {
				return dhcp.Lease{}, false // its tentacle answers it
			}
			if !ok {
				return dhcp.Lease{}, false
			}
			return dhcp.Lease{Node: n.Name, IP: net.ParseIP(i.IP), Hostname: n.Name}, true
		},
		OnLease: func(l dhcp.Lease, mac net.HardwareAddr, msg byte, file string) {
			if msg != dhcp.Ack {
				return
			}
			if windows.DHCP {
				armBoot(sec.tickets, mac, file)
			}
			logf("dhcp: %s %s → %s %s", l.Node, mac, l.IP, redactTokens(file))
			evlog.Append(events.Event{Node: l.Node, Category: events.Boot, Type: "boot.dhcp", Actor: "flapjack-server",
				Message: "leased " + l.IP.String(), Data: map[string]string{"mac": mac.String(), "ip": l.IP.String(), "file": file}})
		},
		OnUnknown: func(mac net.HardwareAddr, p *dhcp.Packet) {
			if _, _, known := st.NodeByMAC(mac.String()); known {
				return // a tentacleDHCP rack's node, heard across a shared segment
			}
			logf("dhcp: ignoring unknown MAC %s (%s)", mac, p.Options[dhcp.OptVendorClass])
			evlog.Append(events.Event{Category: events.Boot, Type: "boot.unknown", Actor: "flapjack-server",
				Message: "DHCP from a MAC with no node", Data: map[string]string{"mac": mac.String(),
					"vendorClass": string(p.Options[dhcp.OptVendorClass]), "arch": strconv.Itoa(p.ClientArch())}})
		},
	}
	if c.Router != "" {
		ds.Router = net.ParseIP(c.Router)
	}
	for _, d := range c.DNS {
		ds.DNS = append(ds.DNS, net.ParseIP(d))
	}
	go func() { errc <- fmt.Errorf("dhcp: %w", ds.Serve(dconn)) }()
	logf("dhcp: listening on %s (%s), %d nodes reserved", iface, c.Address, len(st.Nodes("")))

	// TFTP: iPXE binaries only, for PXE ROMs.
	if *c.TFTP {
		tconn, err := net.ListenPacket("udp4", net.JoinHostPort(ip.String(), "69"))
		if err != nil {
			return fmt.Errorf("tftp: %w", err)
		}
		closers = append(closers, tconn)
		ts := &tftp.Server{Root: files, Allow: IsFirmware, OnRead: func(remote net.Addr, file string, size int64, err error) {
			if err != nil {
				logf("tftp: %s %s: %v", remote, file, err)
			} else {
				logf("tftp: %s %s (%d bytes)", remote, file, size)
			}
		}}
		go func() { errc <- fmt.Errorf("tftp: %w", ts.Serve(tconn)) }()
		logf("tftp: serving the iPXE binaries on %s:69", ip)
	}

	// Overlays
	ov := &Overlays{Store: st, Gens: &gens.Store{Dir: c.GenerationDir()}, Content: staging.Store{Dir: c.ContentDir()},
		Server: ip.String(), Domain: c.Domain, Signer: sec.signer,
		Renderer: &render.Renderer{Dir: c.OverlayDir, SecretsDir: c.SecretsDir, FilesDir: c.FilesDir,
			Nix: render.Nix{Bin: c.Nix.Bin, Nixpkgs: c.Nix.Nixpkgs}}}
	if err := ov.Renderer.Nix.Available(); err != nil {
		logf("overlays: %s; nix overlays will fail to render", err)
	}
	logf("overlays: sources in %s", c.OverlayDir)

	cs, err := pki.LoadCodeSigner(c.PKIDir)
	if err != nil {
		return err
	}
	signing := &BootSigner{Signer: cs, Images: images}
	logf("boot: signing scripts, kernels and initrds as %s", cs.Cert.Subject.CommonName)

	// The head's side of the tentacle protocol, built before the boot
	// server, which asks it where each rack's images are staged.
	var tapi *Tentacles
	if c.TentacleListen != "" {
		tapi = &Tentacles{Overlays: ov, CA: sec.ca, Tickets: sec.tickets, Tokens: sec.tokens, Windows: windows,
			Racks: slices.Sorted(maps.Keys(c.Tentacles)), NodeCertTTL: time.Duration(c.NodeCertTTL), Artifacts: staging.Store{Dir: c.ArtifactDir()}}
		if len(c.TentacleBoot) > 0 {
			tapi.Boot = &BootImages{Images: images, Files: files, Store: tapi.Artifacts, Notify: ov.Bump, Logf: logf, Signing: signing}
		}
	}

	boot := &Boot{Store: st, Base: secureBase, AgentURL: agentURL, Files: files, Images: images, Tickets: sec.tickets,
		DHCPArms: windows.DHCP, Tokens: sec.tokens, Tentacles: c.Tentacles, RackBoot: c.TentacleBoot, Signing: signing}
	if tapi != nil && tapi.Boot != nil {
		boot.Staged = tapi.ServesImage
		tapi.Scripts = boot
	}

	// Plain HTTP, only when configured: the iPXE binaries and nothing else.
	if c.PlainHTTP {
		addr := net.JoinHostPort(ip.String(), strconv.Itoa(c.HTTPPort))
		if err := serve("http", addr, boot.FirmwareHandler(), nil); err != nil {
			return err
		}
		logf("http: serving only the iPXE binaries on %s (plainHTTP)", firmwareBase)
	}

	// HTTPS boot: scripts, iPXE binaries and images (with tokens).
	bootCert, err := pki.FileCert(filepath.Join(c.PKIDir, pki.BootCertFile), filepath.Join(c.PKIDir, pki.BootKeyFile))
	if err != nil {
		return fmt.Errorf("boot TLS: %w (run flapjack pki init --boot-address %s)", err, ip)
	}
	bootCA, err := pki.ParseCertFile(filepath.Join(c.PKIDir, pki.BootCACertFile))
	if err != nil {
		return fmt.Errorf("boot TLS: %w", err)
	}
	bootCert = pki.WithIssuer(bootCert, bootCA) // iPXE needs the root in the chain
	if err := serve("https", net.JoinHostPort(ip.String(), strconv.Itoa(c.HTTPSPort)), boot.Handler(), pki.BootServerConfig(bootCert)); err != nil {
		return err
	}
	logf("https: serving signed boot scripts and images on %s", secureBase)

	// Agents of racks without a tentacle: mTLS, node certificates.
	headCert, err := pki.FileCert(filepath.Join(c.PKIDir, pki.HeadCertFile), filepath.Join(c.PKIDir, pki.HeadKeyFile))
	if err != nil {
		return fmt.Errorf("agents: %w", err)
	}
	agents := &HeadAgents{Overlays: ov, CA: sec.ca, Tickets: sec.tickets, Windows: windows, NodeCertTTL: time.Duration(c.NodeCertTTL), Tentacles: c.Tentacles}
	if err := serve("agents", net.JoinHostPort(ip.String(), strconv.Itoa(c.AgentPort)), agents.Handler(),
		pki.ServerConfig(headCert, sec.ca.Pool, agents.Allow, true)); err != nil {
		return err
	}
	logf("agents: listening on %s (mTLS)", agentURL)

	// Tentacles: the head's side of the fan-out control plane.
	if c.TentacleListen != "" {
		if err := serve("tentacles", c.TentacleListen, tapi.Handler(), pki.ServerConfig(headCert, sec.ca.Pool, tapi.Allow, false)); err != nil {
			return err
		}
		logf("tentacles: listening on %s (mTLS) for racks %s", c.TentacleListen, strings.Join(tapi.Racks, ", "))
	}

	// Power loss, for armed windows: the BMCs say when nodes power on.
	switch {
	case c.BMC != nil && !windows.DHCP:
		drivers, err := RedfishDrivers(*c.BMC, logf)
		if err != nil {
			return fmt.Errorf("bmc: %w", err)
		}
		pw := &PowerWatch{Windows: windows, Every: time.Duration(c.BMC.Poll), Driver: drivers, Logf: logf}
		go pw.Run(ctx)
		logf("bmc watch: reading power state every %s", time.Duration(c.BMC.Poll))
	case !windows.DHCP:
		logf("boot: bootWindow armed with no bmc settings: after a power loss, nodes wait for flapjack node boot")
	}

	// API: TLS, and a cluster certificate (admin or node) on every request.
	apiTLS, err := tlsutil.Server(c.API.TLSCert, c.API.TLSKey, c.API.ClientCA)
	if err != nil {
		return fmt.Errorf("api: %w", err)
	}
	api := &apiserver.Server{Store: st, Tokens: tokens, Overlays: ov, RequireCert: true,
		ArmBoot: func(node, actor string) error { return windows.Arm(node, "an admin opened it", actor) },
		Revoked: func(string) { ov.Bump() }}
	if err := serve("api", c.API.Listen, api.Handler(), apiTLS); err != nil {
		return err
	}
	logf("api: listening on https://%s (mTLS)", c.API.Listen)

	select {
	case <-ctx.Done():
		logf("shutting down")
		return nil
	case err := <-errc:
		return err
	}
}

// Timeouts bounds how long a client may take to send a request and how
// long an idle connection is kept, so slow or idle clients cannot pin the
// listeners' goroutines. Responses have no limit: long-polls wait minutes
// and images take as long as they take.
func Timeouts(srv *http.Server) {
	srv.ReadHeaderTimeout = 10 * time.Second
	srv.ReadTimeout = 2 * time.Minute // a tentacle's 32 MiB status batch at ~2 Mbit/s
	srv.IdleTimeout = 2 * time.Minute
	srv.MaxHeaderBytes = 64 << 10
}

// armBoot opens mac's boot-ticket window when DHCP has just pointed its
// iPXE at a boot script: a network boot is under way. PXE firmware's own
// DHCP (which gets an iPXE binary) and an OS renewing its lease do not.
func armBoot(t *attest.Tickets, mac net.HardwareAddr, file string) {
	if t != nil && strings.HasSuffix(file, ".ipxe") {
		t.Arm(mac.String())
	}
}

// security is what the head's PKI directory provides.
type security struct {
	ca      *pki.CA
	signer  *pki.Signer
	tickets *attest.Tickets
	tokens  *attest.ImageTokens
}

// loadSecurity reads the PKI directory if it has been initialised. Boot
// TLS and tentacles need it; without them it is optional, and the head
// then serves unsigned generations as before.
func loadSecurity(c Config) (security, error) {
	var s security
	if !pki.Exists(c.PKIDir) {
		return s, fmt.Errorf("%s has no cluster CA: run flapjack pki init", c.PKIDir)
	}
	p := func(f string) string { return filepath.Join(c.PKIDir, f) }
	var err error
	if s.ca, err = pki.LoadCA(p(pki.CACertFile), p(pki.CAKeyFile)); err != nil {
		return s, err
	}
	key, err := pki.LoadSigningKey(p(pki.GenKeyFile))
	if err != nil {
		return s, err
	}
	s.signer = &pki.Signer{Key: key, Floor: filepath.Join(c.DataDir, "generation-issued.floor")}
	tk, err := os.ReadFile(p(pki.TicketKeyFile))
	if err != nil {
		return s, err
	}
	s.tickets = &attest.Tickets{Key: tk, TTL: 15 * time.Minute, Armed: true,
		UsedFile: filepath.Join(c.DataDir, "tickets-used.json")}
	s.tokens = &attest.ImageTokens{Key: attest.DeriveImageKey(tk)}
	return s, nil
}

// waitForInterface finds the interface holding ip, waiting for the network
// to come up (systemd's network-online.target is not always enough).
func waitForInterface(ctx context.Context, name string, ip net.IP, logf func(string, ...any)) (string, error) {
	deadline := time.Now().Add(2 * time.Minute)
	for warned := false; ; {
		ifs, err := net.Interfaces()
		if err != nil {
			return "", err
		}
		for _, i := range ifs {
			if name != "" && i.Name != name {
				continue
			}
			addrs, _ := i.Addrs()
			for _, a := range addrs {
				if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
					return i.Name, nil
				}
			}
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("no interface has address %s; configure the provisioning network first", ip)
		}
		if !warned {
			logf("waiting for an interface with address %s", ip)
			warned = true
		}
		select {
		case <-ctx.Done():
			return "", errors.New("cancelled")
		case <-time.After(time.Second):
		}
	}
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (s *statusWriter) WriteHeader(code int) {
	s.code = code
	s.ResponseWriter.WriteHeader(code)
}

func logRequests(h http.Handler, logf func(string, ...any)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, code: 200}
		h.ServeHTTP(sw, r)
		quiet := r.Header.Get("Range") != "" || strings.HasPrefix(r.URL.Path, "/agent/") || strings.HasPrefix(r.URL.Path, "/v1/")
		if !quiet || sw.code >= 400 {
			logf("http: %s %s %s %d", r.RemoteAddr, r.Method, redactTokens(r.URL.Path), sw.code)
		}
	})
}

// redactTokens hides the image token in an /images/<version>/<token>/
// path: logs are not where capabilities belong, even short-lived ones.
func redactTokens(path string) string {
	i := strings.Index(path, "/images/")
	if i < 0 {
		return path
	}
	parts := strings.SplitN(path[i+len("/images/"):], "/", 3)
	if len(parts) < 3 {
		return path
	}
	return path[:i] + "/images/" + parts[0] + "/…/" + parts[2]
}
