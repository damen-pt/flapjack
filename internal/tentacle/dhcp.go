package tentacle

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/damen-pt/flapjack/internal/dhcp"
	"github.com/damen-pt/flapjack/internal/server"
	"github.com/damen-pt/flapjack/internal/staging"
	"github.com/damen-pt/flapjack/internal/tftp"
)

// A tentacle can run its rack's DHCP, and so its whole boot: the rack's
// firmware gets iPXE from the tentacle (TFTP or HTTPS), iPXE gets its
// script from the tentacle over HTTPS, and the script points at images
// the tentacle has staged. Nodes never reach the head.
//
// Reservations come from the rack snapshot, so the tentacle keeps
// answering DHCP from its last snapshot while the head is away. Scripts
// still come from the head, which issues boot tickets: a running rack
// carries on without the head, but a rebooting node waits for it.

// BootWindow is how long a boot window stays open after DHCP answers a
// MAC's iPXE.
const BootWindow = 2 * time.Minute

// DHCPServer returns a DHCP server answering this rack's nodes on subnet,
// as serverIP. httpBase serves iPXE binaries to UEFI HTTP-boot firmware
// (the HTTPS boot listener unless plainHTTP is on); scriptBase is this
// tentacle's HTTPS boot listener. Only interfaces whose reserved address is in
// subnet are answered, so a node's other networks stay the business of
// their own DHCP.
func (t *Tentacle) DHCPServer(serverIP net.IP, subnet *net.IPNet, httpBase, scriptBase string) *dhcp.Server {
	t.init()
	return &dhcp.Server{ServerIP: serverIP, Mask: subnet.Mask, HTTPBase: httpBase, ScriptBase: scriptBase,
		Lookup: func(mac net.HardwareAddr) (dhcp.Lease, bool) {
			name, ip, ok := t.lease(mac.String())
			if !ok || !subnet.Contains(ip) {
				return dhcp.Lease{}, false
			}
			return dhcp.Lease{Node: name, IP: ip, Hostname: name}, true
		},
		OnLease: func(l dhcp.Lease, mac net.HardwareAddr, msg byte, file string) {
			if msg == dhcp.Ack && strings.HasSuffix(file, ".ipxe") {
				t.openWindow(mac.String())
				t.logf("tentacle %s: dhcp: %s %s → %s, boot window open", t.Rack, l.Node, mac, l.IP)
			}
		},
		OnUnknown: func(mac net.HardwareAddr, p *dhcp.Packet) {
			if _, _, known := t.lease(mac.String()); known {
				return // a rack node's NIC on another network
			}
			t.logf("tentacle %s: dhcp: ignoring unknown MAC %s", t.Rack, mac)
		},
	}
}

// lease finds the node and reserved address for mac in the snapshot.
func (t *Tentacle) lease(mac string) (string, net.IP, bool) {
	mac = strings.ToLower(mac)
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, n := range t.nodes {
		for _, i := range n.Interfaces {
			if i.MAC == mac {
				ip := net.ParseIP(i.IP).To4()
				return n.Name, ip, ip != nil
			}
		}
	}
	return "", nil, false
}

// fromNode checks r came from one of node's reserved addresses: a 403 if
// it did not, a 503 (the agent retries) while the tentacle does not know
// the node yet, before its first snapshot or one listing a new node.
func (t *Tentacle) fromNode(r *http.Request, node string) (int, string) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	from := net.ParseIP(host)
	n, ok := t.lookup(node)
	if !ok {
		return http.StatusServiceUnavailable, "this tentacle has no node " + node + " (yet)"
	}
	for _, i := range n.Interfaces {
		if from != nil && net.ParseIP(i.IP).Equal(from) {
			return http.StatusOK, ""
		}
	}
	return http.StatusForbidden, "a boot ticket for " + node + " is only good from its own address"
}

func (t *Tentacle) openWindow(mac string) {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.windows == nil {
		t.windows = map[string]time.Time{}
	}
	for m, e := range t.windows {
		if now.After(e) {
			delete(t.windows, m)
		}
	}
	t.windows[strings.ToLower(mac)] = now.Add(BootWindow)
}

// takeWindow closes mac's boot window, reporting whether one was open.
func (t *Tentacle) takeWindow(mac string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	k := strings.ToLower(mac)
	e, ok := t.windows[k]
	delete(t.windows, k)
	return ok && time.Now().Before(e)
}

// script relays a node's iPXE script from the head. Like the head, it
// serves a MAC's script only to the address reserved for that MAC.
func (t *Tentacle) script(w http.ResponseWriter, r *http.Request, macKey string) {
	hw, err := net.ParseMAC(strings.ReplaceAll(macKey, "-", ":"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	_, ip, ok := t.lease(hw.String())
	if !ok {
		http.NotFound(w, r)
		return
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !net.ParseIP(host).Equal(ip) {
		http.Error(w, "this script belongs to another address", http.StatusForbidden)
		return
	}
	window := t.takeWindow(hw.String())
	q := "0"
	if window {
		q = "1"
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, t.Head+"/tentacle/v1/boot/"+hw.String()+"?window="+q, nil)
	resp, err := t.Up.Do(req)
	if err != nil {
		if window {
			t.openWindow(hw.String()) // iPXE will retry within this boot
		}
		http.Error(w, "head unreachable: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && window {
		t.openWindow(hw.String())
	}
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, io.LimitReader(resp.Body, 64<<10))
}

// FirmwareHandler serves staged iPXE binaries at /boot/<file> over plain
// HTTP (plainHTTP), for UEFI HTTP-boot firmware that cannot do HTTPS.
// Nothing else is served on it: scripts and images are HTTPS only.
func (t *Tentacle) FirmwareHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /boot/{file}", func(w http.ResponseWriter, r *http.Request) {
		t.serveFirmware(w, r, r.PathValue("file"))
	})
	return mux
}

func (t *Tentacle) serveFirmware(w http.ResponseWriter, r *http.Request, f string) {
	if t.Firmware == "" || !server.IsFirmware(f) {
		http.NotFound(w, r)
		return
	}
	os.MkdirAll(t.Firmware, 0o755)
	root, err := os.OpenRoot(t.Firmware)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer root.Close()
	server.ServeFile(w, r, root, f)
}

// stageFirmware makes the Firmware directory hold exactly the iPXE
// binaries the head lists, each verified against its manifest.
func (t *Tentacle) stageFirmware(ctx context.Context, want []staging.Manifest) {
	if err := os.MkdirAll(t.Firmware, 0o755); err != nil {
		t.logf("tentacle %s: firmware: %v", t.Rack, err)
		return
	}
	keep := map[string]bool{}
	f := staging.Fetcher{Store: t.Artifacts, Client: t.Up, Parallel: max(t.Parallel, 4),
		Sources: []staging.Source{{Name: "head", URL: t.Head + "/tentacle/v1", Tier: staging.TierOrigin}}}
	for _, m := range want {
		if !server.IsFirmware(m.Name) {
			continue
		}
		keep[m.Name] = true
		dest := filepath.Join(t.Firmware, m.Name)
		if staging.Fresh(m, dest) {
			continue
		}
		if _, _, err := staging.Ensure(ctx, f, m, dest); err != nil {
			if ctx.Err() == nil {
				t.logf("tentacle %s: staging %s: %v", t.Rack, m.Name, err)
			}
			continue
		}
		os.Chmod(dest, 0o644)
		t.logf("tentacle %s: staged %s (%d bytes)", t.Rack, m.Name, m.Size)
	}
	ents, _ := os.ReadDir(t.Firmware)
	for _, e := range ents {
		name := e.Name()
		// Ensure's stamp and lock files are .<name>.flapjack and .<name>.lock.
		owner := strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(name, "."), ".flapjack"), ".lock")
		if !keep[name] && !(strings.HasPrefix(name, ".") && keep[owner]) {
			os.RemoveAll(filepath.Join(t.Firmware, name))
		}
	}
}

func (t *Tentacle) String() string { return fmt.Sprintf("tentacle %s", t.Rack) }

// serveDHCP starts the rack's DHCP and TFTP servers, and the plain-HTTP
// iPXE server if plainHTTP is on.
func serveDHCP(c Config, t *Tentacle, errc chan<- error, logf func(string, ...any),
	plain func(name, addr string, h http.Handler) error) ([]io.Closer, error) {
	d := c.DHCP
	ip, subnet, _ := net.ParseCIDR(d.Address)
	ip = ip.To4()
	scriptBase := "https://" + c.BootListen
	if h, p, _ := net.SplitHostPort(c.BootListen); p == "443" {
		scriptBase = "https://" + h
	}
	httpAddr := net.JoinHostPort(ip.String(), strconv.Itoa(d.HTTPPort))
	httpBase := scriptBase // UEFI HTTPS boot fetches iPXE from the boot listener
	if d.PlainHTTP {
		httpBase = "http://" + ip.String()
		if d.HTTPPort != 80 {
			httpBase = "http://" + httpAddr
		}
	}
	var closers []io.Closer
	ds := t.DHCPServer(ip, subnet, httpBase, scriptBase)
	if d.Router != "" {
		ds.Router = net.ParseIP(d.Router)
	}
	for _, s := range d.DNS {
		ds.DNS = append(ds.DNS, net.ParseIP(s))
	}
	ds.Domain = d.Domain
	if d.LeaseTime != "" {
		ds.LeaseTime, _ = time.ParseDuration(d.LeaseTime)
	}
	conn, err := dhcp.Listen(d.Interface)
	if err != nil {
		return closers, fmt.Errorf("dhcp: %w", err)
	}
	closers = append(closers, conn)
	go func() { errc <- fmt.Errorf("dhcp: %w", ds.Serve(conn)) }()
	logf("tentacle %s: dhcp on %s (%s); scripts from %s", c.Rack, d.Interface, d.Address, scriptBase)

	if err := os.MkdirAll(t.Firmware, 0o755); err != nil {
		return closers, err
	}
	if *d.TFTP {
		root, err := os.OpenRoot(t.Firmware)
		if err != nil {
			return closers, err
		}
		closers = append(closers, root)
		tconn, err := net.ListenPacket("udp4", net.JoinHostPort(ip.String(), "69"))
		if err != nil {
			return closers, fmt.Errorf("tftp: %w", err)
		}
		closers = append(closers, tconn)
		ts := &tftp.Server{Root: root, Allow: server.IsFirmware, OnRead: func(remote net.Addr, file string, size int64, err error) {
			if err != nil {
				logf("tentacle %s: tftp: %s %s: %v", c.Rack, remote, file, err)
			}
		}}
		go func() { errc <- fmt.Errorf("tftp: %w", ts.Serve(tconn)) }()
		logf("tentacle %s: tftp on %s:69", c.Rack, ip)
	}
	if !d.PlainHTTP {
		return closers, nil
	}
	return closers, plain("ipxe", httpAddr, t.FirmwareHandler())
}

// scriptSig relays the head's signature over the script it last wrote
// for a MAC. The tentacle holds no signing key: altering the script
// breaks this signature, and iPXE refuses it.
func (t *Tentacle) scriptSig(w http.ResponseWriter, r *http.Request, macKey string) {
	hw, err := net.ParseMAC(strings.ReplaceAll(macKey, "-", ":"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	_, ip, ok := t.lease(hw.String())
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !ok || !net.ParseIP(host).Equal(ip) {
		http.Error(w, "this signature belongs to another address", http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, t.Head+"/tentacle/v1/boot/"+hw.String()+".sig", nil)
	resp, err := t.Up.Do(req)
	if err != nil {
		http.Error(w, "head unreachable: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/pkcs7-signature")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, io.LimitReader(resp.Body, 64<<10))
}
