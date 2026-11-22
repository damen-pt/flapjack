package server

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"text/template"
	"time"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/attest"
	"github.com/damen-pt/flapjack/internal/events"
	"github.com/damen-pt/flapjack/internal/store"
)

// Boot serves the provisioning network's boot over HTTPS: each node's
// signed iPXE script, iPXE binaries for UEFI HTTPS boot, and images.
// Nothing here is served over plain HTTP (FirmwareHandler offers only the
// iPXE binaries there, when configured). A node's script is only served
// to the address reserved for it; image files only with a token minted
// into that node's script during its boot window, from that address.
type Boot struct {
	Store *store.Store
	Base  string // the HTTPS boot base, "https://10.99.0.1"
	// AgentURL is where agents of racks without a tentacle reach the head
	// over mTLS ("https://10.99.0.1:8443").
	AgentURL string
	// Tickets puts a single-use boot ticket for the boot MAC on each
	// script's kernel command line, so the node can enroll for a
	// certificate. Tickets.Armed is always set: a ticket (and image
	// tokens) are only issued inside a boot window.
	Tickets *attest.Tickets
	// DHCPArms says a DHCP answer for a node's iPXE opens its boot window
	// (bootWindow "dhcp"); otherwise only Arm callers do ("armed").
	DHCPArms bool
	Tokens   *attest.ImageTokens
	// Tentacles maps rack → the tentacle URL its nodes use.
	Tentacles map[string]string
	// RackBoot maps rack → its tentacle's HTTPS boot base
	// ("https://10.1.1.1"). A node boots its kernel, initrd and root
	// filesystem from there when Staged says the tentacle holds that
	// image version, and from the head if the tentacle does not answer.
	RackBoot map[string]string
	Staged   func(rack, version string) bool
	// Signing signs every script and serves signatures for each image
	// version's kernel and initrd, which scripts imgverify, and puts the
	// root filesystem's digest on the command line.
	Signing *BootSigner
	Files   *os.Root // iPXE binaries
	Images  *os.Root // <image>/{vmlinuz,initrd.img,rootfs.squashfs}
	// Retry is how long a node with no bootable image waits before asking
	// again (default 30s). Nodes keep polling, so building the image is
	// enough to boot them.
	Retry time.Duration

	mu      sync.Mutex
	waiting map[string]string // node → reason last logged
}

// Handler returns the HTTPS routes.
func (b *Boot) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /boot/{file}", func(w http.ResponseWriter, r *http.Request) {
		file := r.PathValue("file")
		if mac, ok := strings.CutSuffix(file, ".ipxe.sig"); ok {
			b.scriptSig(w, r, strings.ReplaceAll(mac, "-", ":"))
			return
		}
		if mac, ok := strings.CutSuffix(file, ".ipxe"); ok {
			b.script(w, r, strings.ReplaceAll(mac, "-", ":"))
			return
		}
		serveFirmware(w, r, b.Files, file)
	})
	mux.HandleFunc("GET /images/{image}/{token}/{file}", func(w http.ResponseWriter, r *http.Request) {
		image, file := r.PathValue("image"), r.PathValue("file")
		if !ImageAllowed(w, r, b.Tokens, image) {
			return
		}
		if f, ok := strings.CutSuffix(file, ".sig"); ok {
			b.imageSig(w, r, image, f)
			return
		}
		if !slices.Contains(BootFiles, file) {
			http.NotFound(w, r)
			return
		}
		ServeFile(w, r, b.Images, image+"/"+file)
	})
	return mux
}

// FirmwareHandler serves only the iPXE binaries, for plainHTTP: firmware
// that cannot do HTTPS fetches iPXE here, and iPXE then verifies
// everything else. Scripts, images and agents are never served on it.
func (b *Boot) FirmwareHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /boot/{file}", func(w http.ResponseWriter, r *http.Request) {
		serveFirmware(w, r, b.Files, r.PathValue("file"))
	})
	return mux
}

func serveFirmware(w http.ResponseWriter, r *http.Request, files *os.Root, name string) {
	if !IsFirmware(name) {
		http.NotFound(w, r)
		return
	}
	ServeFile(w, r, files, name)
}

// ImageAllowed checks the request's image token against its source
// address, answering 403 when it does not hold.
func ImageAllowed(w http.ResponseWriter, r *http.Request, tokens *attest.ImageTokens, version string) bool {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if tokens == nil {
		http.Error(w, "images are not served here", http.StatusForbidden)
		return false
	}
	if err := tokens.Check(r.PathValue("token"), version, net.ParseIP(host)); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return false
	}
	return true
}

// ServeFile serves one regular file from root, with Range support (iPXE
// and dracut resume large downloads) and no directory listings.
func ServeFile(w http.ResponseWriter, r *http.Request, root *os.Root, name string) {
	if !fs.ValidPath(name) {
		http.NotFound(w, r)
		return
	}
	f, err := root.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, st.Name(), st.ModTime(), f)
}

// scriptTmpl is a node's iPXE script. The boot path starts with imgfree:
// iPXE's UEFI build hands the kernel every image it still holds as one
// initrd, and this script (and an autoexec.ipxe, or the embedded
// verifier's copy) would come first and break the kernel's initramfs
// unpacking. A running script survives being freed.
var scriptTmpl = template.Must(template.New("ipxe").Parse(`#!ipxe
{{- if .Wait}}
echo flapjack: {{.Node}}: {{.Wait}}
echo flapjack: asking again in {{.RetrySeconds}}s
sleep {{.RetrySeconds}}
{{- if .Redhcp}}
dhcp ||
{{- end}}
imgfetch --name next {{.Self}} && imgverify next {{.Self}}.sig && chain --replace --autofree next || reboot
{{- else if .Exit}}
echo flapjack: {{.Node}}: {{.Exit}}
exit 1
{{- else}}
echo flapjack: booting {{.Node}} (class {{.Class}}, image {{.Image}})
imgfree
{{- if .RackURL}}
kernel {{.RackURL}}/vmlinuz initrd=initrd.img {{.RackCmdline}} && initrd {{.RackURL}}/initrd.img && imgverify vmlinuz {{.RackURL}}/vmlinuz.sig && imgverify initrd.img {{.RackURL}}/initrd.img.sig && boot ||
echo flapjack: rack image cache did not answer; booting from the head
imgfree
{{- end}}
{{- if .ImageURL}}
kernel {{.ImageURL}}/vmlinuz initrd=initrd.img {{.Cmdline}}
initrd {{.ImageURL}}/initrd.img
imgverify vmlinuz {{.ImageURL}}/vmlinuz.sig
imgverify initrd.img {{.ImageURL}}/initrd.img.sig
boot
{{- else}}
reboot
{{- end}}
{{- end}}
`))

type scriptData struct {
	Node, Class, Image, ImageURL, Cmdline, Self string
	RackURL, RackCmdline                        string
	Wait, Exit                                  string
	RetrySeconds                                int
	Redhcp                                      bool // re-run DHCP before asking again: it opens a window
}

func (b *Boot) script(w http.ResponseWriter, r *http.Request, mac string) {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	n, iface, ok := b.Store.NodeByMAC(hw.String())
	if !ok {
		http.NotFound(w, r)
		return
	}
	// Only the address DHCP gave this MAC may read its script: one node
	// cannot fetch another's boot parameters.
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !net.ParseIP(host).Equal(net.ParseIP(iface.IP)) {
		http.Error(w, "this script belongs to another address", http.StatusForbidden)
		return
	}
	b.writeScript(w, n, hw, net.ParseIP(iface.IP), b.Base, false)
}

// RackScript writes the script for a node of a rack whose tentacle runs
// its DHCP and serves its boot: everything points at the tentacle (the
// node cannot reach the head), and a version the tentacle has not staged
// yet makes the node wait rather than fall back. window says the
// tentacle's DHCP just answered this MAC's iPXE, which opens the node's
// boot window here when windows follow DHCP.
func (b *Boot) RackScript(w http.ResponseWriter, n v1.Node, hw net.HardwareAddr, window bool) {
	base := b.RackBoot[n.Rack]
	if base == "" {
		http.Error(w, "rack "+n.Rack+" has no tentacleBoot URL", http.StatusConflict)
		return
	}
	_, iface, ok := b.Store.NodeByMAC(hw.String())
	if !ok {
		http.Error(w, "unknown MAC", http.StatusNotFound)
		return
	}
	if window && b.DHCPArms {
		b.Tickets.Arm(hw.String())
	}
	b.writeScript(w, n, hw, net.ParseIP(iface.IP), base, true)
}

func (b *Boot) writeScript(w http.ResponseWriter, n v1.Node, hw net.HardwareAddr, ip net.IP, base string, rackOnly bool) {
	retry := b.Retry
	if retry == 0 {
		retry = 30 * time.Second
	}
	d := scriptData{Node: n.Name, Class: n.Class, RetrySeconds: int(retry / time.Second),
		Self: fmt.Sprintf("%s/boot/%s.ipxe", base, strings.ReplaceAll(hw.String(), ":", "-"))}
	if n.Status.Phase == v1.PhaseRetired {
		d.Exit = "node is retired"
	} else if c, err := b.Store.Class(n.Class); err != nil {
		d.Wait = fmt.Sprintf("class %q does not exist", n.Class)
	} else if c.Image == "" {
		d.Wait = fmt.Sprintf("class %q has no image", c.Name)
	} else if missing := b.missing(c.Image); missing != "" {
		d.Wait = fmt.Sprintf("image %q is not built (no %s)", c.Image, missing)
	} else if dir := ResolveImage(b.Images, c.Image); rackOnly && (b.Staged == nil || !b.Staged(n.Rack, dir)) {
		d.Wait = fmt.Sprintf("image %s is being staged to rack %s", dir, n.Rack)
	} else if ticket, err := b.Tickets.Issue(hw.String()); errors.Is(err, attest.ErrNotArmed) {
		// Outside a boot window (or this window's script was already
		// served): no ticket and no image tokens, so nothing to boot.
		d.Wait = "no boot window is open"
		if b.DHCPArms {
			d.Redhcp = true
		} else {
			d.Wait += " (bootWindow armed: flapjack node boot " + n.Name + ")"
		}
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else {
		// Pin the version the image link points at now, so a rebuild during
		// boot cannot mix one version's kernel with another's rootfs.
		d.Image = dir
		staged := !rackOnly && b.RackBoot[n.Rack] != "" && b.Staged != nil && b.Staged(n.Rack, dir)
		var url string
		if rackOnly || staged {
			tok, err := b.Tokens.For(n.Rack).Mint(dir, ip)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			d.RackURL = b.RackBoot[n.Rack] + "/images/" + dir + "/" + tok
			url = d.RackURL
		}
		if !rackOnly {
			tok, err := b.Tokens.Mint(dir, ip)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			d.ImageURL = base + "/images/" + dir + "/" + tok
			url = d.ImageURL
		}
		args, err := b.cmdline(n, c, dir, hw, url, ticket)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		d.Cmdline = strings.Join(args, " ")
		switch {
		case rackOnly:
			// The rack URL is the only one: it is the script's main path.
			d.ImageURL, d.RackURL = d.RackURL, ""
		case staged:
			// Same arguments (and the same single ticket); only where the
			// root filesystem comes from changes.
			d.RackCmdline = strings.Replace(d.Cmdline, "root=live:"+d.ImageURL+"/", "root=live:"+d.RackURL+"/", 1)
		}
	}
	var buf bytes.Buffer
	if err := scriptTmpl.Execute(&buf, d); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Signed before it leaves the head: a tentacle relaying it, or
	// anything on the path, cannot change a word without iPXE (built with
	// the embedded verifying script) refusing it.
	if err := b.Signing.SignScript(hw.String(), buf.Bytes()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write(buf.Bytes())
	b.record(n.Name, d)
}

// missing returns the first boot file the image lacks, or "".
func (b *Boot) missing(image string) string {
	if strings.Contains(image, "/") || !fs.ValidPath(image) {
		return "valid name"
	}
	for _, f := range []string{"vmlinuz", "initrd.img"} {
		if st, err := b.Images.Stat(image + "/" + f); err != nil || !st.Mode().IsRegular() {
			return f
		}
	}
	return ""
}

func (b *Boot) cmdline(n v1.Node, c v1.NodeClass, dir string, mac net.HardwareAddr, imageURL, ticket string) ([]string, error) {
	args := []string{
		// Configure the boot NIC by MAC, whatever the kernel names it.
		"BOOTIF=01-" + strings.ReplaceAll(mac.String(), ":", "-"), "ip=dhcp", "rd.neednet=1",
	}
	if _, err := b.Images.Stat(dir + "/rootfs.squashfs"); err == nil {
		// dracut's livenet module downloads the image into RAM and puts a
		// writable overlay on top: the node runs entirely from memory.
		args = append(args, "root=live:"+imageURL+"/rootfs.squashfs", "rd.live.overlay.overlayfs=1")
	}
	args = append(args, "flapjack.node="+n.Name, "flapjack.generation="+v1.GenerationOf(c).Digest())
	if t, ok := b.Tentacles[n.Rack]; ok {
		args = append(args, "flapjack.tentacle="+t, "flapjack.rack="+n.Rack)
	} else {
		args = append(args, "flapjack.server="+b.AgentURL)
	}
	// The initrd (signed, so genuine) refuses a root filesystem that does
	// not hash to this before switching to it.
	_, rootfs, err := b.Signing.Version(dir)
	if err != nil {
		return nil, err
	}
	if rootfs != "" {
		args = append(args, "flapjack.rootfs="+rootfs)
	}
	// /proc/cmdline is world-readable on the node, but the ticket is
	// single-use and the agent spends it before any user logs in, and the
	// image token only reads this image from this address.
	args = append(args, "flapjack.mac="+mac.String(), "flapjack.ticket="+ticket)
	return append(args, c.BootArgs...), nil
}

// record logs boots, and waits once per reason, so a node polling for an
// image every 30 seconds does not flood the event log.
func (b *Boot) record(node string, d scriptData) {
	if b.Store.Events == nil {
		return
	}
	reason := d.Wait + d.Exit
	b.mu.Lock()
	if b.waiting == nil {
		b.waiting = map[string]string{}
	}
	repeat := reason != "" && b.waiting[node] == reason
	b.waiting[node] = reason
	b.mu.Unlock()
	if repeat {
		return
	}
	e := events.Event{Node: node, Category: events.Boot, Type: "boot.script", Actor: "flapjack-server",
		Data: map[string]string{"image": d.Image}}
	switch {
	case strings.HasPrefix(d.Wait, "no boot window"):
		e.Type, e.Message = "boot.window_closed", "boot script fetched outside a boot window: no ticket or image tokens"
	case d.Wait != "":
		e.Type, e.Message = "boot.waiting", d.Wait
	case d.Exit != "":
		e.Type, e.Message = "boot.refused", d.Exit
	default:
		e.Message = "booting image " + d.Image
	}
	b.event(e)
}

func (b *Boot) event(e events.Event) {
	if b.Store.Events == nil {
		return
	}
	if err := b.Store.Events.Append(e); err != nil && !errors.Is(err, os.ErrClosed) {
		fmt.Fprintln(os.Stderr, "event log:", err)
	}
}
