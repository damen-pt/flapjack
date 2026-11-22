// Package server is the long-running Flapjack service on a head node: DHCP,
// TFTP and HTTP boot on the provisioning network, plus the API.
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Config is /etc/flapjack/server.json.
type Config struct {
	// Address is the head node's address on the provisioning network, with
	// its prefix ("10.99.0.1/16"). DHCP, TFTP, HTTPS boot and the agent
	// listener are here.
	Address string `json:"address"`
	// Interface carrying Address; found automatically when empty.
	Interface string   `json:"interface,omitempty"`
	Router    string   `json:"router,omitempty"` // default gateway for nodes; none when empty
	DNS       []string `json:"dns,omitempty"`
	Domain    string   `json:"domain,omitempty"`
	LeaseTime Duration `json:"leaseTime,omitempty"`
	// PlainHTTP serves the iPXE binaries (and nothing else) over plain
	// HTTP on HTTPPort (default 80), for UEFI HTTP-boot firmware that
	// cannot do HTTPS. Off by default: scripts, images and agents are
	// only ever served over TLS.
	PlainHTTP bool   `json:"plainHTTP,omitempty"`
	HTTPPort  int    `json:"httpPort,omitempty"`
	TFTP      *bool  `json:"tftp,omitempty"`    // iPXE binaries for PXE ROMs; default true
	DataDir   string `json:"dataDir,omitempty"` // default /var/lib/flapjack

	API APIConfig `json:"api"`

	// OverlayDir holds one directory per overlay; SecretsDir whole-file
	// secrets overlays reference by name; FilesDir shared files templates
	// may Include. Defaults: /etc/flapjack/{overlays,secrets,files}.
	OverlayDir string    `json:"overlayDir,omitempty"`
	SecretsDir string    `json:"secretsDir,omitempty"`
	FilesDir   string    `json:"filesDir,omitempty"`
	Nix        NixConfig `json:"nix,omitempty"`

	// PKIDir holds the cluster CA and keys written by `flapjack pki init`
	// (default /etc/flapjack/pki). Once it exists the head signs every
	// generation it serves and can enroll nodes.
	PKIDir      string   `json:"pkiDir,omitempty"`
	NodeCertTTL Duration `json:"nodeCertTTL,omitempty"` // default 24h

	// Boot scripts and images are served over HTTPS only, on HTTPSPort
	// (default 443), with the boot certificate; every script, kernel and
	// initrd is signed with the boot code-signing key and verified by
	// iPXE, and the root filesystem's digest goes on the command line for
	// the initrd to check. Nodes need an iPXE built with
	// TRUST=<pkiDir>/boot-ca.pem, EMBED=<pkiDir>/ipxe-embed.ipxe and
	// IMAGE_TRUST_CMD. An image file is only served with a short-lived
	// token minted into that node's script during its boot window, to the
	// address the token names.
	HTTPSPort int `json:"httpsPort,omitempty"`
	// AgentPort is where node agents reach the head over mTLS (default
	// 8443), to enroll with their boot ticket and then fetch their
	// overlays with their node certificate.
	AgentPort int `json:"agentPort,omitempty"`
	// BootWindow is what opens a node's boot window, the only time its
	// script carries an enrollment ticket and image tokens:
	//   "armed" (default): flapjack power-cycling it through its BMC, its
	//   agent announcing a reboot over mTLS, an admin (flapjack node
	//   boot), or the BMC watcher seeing it power on while its agent is
	//   silent (power loss). A spoofed MAC cannot open one.
	//   "dhcp": its iPXE asking DHCP for a boot script. Anything on the
	//   provisioning network that can send DHCP with a node's MAC and take
	//   its address can then enroll as the node and read its secrets.
	BootWindow string `json:"bootWindow,omitempty"`
	// ArmFor is how long an armed window stays open (default 15m: long
	// enough for server firmware to POST).
	ArmFor Duration `json:"armFor,omitempty"`
	// BMC lets the head watch nodes' power state for bootWindow "armed".
	BMC *BMCConfig `json:"bmc,omitempty"`

	// Removed settings, rejected so an old config cannot silently
	// weaken the head: boot TLS and signed boot are always on, and boot
	// tickets never travel in plaintext.
	BootTLS             *bool `json:"bootTLS,omitempty"`
	SignedBoot          *bool `json:"signedBoot,omitempty"`
	InsecureBootTickets bool  `json:"insecureBootTickets,omitempty"`

	// Tentacles maps each rack to the URL its nodes use to reach that
	// rack's tentacle ("https://10.1.1.1:8443"). Nodes in a listed rack
	// boot with that tentacle and a boot ticket on their command line
	// instead of talking to the head; only listed racks' tentacles may
	// connect.
	Tentacles map[string]string `json:"tentacles,omitempty"`
	// TentacleListen is where the head serves tentacles over mTLS, on
	// the management core ("10.98.0.1:7444").
	TentacleListen string `json:"tentacleListen,omitempty"`
	// TentacleBoot maps a rack to its tentacle's HTTPS boot base
	// ("https://10.1.1.1"). Racks listed here boot their kernel, initrd
	// and root filesystem from the tentacle once it has staged them,
	// falling back to the head. The tentacle needs a boot certificate
	// (flapjack pki issue tentacle RACK --boot-address ...). Signed boot
	// is what stops a tentacle altering what its rack boots.
	TentacleBoot map[string]string `json:"tentacleBoot,omitempty"`
	// TentacleDHCP lists racks whose tentacle runs their DHCP and serves
	// their whole boot (iPXE, scripts, images). The head's DHCP ignores
	// their MACs. Each needs a tentacleBoot entry.
	TentacleDHCP []string `json:"tentacleDHCP,omitempty"`
}

// BMCConfig is how the head reaches nodes' Redfish BMCs.
type BMCConfig struct {
	User         string `json:"user,omitempty"` // default "admin"
	PasswordFile string `json:"passwordFile"`
	// CA signs (or is) the BMCs' certificates. Required: the system trust
	// store is never used for BMCs.
	CA string `json:"ca"`
	// Poll is how often each BMC's power state is read (default 15s).
	Poll Duration `json:"poll,omitempty"`
}

// Boot window modes.
const (
	BootWindowDHCP  = "dhcp"
	BootWindowArmed = "armed"
)

// NixConfig enables the nix overlay engine.
type NixConfig struct {
	Bin     string `json:"bin,omitempty"`     // default /usr/local/bin/nix if present
	Nixpkgs string `json:"nixpkgs,omitempty"` // directory with lib/; default /usr/local/share/flapjack/nixpkgs
}

// APIConfig is the control-plane API listener.
//
// The API is always TLS, and every client must present a cluster
// certificate (an admin's, from flapjack pki issue admin, or a node's) as
// well as a bearer token: a token alone is never enough.
type APIConfig struct {
	Listen string `json:"listen,omitempty"` // default 127.0.0.1:7443
	Tokens string `json:"tokens,omitempty"` // default /etc/flapjack/tokens.json
	// The server certificate; default the head's (pkiDir/head.pem).
	TLSCert string `json:"tlsCert,omitempty"`
	TLSKey  string `json:"tlsKey,omitempty"`
	// ClientCA signs client certificates; default the cluster CA.
	ClientCA string `json:"clientCA,omitempty"`
}

// Duration is a time.Duration written as "1h" in JSON.
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	*d = Duration(v)
	return err
}

// Default paths.
const (
	DefaultConfig  = "/etc/flapjack/server.json"
	DefaultTokens  = "/etc/flapjack/tokens.json"
	DefaultDataDir = "/var/lib/flapjack"
	DefaultAPI     = "127.0.0.1:7443"
)

// LoadConfig reads and validates a config file.
func LoadConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	return c, c.validate()
}

func (c *Config) defaults() {
	if c.DataDir == "" {
		c.DataDir = DefaultDataDir
	}
	if c.HTTPPort == 0 {
		c.HTTPPort = 80
	}
	if c.AgentPort == 0 {
		c.AgentPort = 8443
	}
	if c.BootWindow == "" {
		c.BootWindow = BootWindowArmed
	}
	if c.ArmFor == 0 {
		c.ArmFor = Duration(15 * time.Minute)
	}
	if c.BMC != nil {
		if c.BMC.User == "" {
			c.BMC.User = "admin"
		}
		if c.BMC.Poll == 0 {
			c.BMC.Poll = Duration(15 * time.Second)
		}
	}
	if c.LeaseTime == 0 {
		c.LeaseTime = Duration(time.Hour)
	}
	if c.TFTP == nil {
		t := true
		c.TFTP = &t
	}
	if c.API.Listen == "" {
		c.API.Listen = DefaultAPI
	}
	if c.API.Tokens == "" {
		c.API.Tokens = DefaultTokens
	}
	etc := filepath.Dir(DefaultConfig)
	if c.OverlayDir == "" {
		c.OverlayDir = filepath.Join(etc, "overlays")
	}
	if c.SecretsDir == "" {
		c.SecretsDir = filepath.Join(etc, "secrets")
	}
	if c.FilesDir == "" {
		c.FilesDir = filepath.Join(etc, "files")
	}
	if c.Nix.Bin == "" {
		if _, err := os.Stat("/usr/local/bin/nix"); err == nil {
			c.Nix.Bin = "/usr/local/bin/nix"
		}
	}
	if c.Nix.Nixpkgs == "" {
		c.Nix.Nixpkgs = "/usr/local/share/flapjack/nixpkgs"
	}
	if c.PKIDir == "" {
		c.PKIDir = filepath.Join(etc, "pki")
	}
	if c.HTTPSPort == 0 {
		c.HTTPSPort = 443
	}
	if c.NodeCertTTL == 0 {
		c.NodeCertTTL = Duration(24 * time.Hour)
	}
	if c.API.TLSCert == "" && c.API.TLSKey == "" {
		c.API.TLSCert, c.API.TLSKey = filepath.Join(c.PKIDir, "head.pem"), filepath.Join(c.PKIDir, "head.key")
	}
	if c.API.ClientCA == "" {
		c.API.ClientCA = filepath.Join(c.PKIDir, "ca.pem")
	}
}

func (c *Config) validate() error {
	c.defaults()
	ip, _, err := net.ParseCIDR(c.Address)
	if err != nil || ip.To4() == nil {
		return fmt.Errorf("address %q must be an IPv4 address with prefix, like 10.99.0.1/16", c.Address)
	}
	if c.Router != "" && net.ParseIP(c.Router).To4() == nil {
		return fmt.Errorf("router %q is not an IPv4 address", c.Router)
	}
	for _, d := range c.DNS {
		if net.ParseIP(d).To4() == nil {
			return fmt.Errorf("dns %q is not an IPv4 address", d)
		}
	}
	if (c.API.TLSCert == "") != (c.API.TLSKey == "") {
		return errors.New("api: set both tlsCert and tlsKey, or neither")
	}
	if c.BootTLS != nil && !*c.BootTLS || c.SignedBoot != nil && !*c.SignedBoot {
		return errors.New("bootTLS and signedBoot can no longer be turned off: boot is always HTTPS and signed; remove them")
	}
	if c.InsecureBootTickets {
		return errors.New("insecureBootTickets has been removed: boot tickets only travel over HTTPS")
	}
	switch c.BootWindow {
	case BootWindowDHCP, BootWindowArmed:
	default:
		return fmt.Errorf("bootWindow %q: want %q or %q", c.BootWindow, BootWindowDHCP, BootWindowArmed)
	}
	if c.ArmFor < Duration(time.Minute) {
		return errors.New("armFor must be at least 1m")
	}
	if c.BMC != nil && (c.BMC.PasswordFile == "" || c.BMC.CA == "") {
		return errors.New("bmc: set passwordFile and ca (BMC certificates are never checked against the system trust store)")
	}
	if c.BMC != nil && c.BMC.Poll < Duration(time.Second) {
		return errors.New("bmc: poll must be at least 1s")
	}
	ports := map[int]string{c.HTTPSPort: "httpsPort", c.AgentPort: "agentPort"}
	if len(ports) != 2 || c.PlainHTTP && ports[c.HTTPPort] != "" {
		return errors.New("httpsPort, agentPort and httpPort must differ")
	}
	if len(c.Tentacles) > 0 {
		if c.TentacleListen == "" {
			return errors.New("tentacles: set tentacleListen, the head's address for them")
		}
		if _, _, err := net.SplitHostPort(c.TentacleListen); err != nil {
			return fmt.Errorf("tentacleListen %q: %w", c.TentacleListen, err)
		}
		for rack, u := range c.Tentacles {
			if !strings.HasPrefix(u, "https://") {
				return fmt.Errorf("tentacle for rack %q: %q must be an https:// URL", rack, u)
			}
		}
	}
	for _, rack := range c.TentacleDHCP {
		if _, ok := c.TentacleBoot[rack]; !ok {
			return fmt.Errorf("tentacleDHCP: rack %q needs a tentacleBoot entry: its nodes boot from the tentacle only", rack)
		}
	}
	for rack, u := range c.TentacleBoot {
		if _, ok := c.Tentacles[rack]; !ok {
			return fmt.Errorf("tentacleBoot: rack %q has no entry in tentacles", rack)
		}
		if !strings.HasPrefix(u, "https://") || strings.Count(u, "/") != 2 {
			return fmt.Errorf("tentacleBoot for rack %q: %q must be an https://host[:port] base", rack, u)
		}
	}
	if c.NodeCertTTL < Duration(10*time.Minute) {
		return errors.New("nodeCertTTL must be at least 10m")
	}
	return nil
}

// Paths under DataDir.
func (c Config) statePath() string  { return filepath.Join(c.DataDir, "state.json") }
func (c Config) eventsPath() string { return filepath.Join(c.DataDir, "events.jsonl") }

// BootDir holds iPXE binaries served over TFTP (and plain HTTP if on).
func (c Config) BootDir() string { return filepath.Join(c.DataDir, "boot") }

// ContentDir holds rendered overlay content by digest.
func (c Config) ContentDir() string { return filepath.Join(c.DataDir, "content") }

// GenerationDir holds each node's overlay generations.
func (c Config) GenerationDir() string { return filepath.Join(c.DataDir, "generations") }

// ArtifactDir holds staged-artifact chunks tentacles pre-warm from.
func (c Config) ArtifactDir() string { return filepath.Join(c.DataDir, "artifacts") }

// ImageDir holds one directory per image: vmlinuz, initrd.img and
// optionally rootfs.squashfs.
func (c Config) ImageDir() string { return filepath.Join(c.DataDir, "images") }
