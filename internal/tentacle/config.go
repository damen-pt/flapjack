package tentacle

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/damen-pt/flapjack/internal/pki"
	"github.com/damen-pt/flapjack/internal/server"
	"github.com/damen-pt/flapjack/internal/staging"
)

// DefaultConfig is where `flapjack tentacle` reads its configuration.
const DefaultConfig = "/etc/flapjack/tentacle.json"

// Config is /etc/flapjack/tentacle.json.
type Config struct {
	Rack string `json:"rack"`
	// Head is the head's tentacle endpoint on the management core.
	Head string `json:"head"` // "https://10.98.0.1:7444"
	// Cert and Key are this tentacle's identity (flapjack://tentacle/<rack>),
	// from `flapjack pki issue tentacle`; CA is the cluster CA. They are
	// re-read when they change, so re-issuing needs no restart.
	Cert string `json:"cert,omitempty"` // default /etc/flapjack/tentacle/tentacle.pem
	Key  string `json:"key,omitempty"`  // default /etc/flapjack/tentacle/tentacle.key
	CA   string `json:"ca,omitempty"`   // default /etc/flapjack/tentacle/ca.pem
	// AgentListen is on the rack's management network ("10.1.1.1:8443");
	// ArtifactListen, optional, on its cluster network ("10.2.1.1:8444").
	AgentListen    string `json:"agentListen"`
	ArtifactListen string `json:"artifactListen,omitempty"`
	DataDir        string `json:"dataDir,omitempty"` // default /var/lib/flapjack-tentacle
	// BootListen, optional, serves the rack's boot images over HTTPS on
	// its management network ("10.1.1.1:443"), with BootCert/BootKey
	// from the boot CA (flapjack pki issue tentacle RACK --boot-address).
	// The head's tentacleBoot entry for the rack must point here.
	BootListen string `json:"bootListen,omitempty"`
	BootCert   string `json:"bootCert,omitempty"` // default /etc/flapjack/tentacle/boot.pem
	BootKey    string `json:"bootKey,omitempty"`  // default /etc/flapjack/tentacle/boot.key
	// DHCP, optional, makes this tentacle its rack's DHCP server and the
	// source of its whole boot. It needs bootListen, and the head must
	// list the rack in tentacleDHCP and tentacleBoot.
	DHCP *DHCPConfig `json:"dhcp,omitempty"`
}

// DHCPConfig is the rack management network a tentacle serves DHCP on.
type DHCPConfig struct {
	Interface string   `json:"interface"` // "eth1"
	Address   string   `json:"address"`   // this tentacle on it, with prefix: "10.1.1.1/24"
	Router    string   `json:"router,omitempty"`
	DNS       []string `json:"dns,omitempty"`
	Domain    string   `json:"domain,omitempty"`
	LeaseTime string   `json:"leaseTime,omitempty"` // default 1h
	// TFTP serves iPXE to PXE ROMs on port 69 (default true). UEFI
	// HTTP-boot firmware gets iPXE over HTTPS from bootListen; PlainHTTP
	// also serves it (and only it) over plain HTTP on HTTPPort (default
	// 80), for firmware that cannot do HTTPS.
	TFTP      *bool `json:"tftp,omitempty"`
	PlainHTTP bool  `json:"plainHTTP,omitempty"`
	HTTPPort  int   `json:"httpPort,omitempty"`
}

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
	return c, c.Validate()
}

// Validate fills in defaults and checks c.
func (c *Config) Validate() error {
	dir := "/etc/flapjack/tentacle"
	if c.Cert == "" {
		c.Cert = filepath.Join(dir, "tentacle.pem")
	}
	if c.Key == "" {
		c.Key = filepath.Join(dir, "tentacle.key")
	}
	if c.CA == "" {
		c.CA = filepath.Join(dir, "ca.pem")
	}
	if c.DataDir == "" {
		c.DataDir = "/var/lib/flapjack-tentacle"
	}
	if c.BootCert == "" {
		c.BootCert = filepath.Join(dir, "boot.pem")
	}
	if c.BootKey == "" {
		c.BootKey = filepath.Join(dir, "boot.key")
	}
	if err := (pki.Identity{Role: pki.Tentacle, Name: c.Rack}).Valid(); err != nil {
		return fmt.Errorf("rack: %w", err)
	}
	if !strings.HasPrefix(c.Head, "https://") {
		return fmt.Errorf("head %q must be an https:// URL", c.Head)
	}
	if c.AgentListen == "" {
		return errors.New("agentListen is required: the address on the rack's management network")
	}
	if d := c.DHCP; d != nil {
		if c.BootListen == "" {
			return errors.New("dhcp needs bootListen: iPXE gets its script and images from it")
		}
		if d.Interface == "" {
			return errors.New("dhcp: interface is required")
		}
		ip, _, err := net.ParseCIDR(d.Address)
		if err != nil || ip.To4() == nil {
			return fmt.Errorf("dhcp: address %q must be IPv4 with a prefix, like 10.1.1.1/24", d.Address)
		}
		if h, _, _ := net.SplitHostPort(c.BootListen); h != ip.String() {
			return fmt.Errorf("dhcp: bootListen %q must be on the dhcp address %s, where the rack reaches this tentacle", c.BootListen, ip)
		}
		if d.Router != "" && net.ParseIP(d.Router).To4() == nil {
			return fmt.Errorf("dhcp: router %q", d.Router)
		}
		for _, s := range d.DNS {
			if net.ParseIP(s).To4() == nil {
				return fmt.Errorf("dhcp: dns %q", s)
			}
		}
		if d.LeaseTime != "" {
			if lt, err := time.ParseDuration(d.LeaseTime); err != nil || lt < time.Minute {
				return fmt.Errorf("dhcp: leaseTime %q", d.LeaseTime)
			}
		}
		if d.TFTP == nil {
			on := true
			d.TFTP = &on
		}
		if d.HTTPPort == 0 {
			d.HTTPPort = 80
		}
	}
	for _, a := range []string{c.AgentListen, c.ArtifactListen, c.BootListen} {
		if a == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(a); err != nil {
			return fmt.Errorf("listen address %q: %w", a, err)
		}
	}
	return nil
}

// Serve runs a tentacle from c until ctx ends.
func Serve(ctx context.Context, c Config, logw io.Writer) error {
	if err := c.Validate(); err != nil {
		return err
	}
	logf := func(format string, args ...any) { fmt.Fprintf(logw, format+"\n", args...) }
	cert, err := pki.FileCert(c.Cert, c.Key)
	if err != nil {
		return fmt.Errorf("tentacle certificate: %w", err)
	}
	want := pki.Identity{Role: pki.Tentacle, Name: c.Rack}
	if id, err := pki.IdentityOf(cert().Leaf); err != nil || id != want {
		return fmt.Errorf("%s is for %v, not %s", c.Cert, id, want)
	}
	pool, err := pki.LoadPool(c.CA)
	if err != nil {
		return err
	}
	up := &http.Client{Timeout: 10 * time.Minute, Transport: &http.Transport{
		TLSClientConfig: pki.ClientConfig(cert, pool, pki.AnyOf(pki.Head)), MaxIdleConnsPerHost: 16}}
	t := &Tentacle{Rack: c.Rack, Head: strings.TrimRight(c.Head, "/"), Up: up,
		Cache:     staging.Store{Dir: filepath.Join(c.DataDir, "content")},
		Artifacts: staging.Store{Dir: filepath.Join(c.DataDir, "artifacts")}, Logf: logf}
	var bootCert func() *tls.Certificate
	if c.BootListen != "" {
		if bootCert, err = pki.FileCert(c.BootCert, c.BootKey); err != nil {
			return fmt.Errorf("boot certificate: %w", err)
		}
		t.Images = filepath.Join(c.DataDir, "images")
	}
	if c.DHCP != nil {
		t.Firmware = filepath.Join(c.DataDir, "ipxe")
	}

	quiet := log.New(io.Discard, "", 0) // refused handshakes are routine
	errc := make(chan error, 6)
	var servers []*http.Server
	defer func() {
		for _, s := range servers {
			s.Close()
		}
	}()
	listen := func(name, addr string, h http.Handler, tlsCfg *tls.Config) error {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		srv := &http.Server{Handler: h, ErrorLog: quiet}
		server.Timeouts(srv)
		servers = append(servers, srv)
		go func() { errc <- fmt.Errorf("%s: %w", name, srv.Serve(tls.NewListener(ln, tlsCfg))) }()
		logf("tentacle %s: %s on https://%s", c.Rack, name, addr)
		return nil
	}
	// Agents: a node certificate for this rack, except to enroll.
	if err := listen("agents", c.AgentListen, t.AgentHandler(), pki.ServerConfig(cert, pool, t.AllowNode, true)); err != nil {
		return err
	}
	if c.ArtifactListen != "" {
		if err := listen("artifacts", c.ArtifactListen, t.ArtifactHandler(), pki.ServerConfig(cert, pool, t.AllowNode, false)); err != nil {
			return err
		}
	}
	if c.BootListen != "" {
		if err := listen("boot images", c.BootListen, t.BootHandler(), pki.BootServerConfig(bootCert)); err != nil {
			return err
		}
	}
	if c.DHCP != nil {
		closers, err := serveDHCP(c, t, errc, logf, func(name, addr string, h http.Handler) error {
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			srv := &http.Server{Handler: h, ErrorLog: quiet}
			server.Timeouts(srv)
			servers = append(servers, srv)
			go func() { errc <- fmt.Errorf("%s: %w", name, srv.Serve(ln)) }()
			logf("tentacle %s: %s on http://%s", c.Rack, name, addr)
			return nil
		})
		defer func() {
			for _, cl := range closers {
				cl.Close()
			}
		}()
		if err != nil {
			return err
		}
	}
	logf("tentacle %s: following %s", c.Rack, c.Head)
	go t.Run(ctx)
	select {
	case <-ctx.Done():
		return nil
	case err := <-errc:
		return err
	}
}
