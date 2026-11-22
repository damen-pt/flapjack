package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/events"
	"github.com/damen-pt/flapjack/internal/pki"
	"github.com/damen-pt/flapjack/internal/server"
)

func serverRun(args []string) error {
	fs := flags("server", "")
	config := fs.String("config", server.DefaultConfig, "config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := server.LoadConfig(*config)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return server.Run(ctx, c, os.Stderr)
}

func serverInstall(args []string) error {
	fs := flags("server install", "")
	addr := fs.String("address", "", "head node address on the provisioning network, with prefix (10.99.0.1/16)")
	iface := fs.String("interface", "", "provisioning interface (default: the one holding --address)")
	domain := fs.String("domain", "cluster", "DNS domain handed to nodes")
	router := fs.String("router", "", "default gateway handed to nodes (default: none)")
	window := fs.String("boot-window", "", `what opens a node's boot window: "armed" (default: authorized triggers only) or "dhcp" (a node's DHCP, which a spoofed MAC can also do)`)
	force := fs.Bool("force", false, "replace an existing server.json")
	noStart := fs.Bool("no-start", false, "write files but do not enable or start the service")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *addr == "" {
		if _, err := os.Stat(server.DefaultConfig); err != nil {
			fs.Usage()
			return flagErr
		}
		c, err := server.LoadConfig(server.DefaultConfig)
		if err != nil {
			return err
		}
		*addr = c.Address
	}
	return server.Install(server.InstallOptions{
		Config: server.Config{Address: *addr, Interface: *iface, Domain: *domain, Router: *router, BootWindow: *window},
		Force:  *force, Start: !*noStart, Log: os.Stderr,
	})
}

// apiClient talks to the API over mTLS, with an admin certificate and a
// bearer token: the API refuses either alone.
type apiClient struct {
	base, token string
	http        *http.Client
}

func apiFlags(fs interface {
	String(string, string, string) *string
}) func() (*apiClient, error) {
	api := fs.String("api", "https://"+server.DefaultAPI, "API address")
	tokenFile := fs.String("token-file", "", "API token file (default $FLAPJACK_TOKEN, ~/.config/flapjack/token, then "+server.DefaultAdminFile+")")
	certDir := fs.String("cert-dir", "", "directory with admin.pem, admin.key and ca.pem (default ~/.config/flapjack, then /etc/flapjack/pki)")
	return func() (*apiClient, error) {
		if !strings.HasPrefix(*api, "https://") {
			return nil, fmt.Errorf("--api %s: the API is only reachable over https://", *api)
		}
		tok, err := findToken(*tokenFile)
		if err != nil {
			return nil, err
		}
		cfg, err := adminTLS(*certDir)
		if err != nil {
			return nil, err
		}
		return &apiClient{base: strings.TrimRight(*api, "/"), token: tok,
			http: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}}, nil
	}
}

// adminTLS finds an admin certificate and the cluster CA, and returns a
// client config that presents the one and accepts only a head signed by
// the other.
func adminTLS(dir string) (*tls.Config, error) {
	dirs := []string{dir}
	if dir == "" {
		home, _ := os.UserHomeDir()
		dirs = []string{filepath.Join(home, ".config", "flapjack"), "/etc/flapjack/pki"}
	}
	for _, d := range dirs {
		cert, key, ca := filepath.Join(d, pki.AdminCertFile), filepath.Join(d, pki.AdminKeyFile), filepath.Join(d, pki.CACertFile)
		if _, err := os.Stat(cert); err != nil {
			continue
		}
		c, err := pki.FileCert(cert, key)
		if err != nil {
			return nil, fmt.Errorf("admin certificate: %w", err)
		}
		pool, err := pki.LoadPool(ca)
		if err != nil {
			return nil, err
		}
		return pki.ClientConfig(c, pool, pki.AnyOf(pki.Head)), nil
	}
	return nil, errors.New("no admin certificate (admin.pem): run as root on the head, or get one with flapjack pki issue admin NAME and put it in ~/.config/flapjack")
}

func findToken(path string) (string, error) {
	if path == "" {
		if t := os.Getenv("FLAPJACK_TOKEN"); t != "" {
			return t, nil
		}
		home, _ := os.UserHomeDir()
		for _, p := range []string{filepath.Join(home, ".config", "flapjack", "token"), server.DefaultAdminFile} {
			if _, err := os.Stat(p); err == nil {
				path = p
				break
			}
		}
		if path == "" {
			return "", errors.New("no API token: set FLAPJACK_TOKEN, pass --token-file, or run as root on the head node")
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("API token: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

func (c *apiClient) do(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w (is flapjack.service running? systemctl status flapjack)", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		var e struct{ Error string }
		if json.Unmarshal(b, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s %s: %s", method, path, e.Error)
		}
		return fmt.Errorf("%s %s: %s", method, path, resp.Status)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

func apply(args []string) error {
	fs := flags("apply", "FILE")
	client := apiFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return flagErr
	}
	var cl v1.Cluster
	if err := readJSON(fs.Arg(0), &cl); err != nil {
		return err
	}
	c, err := client()
	if err != nil {
		return err
	}
	for _, k := range cl.Classes {
		if err := c.do("PUT", "/v1/classes/"+url.PathEscape(k.Name), k, nil); err != nil {
			return err
		}
		fmt.Printf("class/%s applied\n", k.Name)
	}
	for _, n := range cl.Nodes {
		if err := c.do("PUT", "/v1/nodes/"+url.PathEscape(n.Name), n, nil); err != nil {
			return err
		}
		fmt.Printf("node/%s applied\n", n.Name)
	}
	return nil
}

func nodesList(args []string) error {
	fs := flags("nodes", "")
	client := apiFlags(fs)
	phase := fs.String("phase", "", "only nodes in this phase")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := client()
	if err != nil {
		return err
	}
	var nodes []v1.Node
	if err := c.do("GET", "/v1/nodes?phase="+url.QueryEscape(*phase), nil, &nodes); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(nodes)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tCLASS\tRACK\tPHASE\tIP\tAPPLIED\tDRIFT\tAGENT")
	for _, n := range nodes {
		var ip string
		if len(n.Interfaces) > 0 {
			ip = n.Interfaces[0].IP
		}
		applied, drift, seen := "-", "-", "never"
		if a := n.Status.Agent; a != nil {
			applied, drift = fmt.Sprint(a.Applied), fmt.Sprint(len(a.Drift))
			seen = time.Since(a.Seen).Round(time.Second).String() + " ago"
			if time.Since(a.Seen) > 3*time.Minute {
				seen += " (stale)"
			}
			if a.Error != "" {
				seen += " error: " + a.Error
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", n.Name, n.Class, n.Rack, n.Status.Phase, ip, applied, drift, seen)
	}
	return tw.Flush()
}

func eventsList(args []string) error {
	fs := flags("events", "")
	client := apiFlags(fs)
	node := fs.String("node", "", "comma-separated nodes")
	typ := fs.String("type", "", `comma-separated types or prefixes ("boot.")`)
	since := fs.String("since", "1h", "duration or RFC3339 time")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := client()
	if err != nil {
		return err
	}
	q := url.Values{"since": {*since}}
	if *node != "" {
		q.Set("node", *node)
	}
	if *typ != "" {
		q.Set("type", *typ)
	}
	var evs []events.Event
	if err := c.do("GET", "/v1/events?"+q.Encode(), nil, &evs); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "TIME\tNODE\tTYPE\tMESSAGE")
	for _, e := range evs {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.Time.Local().Format("15:04:05"), e.Node, e.Type, e.Message)
	}
	return tw.Flush()
}

func nodeBoot(args []string) error {
	fs := flags("node boot", "NODE")
	client := apiFlags(fs)
	if err := fs.Parse(reorder(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return flagErr
	}
	c, err := client()
	if err != nil {
		return err
	}
	if err := c.do("POST", "/v1/nodes/"+url.PathEscape(fs.Arg(0))+"/boot", nil, nil); err != nil {
		return err
	}
	fmt.Printf("%s: boot window open; power it on or let it retry\n", fs.Arg(0))
	return nil
}

func nodeRevoke(args []string) error {
	fs := flags("node revoke", "NODE")
	client := apiFlags(fs)
	reason := fs.String("reason", "", "why (recorded on the event log; required)")
	if err := fs.Parse(reorder(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 1 || *reason == "" {
		fs.Usage()
		return flagErr
	}
	c, err := client()
	if err != nil {
		return err
	}
	var out map[string]string
	if err := c.do("POST", "/v1/nodes/"+url.PathEscape(fs.Arg(0))+"/revoke", map[string]string{"reason": *reason}, &out); err != nil {
		return err
	}
	fmt.Printf("%s: certificates issued before %s revoked; it gets a new one only by booting in a boot window (flapjack node boot %s)\n",
		fs.Arg(0), out["certsFrom"], fs.Arg(0))
	return nil
}
