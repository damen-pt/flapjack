package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/damen-pt/flapjack/internal/pki"
	"github.com/damen-pt/flapjack/internal/server"
	"github.com/damen-pt/flapjack/internal/tentacle"
)

// defaultPKIDir is the head's PKI directory from server.json, or the
// default.
func defaultPKIDir() string {
	if c, err := server.LoadConfig(server.DefaultConfig); err == nil {
		return c.PKIDir
	}
	return "/etc/flapjack/pki"
}

func pkiInit(args []string) error {
	fs := flags("pki init", "")
	dir := fs.String("dir", defaultPKIDir(), "PKI directory")
	boot := fs.String("boot-address", "", "comma-separated addresses or names nodes use for HTTPS boot (default: the server.json address)")
	head := fs.String("head-name", "head", "this head's identity name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var hosts []string
	if *boot != "" {
		hosts = strings.Split(*boot, ",")
	} else if c, err := server.LoadConfig(server.DefaultConfig); err == nil {
		hosts = []string{strings.Split(c.Address, "/")[0]}
	}
	if len(hosts) == 0 {
		return errors.New("pass --boot-address: nodes boot over HTTPS only, so the head needs a boot certificate")
	}
	wrote, err := pki.Init(pki.InitOptions{Dir: *dir, HeadName: *head, BootHosts: hosts})
	for _, f := range wrote {
		fmt.Println("wrote", f)
	}
	if err != nil {
		return err
	}
	if len(wrote) == 0 {
		fmt.Println(*dir, "is already initialised; nothing replaced")
	}
	return nil
}

func pkiIssue(args []string) error {
	fs := flags("pki issue", "tentacle RACK | head NAME | admin NAME")
	dir := fs.String("dir", defaultPKIDir(), "PKI directory (the CA)")
	out := fs.String("out", "", "directory to write the certificate, key and CA into (default ./<role>-<name>)")
	ttl := fs.Duration("ttl", 30*24*time.Hour, "certificate lifetime; re-issue before it ends (the tentacle picks up new files without a restart)")
	bootAddr := fs.String("boot-address", "", "tentacle only: comma-separated addresses its rack's iPXE reaches it on; also issues boot.pem/boot.key from the boot CA, for serving boot images")
	if err := fs.Parse(reorder(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 2 || (fs.Arg(0) != "tentacle" && fs.Arg(0) != "head" && fs.Arg(0) != "admin") {
		fs.Usage()
		return flagErr
	}
	id := pki.Identity{Role: pki.Role(fs.Arg(0)), Name: fs.Arg(1)}
	if err := id.Valid(); err != nil {
		return err
	}
	if *bootAddr != "" && id.Role != pki.Tentacle {
		return errors.New("--boot-address is for tentacles")
	}
	ca, err := pki.LoadCA(filepath.Join(*dir, pki.CACertFile), filepath.Join(*dir, pki.CAKeyFile))
	if err != nil {
		return fmt.Errorf("%w (run flapjack pki init first)", err)
	}
	if *out == "" {
		*out = string(id.Role) + "-" + id.Name
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return err
	}
	c, err := ca.Issue(id, *ttl)
	if err != nil {
		return err
	}
	base := string(id.Role)
	certPath, keyPath := filepath.Join(*out, base+".pem"), filepath.Join(*out, base+".key")
	// A re-issue replaces the old pair; the tentacle reloads it.
	os.Remove(certPath)
	os.Remove(keyPath)
	if err := pki.WriteIdentity(certPath, keyPath, c); err != nil {
		return err
	}
	caPEM, err := os.ReadFile(filepath.Join(*dir, pki.CACertFile))
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "ca.pem"), caPEM, 0o644); err != nil {
		return err
	}
	fmt.Printf("issued %s until %s\n  %s\n  %s\n  %s\n", id, c.Leaf.NotAfter.Local().Format(time.DateTime), certPath, keyPath, filepath.Join(*out, "ca.pem"))
	if *bootAddr != "" {
		bca, err := pki.LoadCA(filepath.Join(*dir, pki.BootCACertFile), filepath.Join(*dir, pki.BootCAKeyFile))
		if err != nil {
			return fmt.Errorf("boot CA: %w", err)
		}
		bc, err := bca.IssueServer(strings.Split(*bootAddr, ","), *ttl)
		if err != nil {
			return err
		}
		bcert, bkey := filepath.Join(*out, "boot.pem"), filepath.Join(*out, "boot.key")
		os.Remove(bcert)
		os.Remove(bkey)
		if err := pki.WriteIdentity(bcert, bkey, bc); err != nil {
			return err
		}
		fmt.Printf("issued boot certificate for %s until %s\n  %s\n  %s\n", *bootAddr, bc.Leaf.NotAfter.Local().Format(time.DateTime), bcert, bkey)
	}
	if id.Role == pki.Admin {
		fmt.Printf("give them to the admin, with an API token: flapjack reads ~/.config/flapjack/{admin.pem,admin.key,ca.pem}\n")
	}
	if id.Role == pki.Tentacle {
		fmt.Printf("copy them to /etc/flapjack/tentacle/ on the tentacle, and add the rack to \"tentacles\" in %s\n", server.DefaultConfig)
	}
	return nil
}

func pkiShow(args []string) error {
	fs := flags("pki show", "CERT.pem")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return flagErr
	}
	b, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	c, err := pki.ParseCert(b)
	if err != nil {
		return err
	}
	id, idErr := pki.IdentityOf(c)
	who := id.String()
	if idErr != nil {
		who = c.Subject.CommonName
	}
	left := time.Until(c.NotAfter).Round(time.Minute)
	state := fmt.Sprintf("valid for %s", left)
	if left <= 0 {
		state = "EXPIRED"
	}
	fmt.Printf("subject   %s\nissuer    %s\nca        %v\nvalid     %s → %s (%s)\n", who, c.Issuer.CommonName, c.IsCA,
		c.NotBefore.Local().Format(time.DateTime), c.NotAfter.Local().Format(time.DateTime), state)
	if len(c.IPAddresses)+len(c.DNSNames) > 0 {
		var hosts []string
		for _, ip := range c.IPAddresses {
			hosts = append(hosts, ip.String())
		}
		fmt.Printf("hosts     %s\n", strings.Join(append(hosts, c.DNSNames...), ", "))
	}
	fmt.Printf("key       %s\n", c.PublicKeyAlgorithm)
	if left <= 0 {
		return errors.New("certificate expired")
	}
	return nil
}

func tentacleRun(args []string) error {
	fs := flags("tentacle", "")
	config := fs.String("config", tentacle.DefaultConfig, "config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := tentacle.LoadConfig(*config)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return tentacle.Serve(ctx, c, os.Stderr)
}
