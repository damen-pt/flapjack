// Package compliance holds the compliance-profile example; this test
// renders it as the head would. It needs nix and nixpkgs' lib:
// FLAPJACK_NIX=/path/to/nix FLAPJACK_NIXPKGS=/path/to/nixpkgs go test ./examples/compliance
package compliance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/render"
)

func renderExample(t *testing.T, edit func(*v1.Cluster)) (map[string]*render.Output, error) {
	t.Helper()
	bin, pkgs := os.Getenv("FLAPJACK_NIX"), os.Getenv("FLAPJACK_NIXPKGS")
	if bin == "" || pkgs == "" {
		t.Skip("set FLAPJACK_NIX and FLAPJACK_NIXPKGS to render the compliance overlays")
	}
	b, err := os.ReadFile("cluster.json")
	if err != nil {
		t.Fatal(err)
	}
	var c v1.Cluster
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(&c)
	}
	// Real paths: nix's restricted mode refuses macOS's /var → /private/var.
	tmp := func() string {
		d, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	dir, err := filepath.Abs("overlays")
	if err != nil {
		t.Fatal(err)
	}
	secrets := tmp()
	os.WriteFile(filepath.Join(secrets, "compliance-log-ca.pem"), []byte("CA\n"), 0o600)
	r := &render.Renderer{Dir: dir, SecretsDir: secrets, FilesDir: tmp(),
		Nix: render.Nix{Bin: bin, Nixpkgs: pkgs, WorkDir: tmp()}}
	var nodes []render.Node
	for _, n := range c.Nodes {
		nodes = append(nodes, render.NodeOf(n))
	}
	cl := render.Cluster{Nodes: nodes, Server: "10.99.0.1", Domain: "cluster"}
	out := map[string]*render.Output{}
	for _, class := range c.Classes {
		var members []render.Node
		for _, n := range nodes {
			if n.Class == class.Name {
				members = append(members, n)
			}
		}
		got, err := r.Render(class, members, cl)
		if err != nil {
			return nil, err
		}
		for k, v := range got {
			out[k] = v
		}
	}
	return out, nil
}

func TestProfiles(t *testing.T) {
	out, err := renderExample(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	file := func(node, p string) string {
		t.Helper()
		o := out[node]
		e, ok := o.Manifest.Entries[p]
		if !ok {
			t.Fatalf("%s: no %s", node, p)
		}
		return string(o.Content[e.Digest])
	}
	has := func(node, p string, want ...string) {
		t.Helper()
		got := file(node, p)
		for _, w := range want {
			if !strings.Contains(got, w) {
				t.Errorf("%s %s: no %q in\n%s", node, p, w, got)
			}
		}
	}

	// No label, nothing at all.
	if n := len(out["r1n01"].Manifest.Entries); n != 0 {
		t.Errorf("r1n01 has no profile but got %d entries: %v", n, out["r1n01"].Manifest.Entries)
	}

	// CIS L1: no audit rules (Level 2), firewall with the site's networks.
	has("r1n02", "/etc/ssh/sshd_config.d/10-compliance.conf", "MaxAuthTries 3\n", "PermitRootLogin prohibit-password\n", "ClientAliveInterval 900\n", "DisableForwarding yes\n")
	has("r1n02", "/etc/security/pwquality.conf.d/50-compliance.conf", "minlen = 14\n")
	has("r1n02", "/etc/firewalld/zones/trusted.xml", `<source address="10.100.0.0/16"/>`)
	has("r1n02", "/etc/crypto-policies/config", "DEFAULT:NO-SHA1\n")
	if _, ok := out["r1n02"].Manifest.Entries["/etc/audit/rules.d/audit.rules"]; ok {
		t.Error("cis-l1 should not install audit rules")
	}

	// CIS L2 + HIPAA: the strictest of both, audit locked.
	has("r1n03", "/etc/security/pwquality.conf.d/50-compliance.conf", "minlen = 14\n")
	has("r1n03", "/etc/security/faillock.conf", "deny = 5\n", "unlock_time = 900\n", "even_deny_root\n")
	has("r1n03", "/etc/audit/rules.d/audit.rules", "-k identity\n", "\n-e 2\n")
	has("r1n03", "/etc/rsyslog.d/90-compliance-forward.conf", `port="6514"`, `target="loghost.cluster"`)
	has("r1n03", "/etc/compliance/tailoring.xml", "content_profile_cis\"", "content_profile_hipaa\"", "grub2_audit_argument")

	// PCI DSS 4.
	has("r1n04", "/etc/security/faillock.conf", "deny = 10\n", "unlock_time = 1800\n")
	has("r1n04", "/etc/login.defs", "PASS_MAX_DAYS 90\n")

	// STIG.
	has("r2n01", "/etc/sysctl.d/99-compliance.conf", "user.max_user_namespaces = 0\n", "kernel.kexec_load_disabled = 1\n")
	has("r2n01", "/etc/crypto-policies/config", "FIPS\n")
	has("r2n01", "/etc/security/faillock.conf", "deny = 3\n", "unlock_time = 0\n")
	has("r2n01", "/etc/audit/rules.d/audit.rules", "-F path=/usr/bin/sudo -F perm=x", "-C uid!=euid -F euid=0")
	has("r2n01", "/etc/audit/auditd.conf", "admin_space_left_action = SINGLE\n")
	has("r2n01", "/etc/issue", "U.S. Government (USG) Information System")
	has("r2n01", "/etc/compliance/masked-units", "kdump.service\n")
	has("r2n01", "/etc/compliance/waivers", "sshd_disable_root_login: ", "grub2_pti_argument: ")
	if w := strings.Join(out["r2n01"].Warnings, "\n"); strings.Contains(w, "kernel arguments") || strings.Contains(w, "fips=1") {
		t.Errorf("compute-stig carries every argument, yet: %s", w)
	}
	// The GPU node's site exception.
	if s := file("r2n02", "/etc/sysctl.d/99-compliance.conf"); strings.Contains(s, "max_user_namespaces") {
		t.Errorf("r2n02 is a GPU node, user namespaces stay on:\n%s", s)
	}
	has("r2n02", "/etc/compliance/waivers", "sysctl_user_max_user_namespaces: ")
}

func TestMistakes(t *testing.T) {
	label := func(name, v string) func(*v1.Cluster) {
		return func(c *v1.Cluster) {
			for i := range c.Nodes {
				if c.Nodes[i].Name == name {
					c.Nodes[i].Labels["compliance"] = v
				}
			}
		}
	}
	if _, err := renderExample(t, label("r1n02", "stg")); err == nil || !strings.Contains(err.Error(), "unknown profile 'stg'") {
		t.Errorf("typo in a label: %v", err)
	}
	// STIG on a class without its kernel arguments: a warning, not a failure.
	out, err := renderExample(t, label("r1n02", "stig"))
	if err != nil {
		t.Fatal(err)
	}
	if w := strings.Join(out["r1n02"].Warnings, "\n"); !strings.Contains(w, "pti=on") || !strings.Contains(w, "fips=1") {
		t.Errorf("warnings: %s", w)
	}
}
