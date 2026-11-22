package render

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/overlay"
)

func write(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, c := range files {
		full := filepath.Join(root, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		mode := os.FileMode(0o644)
		if strings.HasSuffix(p, ".sh") {
			mode = 0o755
		}
		if target, ok := strings.CutPrefix(c, "->"); ok {
			if err := os.Symlink(target, full); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(full, []byte(c), mode); err != nil {
			t.Fatal(err)
		}
	}
}

var cluster = Cluster{Server: "10.99.0.1", Domain: "cluster", Nodes: []Node{
	{Name: "r1n01", Class: "compute", Rack: "r1", IP: "10.99.1.1", Labels: map[string]string{"gpu": "none"}},
	{Name: "r2n01", Class: "compute", Rack: "r2", IP: "10.99.2.1", Labels: map[string]string{}},
}}

func renderer(t *testing.T) *Renderer {
	dir := t.TempDir()
	r := &Renderer{Dir: filepath.Join(dir, "overlays"), SecretsDir: filepath.Join(dir, "secrets"), FilesDir: filepath.Join(dir, "files")}
	write(t, dir, map[string]string{
		"secrets/munge.key":   "SECRET-KEY",
		"files/ssh/admin.pub": "ssh-ed25519 AAAA admin@head\n",
		"overlays/base/rootfs/etc/hosts.ww": `{{range .Nodes}}{{.IP}} {{.Name}}.{{$.Domain}} {{.Name}}
{{end}}`,
		"overlays/base/rootfs/etc/motd.ww":                  "{{.Hostname}} in rack {{.Node.Rack}} ({{.Class.Name}})\n",
		"overlays/base/rootfs/root/.ssh/authorized_keys.ww": `{{Include "ssh/admin.pub"}}`,
		"overlays/base/rootfs/usr/local/bin/hello.sh":       "#!/bin/sh\necho hi\n",
		"overlays/base/rootfs/etc/rack2-only.ww":            `{{if ne .Node.Rack "r2"}}{{abort}}{{end}}rack 2`,
		"overlays/base/rootfs/etc/localtime":                "->/usr/share/zoneinfo/UTC",
		"overlays/base/overlay.json": `{
  "paths": {
    "/root/.ssh/*": {"mode": "0600"},
    "/etc/motd": {"policy": "report", "onChange": ["true"]}
  },
  "directories": {"/root/.ssh": {"mode": "0700"}},
  "secrets": {"/etc/munge/munge.key": {"secret": "munge.key", "mode": "0400", "owner": "munge", "group": "munge"}},
  "exclusive": ["/etc/slurm/conf.d"]
}`,
		"overlays/site/rootfs/etc/motd": "site motd\n",
	})
	return r
}

func TestTemplateOverlay(t *testing.T) {
	r := renderer(t)
	out, err := r.Render(v1.NodeClass{Name: "compute", Overlays: []string{"base"}}, cluster.Nodes, cluster)
	if err != nil {
		t.Fatal(err)
	}
	o := out["r1n01"]
	read := func(p string) string { return string(o.Content[o.Manifest.Entries[p].Digest]) }
	if got := read("/etc/hosts"); got != "10.99.1.1 r1n01.cluster r1n01\n10.99.2.1 r2n01.cluster r2n01\n" {
		t.Errorf("hosts = %q", got)
	}
	if got := read("/etc/motd"); got != "r1n01 in rack r1 (compute)\n" {
		t.Errorf("motd = %q", got)
	}
	e := o.Manifest.Entries
	if e["/etc/motd"].Policy != overlay.PolicyReport || len(e["/etc/motd"].OnChange) != 1 || e["/etc/motd"].Overlay != "base" {
		t.Errorf("motd entry = %+v", e["/etc/motd"])
	}
	if e["/root/.ssh/authorized_keys"].Mode != 0o600 || read("/root/.ssh/authorized_keys") != "ssh-ed25519 AAAA admin@head\n" {
		t.Errorf("authorized_keys = %+v", e["/root/.ssh/authorized_keys"])
	}
	if e["/root/.ssh"].Kind != overlay.KindDir || e["/root/.ssh"].Mode != 0o700 {
		t.Errorf("/root/.ssh = %+v", e["/root/.ssh"])
	}
	if _, ok := e["/root"]; ok {
		t.Error("container directories must not be managed")
	}
	if e["/usr/local/bin/hello.sh"].Mode != 0o755 {
		t.Errorf("mode not taken from the source file: %v", e["/usr/local/bin/hello.sh"].Mode)
	}
	if e["/etc/localtime"].Kind != overlay.KindSymlink || e["/etc/localtime"].Target != "/usr/share/zoneinfo/UTC" {
		t.Errorf("symlink = %+v", e["/etc/localtime"])
	}
	if k := e["/etc/munge/munge.key"]; k.Owner != "munge" || k.Mode != 0o400 || read("/etc/munge/munge.key") != "SECRET-KEY" {
		t.Errorf("secret = %+v", k)
	}
	if _, ok := e["/etc/rack2-only"]; ok {
		t.Error("abort did not skip the file on rack 1")
	}
	if _, ok := out["r2n01"].Manifest.Entries["/etc/rack2-only"]; !ok {
		t.Error("rack 2 file missing on r2n01")
	}
	if len(o.Manifest.Exclusive) != 1 {
		t.Errorf("exclusive = %v", o.Manifest.Exclusive)
	}
}

func TestLaterOverlayWins(t *testing.T) {
	r := renderer(t)
	out, err := r.Render(v1.NodeClass{Name: "compute", Overlays: []string{"base", "site"}}, cluster.Nodes[:1], cluster)
	if err != nil {
		t.Fatal(err)
	}
	o := out["r1n01"]
	if e := o.Manifest.Entries["/etc/motd"]; e.Overlay != "site" || string(o.Content[e.Digest]) != "site motd\n" {
		t.Fatalf("motd = %+v", e)
	}
	if len(o.Warnings) != 1 || !strings.Contains(o.Warnings[0], "site replaces base") {
		t.Fatalf("warnings = %v", o.Warnings)
	}
}

func TestTemplateErrorsAndConfinement(t *testing.T) {
	r := renderer(t)
	write(t, r.Dir, map[string]string{
		"bad/rootfs/etc/x.ww":      "{{.Node.Nope}}",
		"escape/rootfs/etc/x.ww":   `{{Include "../../secrets/munge.key"}}`,
		"empty/README":             "",
		"both/default.nix":         "{}",
		"both/rootfs/etc/x":        "",
		"badmeta/rootfs/etc/x":     "",
		"badmeta/overlay.json":     `{"pathz": {}}`,
		"badsecret/overlay.json":   `{"secrets": {"/etc/k": {"secret": "../munge.key"}}}`,
		"badsecret/rootfs/etc/.ok": "",
	})
	for name, want := range map[string]string{
		"bad": "Nope", "escape": "not found", "empty": "neither", "both": "both", "missing": "does not exist",
		"badmeta": "unknown field", "badsecret": "invalid secret name", "../base": "invalid overlay name",
	} {
		_, err := r.Render(v1.NodeClass{Overlays: []string{name}}, cluster.Nodes[:1], cluster)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", name, err, want)
		}
	}
	srcs, err := r.Sources()
	if err == nil {
		t.Errorf("Sources = %v; want an error for the overlay with both engines", srcs)
	}
}

// TestSecretsAreMarked: a secret's manifest entry says so, so the head
// serves its content sealed to the node and never in the clear.
func TestSecretsAreMarked(t *testing.T) {
	r := renderer(t)
	write(t, r.Dir, map[string]string{
		"keys/overlay.json":   `{"secrets": {"/etc/k": {"secret": "munge.key"}}}`,
		"keys/rootfs/etc/.ok": "",
	})
	n := cluster.Nodes[0]
	out, err := r.Render(v1.NodeClass{Overlays: []string{"keys"}}, []Node{n}, cluster)
	if err != nil {
		t.Fatal(err)
	}
	e := out[n.Name].Manifest.Entries["/etc/k"]
	if !e.Secret || e.Mode != 0o600 || string(out[n.Name].Content[e.Digest]) != "SECRET-KEY" {
		t.Fatalf("secret entry %+v", e)
	}
	if out[n.Name].Manifest.Entries["/etc/.ok"].Secret {
		t.Fatal("a plain file was marked secret")
	}
}

// TestNixOverlays needs nix and nixpkgs' lib: FLAPJACK_NIX=/path/to/nix
// FLAPJACK_NIXPKGS=/path/to/nixpkgs.
func TestNixOverlays(t *testing.T) {
	bin, pkgs := os.Getenv("FLAPJACK_NIX"), os.Getenv("FLAPJACK_NIXPKGS")
	if bin == "" || pkgs == "" {
		t.Skip("set FLAPJACK_NIX and FLAPJACK_NIXPKGS to run nix engine tests")
	}
	r := renderer(t)
	r.Nix = Nix{Bin: bin, Nixpkgs: pkgs, WorkDir: t.TempDir()}
	write(t, r.Dir, map[string]string{
		"options/default.nix": `{ lib, config, node, ... }: {
  options.site.banner = lib.mkOption { type = lib.types.str; default = "Flapjack"; };
  options.site.sysctl = lib.mkOption { type = with lib.types; attrsOf (oneOf [ int str ]); default = { }; };
  config = {
    site.sysctl."vm.swappiness" = lib.mkDefault 10;
    files."/etc/sysctl.d/90-site.conf" = {
      text = lib.concatStrings (lib.mapAttrsToList (k: v: "${k} = ${toString v}\n") config.site.sysctl);
      onChange = [ "sysctl --system" ];
    };
    files."/etc/issue".text = "${config.site.banner} ${node.name}";
    files."/etc/motd".source = ./motd;
    files."/etc/munge/munge.key" = { secret = "munge.key"; owner = "munge"; };
    symlinks."/etc/localtime" = "/usr/share/zoneinfo/UTC";
    directories."/var/spool/site".mode = "0750";
    assertions = [ { assertion = config.site.sysctl."vm.swappiness" < 100; message = "swappiness too high"; } ];
  };
}`,
		"options/motd": "from source file\n",
		"rack2/default.nix": `{ lib, node, ... }: lib.mkIf (node.rack == "r2") {
  site.sysctl."vm.swappiness" = lib.mkForce 1;
  site.banner = "Rack 2";
  files."/etc/issue".text = lib.mkAfter "(rack 2)";
}`,
		"broken/default.nix": `{ lib, ... }: { assertions = [ { assertion = false; message = "always fails"; } ]; }`,
		"sneaky/default.nix": `{ ... }: { files."/etc/x".text = builtins.readFile /etc/passwd; }`,
		"keys/default.nix":   `{ ... }: { files."/etc/k".secret = "munge.key"; }`,
	})
	class := v1.NodeClass{Name: "compute", Overlays: []string{"base", "options", "rack2"}}
	out, err := r.Render(class, cluster.Nodes, cluster)
	if err != nil {
		t.Fatal(err)
	}
	read := func(n, p string) string {
		o := out[n]
		return string(o.Content[o.Manifest.Entries[p].Digest])
	}
	if got := read("r1n01", "/etc/sysctl.d/90-site.conf"); got != "vm.swappiness = 10\n" {
		t.Errorf("r1 sysctl = %q", got)
	}
	if got := read("r2n01", "/etc/sysctl.d/90-site.conf"); got != "vm.swappiness = 1\n" {
		t.Errorf("r2 sysctl (mkForce) = %q", got)
	}
	if got := read("r2n01", "/etc/issue"); got != "Rack 2 r2n01\n(rack 2)" {
		t.Errorf("r2 issue (lines merge) = %q", got)
	}
	if got := read("r1n01", "/etc/motd"); got != "from source file\n" {
		t.Errorf("motd: nix overlays come after base and replace it: %q", got)
	}
	e := out["r1n01"].Manifest.Entries
	if e["/etc/munge/munge.key"].Mode != 0o600 || e["/etc/munge/munge.key"].Owner != "munge" || read("r1n01", "/etc/munge/munge.key") != "SECRET-KEY" {
		t.Errorf("secret = %+v", e["/etc/munge/munge.key"])
	}
	if e["/etc/sysctl.d/90-site.conf"].Overlay != "options+rack2" || e["/var/spool/site"].Mode != 0o750 || e["/etc/localtime"].Target == "" {
		t.Errorf("entries = %+v", e)
	}
	if _, err := r.Render(v1.NodeClass{Overlays: []string{"broken"}}, cluster.Nodes[:1], cluster); err == nil || !strings.Contains(err.Error(), "always fails") {
		t.Errorf("assertion: %v", err)
	}
	if _, err := r.Render(v1.NodeClass{Overlays: []string{"sneaky"}}, cluster.Nodes[:1], cluster); err == nil || !strings.Contains(err.Error(), "restricted") && !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("restrict-eval: %v", err)
	}
	n := cluster.Nodes[0]
	if out, err := r.Render(v1.NodeClass{Overlays: []string{"keys"}}, []Node{n}, cluster); err != nil || !out[n.Name].Manifest.Entries["/etc/k"].Secret {
		t.Errorf("nix secret not marked secret: %v", err)
	}
}
