// Package image builds stateless node images on the head node: an EL root
// filesystem from dnf (no internet needed when the repos are local
// mirrors), a kernel, and an initramfs whose livenet module downloads the
// root filesystem into RAM at boot. Images are versioned: each build lands
// in <name>@<id>/ and <name> is a symlink to the current version, so a bad
// image is rolled back by moving the link.
package image

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Spec describes an image. Missing fields take DefaultSpec's values.
type Spec struct {
	Release  string   `json:"release,omitempty"`  // dnf releasever
	Packages []string `json:"packages,omitempty"` // installed in addition to Base
	Services []string `json:"services,omitempty"` // enabled at boot
	ReposDir string   `json:"reposDir,omitempty"` // dnf repo definitions
	// VarsDir holds the dnf variables the repo definitions use (Rocky's
	// mirrorlists need $rltype); default /etc/dnf/vars, if it exists.
	VarsDir      string   `json:"varsDir,omitempty"`
	DisableRepos []string `json:"disableRepos,omitempty"` // repo ids or globs
	SELinux      *bool    `json:"selinux,omitempty"`      // label the image (default true)
	// ReleasePackage is the distribution's release package, which carries
	// its repo definitions and GPG keys ("rocky-release",
	// "almalinux-release"). Default: the head node's own distribution.
	ReleasePackage string `json:"releasePackage,omitempty"`
}

// Base packages every image needs to boot statelessly and run the agent.
var Base = []string{
	"kernel-core", "systemd", "dracut-live", "dracut-network", "NetworkManager", "openssh-server",
	"openssh-clients", "iproute", "iputils", "procps-ng", "sudo", "chrony", "rootfiles", "bash",
	"coreutils", "util-linux", "passwd", "shadow-utils", "less", "vim-minimal", "kmod",
	"selinux-policy-targeted", "policycoreutils",
}

// releasePackages maps an os-release ID to its release package.
var releasePackages = map[string]string{
	"rocky": "rocky-release", "almalinux": "almalinux-release", "rhel": "redhat-release",
	"centos": "centos-stream-release", "ol": "oraclelinux-release",
}

// HostReleasePackage is the release package of the distribution in
// osRelease (/etc/os-release), or almalinux-release if it is not known.
func HostReleasePackage(osRelease string) string {
	b, _ := os.ReadFile(osRelease)
	for _, line := range strings.Split(string(b), "\n") {
		if id, ok := strings.CutPrefix(line, "ID="); ok {
			if p := releasePackages[strings.Trim(id, `"'`)]; p != "" {
				return p
			}
		}
	}
	return "almalinux-release"
}

// DefaultSpec is used when an image has no spec file.
func DefaultSpec() Spec {
	t := true
	return Spec{Release: "9", Services: []string{"sshd", "chronyd", "NetworkManager"}, ReposDir: "/etc/yum.repos.d",
		DisableRepos: []string{"epel*"}, SELinux: &t}
}

func (s *Spec) fill() {
	d := DefaultSpec()
	if s.Release == "" {
		s.Release = d.Release
	}
	if s.Services == nil {
		s.Services = d.Services
	}
	if s.ReposDir == "" {
		s.ReposDir = d.ReposDir
	}
	if s.VarsDir == "" {
		if _, err := os.Stat("/etc/dnf/vars"); err == nil {
			s.VarsDir = "/etc/dnf/vars"
		}
	}
	if s.DisableRepos == nil {
		s.DisableRepos = d.DisableRepos
	}
	if s.SELinux == nil {
		s.SELinux = d.SELinux
	}
	if s.ReleasePackage == "" {
		s.ReleasePackage = HostReleasePackage("/etc/os-release")
	}
}

// Info is image.json, written next to each built version.
type Info struct {
	Name     string    `json:"name"`
	Version  string    `json:"version"` // <name>@<id>
	Created  time.Time `json:"created"`
	Kernel   string    `json:"kernel"`
	Rootfs   string    `json:"rootfs"` // sha256 of rootfs.squashfs
	Size     int64     `json:"size"`
	Packages int       `json:"packages"`
	Agent    string    `json:"agent"` // sha256 of the flapjack binary installed as the agent
	Spec     Spec      `json:"spec"`
}

// Builder builds images into Dir.
type Builder struct {
	Dir   string // images directory served by flapjack.service
	Agent string // flapjack binary to install in the image
	// PKIDir, if set, is the head's PKI directory. Its public parts go
	// into the image: the cluster CA and generation key the agent trusts,
	// and the boot CA, which is also added to the system trust store so
	// dracut can fetch the root filesystem over HTTPS.
	PKIDir string
	// Exec replaces running commands (tests).
	Exec func(name string, args ...string) error
	Log  io.Writer // progress
}

// AgentUnit is the node agent's systemd unit. It is ordered before the
// services overlays usually configure, so they start with their config.
const AgentUnit = `[Unit]
Description=Flapjack node agent (overlays)
Wants=network-online.target
After=network-online.target
Before=sshd.service chronyd.service munge.service slurmd.service systemd-user-sessions.service

[Service]
Type=notify
NotifyAccess=main
ExecStart=/usr/local/bin/flapjack agent
Restart=always
RestartSec=5s
TimeoutStartSec=90s

[Install]
WantedBy=multi-user.target
`

func validName(n string) bool {
	return n != "" && !strings.HasPrefix(n, ".") && !strings.ContainsAny(n, `/\@ `) && fs.ValidPath(n)
}

func (b *Builder) logf(format string, args ...any) {
	if b.Log != nil {
		fmt.Fprintf(b.Log, format+"\n", args...)
	}
}

func (b *Builder) run(name string, args ...string) error {
	b.logf("+ %s %s", name, strings.Join(args, " "))
	if b.Exec != nil {
		return b.Exec(name, args...)
	}
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = b.Log, b.Log
	if b.Log == nil {
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// Build builds image name from spec and makes it current.
func (b *Builder) Build(name string, spec Spec) (Info, error) {
	var info Info
	if !validName(name) {
		return info, fmt.Errorf("invalid image name %q", name)
	}
	if os.Geteuid() != 0 {
		return info, errors.New("image build must run as root")
	}
	for _, tool := range []string{"dnf", "chroot", "mksquashfs", "mount", "umount"} {
		if _, err := exec.LookPath(tool); err != nil {
			return info, fmt.Errorf("%s is required (dnf install squashfs-tools)", tool)
		}
	}
	spec.fill()
	start := time.Now()
	work, err := os.MkdirTemp(b.Dir, ".build-"+name+"-")
	if err != nil {
		return info, err
	}
	defer os.RemoveAll(work)
	root := filepath.Join(work, "root")

	pkgs := append(append(slices.Clone(Base), spec.ReleasePackage), spec.Packages...)
	args := []string{"-y", "--installroot=" + root, "--releasever=" + spec.Release,
		"--setopt=install_weak_deps=False", "--setopt=tsflags=nodocs", "--setopt=reposdir=" + spec.ReposDir}
	if spec.VarsDir != "" {
		// Otherwise dnf reads variables from the empty install root.
		args = append(args, "--setopt=varsdir="+spec.VarsDir)
	}
	for _, r := range spec.DisableRepos {
		args = append(args, "--disablerepo="+r)
	}
	b.logf("installing %d packages into %s", len(pkgs), root)
	if err := b.run("dnf", append(append(args, "install"), pkgs...)...); err != nil {
		return info, err
	}

	if err := b.customize(root, spec); err != nil {
		return info, err
	}

	mods, err := os.ReadDir(filepath.Join(root, "lib", "modules"))
	if err != nil || len(mods) != 1 {
		return info, fmt.Errorf("expected exactly one kernel in the image, found %d", len(mods))
	}
	kver := mods[0].Name()
	if err := b.initramfs(root, kver, filepath.Join(work, "initrd.img")); err != nil {
		return info, err
	}
	if err := copyFile(filepath.Join(root, "lib", "modules", kver, "vmlinuz"), filepath.Join(work, "vmlinuz"), 0o644); err != nil {
		return info, err
	}
	matches, _ := filepath.Glob(filepath.Join(root, "boot", "initramfs-*"))
	for _, m := range matches {
		os.Remove(m) // the image boots from our initramfs, not one inside it
	}
	os.RemoveAll(filepath.Join(root, "var", "cache", "dnf"))

	if *spec.SELinux {
		fc := filepath.Join(root, "etc", "selinux", "targeted", "contexts", "files", "file_contexts")
		if err := b.run("setfiles", "-r", root, fc, root); err != nil {
			return info, err
		}
	}
	squash := filepath.Join(work, "rootfs.squashfs")
	if err := b.run("mksquashfs", root, squash, "-comp", "zstd", "-noappend", "-quiet", "-no-progress"); err != nil {
		return info, err
	}
	sum, size, err := hashFile(squash)
	if err != nil {
		return info, err
	}
	n, _ := countPackages(root)
	agentSum, _, err := hashFile(b.Agent)
	if err != nil {
		return info, err
	}
	info = Info{Name: name, Version: name + "@" + sum[:12], Created: time.Now().UTC(), Kernel: kver,
		Rootfs: "sha256:" + sum, Size: size, Packages: n, Agent: "sha256:" + agentSum, Spec: spec}
	if err := os.RemoveAll(root); err != nil {
		return info, err
	}
	meta, _ := json.MarshalIndent(info, "", "  ")
	if err := os.WriteFile(filepath.Join(work, "image.json"), append(meta, '\n'), 0o644); err != nil {
		return info, err
	}
	if err := os.Chmod(work, 0o755); err != nil {
		return info, err
	}
	final := filepath.Join(b.Dir, info.Version)
	os.RemoveAll(final) // an identical rebuild replaces itself
	if err := os.Rename(work, final); err != nil {
		return info, err
	}
	if err := b.Use(name, info.Version); err != nil {
		return info, err
	}
	b.logf("built %s in %s (%d packages, kernel %s, rootfs %d MiB)", info.Version, time.Since(start).Round(time.Second), n, kver, size>>20)
	return info, nil
}

func (b *Builder) customize(root string, spec Spec) error {
	b.logf("installing the flapjack agent")
	if err := copyFile(b.Agent, filepath.Join(root, "usr", "local", "bin", "flapjack"), 0o755); err != nil {
		return fmt.Errorf("agent: %w", err)
	}
	if err := b.installTrust(root); err != nil {
		return fmt.Errorf("trust: %w", err)
	}
	unit := filepath.Join(root, "etc", "systemd", "system", "flapjack-agent.service")
	if err := os.WriteFile(unit, []byte(AgentUnit), 0o644); err != nil {
		return err
	}
	// Stateless: identity comes from DHCP and the agent, not the image.
	for _, f := range []string{"etc/machine-id", "etc/hostname"} {
		if err := os.WriteFile(filepath.Join(root, f), nil, 0o644); err != nil {
			return err
		}
	}
	return b.run("systemctl", append([]string{"--root=" + root, "enable", "flapjack-agent.service"}, spec.Services...)...)
}

// TrustFiles are the public PKI files an image carries, in
// /etc/flapjack/pki. Never keys.
var TrustFiles = []string{"ca.pem", "generation.pub", "boot-ca.pem"}

func (b *Builder) installTrust(root string) error {
	if b.PKIDir == "" {
		return nil
	}
	dst := filepath.Join(root, "etc", "flapjack", "pki")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	for _, f := range TrustFiles {
		src := filepath.Join(b.PKIDir, f)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if err := copyFile(src, filepath.Join(dst, f), 0o644); err != nil {
			return err
		}
	}
	anchor := filepath.Join(b.PKIDir, "boot-ca.pem")
	if _, err := os.Stat(anchor); err != nil {
		return nil
	}
	b.logf("trusting the boot CA for HTTPS boot")
	if err := copyFile(anchor, filepath.Join(root, "etc", "pki", "ca-trust", "source", "anchors", "flapjack-boot-ca.pem"), 0o644); err != nil {
		return err
	}
	return b.run("chroot", root, "update-ca-trust", "extract")
}

// initramfs builds a generic (not host-only) initramfs inside the image,
// with dmsquash-live and livenet so it can fetch the root filesystem.
func (b *Builder) initramfs(root, kver, out string) error {
	var mounted []string
	defer func() {
		for _, m := range slices.Backward(mounted) {
			exec.Command("umount", m).Run()
		}
	}()
	for _, m := range []string{"proc", "sys", "dev"} {
		target := filepath.Join(root, m)
		if err := b.run("mount", "--bind", "/"+m, target); err != nil {
			return err
		}
		mounted = append(mounted, target)
	}
	if err := installVerifyModule(root); err != nil {
		return err
	}
	tmp := "/tmp/flapjack-initrd.img"
	if err := b.run("chroot", root, "dracut", "-q", "--no-hostonly", "--no-hostonly-cmdline",
		"--add", "dmsquash-live livenet network-manager flapjack-verify", "--omit", "plymouth", "-f", tmp, kver); err != nil {
		return err
	}
	if err := copyFile(filepath.Join(root, tmp), out, 0o644); err != nil {
		return err
	}
	return os.Remove(filepath.Join(root, tmp))
}

// Use makes version the current image for name.
func (b *Builder) Use(name, version string) error {
	if !validName(name) || !strings.HasPrefix(version, name+"@") || strings.ContainsAny(version, `/\`) {
		return fmt.Errorf("%s is not a version of %s", version, name)
	}
	if _, err := os.Stat(filepath.Join(b.Dir, version, "rootfs.squashfs")); err != nil {
		return fmt.Errorf("%s: %w", version, err)
	}
	link := filepath.Join(b.Dir, name)
	if fi, err := os.Lstat(link); err == nil && fi.Mode()&fs.ModeSymlink == 0 {
		return fmt.Errorf("%s is not a symlink; move it aside to manage it with flapjack image", link)
	}
	tmp := link + ".new"
	os.Remove(tmp)
	if err := os.Symlink(version, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, link)
}

// Version is one built version of an image.
type Version struct {
	Info
	Current bool `json:"current"`
}

// List returns every image version, newest first per image.
func (b *Builder) List() ([]Version, error) {
	ents, err := os.ReadDir(b.Dir)
	if err != nil {
		return nil, err
	}
	var out []Version
	for _, e := range ents {
		if !e.IsDir() || !strings.Contains(e.Name(), "@") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(b.Dir, e.Name(), "image.json"))
		if err != nil {
			continue
		}
		var v Version
		if json.Unmarshal(raw, &v.Info) != nil {
			continue
		}
		cur, _ := os.Readlink(filepath.Join(b.Dir, v.Name))
		v.Current = cur == v.Version
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b Version) int {
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return b.Created.Compare(a.Created)
	})
	return out, nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, mode)
}

func hashFile(p string) (string, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n, err
}

func countPackages(root string) (int, error) {
	out, err := exec.Command("rpm", "--root", root, "-qa").Output()
	if err != nil {
		return 0, err
	}
	return len(strings.Fields(string(out))), nil
}
