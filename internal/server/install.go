package server

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/damen-pt/flapjack/internal/apiserver"
	"github.com/damen-pt/flapjack/internal/pki"
)

// Service account and files written by Install.
const (
	ServiceUser      = "flapjackd"
	UnitPath         = "/etc/systemd/system/flapjack.service"
	DefaultAdminFile = "/etc/flapjack/admin.token"
)

// Unit returns the systemd unit. The service runs unprivileged with only
// the two capabilities DHCP needs (port 67 and binding to one interface),
// can write nothing but its state directory, and reads images and boot
// files that root installs.
func Unit(binary, config string) string {
	return fmt.Sprintf(`[Unit]
Description=Flapjack cluster manager (DHCP, TFTP, HTTP boot, API)
Documentation=https://github.com/damen-pt/flapjack
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=%s server --config %s
Restart=on-failure
RestartSec=2s
User=%s
Group=%s
StateDirectory=flapjack
StateDirectoryMode=0755
UMask=0027
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`, binary, config, ServiceUser, ServiceUser)
}

// InstallOptions configure Install.
type InstallOptions struct {
	Config    Config
	ConfigDir string // default /etc/flapjack
	Binary    string // default: this executable
	Force     bool   // overwrite an existing server.json
	Start     bool   // enable and (re)start the service
	Log       io.Writer
}

// Install sets up the head node: service account, config, an admin API
// token, and the systemd unit. It is idempotent: an existing config and
// tokens are kept unless Force is set, so rerunning it only refreshes the
// unit and restarts the service.
func Install(o InstallOptions) error {
	logf := func(format string, args ...any) {
		if o.Log != nil {
			fmt.Fprintf(o.Log, format+"\n", args...)
		}
	}
	if os.Geteuid() != 0 {
		return errors.New("server install must run as root")
	}
	if o.ConfigDir == "" {
		o.ConfigDir = filepath.Dir(DefaultConfig)
	}
	if o.Binary == "" {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		o.Binary = exe
	}
	if err := o.Config.validate(); err != nil {
		return err
	}

	if _, err := user.Lookup(ServiceUser); err != nil {
		out, err := exec.Command("useradd", "--system", "--user-group", "--no-create-home",
			"--home-dir", o.Config.DataDir, "--shell", "/sbin/nologin", "--comment", "Flapjack service", ServiceUser).CombinedOutput()
		if err != nil {
			return fmt.Errorf("useradd: %v: %s", err, out)
		}
		logf("created system user %s", ServiceUser)
	}
	grp, err := user.LookupGroup(ServiceUser)
	if err != nil {
		return err
	}
	gid, _ := strconv.Atoi(grp.Gid)

	if err := os.MkdirAll(o.ConfigDir, 0o755); err != nil {
		return err
	}
	cfgPath := filepath.Join(o.ConfigDir, "server.json")
	if _, err := os.Stat(cfgPath); err == nil && !o.Force {
		logf("keeping %s (use --force to replace it)", cfgPath)
	} else {
		o.Config.API.Tokens = filepath.Join(o.ConfigDir, "tokens.json")
		b, _ := json.MarshalIndent(o.Config, "", "  ")
		if err := writeFile(cfgPath, append(b, '\n'), 0o644, -1); err != nil {
			return err
		}
		logf("wrote %s", cfgPath)
	}

	tokPath, adminPath := filepath.Join(o.ConfigDir, "tokens.json"), filepath.Join(o.ConfigDir, "admin.token")
	if _, err := os.Stat(tokPath); errors.Is(err, fs.ErrNotExist) {
		tok := rand.Text()
		b, _ := json.MarshalIndent(map[string]apiserver.Principal{apiserver.HashToken(tok): {Name: "admin", Role: apiserver.Admin}}, "", "  ")
		// The service reads hashes only; the token itself is root's.
		if err := writeFile(tokPath, append(b, '\n'), 0o640, gid); err != nil {
			return err
		}
		if err := writeFile(adminPath, []byte(tok+"\n"), 0o600, -1); err != nil {
			return err
		}
		logf("wrote %s and an admin token in %s", tokPath, adminPath)
	}

	for _, d := range []string{o.Config.BootDir(), o.Config.ImageDir(), o.Config.OverlayDir, o.Config.FilesDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	// Secrets: root writes them, the service reads them, nobody else can.
	if err := os.MkdirAll(o.Config.SecretsDir, 0o750); err != nil {
		return err
	}
	if err := os.Chown(o.Config.SecretsDir, 0, gid); err != nil {
		return err
	}
	// The cluster CA and keys. The service reads them through its group;
	// existing files are kept, so reinstalling never rotates the CA.
	ip, _, _ := net.ParseCIDR(o.Config.Address)
	wrote, err := pki.Init(pki.InitOptions{Dir: o.Config.PKIDir, BootHosts: []string{ip.String()}, GID: gid})
	if err != nil {
		return fmt.Errorf("pki: %w", err)
	}
	if err := os.Chown(o.Config.PKIDir, 0, gid); err != nil {
		return err
	}
	if len(wrote) > 0 {
		logf("wrote the cluster PKI in %s", o.Config.PKIDir)
	}
	if err := writeFile(UnitPath, []byte(Unit(o.Binary, cfgPath)), 0o644, -1); err != nil {
		return err
	}
	logf("wrote %s", UnitPath)
	if !o.Start {
		return nil
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "flapjack.service"}, {"restart", "flapjack.service"}} {
		if out, err := exec.Command("systemctl", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	logf("flapjack.service enabled and started; logs: journalctl -u flapjack -f")
	return nil
}

// writeFile writes atomically with mode, and group gid unless it is -1.
func writeFile(path string, b []byte, mode os.FileMode, gid int) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		return err
	}
	if gid >= 0 {
		if err := os.Chown(tmp.Name(), 0, gid); err != nil {
			return err
		}
	}
	return os.Rename(tmp.Name(), path)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}
