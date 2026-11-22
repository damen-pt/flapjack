package lab

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"text/template"
	"time"
)

// staticNIC is a NIC cloud-init gives a fixed address, found by MAC.
type staticNIC struct{ MAC, Address, Conn string }

// cloudConfig is a lab VM's cloud-init user-data: the flapjack user with
// the Mac's SSH key, static addresses on its lab NICs, and fj-sync, which
// on every boot installs the Mac's current flapjack binary and runs the
// VM's setup script from the seed server.
func (st State) cloudConfig(hostname string, nics []staticNIC, setupPath, before string) (string, error) {
	pub, err := os.ReadFile(st.SSHKey() + ".pub")
	if err != nil {
		return "", err
	}
	var netScript strings.Builder
	for _, n := range nics {
		fmt.Fprintf(&netScript, `      IF=$(ip -o link | awk -F': ' 'tolower($0) ~ /%[1]s/ {print $2; exit}')
      nmcli -t -f NAME con show | grep -qx %[3]s && nmcli con delete %[3]s
      nmcli con add type ethernet ifname "$IF" con-name %[3]s ipv4.method manual ipv4.addresses %[2]s ipv6.method link-local connection.autoconnect yes
      nmcli con up %[3]s
`, n.MAC, n.Address, n.Conn)
	}
	return fmt.Sprintf(`#cloud-config
hostname: %[1]s
users:
  - name: flapjack
    groups: [wheel]
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    shell: /bin/bash
    ssh_authorized_keys: [%[2]q]
write_files:
  - path: /usr/local/sbin/fj-prov-net
    permissions: "0755"
    content: |
      #!/bin/sh
      # Static addresses on the lab NICs, found by MAC.
%[3]s  - path: /usr/local/sbin/fj-sync
    permissions: "0755"
    content: |
      #!/bin/sh
      # Every boot: install the flapjack binary the Mac is serving, then run
      # this VM's lab setup, so it always matches the Mac's build.
      set -e
      S=http://10.0.2.2:%[4]d
      curl -fsS --retry 5 --retry-connrefused $S/flapjack -o /usr/local/bin/flapjack.new
      chmod 0755 /usr/local/bin/flapjack.new && mv /usr/local/bin/flapjack.new /usr/local/bin/flapjack
      curl -fsS --retry 5 $S/%[5]s -o /usr/local/sbin/fj-setup.new && chmod 0755 /usr/local/sbin/fj-setup.new
      mv /usr/local/sbin/fj-setup.new /usr/local/sbin/fj-lab-setup
      exec /usr/local/sbin/fj-lab-setup
  - path: /etc/systemd/system/fj-sync.service
    content: |
      [Unit]
      Description=Install flapjack and set up this lab VM
      Wants=network-online.target
      After=network-online.target
      Before=%[6]s
      [Service]
      Type=oneshot
      RemainAfterExit=yes
      ExecStart=/usr/local/sbin/fj-sync
      TimeoutStartSec=20min
      [Install]
      WantedBy=multi-user.target
runcmd:
  - [/usr/local/sbin/fj-prov-net]
  - [systemctl, daemon-reload]
  - [systemctl, enable, fj-sync.service]
  - [systemctl, restart, fj-sync.service]
`, hostname, strings.TrimSpace(string(pub)), netScript.String(), st.Spec.SeedPort, setupPath, before), nil
}

func metaData(hostname, userData string) string {
	sum := sha256.Sum256([]byte(userData))
	return fmt.Sprintf("instance-id: %s-%s\nlocal-hostname: %s\n", hostname, hex.EncodeToString(sum[:6]), hostname)
}

//go:embed tentacle-setup.sh
var tentacleSetupSrc string

var tentacleSetup = template.Must(template.New("tentacle-setup").Parse(tentacleSetupSrc))

//go:embed welcome.sh
var welcomeSrc string

var welcome = template.Must(template.New("welcome").Parse(welcomeSrc))

// ComputeImageSpec is the compute image's spec (/etc/flapjack/images/
// rocky9-aarch64.json): Rocky 9 from the head's repositories, with EPEL
// for Slurm and munge.
const ComputeImageSpec = `{
  "release": "9",
  "releasePackage": "rocky-release",
  "packages": ["munge", "slurm", "slurm-slurmd", "nfs-utils", "hostname", "procps-ng", "nano", "jq"],
  "services": ["sshd", "chronyd", "NetworkManager", "munge", "slurmd"],
  "disableRepos": []
}
`

// setupData is what the head-setup, tentacle-setup and welcome templates
// see.
func (st State) setupData() map[string]any {
	image := "el9-aarch64"
	if st.Spec.Tentacles {
		image = ComputeImage
	}
	return map[string]any{
		"Seed": fmt.Sprintf("http://10.0.2.2:%d", st.Spec.SeedPort), "Address": st.HeadAddress(),
		"NixSHA": nixSHA256, "NixpkgsRev": nixpkgsRev, "IPXERev": ipxeRev,
		"Tentacles": st.Spec.Tentacles, "TentacleList": st.Tentacles, "Nodes": st.Nodes,
		"Image": image, "HeadCore": bare(HeadCoreIP), "HeadCluster": bare(HeadClusterIP),
		"RESTPort": st.Spec.RESTPort, "SSHPort": st.Spec.SSHPort, "TentaclePort": TentaclePort,
		"Users": LabUsers, "HomeRoot": HomeRoot, "Login": st.loginNodes(),
		"Compute": len(st.Nodes) - len(st.loginNodes()),
	}
}

func execTemplate(t *template.Template, data any) ([]byte, error) {
	var b bytes.Buffer
	err := t.Execute(&b, data)
	return b.Bytes(), err
}

// seedServer serves cloud-init NoCloud data to the head node and the
// tentacles (reachable from the guests as 10.0.2.2 through QEMU user
// networking), plus the flapjack binary, their setup scripts and what
// they install. It serves no secrets: the head installs tentacle keys
// itself, over the core network.
func (st State) seedServer() (*http.Server, error) {
	mux := http.NewServeMux()
	text := func(route string, body []byte) {
		mux.HandleFunc("GET "+route, func(w http.ResponseWriter, r *http.Request) { w.Write(body) })
	}

	headNICs := []staticNIC{{HeadProvMAC, HeadProvIP, "prov"}}
	if st.Spec.Tentacles {
		headNICs = []staticNIC{{HeadProvMAC, HeadCoreIP, "core"}, {HeadClusterMAC, HeadClusterIP, NetCluster}}
	}
	userData, err := st.cloudConfig("fj-head", headNICs, "head-setup.sh", "flapjack.service")
	if err != nil {
		return nil, err
	}
	text("/meta-data", []byte(metaData("fj-head", userData)))
	text("/user-data", []byte(userData))
	text("/vendor-data", nil)

	cluster, err := json.MarshalIndent(st.Cluster(), "", "  ")
	if err != nil {
		return nil, err
	}
	text("/cluster.json", cluster)
	bootFiles := map[string]string{"ipxe-arm64.efi": st.IPXEARM64, "ipxe-x86_64.efi": st.IPXEX86, "undionly.kpxe": st.IPXEBIOS}
	mux.HandleFunc("GET /boot/{name}", func(w http.ResponseWriter, r *http.Request) {
		if p := bootFiles[r.PathValue("name")]; p != "" {
			http.ServeFile(w, r, p)
			return
		}
		http.NotFound(w, r)
	})
	data := st.setupData()
	setup, err := execTemplate(headSetup, data)
	if err != nil {
		return nil, err
	}
	text("/head-setup.sh", setup)
	wel, err := execTemplate(welcome, data)
	if err != nil {
		return nil, err
	}
	text("/welcome.sh", wel)
	// The head hands back the iPXE it built against its boot CA; nodes
	// boot it from their boot disk.
	mux.HandleFunc("PUT /ipxe/arm64", func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<20))
		if err != nil || len(b) < 2 || string(b[:2]) != "MZ" {
			http.Error(w, "want an EFI binary", http.StatusBadRequest)
			return
		}
		tmp := st.SignedIPXE() + ".new"
		if err := os.WriteFile(tmp, b, 0o644); err != nil || os.Rename(tmp, st.SignedIPXE()) != nil {
			http.Error(w, "cannot save it", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	text("/hosts", []byte(st.hosts()))
	mux.HandleFunc("GET /overlays.tar.gz", func(w http.ResponseWriter, r *http.Request) {
		if err := tarFS(w, exampleOverlays, "overlays"); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	for route, file := range map[string]string{"/nix": st.NixBin, "/nixpkgs.tar.gz": st.Nixpkgs, "/flapjack": st.HeadBinary} {
		mux.HandleFunc("GET "+route, func(w http.ResponseWriter, r *http.Request) {
			if file == "" {
				http.NotFound(w, r)
				return
			}
			http.ServeFile(w, r, file)
		})
	}

	if st.Spec.Tentacles {
		if err := st.seedTentacles(mux, text, data); err != nil {
			return nil, err
		}
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", st.Spec.SeedPort))
	if err != nil {
		return nil, fmt.Errorf("seed server: %w", err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln)
	return srv, nil
}

// seedTentacles adds the tentacle layout's routes: the head's server.json,
// slurm.conf and compute image spec; each tentacle's cloud-init and setup;
// and a relay for the head's SSH public key, which tentacles authorize so
// the head can install their certificates over the core network.
func (st State) seedTentacles(mux *http.ServeMux, text func(string, []byte), data map[string]any) error {
	cfg, err := json.MarshalIndent(st.ServerConfig(), "", "  ")
	if err != nil {
		return err
	}
	text("/server.json", append(cfg, '\n'))
	text("/slurm.conf", []byte(st.SlurmConf()))
	// The Mac's lab key (public), authorized for the users so the Mac can
	// log in to login nodes as them.
	pub, err := os.ReadFile(st.SSHKey() + ".pub")
	if err != nil {
		return err
	}
	text("/lab-key.pub", pub)
	text("/image-spec.json", []byte(ComputeImageSpec))

	keyFile := filepath.Join(st.Dir, "head-key.pub")
	var mu sync.Mutex
	mux.HandleFunc("PUT /head-key", func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<10))
		key := strings.TrimSpace(string(b))
		if err != nil || !strings.HasPrefix(key, "ssh-ed25519 ") || strings.ContainsAny(key, "\n\r") {
			http.Error(w, "want one ssh-ed25519 public key", http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		// Write once: the first head key stays until the lab is destroyed,
		// so a tentacle cannot swap in its own.
		if old, err := os.ReadFile(keyFile); err == nil {
			if strings.TrimSpace(string(old)) != key {
				http.Error(w, "a different head key is already registered", http.StatusConflict)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if err := os.WriteFile(keyFile, []byte(key+"\n"), 0o644); err != nil {
			http.Error(w, "cannot save it", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /head-key", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		b, err := os.ReadFile(keyFile)
		if err != nil {
			http.Error(w, "the head has not sent its key yet", http.StatusNotFound)
			return
		}
		w.Write(b)
	})

	for _, t := range st.Tentacles {
		ud, err := st.cloudConfig(t.Name, []staticNIC{{t.CoreMAC, t.CoreIP + "/24", "core"}, {t.RackMAC, t.RackSubnet(), "rack"}},
			"tentacle/"+t.Rack+"/setup.sh", "flapjack-tentacle.service")
		if err != nil {
			return err
		}
		p := "/tentacle/" + t.Rack + "/"
		text(p+"meta-data", []byte(metaData(t.Name, ud)))
		text(p+"user-data", []byte(ud))
		text(p+"vendor-data", nil)
		d := map[string]any{"T": t}
		for k, v := range data {
			d[k] = v
		}
		b, err := execTemplate(tentacleSetup, d)
		if err != nil {
			return err
		}
		text(p+"setup.sh", b)
	}
	return nil
}
