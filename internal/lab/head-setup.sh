#!/bin/sh
# Head-node setup for the Flapjack lab. fj-sync.service downloads and runs
# this on every boot, after installing the latest flapjack binary, so a lab
# rebuilt on the Mac reaches an existing head disk. Every step is idempotent.
set -eu
SEED={{.Seed}}
FJ=/usr/local/bin/flapjack

get() { # URL-path dest mode; an unchanged file keeps its mtime
  curl -fsS --retry 5 --retry-connrefused "$SEED/$1" -o "$2.new"
  chmod "$3" "$2.new"
  if cmp -s "$2.new" "$2"; then rm -f "$2.new"; else mv "$2.new" "$2"; fi
}
log() { echo "head-setup: $*"; }

mkdir -p /var/lib/flapjack/boot /etc/flapjack/files/ssh /etc/flapjack/overlays /etc/flapjack/images /usr/local/share/flapjack

get cluster.json /etc/flapjack/lab-cluster.json 0644

# Names for the nodes on the head node itself.
get hosts /etc/flapjack/lab-hosts 0644
awk '/# BEGIN flapjack-lab/{skip=1} !skip{print} /# END flapjack-lab/{skip=0}' /etc/hosts > /etc/hosts.new
cat /etc/flapjack/lab-hosts >> /etc/hosts.new && mv /etc/hosts.new /etc/hosts

# Nix, for the nix overlay engine: a pinned static binary and nixpkgs' lib.
if ! echo "{{.NixSHA}}  /usr/local/bin/nix" | sha256sum -c --status 2>/dev/null; then
  log "installing nix"
  get nix /usr/local/bin/nix 0755
fi
if [ "$(cat /usr/local/share/flapjack/nixpkgs/.rev 2>/dev/null)" != "{{.NixpkgsRev}}" ]; then
  log "installing nixpkgs lib {{.NixpkgsRev}}"
  rm -rf /usr/local/share/flapjack/nixpkgs /tmp/nixpkgs-extract && mkdir -p /tmp/nixpkgs-extract
  curl -fsS "$SEED/nixpkgs.tar.gz" | tar xz -C /tmp/nixpkgs-extract --wildcards '*/lib'
  mv /tmp/nixpkgs-extract/nixpkgs-* /usr/local/share/flapjack/nixpkgs
  echo "{{.NixpkgsRev}}" > /usr/local/share/flapjack/nixpkgs/.rev
  rm -rf /tmp/nixpkgs-extract
fi

# Tools for building node images, and jq for the login screen.
for p in squashfs-tools tcpdump gcc make perl xz-devel git binutils jq; do
  rpm -q "$p" >/dev/null || dnf -y -q install "$p"
done
{{- if .Tentacles}}

# EPEL (and CRB, which EPEL builds against) for Slurm and munge, on the head
# and in the node image, which is built from these repositories.
if ! rpm -q epel-release >/dev/null; then
  log "enabling EPEL and CRB"
  dnf -y -q install epel-release dnf-plugins-core
fi
dnf config-manager --set-enabled crb
for p in munge slurm slurm-slurmctld slurm-slurmrestd nfs-utils; do
  rpm -q "$p" >/dev/null || dnf -y -q install "$p"
done
{{- end}}

# An SSH key for the flapjack user, authorized for root on every node by
# the base overlay.
if [ ! -f /home/flapjack/.ssh/id_ed25519 ]; then
  runuser -u flapjack -- ssh-keygen -q -t ed25519 -N "" -C "flapjack@fj-head" -f /home/flapjack/.ssh/id_ed25519
fi
cat /home/flapjack/.ssh/id_ed25519.pub > /etc/flapjack/files/ssh/authorized_keys
cat > /home/flapjack/.ssh/config <<EOF
Host r* 10.99.* 10.100.*
  User root
  StrictHostKeyChecking accept-new
Host login*
  StrictHostKeyChecking accept-new
Host tentacle-* 10.98.*
  User flapjack
  StrictHostKeyChecking accept-new
  BatchMode yes
  ConnectTimeout 3
EOF
chown flapjack:flapjack /home/flapjack/.ssh/config && chmod 0600 /home/flapjack/.ssh/config

# Nodes take their time from the head node{{if .Tentacles}} (through their tentacle){{end}}.
if ! grep -q '^allow 10.99.0.0/16' /etc/chrony.conf; then
  printf 'allow 10.99.0.0/16\nlocal stratum 10\n' >> /etc/chrony.conf
  systemctl try-restart chronyd
fi
{{- if .Tentacles}}
if ! grep -q '^allow 10.98.0.0/24' /etc/chrony.conf; then
  printf 'allow 10.98.0.0/24\nallow 10.100.0.0/16\n' >> /etc/chrony.conf
  systemctl try-restart chronyd
fi
{{- end}}

# Example overlays, only into an empty directory: after that they are the
# admin's to edit.
if [ -z "$(ls -A /etc/flapjack/overlays)" ]; then
  log "installing example overlays"
  curl -fsS "$SEED/overlays.tar.gz" | tar xz -C /etc/flapjack/overlays
fi
{{- if .Tentacles}}

# The lab's server.json: flapjack on the management core, every rack
# leased, booted and served by its tentacle. It is the lab's, replaced on
# every boot; `server install` below keeps it.
get server.json /etc/flapjack/server.json 0644
get image-spec.json /etc/flapjack/images/{{.Image}}.json 0644
{{- end}}

# flapjack.service. --no-start: this runs before flapjack.service at boot,
# so waiting for a restart here would deadlock; it is started below instead.
# --boot-window dhcp: the lab powers its VMs on itself, not through the
# head, and its provisioning network is a private QEMU switch. Real sites
# keep the default, armed.
$FJ server install --address {{.Address}} --boot-window dhcp --no-start
install -d -o flapjack -g flapjack -m 0700 /home/flapjack/.config/flapjack
install -o flapjack -g flapjack -m 0600 /etc/flapjack/admin.token /home/flapjack/.config/flapjack/token
# The API also wants an admin certificate with the token.
if [ ! -f /home/flapjack/.config/flapjack/admin.pem ]; then
  $FJ pki issue admin flapjack --ttl 8760h --out /home/flapjack/.config/flapjack >/dev/null
  chown -R flapjack:flapjack /home/flapjack/.config/flapjack
fi
{{- if .Tentacles}}

# Slurm: slurmctld and slurmrestd here, configless slurmd on the nodes,
# which fetch slurm.conf from slurmctld over the cluster network.
getent group slurm >/dev/null || groupadd -r -g 450 slurm
getent passwd slurm >/dev/null || useradd -r -u 450 -g slurm -d /var/lib/slurm -s /sbin/nologin -c "Slurm" slurm
getent group slurmrestd >/dev/null || groupadd -r -g 451 slurmrestd
getent passwd slurmrestd >/dev/null || useradd -r -u 451 -g slurmrestd -d /nonexistent -s /sbin/nologin -c "Slurm REST API" slurmrestd
install -d -o slurm -g slurm -m 0755 /var/spool/slurmctld /var/lib/slurm
install -d -m 0755 /etc/slurm
# The munge key: on the head, and to the nodes as a flapjack secret (the
# slurm overlay installs it, owned by munge, mode 0400).
if [ ! -s /etc/munge/munge.key ]; then
  log "creating the munge key"
  dd if=/dev/urandom of=/etc/munge/munge.key bs=1024 count=1 status=none
fi
chown munge:munge /etc/munge/munge.key && chmod 0400 /etc/munge/munge.key
install -m 0640 -o root -g flapjackd /etc/munge/munge.key /etc/flapjack/secrets/munge.key
# Only slurmctld reads the JWT key; slurmrestd passes tokens through.
if [ ! -s /etc/slurm/jwt_hs256.key ]; then
  dd if=/dev/urandom of=/etc/slurm/jwt_hs256.key bs=32 count=1 status=none
fi
chown slurm:slurm /etc/slurm/jwt_hs256.key && chmod 0600 /etc/slurm/jwt_hs256.key
old=$(sha256sum /etc/slurm/slurm.conf 2>/dev/null || true)
get slurm.conf /etc/slurm/slurm.conf 0644
[ "$old" = "$(sha256sum /etc/slurm/slurm.conf)" ] || slurm_changed=1
# Login nodes submit jobs, so they need slurm.conf too: the login overlay
# includes this copy (flapjack switch --class login after editing it).
install -d -m 0755 /etc/flapjack/files/slurm
install -m 0644 /etc/slurm/slurm.conf /etc/flapjack/files/slurm/slurm.conf

# Users, with the UIDs the accounts overlay gives them on every node, and
# their homes in {{.HomeRoot}}, which the head exports over NFS to the
# cluster network. The Mac's lab key and this head's key may log in as
# them (to login nodes); there are no passwords.
install -d -m 0755 {{.HomeRoot}}
get lab-key.pub /etc/flapjack/lab-key.pub 0644
{{- range .Users}}
getent group {{.Name}} >/dev/null || groupadd -g {{.UID}} {{.Name}}
getent passwd {{.Name}} >/dev/null || useradd -u {{.UID}} -g {{.Name}} -d {{$.HomeRoot}}/{{.Name}} -m -s /bin/bash -c "{{.Name}} (lab user)" {{.Name}}
install -d -o {{.Name}} -g {{.Name}} -m 0700 {{$.HomeRoot}}/{{.Name}}/.ssh
cat /etc/flapjack/lab-key.pub /home/flapjack/.ssh/id_ed25519.pub > {{$.HomeRoot}}/{{.Name}}/.ssh/authorized_keys
chown {{.Name}}:{{.Name}} {{$.HomeRoot}}/{{.Name}}/.ssh/authorized_keys && chmod 0600 {{$.HomeRoot}}/{{.Name}}/.ssh/authorized_keys
{{- end}}
restorecon -R {{.HomeRoot}} 2>/dev/null || true
# NFS v4.2 only, to the cluster network; root on a node is nobody here.
# sec=sys trusts the client's UIDs: fine for a lab, use sec=krb5p for real.
cat > /etc/exports.d/flapjack-lab.exports <<'EOF'
{{.HomeRoot}} 10.100.0.0/16(rw,sync,root_squash,no_subtree_check,sec=sys)
EOF
if ! grep -q '^vers3=n' /etc/nfs.conf; then
  sed -i 's/^\[nfsd\]$/[nfsd]\nvers3=n/' /etc/nfs.conf
fi
nfs_reload=1
# The REST API: JWT authentication only, on loopback and on the NAT NIC
# that the Mac forwards 127.0.0.1:{{.RESTPort}} to. slurmrestd refuses to
# run as root or SlurmUser, so it has its own user.
cat > /etc/systemd/system/slurmrestd.service <<'EOF'
[Unit]
Description=Slurm REST API (flapjack lab)
Wants=network-online.target
After=network-online.target munge.service slurmctld.service

[Service]
User=slurmrestd
Group=slurmrestd
Environment=SLURM_JWT=daemon
ExecStart=/usr/local/sbin/fj-slurmrestd
Restart=on-failure
RestartSec=5s
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
# Without slurmdbd, the accounting (openapi/dbv*) plugins abort slurmrestd:
# load only the Slurm ones this version has.
cat > /usr/local/sbin/fj-slurmrestd <<'EOF'
#!/bin/sh
plugins=$(/usr/sbin/slurmrestd -s list 2>&1 | grep -o 'openapi/v[0-9.]*' | sort -u | paste -sd, -)
exec /usr/sbin/slurmrestd -a rest_auth/jwt -s "${plugins:-openapi/v0.0.38}" 127.0.0.1:6820 10.0.2.15:6820
EOF
chmod 0755 /usr/local/sbin/fj-slurmrestd
# Calls the REST API with a fresh token: fj-slurm-api ping | nodes | jobs | diag | PATH
cat > /usr/local/bin/fj-slurm-api <<'EOF'
#!/bin/sh
# Call slurmrestd as the current user, with a short-lived JWT from
# 'scontrol token'. The API version is found from the server's OpenAPI.
#   fj-slurm-api                      GET /slurm/<version>/ping
#   fj-slurm-api nodes | jobs | diag | partitions
#   fj-slurm-api /openapi/v3          any absolute path
#   fj-slurm-api job/submit -X POST -d @job.json
set -e
URL=${SLURM_REST_URL:-http://127.0.0.1:6820}
[ -n "${SLURM_JWT:-}" ] || SLURM_JWT=$(scontrol token lifespan=600 | sed 's/^SLURM_JWT=//')
api() { curl -fsS -H "X-SLURM-USER-NAME: $(id -un)" -H "X-SLURM-USER-TOKEN: $SLURM_JWT" "$@"; }
path=${1:-ping}
[ $# -gt 0 ] && shift
case "$path" in
  /*) ;;
  *)
    ver=${SLURM_API_VERSION:-$(api "$URL/openapi/v3" | tr -d '\\' | grep -o '/slurm/v0\.0\.[0-9]*/' | sort -uV | tail -1 | cut -d/ -f3)}
    path=/slurm/$ver/$path ;;
esac
api -H 'Content-Type: application/json' "$@" "$URL$path"
echo
EOF
chmod 0755 /usr/local/bin/fj-slurm-api
{{- end}}

# iPXE for the lab's nodes, built against this head's boot CA: it trusts
# only the head's HTTPS certificate and runs only scripts, kernels and
# initrds the head signed (pki/ipxe-embed.ipxe). Rebuilt when the CA or
# the embedded script changes, and handed to the Mac, which puts it on
# each node's boot disk.
IPXE_REV={{.IPXERev}}
PKI=/etc/flapjack/pki
stamp=$(cat $PKI/boot-ca.pem $PKI/ipxe-embed.ipxe | sha256sum | cut -c1-16)-$IPXE_REV
if [ "$(cat /var/lib/flapjack/boot/.ipxe-arm64.stamp 2>/dev/null)" != "$stamp" ]; then
  log "building signed iPXE ($IPXE_REV)"
  src=/usr/local/src/ipxe
  [ -d $src/.git ] || git clone -q https://github.com/ipxe/ipxe.git $src
  git -C $src fetch -q origin && git -C $src checkout -q --force $IPXE_REV
  printf '#define DOWNLOAD_PROTO_HTTPS\n#define IMAGE_TRUST_CMD\n' > $src/src/config/local/general.h
  make -s -C $src/src -j"$(nproc)" bin-arm64-efi/ipxe.efi TRUST=$PKI/boot-ca.pem EMBED=$PKI/ipxe-embed.ipxe
  install -m 0644 $src/src/bin-arm64-efi/ipxe.efi /var/lib/flapjack/boot/ipxe-arm64.efi
  echo "$stamp" > /var/lib/flapjack/boot/.ipxe-arm64.stamp
fi
curl -fsS --retry 5 -X PUT --data-binary @/var/lib/flapjack/boot/ipxe-arm64.efi "$SEED/ipxe/arm64"
{{- if .Tentacles}}

# Tentacle certificates: an identity from the cluster CA and a boot
# certificate from the boot CA, for each rack. They go to the tentacles
# over the management core with this head's SSH key, which the tentacles
# authorize for exactly two commands; no key passes through the Mac.
curl -fsS --retry 5 -X PUT --data-binary @/home/flapjack/.ssh/id_ed25519.pub "$SEED/head-key"
{{- range .TentacleList}}
d=/etc/flapjack/tentacles/{{.Rack}}
# Re-issued when missing or older than 20 days (they last 30).
if [ ! -s $d/tentacle.pem ] || [ -n "$(find $d/tentacle.pem -mtime +20)" ]; then
  log "issuing tentacle {{.Rack}}'s certificates"
  $FJ pki issue tentacle {{.Rack}} --out $d --boot-address {{.RackIP}} >/dev/null
fi
{{- end}}
cat > /usr/local/sbin/fj-lab-tentacles <<'EOF'
#!/bin/sh
# Install each tentacle's certificates on it (idempotent); retried by
# systemd until every tentacle has them.
rc=0
{{- range .TentacleList}}
tar czf - -C /etc/flapjack/tentacles/{{.Rack}} tentacle.pem tentacle.key ca.pem boot.pem boot.key |
  runuser -u flapjack -- ssh {{.CoreIP}} install-certs || rc=1
{{- end}}
exit $rc
EOF
chmod 0700 /usr/local/sbin/fj-lab-tentacles
cat > /etc/systemd/system/fj-lab-tentacles.service <<'EOF'
[Unit]
Description=Install the lab tentacles' certificates
Wants=network-online.target
After=network-online.target flapjack.service
StartLimitIntervalSec=0
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/fj-lab-tentacles
Restart=on-failure
RestartSec=10s
[Install]
WantedBy=multi-user.target
EOF
{{- end}}

cat > /etc/systemd/system/fj-lab-apply.service <<'EOF'
[Unit]
Description=Load the lab's nodes into flapjack
Requires=flapjack.service
After=flapjack.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/fj-lab-apply
[Install]
WantedBy=multi-user.target
EOF
cat > /usr/local/sbin/fj-lab-apply <<'EOF'
#!/bin/sh
# Load the lab's nodes once the API is up, and give every node its first
# overlay generation on a fresh lab.
set -e
for i in $(seq 30); do
  /usr/local/bin/flapjack apply --token-file /etc/flapjack/admin.token /etc/flapjack/lab-cluster.json >/dev/null && break
  sleep 1
done
if [ -z "$(ls -A /var/lib/flapjack/generations 2>/dev/null)" ]; then
  /usr/local/bin/flapjack switch --token-file /etc/flapjack/admin.token --all -m "lab bootstrap"
fi
EOF
chmod 0755 /usr/local/sbin/fj-lab-apply

cat > /etc/systemd/system/fj-lab-image.service <<'EOF'
[Unit]
Description=Build the lab's node image if it is missing or its agent is out of date
After=flapjack.service network-online.target
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/fj-lab-image
TimeoutStartSec=30min
[Install]
WantedBy=multi-user.target
EOF
cat > /usr/local/sbin/fj-lab-image <<'EOF'
#!/bin/sh
# Rebuild {{.Image}} when the flapjack binary (the node agent inside the
# image) or the image spec changed. Nodes waiting for an image boot as
# soon as it exists; running nodes pick up a new one when they reboot.
set -e
img=/var/lib/flapjack/images/{{.Image}}/image.json
want=$(sha256sum /usr/local/bin/flapjack | cut -d' ' -f1)
spec=/etc/flapjack/images/{{.Image}}.json
if [ -f "$img" ] && grep -q "\"agent\": \"sha256:$want\"" "$img" && { [ ! -f "$spec" ] || [ ! "$spec" -nt "$img" ]; }; then
  exit 0
fi
exec /usr/local/bin/flapjack image build -q {{.Image}}
EOF
chmod 0755 /usr/local/sbin/fj-lab-image

# The login screen: flapjack status, the layout, and things to try.
get welcome.sh /usr/local/bin/fj-welcome 0755
cat > /etc/profile.d/zz-flapjack-lab.sh <<'EOF'
# Flapjack lab: status and layout on interactive login (run fj-welcome
# again any time; touch ~/.hushlogin to skip it).
case $- in *i*) ;; *) return 0 2>/dev/null || exit 0 ;; esac
if [ -z "${FJ_WELCOMED:-}" ] && [ ! -e "$HOME/.hushlogin" ] && [ -x /usr/local/bin/fj-welcome ]; then
  export FJ_WELCOMED=1
  /usr/local/bin/fj-welcome
fi
EOF

systemctl daemon-reload
UNITS="flapjack.service fj-lab-apply.service fj-lab-image.service"
{{- if .Tentacles}}
UNITS="$UNITS fj-lab-tentacles.service munge.service slurmctld.service slurmrestd.service nfs-server.service"
{{- end}}
systemctl enable $UNITS
systemctl start --no-block $UNITS
{{- if .Tentacles}}
if [ -n "${nfs_reload:-}" ] && systemctl -q is-active nfs-server; then
  exportfs -ra
fi
# A changed slurm.conf reaches slurmctld (and, configless, every slurmd).
if [ -n "${slurm_changed:-}" ] && systemctl -q is-active slurmctld; then
  scontrol reconfigure || systemctl restart --no-block slurmctld
fi
{{- end}}
touch /var/lib/flapjack-lab-ready
log "done"
