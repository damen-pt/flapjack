#!/bin/sh
# Setup for {{.T.Name}}, rack {{.T.Rack}}'s tentacle in the Flapjack lab.
# fj-sync.service runs this on every boot after installing the latest
# flapjack binary. Every step is idempotent.
#
# The tentacle runs the rack's DHCP, serves its iPXE, boot scripts and
# images, and relays its agents to the head; the rack's nodes never reach
# the head. Its certificates come from the head over the management core,
# installed by the head's SSH key (authorized below for two commands only).
set -eu
SEED={{.Seed}}
log() { echo "tentacle-setup: $*"; }
get() { # URL-path dest mode
  curl -fsS --retry 5 --retry-connrefused "$SEED/$1" -o "$2.new"
  chmod "$3" "$2.new"
  if cmp -s "$2.new" "$2"; then rm -f "$2.new"; else mv "$2.new" "$2"; fi
}

# Names.
get hosts /etc/flapjack-lab-hosts 0644
awk '/# BEGIN flapjack-lab/{skip=1} !skip{print} /# END flapjack-lab/{skip=0}' /etc/hosts > /etc/hosts.new
cat /etc/flapjack-lab-hosts >> /etc/hosts.new && mv /etc/hosts.new /etc/hosts

# The rack takes its time from here; this tentacle from the head.
if ! grep -q '^allow {{.T.RackSubnet}}' /etc/chrony.conf; then
  sed -i 's/^\(pool\|server\) /#&/' /etc/chrony.conf
  printf 'server {{.HeadCore}} iburst\nallow {{.T.RackSubnet}}\nlocal stratum 11\n' >> /etc/chrony.conf
  systemctl try-restart chronyd
fi

# A lab firewall, if the image runs one, must let the rack boot.
if systemctl -q is-active firewalld 2>/dev/null; then
  for c in core rack; do
    firewall-cmd -q --zone=trusted --change-interface="$(nmcli -g connection.interface-name con show $c)"
  done
fi

getent group flapjack-tentacle >/dev/null || groupadd -r flapjack-tentacle
getent passwd flapjack-tentacle >/dev/null ||
  useradd -r -g flapjack-tentacle -d /var/lib/flapjack-tentacle -s /sbin/nologin -c "Flapjack tentacle" flapjack-tentacle
install -d -m 0750 -g flapjack-tentacle /etc/flapjack/tentacle

RACKIF=$(nmcli -g connection.interface-name con show rack)
cat > /etc/flapjack/tentacle.json.new <<EOF
{
  "rack": "{{.T.Rack}}",
  "head": "https://{{.HeadCore}}:{{.TentaclePort}}",
  "agentListen": "{{.T.RackIP}}:8443",
  "bootListen": "{{.T.RackIP}}:443",
  "dhcp": {
    "interface": "$RACKIF",
    "address": "{{.T.RackSubnet}}",
    "domain": "cluster",
    "leaseTime": "1h"
  }
}
EOF
if cmp -s /etc/flapjack/tentacle.json.new /etc/flapjack/tentacle.json; then
  rm /etc/flapjack/tentacle.json.new
else
  mv /etc/flapjack/tentacle.json.new /etc/flapjack/tentacle.json
  tentacle_changed=1
fi

# What the head's key may run here: install-certs (a tarball on stdin)
# and status.
cat > /usr/local/sbin/fj-install-certs <<'EOF'
#!/bin/sh
# Install this tentacle's certificates from a tarball on stdin.
set -eu
umask 077
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
tar xzf - -C "$tmp"
changed=
for f in tentacle.pem tentacle.key ca.pem boot.pem boot.key; do
  test -s "$tmp/$f" || { echo "missing $f" >&2; exit 1; }
  case $f in *.key) mode=0640 ;; *) mode=0644 ;; esac
  if ! cmp -s "$tmp/$f" "/etc/flapjack/tentacle/$f"; then
    install -m $mode -o root -g flapjack-tentacle "$tmp/$f" "/etc/flapjack/tentacle/$f.new"
    mv "/etc/flapjack/tentacle/$f.new" "/etc/flapjack/tentacle/$f"
    changed=1
  fi
done
# The tentacle re-reads changed certificates itself; a first install
# starts it.
if [ -n "$changed" ] || ! systemctl -q is-active flapjack-tentacle; then
  systemctl restart flapjack-tentacle
fi
echo "{{.T.Name}}: certificates installed"
EOF
cat > /usr/local/sbin/fj-tentacle-status <<'EOF'
#!/bin/sh
# One line for the head's login screen.
d=/var/lib/flapjack-tentacle
state=$(systemctl is-active flapjack-tentacle)
since=$(systemctl show -p ActiveEnterTimestamp --value flapjack-tentacle)
images=$(ls "$d/images" 2>/dev/null | tr '\n' ' ')
cert=$(/usr/local/bin/flapjack pki show /etc/flapjack/tentacle/tentacle.pem 2>/dev/null | grep -i -m1 'until\|not after\|expires' | sed 's/^ *//')
echo "service=$state since=\"$since\" images=\"${images% }\" cert=\"$cert\""
EOF
cat > /usr/local/sbin/fj-head-command <<'EOF'
#!/bin/sh
# Forced command for the head's SSH key.
case "${SSH_ORIGINAL_COMMAND:-}" in
  install-certs) exec sudo -n /usr/local/sbin/fj-install-certs ;;
  status) exec sudo -n /usr/local/sbin/fj-tentacle-status ;;
  *) echo "this key may run: install-certs, status" >&2; exit 1 ;;
esac
EOF
chmod 0755 /usr/local/sbin/fj-install-certs /usr/local/sbin/fj-tentacle-status /usr/local/sbin/fj-head-command

# The head's public key comes through the Mac (it is public); retried in
# the background until the head has sent it.
cat > /usr/local/sbin/fj-head-key <<'EOF'
#!/bin/sh
set -e
key=$(curl -fsS {{.Seed}}/head-key)
case "$key" in ssh-ed25519\ *) ;; *) exit 1 ;; esac
line="from=\"{{.HeadCore}}\",command=\"/usr/local/sbin/fj-head-command\",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding $key"
f=/home/flapjack/.ssh/authorized_keys
grep -qxF "$line" "$f" || echo "$line" >> "$f"
EOF
chmod 0755 /usr/local/sbin/fj-head-key
cat > /etc/systemd/system/fj-head-key.service <<'EOF'
[Unit]
Description=Authorize the lab head's SSH key (certificate installs)
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=0
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/fj-head-key
Restart=on-failure
RestartSec=10s
[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/flapjack-tentacle.service <<'EOF'
[Unit]
Description=Flapjack tentacle for rack {{.T.Rack}} (DHCP, boot, agent relay)
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=0

[Service]
# Waits for the head to install certificates.
ExecStartPre=/usr/bin/test -s /etc/flapjack/tentacle/tentacle.pem
ExecStart=/usr/local/bin/flapjack tentacle
Restart=always
RestartSec=10s
User=flapjack-tentacle
Group=flapjack-tentacle
StateDirectory=flapjack-tentacle
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
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK AF_PACKET
LockPersonality=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable fj-head-key.service flapjack-tentacle.service
systemctl start --no-block fj-head-key.service
if [ -n "${tentacle_changed:-}" ]; then
  systemctl try-restart --no-block flapjack-tentacle.service
fi
systemctl start --no-block flapjack-tentacle.service
log "done"
