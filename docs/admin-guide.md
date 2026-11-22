# Flapjack administrator guide

This guide covers running Flapjack on a real cluster: installing the head
node, describing nodes, building images, managing configuration with
overlays, and day-to-day operations. For the design and the reasoning behind
it, see [ARCHITECTURE.md](ARCHITECTURE.md). To try Flapjack without hardware,
see the [Mac test lab](testing/mac-lab.md).

Flapjack is in early development. Where something is planned rather than
built, this guide says so.

## Contents

1. [How a Flapjack cluster fits together](#1-how-a-flapjack-cluster-fits-together)
2. [Requirements](#2-requirements)
3. [Installing the head node](#3-installing-the-head-node) (and [3.7 Boot windows](#37-boot-windows))
4. [API access and tokens](#4-api-access-and-tokens)
5. [Describing the cluster](#5-describing-the-cluster)
6. [Node images](#6-node-images)
7. [How nodes boot](#7-how-nodes-boot)
8. [Overlays](#8-overlays)
9. [Generations: build, switch, rollback](#9-generations-build-switch-rollback)
10. [Drift and the node agent](#10-drift-and-the-node-agent)
11. [Node lifecycle](#11-node-lifecycle)
12. [Events and auditing](#12-events-and-auditing)
13. [Upgrades, backups and recovery](#13-upgrades-backups-and-recovery)
14. [Troubleshooting](#14-troubleshooting)
15. [Security model](#15-security-model)
16. [Racks and tentacles](#16-racks-and-tentacles)
17. [Other tools](#17-other-tools)
18. [Reference](#18-reference)

## 1. How a Flapjack cluster fits together

```
                 admin (ssh)
                     │
             ┌───────┴────────┐  provisioning network (e.g. 10.99.0.0/16)
             │   head node    │──────────┬──────────┬──────────┐
             │ flapjack.service│         │          │          │
             └────────────────┘       node        node       node
               DHCP 67, TFTP 69,     (no disk needed; boots from the
               HTTPS 443, agents      network into RAM, runs the agent)
               8443, API 7443
```

- **Head node:** runs `flapjack.service`, a single static binary that answers
  DHCP, serves boot files and images, renders overlays and hosts the API.
  All state lives in `/etc/flapjack` (what you write) and `/var/lib/flapjack`
  (what Flapjack writes).
- **Nodes:** network-boot an image you build, run it from RAM, and run
  `flapjack agent`, which keeps their files equal to their current overlay
  generation.
- **Treat nodes like containers:** a node is defined by its class (image and
  overlays) plus its identity (name, MAC, IP, rack). Rebooting a node gives
  back exactly that, with nothing left over from before.

## 2. Requirements

**Head node**

- An EL9 system (RHEL, Rocky, AlmaLinux) on x86_64 or aarch64, as root.
- A network interface on the provisioning network with a static address,
  for example `10.99.0.1/16`.
- No other DHCP server on the provisioning network. Flapjack only answers
  MACs it knows, but other servers will still answer them.
- `dnf`, `systemd`, `squashfs-tools` and `restorecon` (in
  `policycoreutils`), all from the distribution.
- Package repositories for building node images, either the distribution
  mirrors or local mirrors for airgapped sites.
- Optional: a static `nix` binary and nixpkgs' `lib/` for the Nix overlay
  engine ([section 8.3](#83-nix-modules)).

**Nodes**

- Network boot (PXE or UEFI HTTP boot), or iPXE in the NIC.
- RAM for the root filesystem: the image is downloaded into memory. A minimal
  EL9 image is about 130 MiB compressed; 2 GiB of RAM is a comfortable
  minimum for small images.
- Optional but recommended: a BMC (Redfish or IPMI) for power control.
- The same CPU architecture as the head node (see the
  [image limitations](#64-limitations)).

## 3. Installing the head node

### 3.1 Get the binary

Flapjack is one static binary with no dependencies. Build it from source
(Go 1.26):

```sh
make dist      # bin/flapjack-linux-amd64 and bin/flapjack-linux-arm64
```

Copy the one for your head node's architecture to
`/usr/local/bin/flapjack` on the head node.

For tab completion of commands, flags, node names, classes and images:

```sh
flapjack completion bash | sudo tee /etc/bash_completion.d/flapjack >/dev/null
```

It takes effect in new shells. Node and class names come from the API, so
they complete for users who can run `flapjack nodes`. Other users still get
commands and flags.

### 3.2 Install the service

```sh
sudo flapjack server install --address 10.99.0.1/16
```

This:

- creates the `flapjackd` system user;
- writes `/etc/flapjack/server.json`, `/etc/flapjack/tokens.json` and an
  admin token in `/etc/flapjack/admin.token` (readable by root only);
- creates the cluster PKI in `/etc/flapjack/pki` ([3.6](#36-pki-and-encrypted-boot)),
  including an admin certificate for root (`admin.pem`, `admin.key`);
- creates `/etc/flapjack/{overlays,files,secrets}` and
  `/var/lib/flapjack/{boot,images}`;
- writes `/etc/systemd/system/flapjack.service`, then enables and starts
  it.

Options: `--interface` (default: the interface holding `--address`),
`--domain` (DNS domain given to nodes, default `cluster`), `--router` (a
default gateway for nodes; none by default, which suits an isolated
provisioning network), `--no-start`, and `--force` to replace an existing
`server.json`.

Rerunning `server install` is safe. It keeps the existing config and token,
rewrites the unit, and restarts the service.

### 3.3 Check it

```sh
systemctl status flapjack
journalctl -u flapjack -f
sudo ss -tulpn | grep flapjack
```

You should see UDP 67 (bound to the provisioning interface), UDP 69 and
TCP 443 and 8443 on the provisioning address, and TCP 7443 on 127.0.0.1.
Nothing listens on TCP 80 unless you turn on `plainHTTP`.

If `firewalld` is running, open DHCP, TFTP, HTTPS and the agent port on
the provisioning interface's zone, for example:

```sh
sudo firewall-cmd --zone=internal --change-interface=eth1 --permanent
sudo firewall-cmd --zone=internal --add-service={dhcp,tftp,https} --add-port=8443/tcp --permanent
sudo firewall-cmd --reload
```

### 3.4 iPXE binaries

PXE ROMs load iPXE over TFTP first, and UEFI HTTP boot loads it over
HTTPS. Put the iPXE builds you need in `/var/lib/flapjack/boot/`. They must
be built against your boot CA, with the verifying script embedded
([3.6](#36-pki-and-encrypted-boot)): the head only serves signed scripts over
HTTPS, so upstream builds from ipxe.org cannot boot anything.

| File | For |
|---|---|
| `undionly.kpxe` | legacy BIOS PXE |
| `ipxe-x86_64.efi` | x86_64 UEFI (PXE and HTTP boot) |
| `ipxe-arm64.efi` | aarch64 UEFI (PXE and HTTP boot) |

TFTP serves only these files (`.efi` and `.kpxe`), nothing else in the
directory. Nodes whose NIC already runs a suitably built iPXE skip this
step.

### 3.5 Configuration file

`/etc/flapjack/server.json`, as written by `server install`:

```json
{
  "address": "10.99.0.1/16",
  "domain": "cluster",
  "leaseTime": "1h0m0s",
  "tftp": true,
  "dataDir": "/var/lib/flapjack",
  "api": {
    "listen": "127.0.0.1:7443",
    "tokens": "/etc/flapjack/tokens.json"
  },
  "overlayDir": "/etc/flapjack/overlays",
  "secretsDir": "/etc/flapjack/secrets",
  "filesDir": "/etc/flapjack/files",
  "nix": {
    "bin": "/usr/local/bin/nix",
    "nixpkgs": "/usr/local/share/flapjack/nixpkgs"
  }
}
```

| Field | Meaning |
|---|---|
| `address` | Head node address and prefix on the provisioning network. DHCP, TFTP, HTTPS boot and the agent listener bind here |
| `interface` | Provisioning interface; found from `address` when empty |
| `router`, `dns`, `domain` | Gateway, DNS servers and domain handed to nodes by DHCP |
| `leaseTime` | DHCP lease time. Addresses are fixed reservations, so this only sets how often nodes renew |
| `tftp` | Serve the iPXE binaries over TFTP for PXE ROMs (default `true`) |
| `plainHTTP`, `httpPort` | Off by default. Serve the iPXE binaries, and nothing else, over plain HTTP on `httpPort` (default 80), for UEFI HTTP-boot firmware that cannot do HTTPS |
| `httpsPort` | HTTPS boot: signed scripts, iPXE binaries and images (default 443) |
| `agentPort` | Agents of racks without a tentacle, over mTLS (default 8443) |
| `bootWindow`, `armFor`, `bmc` | What lets a node boot ([3.7](#37-boot-windows)) |
| `dataDir` | Flapjack's state |
| `api.listen` | API address (default `127.0.0.1:7443`). Always TLS, and every client needs a cluster certificate as well as a token ([4](#4-api-access-and-tokens)) |
| `api.tlsCert`, `api.tlsKey`, `api.clientCA` | Override the API's server certificate (default the head's, `pki/head.pem`) and the CA its clients' certificates must chain to (default the cluster CA) |
| `overlayDir`, `secretsDir`, `filesDir` | Overlay sources, secrets, and shared files templates may include |
| `nix.bin`, `nix.nixpkgs` | The Nix engine. Leave unset if you only use templates |

| `pkiDir` | The cluster CA and keys (default `/etc/flapjack/pki`; see [3.6](#36-pki-and-encrypted-boot)) |
| `nodeCertTTL` | Lifetime of node certificates (default `24h`) |
| `tentacleListen`, `tentacles` | Per-rack tentacles ([16](#16-racks-and-tentacles)) |
| `tentacleBoot` | Racks that boot their images from their tentacle ([16](#16-racks-and-tentacles)) |
| `tentacleDHCP` | Racks whose tentacle runs their DHCP and whole boot; the head's DHCP ignores them ([16](#16-racks-and-tentacles)) |

Restart the service after editing: `sudo systemctl restart flapjack`.

There is no setting that turns any of this off. `bootTLS` and `signedBoot`
from older configs are accepted only as `true`, and `insecureBootTickets`
is refused, so an old config can't quietly weaken the head.

### 3.6 PKI and encrypted boot

`server install` runs `flapjack pki init`, which creates the cluster's keys
in `/etc/flapjack/pki` (rerunning it never replaces them):

| File | Use |
|---|---|
| `ca.pem`, `ca.key` | Cluster CA (Ed25519): mutual TLS between the head, tentacles and nodes |
| `generation.key`, `generation.pub` | The head signs every generation it serves; agents verify with the public key |
| `ticket.key` | Boot tickets nodes use to enroll |
| `head.pem`, `head.key` | The head's identity towards tentacles and agents, and the API's server certificate |
| `admin.pem`, `admin.key` | An admin certificate for root on the head (key 0600, root only). The CLI presents it to the API |
| `boot-ca.pem`, `boot-ca.key`, `boot.pem`, `boot.key` | A separate RSA CA and certificate for HTTPS boot, because iPXE verifies RSA and speaks TLS 1.2 |
| `codesign.pem`, `codesign.key`, `ipxe-embed.ipxe` | The boot CA's code-signing certificate, which signs every script, kernel and initrd, and the script to embed in iPXE |

`image build` copies the public files (`ca.pem`, `generation.pub`,
`boot-ca.pem`) into images and adds the boot CA to their trust store.
Agents refuse unsigned generations, so images built before `pki init`
can't run an agent; rebuild them.

**Encrypted, signed boot.** This is how every node boots; there is no
other mode. Scripts, kernels, initrds and root filesystems are served only
over HTTPS (port 443, the boot certificate), and DHCP points iPXE at
`https://`. The head signs every script, kernel and initrd with
`codesign.pem`, and scripts `imgverify` them before booting. The root
filesystem's sha256 goes on the kernel command line, and the image's
initrd refuses to switch to anything else. Images must be built after
`pki init`, because they carry the `flapjack-verify` dracut module. iPXE
must trust the boot CA, run only signed scripts and have the trust
commands, so build it with the script `pki init` wrote:

```sh
git clone https://github.com/ipxe/ipxe && cd ipxe/src
printf '#define DOWNLOAD_PROTO_HTTPS\n#define IMAGE_TRUST_CMD\n' >> config/local/general.h
make bin-x86_64-efi/ipxe.efi bin/undionly.kpxe TRUST=/etc/flapjack/pki/boot-ca.pem EMBED=/etc/flapjack/pki/ipxe-embed.ipxe
make bin-arm64-efi/ipxe.efi CROSS=aarch64-linux-gnu- TRUST=/etc/flapjack/pki/boot-ca.pem EMBED=/etc/flapjack/pki/ipxe-embed.ipxe
```

iPXE source leaves HTTPS off by default (`DOWNLOAD_PROTO_HTTPS`), hence
the first line. An iPXE without `IMAGE_TRUST_CMD` stops at the first
`imgverify`.

**Image tokens.** Nothing on the provisioning network can download an
image just by asking. A node's script carries a token for its image
version, minted for that node's reserved IP during its boot window
([3.7](#37-boot-windows)) and valid for an hour. The head, and a rack's
tentacle, serve an image file only with a valid token, presented from the
address it names, for the version it names (`/images/VERSION/TOKEN/FILE`).
Tentacles check tokens with a key derived for their rack, which can't
mint tokens for other racks. Logs show tokens as `…`. Admins read images
on the head's filesystem.

This path has been run end to end in the Mac lab with iPXE built from
master (`e6555a5`, "2.0.0+"): the script, kernel and initrd verified, and
the initrd checked the root filesystem. A root filesystem with 4 KiB
appended was refused in the initrd, and a kernel with 512 bytes appended
was refused by iPXE ("Could not verify: Permission denied"). The boot
listener sends the boot CA along with its certificate, because iPXE's
`TRUST=` holds only fingerprints, and it negotiates TLS 1.2 only, because
iPXE 2.0's TLS 1.3 handshake with Go fails.

Install the results as in [3.4](#34-ipxe-binaries). Check the boot
certificate's addresses with `flapjack pki show /etc/flapjack/pki/boot.pem`;
if the head's address changes, delete `boot.pem` and `boot.key` and rerun
`flapjack pki init --boot-address NEW`.

### 3.7 Boot windows

A node's script carries its enrollment ticket and image tokens only during
its boot window. Outside one, the script waits and asks again, and nothing
boots. Each window is good for one bootable script. `bootWindow` chooses
what opens one:

| `bootWindow` | Windows open when |
|---|---|
| `armed` (default) | Only on authorized triggers, open `armFor` (default `15m`, enough for server firmware to POST): flapjack power-cycling the node through its BMC; the node's agent announcing a reboot (over mTLS, or through its tentacle with a notice the node signed); an admin running `flapjack node boot NODE`; or the BMC watcher (below) |
| `dhcp` | DHCP answers the node's iPXE (MAC) with a boot script. Open 2 minutes. A node outside a window re-runs DHCP before asking again |

`armed` means a spoofed MAC opens nothing. The cost is that a boot nothing
authorized has to wait, for example a node someone power-cycled by hand,
or a new node's first boot: run `flapjack node boot NODE`, or give the head
its BMC settings (below). `dhcp` keeps crashed nodes coming back
unattended, but anything on the provisioning network that can send DHCP
with a node's MAC and take its address can open that node's window, enroll
as the node and read its secrets. Choose it at install with
`flapjack server install --boot-window dhcp`, or set it in `server.json`,
only on a provisioning network nothing untrusted can reach.

For power loss, give the head its BMC settings and it watches each node's
power state over Redfish:

```json
"bootWindow": "armed",
"bmc": { "user": "admin", "passwordFile": "/etc/flapjack/secrets/bmc-password", "ca": "/etc/flapjack/bmc-ca.pem", "poll": "15s" }
```

When a BMC reports a node going from off to on, the head opens its window.
When the BMC is unreachable or the head is just starting (after a site
outage, say), the head opens the window only if the BMC reports the node on
and its agent has been silent for 2 minutes. Each power-on opens one window. BMC
certificates must chain to `bmc.ca`; the system trust store is never used,
and IPMI BMCs are skipped.

Every window opened is logged as `boot.window_opened` with what opened it,
and a script served outside one as `boot.window_closed`.

## 4. API access and tokens

Every `flapjack` admin command talks to the API on `https://127.0.0.1:7443`,
and the API requires two things on every request:

- **A cluster certificate.** Admin tokens need an admin certificate
  (`flapjack://admin/NAME`). A node-scoped token needs that node's own
  certificate. A stolen token alone is useless.
- **A bearer token**, which decides the role.

Commands look for `admin.pem`, `admin.key` and `ca.pem` in `--cert-dir`,
then `~/.config/flapjack`, then `/etc/flapjack/pki` (works as root). They
find a token in this order:

1. `--token-file FILE`
2. `$FLAPJACK_TOKEN`
3. `~/.config/flapjack/token`
4. `/etc/flapjack/admin.token` (works as root)

To let an admin account run commands without `sudo`, give it its own admin
certificate and a token:

```sh
sudo flapjack pki issue admin alice --ttl 2160h --out ~alice/.config/flapjack
sudo install -D -m 0600 /etc/flapjack/admin.token ~alice/.config/flapjack/token
sudo chown -R alice: ~alice/.config/flapjack
```

**Roles:** `1` viewer (read), `2` operator (switch, rollback, drain,
quarantine), `3` admin (create classes and nodes). The service stores only
SHA-256 hashes of tokens. To add a token:

```sh
TOKEN=$(head -c 24 /dev/urandom | base32)
HASH=$(printf %s "$TOKEN" | sha256sum | cut -d' ' -f1)
sudo vi /etc/flapjack/tokens.json     # add: "<HASH>": {"name": "grafana", "role": 1}
sudo systemctl restart flapjack
echo "$TOKEN"                         # give this to the user; it is not stored anywhere
```

An admin token can also name the one admin certificate it works with, so
a token copied from one admin is useless with another's certificate, and
the audit trail's actor really is that certificate's holder:
`"<HASH>": {"name": "alice", "role": 3, "cert": "alice"}`. Tokens without
`cert` work with any admin certificate.

A node-scoped token works only with a certificate the node still accepts:
not one revoked (`flapjack node revoke`) or replaced by a newer enrollment,
and not a retired node's ([15](#15-security-model)).

**Remote access:** run commands on the head node over SSH, or set
`api.listen` to a routable address and use `--api https://HEAD:7443` from
a machine holding an admin certificate. The API is never plaintext, and
it checks the client certificate before the token.

## 5. Describing the cluster

The cluster is declared in JSON as classes and nodes, then loaded with
`flapjack apply`:

```json
{
  "classes": [
    {
      "name": "compute",
      "image": "el9-compute",
      "rootfs": "tmpfs",
      "bootArgs": ["console=ttyS0,115200"],
      "overlays": ["base", "site", "compute"]
    }
  ],
  "nodes": [
    {
      "name": "r1n01",
      "class": "compute",
      "rack": "r1",
      "firmware": "uefi",
      "labels": {"gpu": "none"},
      "bmc": {"driver": "redfish", "address": "https://10.98.1.1"},
      "interfaces": [
        {"name": "prov", "mac": "52:54:00:01:01:01", "network": "provisioning", "ip": "10.99.1.1"}
      ]
    }
  ]
}
```

```sh
flapjack apply cluster.json
flapjack nodes
```

- A **class** is the template shared by a group of nodes: the image they
  boot, extra kernel arguments, and the overlays they get, in order.
- A **node** is one machine. Its first interface's MAC and IP become its DHCP
  reservation. MACs and IPs must be unique across nodes; `apply` refuses
  duplicates.
- `apply` is idempotent. It creates or replaces specs and keeps each node's
  status. Keep the file in git and re-apply it after every change.
- `labels` are free-form; templates and Nix modules can use them, for
  example to configure GPU nodes differently.

New nodes start in the `Discovered` phase ([section 11](#11-node-lifecycle)).

## 6. Node images

### 6.1 Building

```sh
sudo flapjack image build el9-compute
flapjack image list
```

`image build` runs on the head node as root. It:

1. installs packages into a new root with `dnf --installroot`, using the
   head node's repositories;
2. installs the Flapjack agent (this same binary) and enables
   `flapjack-agent.service`;
3. builds a generic initramfs with dracut's `livenet` and `dmsquash-live`
   modules, so a node can download its root filesystem at boot;
4. applies SELinux labels and packs a zstd squashfs;
5. stores the result as `/var/lib/flapjack/images/el9-compute@<id>/` and
   points the `el9-compute` link at it.

A minimal image builds in about 80 s and is about 130 MiB.

### 6.2 Image specs

Without a spec file, an image gets the base packages Flapjack needs (kernel,
systemd, NetworkManager, OpenSSH, chrony, sudo, SELinux policy and a few
tools). Add packages with `/etc/flapjack/images/NAME.json`:

```json
{
  "release": "9",
  "packages": ["munge", "slurm-slurmd", "nfs-utils", "rdma-core"],
  "services": ["sshd", "chronyd", "NetworkManager", "munge", "slurmd"],
  "reposDir": "/etc/yum.repos.d",
  "disableRepos": ["epel*"],
  "selinux": true
}
```

| Field | Default | Meaning |
|---|---|---|
| `release` | `9` | dnf `releasever` |
| `packages` | none | Installed in addition to the base set |
| `services` | `sshd`, `chronyd`, `NetworkManager` | Units enabled at boot. Setting this replaces the default list, so include those three |
| `reposDir` | `/etc/yum.repos.d` | Repository definitions. Point it at local mirrors for airgapped builds |
| `disableRepos` | `epel*` | Repository IDs or globs to skip |
| `selinux` | `true` | Label the image so nodes can run enforcing |

Configuration does not belong in the image: put it in overlays, which change
without a rebuild or reboot.

### 6.3 Versions and rollback

Every build is kept. Nodes boot whatever the image link points at when they
boot, and the boot script names that exact version, so a build that finishes
mid-boot cannot mix two versions.

```sh
flapjack image list                         # * marks the current version
sudo flapjack image use el9-compute el9-compute@3f2a9c0e41d7   # roll back
```

Running nodes keep the image they booted. Reboot them to pick up a new one.
Old versions are not deleted automatically; remove unused
`images/NAME@<id>/` directories by hand.

### 6.4 Limitations

- Images are built for the head node's architecture only.
- The image is versioned separately from overlay generations; it is not yet
  part of a node's generation.
- The agent inside an image is the `flapjack` binary that built it. After
  upgrading Flapjack, rebuild images ([section 13](#13-upgrades-backups-and-recovery)).

## 7. How nodes boot

```
power on ─► NIC PXE/HTTP boot ─► DHCP (head answers known MACs only)
        ─► iPXE (TFTP or HTTPS, or already in the NIC), built with the boot CA
        ─► https://HEAD/boot/<mac>.ipxe + .sig   (only to that node's IP; verified)
        ─► kernel + initramfs over HTTPS, each verified (imgverify)
        ─► initramfs downloads rootfs.squashfs into RAM, checks its sha256,
           overlayfs on top
        ─► systemd ─► flapjack-agent enrolls with its boot ticket (mTLS),
           then applies the node's signed overlay generation
        ─► sshd, chronyd, … start with their configuration in place
```

Only inside the node's boot window ([3.7](#37-boot-windows)) does its script
carry the enrollment ticket and the image tokens.

- DHCP chooses what to send from what the client reports. iPXE gets its node
  script, UEFI HTTP boot gets iPXE over HTTPS (HTTP with `plainHTTP`), and
  PXE ROMs get iPXE over TFTP. Relayed DHCP (`giaddr`) works for routed
  racks.
- If a node's class has no built image, its script prints why on the console
  and asks again every 30 s. Building the image is enough to boot it.
- A `Retired` node's script exits without booting.
- The kernel command line carries `flapjack.node`, `flapjack.server` (the
  head's agent listener, or `flapjack.tentacle` and `flapjack.rack`),
  `flapjack.generation`, `flapjack.rootfs`, `flapjack.mac` and
  `flapjack.ticket`, plus the class's `bootArgs`.

Check what a node is doing with `flapjack events --node r1n01 --type boot.`
and its serial console.

## 8. Overlays

Overlays are how nodes get their configuration. Each overlay is a directory
in `/etc/flapjack/overlays/` (keep it in git). A class lists its overlays in
order, and later overlays replace earlier ones path by path; the build output
warns when that happens.

Overlays are rendered on the head node. Nodes receive plain files and never
run a template or Nix.

Two engines are available. Each overlay uses exactly one:

| Engine | Overlay contains | Good for |
|---|---|---|
| Template | `rootfs/` tree, optional `overlay.json` | Files that are mostly static, Warewulf-style per-node templating |
| Nix | `default.nix` | Typed, composable settings where several overlays contribute to the same files |

[Overlays by example](overlay-use-cases.md) shows which engine fits Slurm,
PBS, Lmod, per-project environments, setting nodes aside for a group, and
turning a compute node into an RKE2 worker.

```sh
flapjack overlay list      # name, engine, which classes use it
```

### 8.1 Template overlays

```
/etc/flapjack/overlays/base/
├── overlay.json
└── rootfs/
    ├── etc/
    │   ├── chrony.conf.ww
    │   ├── hosts.ww
    │   └── sudoers.d/admins
    └── root/.ssh/authorized_keys.ww
```

- Every file under `rootfs/` is installed at the same path on the node, with
  the same mode.
- Files ending in `.ww` are Go templates rendered per node, and lose the
  suffix.
- Symlinks are installed as symlinks.
- Directories are created as needed but are not managed (never chmod-ed or
  removed) unless listed under `directories` in `overlay.json`.

**Template data:**

| Name | Value |
|---|---|
| `.Node.Name`, `.Node.Rack`, `.Node.IP`, `.Node.MAC`, `.Node.Class`, `.Node.Labels` | This node |
| `.Nodes` | Every node in the cluster, sorted by name |
| `.Class` | This node's class (`.Class.Name`, `.Class.Image`, `.Class.Overlays`) |
| `.Server`, `.Domain` | Head node address and DNS domain |
| `.Id`, `.Hostname`, `.Ipaddr` | Warewulf-compatible names for the node name and IP |

**Functions:** `Include "path"` (a file from this overlay's directory or
`/etc/flapjack/files`, nowhere else), `abort` (produce no file for this
node), `inRack "r1"`, `inClass "gpu"`, `label .Node "gpu"`, `join`, `split`,
`lower`, `upper`, `trim`, `replace` and `hasPrefix`. A missing field is an
error rather than an empty string.

```
# /etc/flapjack/overlays/base/rootfs/etc/hosts.ww
127.0.0.1   localhost
{{.Server}}  head.{{.Domain}} head
{{range .Nodes}}{{.IP}}  {{.Name}}.{{$.Domain}} {{.Name}}
{{end -}}
```

```
# Only on GPU nodes:
{{if ne (label .Node "gpu") "a100"}}{{abort}}{{end}}options nvidia NVreg_...
```

**`overlay.json`** (optional) sets metadata by node path. Keys can be exact
paths or globs; an exact path wins over a glob.

```json
{
  "paths": {
    "/etc/chrony.conf": {"onChange": ["systemctl try-restart chronyd"]},
    "/etc/ssh/sshd_config.d/*": {"mode": "0600", "onChange": ["systemctl try-reload-or-restart sshd"]},
    "/etc/sudoers.d/*": {"mode": "0440"},
    "/etc/motd": {"policy": "report"}
  },
  "directories": {
    "/root/.ssh": {"mode": "0700"}
  },
  "secrets": {
    "/etc/munge/munge.key": {"secret": "munge.key", "mode": "0400", "owner": "munge", "group": "munge"}
  },
  "exclusive": ["/etc/sudoers.d"]
}
```

| Key | Fields |
|---|---|
| `paths` | `mode`, `owner`, `group`, `policy`, `seContext`, `onChange`, `onRemove` |
| `directories` | Directories to manage explicitly: `mode`, `owner`, `group` |
| `secrets` | Files whose content is a secret ([8.4](#84-secrets)): `secret` plus any `paths` field |
| `exclusive` | Directories that must hold exactly what the overlays declare ([8.5](#85-policies-hooks-and-exclusive-directories)) |

Unknown keys are an error, so typos fail the build instead of being ignored.

### 8.2 Ownership

`owner` and `group` are names, resolved on each node against its own
`/etc/passwd` and `/etc/group` when the agent applies the overlay. System
users (such as `munge` or `slurm`) can therefore have different IDs in
different images. A name that does not exist on the node fails the apply, so
a key meant for `munge` never ends up owned by root.

### 8.3 Nix modules

A Nix overlay is a `default.nix` written like a NixOS module. All Nix overlays
of a class are evaluated together for each node with nixpkgs'
`lib.evalModules`. You get the NixOS module system's behaviour:

- one overlay declares typed options and another sets them;
- `lib.mkDefault` and `lib.mkForce` decide which value wins;
- `lib.mkIf` makes settings conditional on the node;
- `lines` and lists merge across modules;
- `assertions` fail the build with your message.

Modules receive `node` (as in templates: `node.name`, `node.rack`,
`node.labels`…), `nodes`, `cluster` and `class`. They produce files through
these options:

```nix
{ lib, config, node, ... }:
{
  options.site.sysctl = lib.mkOption {
    type = with lib.types; attrsOf (oneOf [ int str ]);
    default = { };
  };

  config = {
    site.sysctl."vm.swappiness" = lib.mkDefault 10;

    files."/etc/sysctl.d/90-site.conf" = {
      text = lib.concatStrings (lib.mapAttrsToList (k: v: "${k} = ${toString v}\n") config.site.sysctl);
      onChange = [ "sysctl --system" ];
    };
    files."/etc/motd".source = ./motd;              # a file in this overlay
    files."/etc/munge/munge.key" = { secret = "munge.key"; owner = "munge"; mode = "0400"; };
    directories."/var/spool/site".mode = "0750";
    symlinks."/etc/localtime" = "/usr/share/zoneinfo/UTC";
    exclusive = [ "/etc/slurm/conf.d" ];

    assertions = [{
      assertion = config.site.sysctl."vm.swappiness" <= 100;
      message = "vm.swappiness must be 0-100";
    }];
  };
}
```

A second overlay can then override per rack:

```nix
{ lib, node, ... }:
lib.mkIf (node.rack == "r2") {
  site.sysctl."vm.swappiness" = lib.mkForce 1;
}
```

**`files.<path>` options:** exactly one of `text`, `source` or `secret`, plus
`mode` (default `0644`), `owner`, `group` (default `root`), `policy`,
`seContext`, `onChange`, `onRemove`, and `enable` (default `true`). Also
available: `directories.<path>` (`mode`, `owner`, `group`),
`symlinks.<path> = target`, `exclusive`, `assertions` and `warnings`.

**Setting up Nix on the head node.** Flapjack needs a static `nix` binary and
the `lib/` directory of a nixpkgs checkout; it does not need a Nix store, a
daemon or root. The [Mac lab](testing/mac-lab.md) pins:

```sh
# Static Nix 2.35.5. aarch64:
curl -L -o /usr/local/bin/nix https://hydra.nixos.org/build/351751017/download/1/nix
echo "e1f2ac2d70425a030d0267bd7afa91e3f11d966edc4fd507042e23bdfbe0dfd5  /usr/local/bin/nix" | sha256sum -c
# x86_64: https://hydra.nixos.org/build/351751030/download/1/nix
#   sha256 5dd75cf116e6e0766df1a433bf555f7033cc8dacbe5e0b0542c0838c3b2c5ae0
chmod 0755 /usr/local/bin/nix

# nixpkgs 26.05; only lib/ is used.
curl -L https://github.com/NixOS/nixpkgs/archive/7dcdd87373d72e7a2173e4db02e20d3d7f495cfd.tar.gz \
  | tar xz --wildcards '*/lib'
sudo mkdir -p /usr/local/share/flapjack
sudo mv nixpkgs-7dcdd87373d72e7a2173e4db02e20d3d7f495cfd /usr/local/share/flapjack/nixpkgs
sudo systemctl restart flapjack
```

For airgapped sites, download both elsewhere and copy them in. The service
logs `the nix engine is not configured` at start if it cannot find them; only
Nix overlays are affected.

**Evaluation is confined.** It runs with `--store dummy://` and
`restrict-eval`: modules can read the overlays being evaluated and nixpkgs'
`lib`, and nothing else, so they cannot read other files on the head node or
fetch from the network. NixOS's own service modules (`services.*`) are not
available, because they assume `/nix/store` paths.

### 8.4 Secrets

Put secrets in `/etc/flapjack/secrets/` (owned by root, group `flapjackd`,
mode 0750 on the directory) and reference them by file name:

```sh
sudo install -m 0640 -g flapjackd /dev/null /etc/flapjack/secrets/munge.key
sudo dd if=/dev/urandom of=/etc/flapjack/secrets/munge.key bs=1024 count=1
```

Secrets never pass through a template or a Nix evaluation: the head node
reads the file when it builds the generation. Secret files default to mode
0600 on nodes. The content is only served to nodes whose generation contains
it (see [section 15](#15-security-model) for the current limits of node
identity).

Secrets are **sealed to their node** on the way. Each node makes a seal
key when it enrolls with its boot ticket (it lives in RAM with the node's
certificate and is gone at reboot), and the head encrypts every secret it
serves the node to that key with HPKE (ML-KEM-768 + X25519, AES-256-GCM),
bound to the node and the file. A tentacle caches and relays the sealed
blob but cannot open it, and the agent checks what it opens against the
signed manifest as for any file. A node whose agent enrolled without a
seal key (an image built before this release) gets a 409 for its secrets
until it reboots into a current image.

### 8.5 Policies, hooks and exclusive directories

Every managed path has a **policy**:

| Policy | Local edit on the node | Overlay changes the file | File removed from the overlay |
|---|---|---|---|
| `enforce` (default) | Reverted within a minute; logged as drift and repaired | Overwritten | Deleted, or the image's own copy restored |
| `report` | Kept; shown as drift | Overwritten | Kept if edited, otherwise removed |
| `seed` | Kept; never reported | Updated only if untouched since Flapjack wrote it | Kept if edited, otherwise removed |

**Hooks:** `onChange` commands run after a path is written, and `onRemove`
commands after it is removed. Each runs once per apply even if many files
asked for it, with a two-minute timeout. Prefer `try-restart` and
`try-reload-or-restart`, which do nothing when the service is not running.
Failures are logged as `overlay.hook_failed` events and do not stop the
apply. Hooks run only once the whole apply has succeeded. If an apply
stops partway (a file could not be fetched, or the agent restarted), the
hooks of what it already wrote are kept on the node and run when an apply
next completes, so a retry that finds those files in place still runs them.

**Exclusive directories** hold exactly what the overlays declare. Anything
else found in them is deleted on apply and by the drift check, which makes
them a good fit for `/etc/sudoers.d`, `/etc/yum.repos.d` or `/etc/slurm`. They
must be at least two levels deep (`/etc/x`, never `/etc`). Do not mark a
directory exclusive if the image ships files in it that you have not added
to an overlay: those would be deleted too.

### 8.6 Removing things

Removing a file from an overlay and switching removes it from the nodes. If
the image has its own version of that path (say `/etc/chrony.conf`), that
version is restored instead. This is the main difference from Warewulf's
`wwclient`, which never deletes anything. Flapjack only ever deletes paths it
recorded writing, or unmanaged files in exclusive directories.

## 9. Generations: build, switch, rollback

Each node has numbered, immutable **generations**, as NixOS does. A
generation is the full set of files the node should have. The node's current
generation is a pointer; its agent applies whatever the pointer names.

```sh
flapjack build --class compute              # dry run: what would change on each node
flapjack build r1n01 r1n02 -v               # specific nodes, every changed path
flapjack switch --class compute -m "chrony from head node"
flapjack switch --all -m "new sudo rules"
```

- **`build`** renders the overlays and compares the result with each node's
  current generation, without changing anything. Lines read `+` created,
  `~` changed, `m` mode or owner only, `-` removed, followed by the overlay
  the path comes from.
- **`switch`** does the same, then records a new generation for every node
  whose result changed and makes it current. Agents apply it within about a
  second. A node whose result is identical gets no new generation.
- Errors stop the switch for the affected class only: a template error, a
  failed Nix assertion or a missing secret is reported for each node of that
  class, and those nodes keep their current generation. Other classes in the
  same switch go ahead.

Select nodes by name, `--class` (comma-separated) or `--all`. `-m` records a
message with the generation.

```sh
flapjack generations r1n01                  # * marks the current one
flapjack overlay show r1n01                 # every managed path: mode, owner, policy, overlay
flapjack overlay show r1n01 3 --json        # a past generation's full manifest
flapjack diff r1n01                         # current against the one before
flapjack diff r1n01 --from 2 --to 4
flapjack rollback r1n01 --reason "bad sysctl"           # the previous generation
flapjack rollback r1n01 --to 2 --reason "last known good"
```

`rollback` moves the pointer to an existing generation. Nothing is
re-rendered, so the node gets exactly what it had. Rolling back does not
change your overlay sources: the next `switch` renders them again. Fix the
source (or `git revert` it) before switching again.

Generations are kept in `/var/lib/flapjack/generations/<node>/` and are never
deleted automatically.

## 10. Drift and the node agent

`flapjack-agent.service` runs on every node and:

- waits on the head node for a new generation, and applies it as soon as
  there is one;
- after applying, restores SELinux labels on what it wrote and runs hooks;
- every minute, checks every managed path, repairs `enforce` drift
  (including stray files in exclusive directories), and reports what is
  left;
- at boot, applies the node's generation before `sshd`, `chronyd`, `munge`
  and `slurmd` start. If the head node is unreachable, it lets boot continue
  after 45 s and keeps trying.

```sh
flapjack nodes
```
```
NAME   CLASS    RACK  PHASE       IP         APPLIED  DRIFT  AGENT
r1n01  compute  r1    Discovered  10.99.1.1  4        0      3s ago
r1n02  compute  r1    Discovered  10.99.1.2  4        1      5s ago
```

`APPLIED` is the generation the agent last applied, `DRIFT` counts paths
that differ from it (normally `report`-policy files someone edited), and
`AGENT` is the last report. Agents report at least every minute; `(stale)`
after three minutes means the node is down or cannot reach the head node.

On a node, `journalctl -u flapjack-agent` shows each apply and repair.

## 11. Node lifecycle

Nodes have a phase, and only these transitions are allowed:

| From | To |
|---|---|
| `Discovered` | `BurnIn`, `Retired` |
| `BurnIn` | `Ready`, `Quarantined` |
| `Ready` | `Draining`, `Quarantined`, `Provisioning` |
| `Draining` | `Ready`, `Provisioning`, `Quarantined` |
| `Provisioning` | `BurnIn`, `Quarantined` |
| `Quarantined` | `BurnIn`, `Retired` |
| `Retired` | none |

A quarantined node can only return through `BurnIn`, never straight to
`Ready`. Operators change phases through the API; each change needs a reason
and is recorded with who made it:

```sh
# as root on the head; elsewhere, your own admin certificate (section 4)
TOKEN=$(cat /etc/flapjack/admin.token) P=/etc/flapjack/pki
api() { curl -s --cacert $P/ca.pem --cert $P/admin.pem --key $P/admin.key -H "Authorization: Bearer $TOKEN" "$@"; }
api -d '{"reason":"DIMM errors"}' https://localhost:7443/v1/nodes/r1n01/quarantine
api -d '{"reason":"DIMM replaced"}' https://localhost:7443/v1/nodes/r1n01/release
api -d '{"reason":"maintenance"}' https://localhost:7443/v1/nodes/r1n01/drain
api https://localhost:7443/v1/nodes/r1n01/explain
```

(Head certificates issued before this release don't name `localhost`;
the `flapjack` CLI doesn't need that.)

Current state: phases are recorded and enforced, and a `Retired` node is
refused at boot, but nothing moves nodes between phases automatically yet.
Health-gated burn-in and Slurm drain integration are built as libraries
(see [ARCHITECTURE.md](ARCHITECTURE.md#platform-features)) and are not yet
wired into the service. CLI commands for phase changes are planned.

## 12. Events and auditing

Every boot step, configuration change, agent report and admin action is an
event in `/var/lib/flapjack/events.jsonl`:

```sh
flapjack events                         # last hour
flapjack events --since 24h --node r1n01
flapjack events --type overlay.,boot.dhcp
```

| Type | Meaning |
|---|---|
| `boot.dhcp` | A node was given its address |
| `boot.unknown` | DHCP from a MAC no node has (at most every 10 minutes per MAC) |
| `boot.script` | A node fetched its boot script and is booting an image |
| `boot.waiting` | A node is waiting: no class, no image, or image not built |
| `boot.refused` | A retired node tried to boot |
| `class.put`, `node.put` | `apply` created or changed a class or node |
| `node.phase` | A phase change, with who made it and why |
| `overlay.switch` | A new generation was made current |
| `overlay.rollback` | A node was pointed at an earlier generation |
| `overlay.applied` | An agent applied a generation |
| `overlay.drift` | An agent found paths that differ from its generation |
| `overlay.repaired` | An agent repaired enforce-policy drift |
| `overlay.error` | An agent could not apply its generation |
| `overlay.hook_failed` | An `onChange`/`onRemove` command failed |

`boot.unknown` events are how new hardware shows up: power on an unlisted
machine and its MAC appears here, ready to be added to your cluster file.

## 13. Upgrades, backups and recovery

**Upgrading Flapjack**

```sh
sudo install -m 0755 flapjack-linux-amd64 /usr/local/bin/flapjack
sudo systemctl restart flapjack
sudo flapjack image build el9-compute       # so nodes get the new agent
# then reboot nodes when convenient, a few at a time
```

Nodes keep running their old agent until they reboot into the new image.

From a release without sealed secrets: run `flapjack switch --all` after
upgrading the head, so every generation marks its secrets and they are
served only sealed from then on; tentacles then delete any secret they
cached in the clear. Nodes get their secrets again once they reboot into a
rebuilt image, whose agent makes a seal key.
Agents and server use a versioned API (`/agent/v1/`), so mixed versions
during a rolling reboot are expected.

This release drops the hot-spare, tenancy, power-allocation, canary-rollout
and libvirt-twin commands, and trust tiers (`minTier`): nothing could reach
a tier above legacy. A node in the old `Spare` phase loads as `Ready`, and
an overlay that still sets `minTier` fails to build until you remove it.
`firmware converge` now goes through the API instead of a state file.

**Upgrading from a release with plaintext options.** Boot TLS, signed
boot, mTLS agents and the API's certificate check are now always on.
Before restarting the new binary:

1. `sudo flapjack pki init` adds what's missing (the admin certificate);
   existing keys are kept.
2. Build and install iPXE against the boot CA with the embedded script
   ([3.6](#36-pki-and-encrypted-boot)), and rebuild images, so nodes carry
   the verify module, the cluster CA and the generation key.
3. Open TCP 443 and 8443 on the provisioning interface; port 80 closes.
4. Remove `bootTLS`, `signedBoot`, `insecureBootTickets` and `httpPort`
   from `server.json` (or set `plainHTTP` if firmware needs iPXE over
   HTTP).
5. Give admins certificates (`flapjack pki issue admin NAME`). API
   clients that are not the `flapjack` CLI need one too.

Nodes running an older image talk plain HTTP to port 80 and lose contact
until they reboot into a new image.

**Backups:** back up `/etc/flapjack` (configuration, overlays, secrets,
tokens) and `/var/lib/flapjack/{state.json,events.jsonl,generations,content}`.
Images can be rebuilt; `content` can be regenerated by switching again.

**Restoring a head node:** reinstall the binary, restore both directories,
run `sudo flapjack server install --address ...` (it keeps the restored
config and tokens), and copy the iPXE files back if they were not in the
backup. Nodes keep running while the head node is down; they only need it to
boot and to receive changes.

## 14. Troubleshooting

| Symptom | Check |
|---|---|
| Node gets no address | `flapjack events --type boot.unknown`: is its MAC in your cluster file? Is the MAC from the NIC that actually boots? Is another DHCP server answering? Is `firewalld` blocking 67/udp? |
| Node shows "asking again in 30s" on its console | `flapjack events --node N --type boot.waiting` gives the reason: missing class, class without an image, or image not built |
| PXE ROM gets an address but no iPXE | Is the right file in `/var/lib/flapjack/boot/`? `journalctl -u flapjack` logs each TFTP transfer |
| UEFI HTTP boot can't fetch iPXE | It fetches over HTTPS from the head, so the firmware must trust the boot CA. If it can't do HTTPS, set `plainHTTP` (iPXE binaries only) |
| Node shows "no boot window is open" | With `bootWindow: dhcp` it re-runs DHCP and boots on its next try; if not, check `flapjack events --node N --type boot.`. With `armed`: `flapjack node boot N`, or check the BMC watcher (`bmc` in `server.json`, `journalctl -u flapjack` for "bmc watch") |
| Image download gets 403 | The token in the URL expired (1 h), is for another image version, or the request came from an address other than the node's. Reboot the node for a fresh script |
| CLI or curl gets 403 "a cluster client certificate is required" or "may not use an admin token" | The API wants an admin certificate with an admin token ([4](#4-api-access-and-tokens)) |
| Agent logs "refusing generation … replayed", "signature does not verify" or "not signed" | Something between the node and the head served a generation the head did not sign for it, now. Check which tentacle the node uses, and `flapjack events --node N` |
| Agent logs "enrolling … 403" | The ticket was used, expired (15 min) or the node's rack does not match where it enrolls (its tentacle, or the head for racks without one). Reboot the node: every boot window gets a fresh ticket; check `flapjack events --type pki.enroll_refused` |
| iPXE stops with "Permission denied" or "imgverify: command not found" | A signature didn't verify (a file or script changed after signing, or a tentacle serving something else), or the iPXE build lacks `IMAGE_TRUST_CMD`/`EMBED` ([3.6](#36-pki-and-encrypted-boot)) |
| Boot stops in dracut with "refusing a root filesystem the head did not sign for" | The downloaded `rootfs.squashfs` doesn't match the digest in the script. Re-run `image build` if the file was changed in place; otherwise suspect whatever served it |
| Agent logs "no boot ticket" | The node booted without a ticket, so it isn't running a script the head served it in a window. Reboot it |
| A `tentacleDHCP` node gets no lease | Its interface's reserved IP is outside the tentacle's `dhcp.address` subnet, or the tentacle hasn't synced (check its log for "dhcp on") |
| A `tentacleDHCP` node shows "being staged" for long | The tentacle can't fetch the image; check its log for "staging image" errors |
| A rack still boots from the head with `tentacleBoot` | The tentacle hasn't staged that version yet, or its reports stopped. Check its log for "staged image" and that `bootListen` matches the `tentacleBoot` URL |
| Node stops in the dracut shell | Not enough RAM for the root filesystem, or it could not download `https://HEAD/images/...` (403: see image tokens above). The console shows the download error |
| `switch` fails for a class | The error names the overlay and file: a template field that does not exist, a failed Nix assertion, or a missing secret. That class's nodes keep their current generation |
| "the nix engine is not configured" | `nix.bin` and `nix.nixpkgs` in `server.json` ([8.3](#83-nix-modules)) |
| `APPLIED` does not advance | `journalctl -u flapjack-agent` on the node. Common causes: an `owner` or `group` that does not exist in the image, or the node cannot reach the head node |
| A file keeps reverting | It is `enforce`-policy and managed by an overlay: change it in the overlay, or set `policy` to `report` or `seed` |
| A service did not pick up new config | Add an `onChange` hook for that file |
| `ssh` rejects a key the overlay installed | Check labels with `ls -Z`. The agent runs `restorecon` on what it writes; a custom `seContext` may be wrong |

Logs: `journalctl -u flapjack` on the head node (DHCP, TFTP, HTTPS, boot
windows and overlay rendering) and `journalctl -u flapjack-agent` on nodes.

## 15. Security model

Flapjack has no insecure mode: nothing below can be turned off in
`server.json`.

What Flapjack enforces:

- **No plaintext but DHCP and TFTP.** Boot scripts, kernels, initrds, root
  filesystems, agents and the API are only ever served over TLS. TFTP
  serves only the iPXE binaries, which hold nothing secret. So does plain
  HTTP, and only when `plainHTTP` is on. DHCP answers reserved MACs only.
- **Images only to booting nodes.** An image file is served only with a
  token minted into a node's script during its boot window, from that
  node's address, for that version, for an hour ([3.6](#36-pki-and-encrypted-boot)).
  Nobody else on the network can pull one. Admins read them on the head.
- **Boot is signed.** iPXE trusts only the boot CA and runs only scripts,
  kernels and initrds the head signed, and the initrd checks the root
  filesystem's digest. A node's script is served only to its reserved IP.
- **Boot windows.** Tickets and image tokens exist only inside a window,
  one bootable script per window. With `bootWindow: armed` (the default),
  only authorized triggers open one, not DHCP ([3.7](#37-boot-windows)). A
  tentacle cannot open one by itself: a reboot it relays must carry a
  fresh notice signed by the node's own key, used once.
- **Agents use mTLS.** Every node enrolls with its single-use boot ticket
  for a node certificate, then gets its overlays (secrets included) only
  for that certificate's node, from the head's agent listener or its
  rack's tentacle. A ticket is only good from one of the node's reserved
  addresses, and stays spent across head restarts
  (`/var/lib/flapjack/tickets-used.json`).
- **One live identity per node.** Each ticket enrollment revokes the node's
  earlier certificates, everywhere they are checked (the agent listener,
  renewal, tentacles, node tokens on the API), and is logged as
  `pki.superseded`. An impostor that wins a node's ticket cuts the real
  node off, loudly, instead of sharing its identity, and a stolen
  certificate dies at the node's next boot. `flapjack node revoke NODE
  --reason R` does the same on demand (`pki.revoked`); the node gets a new
  certificate only by booting in a boot window. A retired node's
  certificates are refused, renewal included.
- **Generations are signed**, and agents refuse unsigned, altered,
  misaddressed or replayed generations.
- **The API** needs a cluster certificate (admin, or the node's own for a
  node token) and a token. Tokens are stored only as hashes. Roles
  separate reading, operating and changing the cluster, and every change
  is recorded with its author.
- **BMCs:** Redfish over HTTPS only, checked against a BMC CA you supply,
  never the system trust store. IPMI works only on nodes with
  `bmc.allowIPMI`, and every use is logged as `bmc.insecure_protocol`.
- **The service:** `flapjack.service` runs as the unprivileged `flapjackd`
  user with only `CAP_NET_BIND_SERVICE` and `CAP_NET_RAW`. It can write only
  `/var/lib/flapjack` and runs under a syscall filter.
- **Overlays:** secrets never pass through an engine. Nix evaluation cannot
  read beyond its inputs or use the network. Template `Include` is limited to
  the overlay and `/etc/flapjack/files`. All node-side writes go through a
  root-confined filesystem handle, so a planted symlink cannot redirect them.
- **Nodes:** images run SELinux enforcing, and the agent restores labels on
  everything it writes.

Limits, to plan around:

- **A boot ticket proves network position, not hardware.** With
  `bootWindow: dhcp`, something that can spoof a
  node's MAC and IP can open its window and race it for the ticket and
  image token, then enroll as the node and read its secrets. That revokes the real node's certificate (`pki.superseded`)
  and the real node fails to enroll at its next boot
  (`pki.enroll_refused`), so it is loud, but the secrets are already
  read. `armed` removes the DHCP trigger, but whatever holds the node's
  address during an authorized window can still race it. TPM-backed
  identity is not yet written ([ARCHITECTURE.md](ARCHITECTURE.md#node-identity)).
- **The iPXE binary itself** is verified only by UEFI Secure Boot, if
  you use it. Everything iPXE loads after it is verified.
- **Signed boot files do not expire.** Whatever serves a node's boot (a
  tentacle with `tentacleBoot`) can replay an older signed script, kernel
  or initrd, booting the node into an older image. A replayed script's
  ticket is spent or expired, so the node then cannot enroll.
- **`/proc/cmdline` is world-readable on the node.** The ticket is spent
  before users log in, stays spent across head restarts, and is only good
  from the node's address; a local user who beats the agent to it takes
  the node's identity loudly (the agent's enrollment then fails). The
  image token reads only that image from that address, for an hour.
- **Tentacles see their rack's overlay content, but not its secrets.**
  Secret files reach a tentacle, and sit in its memory, only sealed to
  their node ([8.4](#84-secrets)). A tentacle does relay its nodes' boot
  scripts, tickets included, so one an attacker controls can race a
  booting node for its ticket and enroll with a seal key of its own,
  which reads that node's secrets. That is an active attack: it revokes
  the real node's certificate (`pki.superseded`) and the real node fails
  to enroll, loudly. Reading a tentacle's disk or memory, or its traffic,
  yields no secrets, nor do the secrets of nodes that do not boot while
  the attacker holds it. With `bootWindow: dhcp` a tentacle running its
  rack's DHCP opens its nodes' windows itself, so it can stage that race
  at will; with `armed` it cannot open one. Tentacles cannot alter
  generations, boot files or scripts, act for other racks, or mint image
  tokens for anything but their own rack. A rack in `tentacleDHCP` gets
  its iPXE binary from its tentacle. TPM enrollment is what closes the
  remaining race.
- **Secret digests are in manifests.** A manifest names each file by the
  SHA-256 of its content, secrets included, and tentacles and API viewers
  read manifests. A random key's digest gives nothing away, but a short
  password's could be guessed offline: make secrets keys, not passwords.

## 16. Racks and tentacles

Past a few racks, one head node serving every agent directly becomes the
bottleneck. A **tentacle** is a per-rack relay: the same binary, run as
`flapjack tentacle` on a machine in (or next to) the rack, with no state of
its own. It holds one connection to the head and serves its rack's agents,
so a `switch` costs the head one request per rack per file instead of one
per node. Its nodes never talk to the head at all. The design and its test
topology are in [design/tentacles.md](design/tentacles.md).

Every hop is mutual TLS from the cluster CA, and every generation carries
the head's signature, so a tentacle can delay changes but not alter them.
A tentacle only ever acts for the rack its certificate names.

**Prerequisite: HTTPS boot.** A node enrolls for its certificate with a
single-use boot ticket that the head puts on its kernel command line, so
boot scripts must travel encrypted ([3.6](#36-pki-and-encrypted-boot)).

**1. Issue the tentacle a certificate** (on the head):

```sh
sudo flapjack pki issue tentacle r1 --out /root/tentacle-r1
# tentacle-r1/{tentacle.pem,tentacle.key,ca.pem}: copy to the tentacle
```

**2. Configure and start the tentacle.** Put the three files in
`/etc/flapjack/tentacle/` and write `/etc/flapjack/tentacle.json`:

```json
{
  "rack": "r1",
  "head": "https://10.98.0.1:7444",
  "agentListen": "10.1.1.1:8443",
  "artifactListen": "10.2.1.1:8444"
}
```

| Field | Meaning |
|---|---|
| `rack` | The rack it serves; must match its certificate |
| `head` | The head's tentacle endpoint, on the management core |
| `agentListen` | Address on the rack's management network; the rack's agents connect here |
| `artifactListen` | Optional. Address on the rack's cluster network, serving staged artifacts (`stage fetch`) from its cache |
| `bootListen` | Optional. Address on the rack's management network serving boot images over HTTPS (step 4) |
| `dhcp` | Optional. Run the rack's DHCP, TFTP and iPXE (step 5) |
| `cert`, `key`, `ca`, `bootCert`, `bootKey`, `dataDir` | Default to `/etc/flapjack/tentacle/{tentacle.pem,tentacle.key,ca.pem,boot.pem,boot.key}` and `/var/lib/flapjack-tentacle` |

Run `flapjack tentacle` under systemd. It re-reads its certificate when the
files change, so re-issuing one (every 30 days by default) needs no restart.

**3. Tell the head** in `server.json`, and restart it:

```json
"tentacleListen": "10.98.0.1:7444",
"tentacles": {
  "r1": "https://10.1.1.1:8443",
  "r2": "https://10.1.2.1:8443"
}
```

Nodes whose `rack` is listed boot with `flapjack.tentacle=`, `flapjack.rack=`
and a boot ticket on their command line. Their agent generates a key,
enrolls through the tentacle, keeps the certificate in RAM, and renews it
at half its lifetime (`nodeCertTTL`, default 24h). Removing a rack from
`tentacles` cuts its tentacle off at the next request.

**Check it:**

```sh
flapjack events --type pki.        # pki.enrolled (with renewal=true), pki.enroll_refused
flapjack nodes                     # APPLIED advances as before; reports arrive via the tentacle
flapjack pki show /etc/flapjack/tentacle/tentacle.pem    # on the tentacle: identity and expiry
```

If a tentacle is down, its rack keeps running what it has, and agents retry.
A replacement with the same certificate needs nothing restored.

**4. Optional: boot the rack from its tentacle.** So a rack reboot pulls
the root filesystem across the rack once instead of once per node, give
the tentacle a boot certificate and a boot listener:

```sh
sudo flapjack pki issue tentacle r1 --out /root/tentacle-r1 --boot-address 10.1.1.1
# adds boot.pem and boot.key (RSA, from the boot CA iPXE trusts)
```

```json
"bootListen": "10.1.1.1:443"
```

and list the rack in the head's `server.json`:

```json
"tentacleBoot": { "r1": "https://10.1.1.1" }
```

The head chunks each image version its racks boot into the staging
origin, the tentacle fetches and verifies it, and reports it staged. Only
then do the rack's boot scripts try the tentacle first, falling back to
the head if it doesn't answer. After `image build`, nodes boot the new
version from the head until the tentacle has staged it, within about a
minute plus the copy. Staged versions live in `dataDir/images/`; old ones
are deleted. A tentacle that stops reporting for 3 minutes stops getting
boots.

The tentacle serves the files, but the head's signatures decide what
boots ([3.6](#36-pki-and-encrypted-boot)), so a compromised tentacle can't
substitute a kernel, initrd or root filesystem. If the rack copy fails
verification, the node falls back to the head. The tentacle serves image
files only with the image tokens in its rack's scripts, checked with its
rack's key, which the head sends it.

**5. Optional: the rack's DHCP on its tentacle.** Then the rack's nodes
need no route to the head at all: firmware, iPXE, scripts and images all
come from the tentacle. Do step 4 first, and add to `tentacle.json`:

```json
"bootListen": "10.1.1.1:443",
"dhcp": {
  "interface": "eth1",
  "address": "10.1.1.1/24",
  "domain": "cluster",
  "leaseTime": "1h"
}
```

| `dhcp` field | Meaning |
|---|---|
| `interface`, `address` | The rack management network and the tentacle's address on it. Only node interfaces reserved in this subnet get leases. `bootListen` must be on this address |
| `router`, `dns`, `domain`, `leaseTime` | Usual DHCP options; `leaseTime` defaults to `1h` |
| `tftp` | iPXE for PXE ROMs on UDP 69 (default on); only the iPXE binaries |
| `plainHTTP`, `httpPort` | Off by default: UEFI HTTP boot gets iPXE over HTTPS from `bootListen`. On, also serve the iPXE binaries (only) over plain HTTP on `httpPort` (default 80) |

In the head's `server.json`, list the rack:

```json
"tentacleDHCP": ["r1"]
```

and put iPXE built for signed boot ([3.6](#36-pki-and-encrypted-boot)) in the
head's boot directory as usual; tentacles copy it from there. Firmware
loads that binary unverified unless UEFI Secure Boot checks it, so on
these racks the tentacle is trusted with iPXE itself; everything iPXE
loads after it is verified. The
head's DHCP stops answering the rack's MACs. The tentacle needs
`CAP_NET_BIND_SERVICE` and `CAP_NET_RAW`, like the head.

The rack keeps getting leases while the head is down, but a rebooting
node's script comes from the head (it issues the boot ticket), so reboots
wait for it. Nodes whose image the tentacle is still staging show
"being staged to rack r1" and ask again every 30 s.

## 17. Other tools

These ship in the same binary:

| Command | Use |
|---|---|
| `flapjack firmware converge NODE --bmc-password-file F --bmc-ca C [--dry-run]` | Flash firmware and set BIOS to the class's `firmware` spec over Redfish, then verify. Reads the node and class from the API and records each change on the node's timeline (`firmware.flashed`, `bios.configured`); refuses a `Ready` node, so drain it first |
| `flapjack health run [--gpus N --mem-gib G --min-ib-rate R]` | Run node health checks (PCIe, GPUs, Xid, RDMA ports, memory); `--evidence FILE` writes an RMA bundle on failure |
| `flapjack topology validate`, `topology slurm` | Check InfiniBand cabling against a blueprint; generate Slurm `topology.conf` from `ibnetdiscover -p` |
| `flapjack stage split / serve / fetch` | Content-addressed distribution of large files (models, datasets) with rack peers and caches |
| `flapjack events correlate` | Rank the changes that best explain a set of failures |
| `flapjack mcp` | Read-only MCP server on stdio, for AI assistants (works with local models) |

## 18. Reference

### Commands

| Command | Role | Purpose |
|---|---|---|
| `server install --address A/P` | root | Install and start the head-node service |
| `server --config FILE` | systemd | Run the service |
| `apply FILE` | admin | Create or update classes and nodes |
| `nodes [--phase P] [--json]` | viewer | Nodes, phase, applied generation, drift, agent heartbeat |
| `events [--node N] [--type T] [--since D]` | viewer | Event timeline |
| `overlay list` | viewer | Overlays, engine, classes using them |
| `overlay show NODE [GEN] [--json]` | viewer | A generation's managed paths |
| `build NODE…\|--class C\|--all [-v]` | operator | Dry run |
| `switch NODE…\|--class C\|--all [-m MSG] [-v]` | operator | New generations |
| `generations NODE` | viewer | Generation history |
| `diff NODE [--from N] [--to M]` | viewer | Compare generations |
| `rollback NODE --reason R [--to N]` | operator | Point a node at an earlier generation |
| `image build NAME [--spec F] [-q]` | root | Build an image |
| `image list`, `image use NAME VERSION` | root | Image versions and rollback |
| `node boot NODE` | operator | Open a node's boot window (`bootWindow: armed`) |
| `node revoke NODE --reason R` | admin | Revoke the node's certificates; it re-enrolls by booting in a boot window |
| `firmware converge NODE` | admin | Converge firmware and BIOS over the BMC ([17](#17-other-tools)) |
| `agent` | systemd, on nodes | The node agent, over mTLS (via `flapjack.tentacle=` or `flapjack.server=`) |
| `tentacle [--config F]` | systemd, on tentacles | A rack's relay and cache |
| `pki init [--boot-address A,…]` | root | Create the cluster CA and keys (idempotent) |
| `pki issue tentacle RACK [--out D] [--ttl T]` | root | Certificate for a tentacle |
| `pki issue admin NAME [--out D] [--ttl T]` | root | Admin certificate for the API |
| `pki show CERT` | anyone | A certificate's identity, hosts and expiry |

API commands accept `--api URL`, `--token-file FILE` and `--cert-dir DIR`
(with `admin.pem`, `admin.key`, `ca.pem`).

### Files

| Path | Owner | Contents |
|---|---|---|
| `/usr/local/bin/flapjack` | root | The binary |
| `/etc/flapjack/server.json` | root | Service configuration |
| `/etc/flapjack/tokens.json` | root:flapjackd 0640 | Token hashes and roles |
| `/etc/flapjack/admin.token` | root 0600 | The admin token |
| `/etc/flapjack/pki/admin.pem`, `admin.key` | root, key 0600 | Root's admin certificate for the API |
| `/etc/flapjack/overlays/` | root | Overlay sources |
| `/etc/flapjack/files/` | root | Shared files templates may `Include` |
| `/etc/flapjack/secrets/` | root:flapjackd 0750 | Secrets |
| `/etc/flapjack/images/NAME.json` | root | Image specs |
| `/etc/flapjack/pki/` | root:flapjackd 0750, keys 0640 | Cluster CA, signing, ticket, head and boot keys |
| `/etc/flapjack/tentacle.json`, `/etc/flapjack/tentacle/` | root, on tentacles | Tentacle config, certificate (key 0600) and CA |
| `/var/lib/flapjack/artifacts/` | flapjackd | Staged-artifact chunks tentacles pre-warm from |
| `/var/lib/flapjack/state.json` | flapjackd | Classes, nodes, status |
| `/var/lib/flapjack/events.jsonl` | flapjackd | Event timeline |
| `/var/lib/flapjack/generations/` | flapjackd | Per-node generations |
| `/var/lib/flapjack/content/` | flapjackd | Rendered overlay content, by digest |
| `/var/lib/flapjack/images/` | root | Image versions and current links |
| `/var/lib/flapjack/boot/` | root | iPXE binaries |
| `/var/lib/flapjack-agent/` | root, on nodes | The agent's applied manifest, newest generation signature time and `identity.pem` (key 0600), in RAM on stateless nodes |

### Network

| Port | Protocol | Bound to | Serves |
|---|---|---|---|
| 67 | UDP | provisioning interface | DHCP |
| 69 | UDP | provisioning address | TFTP (iPXE only) |
| 443 | TCP | provisioning address | `/boot/` signed scripts and iPXE, `/images/` with tokens (TLS 1.2, boot CA) |
| 8443 | TCP | provisioning address | Agents of racks without a tentacle (`/agent/v1/`, mTLS except enrollment, TLS 1.3) |
| 80 | TCP | provisioning address | Only with `plainHTTP`: the iPXE binaries |
| 7443 | TCP | 127.0.0.1 | Admin API (`/v1/`, mTLS: admin or node certificate, plus token) |
| 7444 | TCP | `tentacleListen` | Tentacles (`/tentacle/v1/`, mTLS, TLS 1.3) |
| 8443 | TCP | tentacle, rack management | Agents (`/agent/v1/`, mTLS except enrollment) |
| 8444 | TCP | tentacle, rack cluster network | Staged artifacts (`/chunks/`, mTLS) |
| 443 | TCP | tentacle `bootListen` | Boot images for its rack (`/images/` with tokens, TLS 1.2, boot CA); with `dhcp`, also `/boot/` scripts and iPXE |
| 67, 69 | UDP | tentacle `dhcp.interface` | With `dhcp`: the rack's DHCP, and TFTP (iPXE only) |
| 80 | TCP | tentacle `dhcp.address` | Only with `dhcp.plainHTTP`: the iPXE binaries |
