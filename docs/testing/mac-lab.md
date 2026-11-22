# Test cluster on a Mac

`flapjack lab` runs a complete Flapjack cluster as QEMU VMs on an Apple
silicon Mac, with no root and no kernel extensions: a head node running
`flapjack.service`, racks of diskless nodes that network-boot from it,
a Redfish BMC per node, and a capture of every frame on the provisioning
network. Use it to learn Flapjack, try overlay changes, and test Flapjack
itself.

What it does not cover: GPUs, InfiniBand, real firmware flashing and IPMI
(those are tested with fakes).

## Setup

```sh
brew install qemu swtpm
make lab-up
```

The first run downloads about 900 MiB into `~/.flapjack/cache`: the Rocky
Linux 9 cloud image, iPXE builds, a static Nix and nixpkgs. Later runs reuse
the cache.

## The default layout: tentacles and Slurm

```
                       ┌──────────────── fj-head ────────────────┐
                       │ flapjack.service · slurmctld · slurmrestd│
                       └──┬───────────────────────────────────┬──┘
     management core      │ 10.98.0.0/24 (mTLS)               │ cluster network
       ┌──────────────────┴───┐        ┌────────────────────┐ │ 10.100.0.0/16
       │ tentacle-r1          │        │ tentacle-r2        │ │ Slurm, ssh, jobs
       │ DHCP · iPXE · images │        │ DHCP · iPXE ·images│ │
       └──────────┬───────────┘        └─────────┬──────────┘ │
       rack r1 10.1.1.0/24              rack r2 10.1.2.0/24   │
          r1n01     r1n02                  r2n01    r2n02 ────┘
```

| Machine | What it runs | Addresses |
|---|---|---|
| `fj-head` | `flapjack.service` (on the core only), slurmctld, slurmrestd, munge, chrony | core `10.98.0.1`, cluster `10.100.0.1`; SSH `127.0.0.1:2222`, REST API `127.0.0.1:6820` |
| `tentacle-r1`, `tentacle-r2` | `flapjack tentacle`: the rack's DHCP, iPXE, signed boot scripts and staged images, agent relay and enrollment; chrony for the rack | core `10.98.0.1R`, rack `10.1.R.1`; SSH `127.0.0.1:2222+R` |
| `r1n01` … `r2n02` | Stateless Rocky 9 (`rocky9-aarch64`, built on the head), the flapjack agent, munge, configless slurmd | rack `10.1.R.1N`, cluster `10.100.R.1N` |

This is the shape in [design/tentacles.md](../design/tentacles.md): each
rack network reaches only its tentacle, so nodes have no route to flapjack
on the head. Firmware, iPXE, scripts, images, overlays and node
certificates all come through the tentacle, and every generation and boot
file is still signed by the head. The cluster network carries Slurm and
SSH between the head and the nodes, and no flapjack traffic.

How the pieces get there, all automatically:

1. The head installs flapjack with a lab `server.json` (`tentacles`,
   `tentacleBoot` and `tentacleDHCP` for every rack), Slurm and munge from
   EPEL, and builds signed iPXE.
2. It issues each tentacle an identity and a boot certificate and installs
   them over the core with its SSH key. The tentacles authorize that key
   for exactly two commands, `install-certs` and `status`, so no private
   key ever passes through the Mac.
3. It builds `rocky9-aarch64` (Rocky 9 plus munge and slurmd) and the
   tentacles stage it. The nodes are powered on as soon as the signed
   iPXE exists, lease from their tentacle and boot from it.
4. The agents enroll through their tentacle and apply the overlays:
   `base` (templates), then `site`, `rack-overrides`, `fabric` (the cluster
   NIC, from `cluster.json`) and `slurm` (munge key as a secret, configless
   `slurmd --conf-server`, job users), all Nix modules.
5. slurmd fetches `slurm.conf` from slurmctld and the nodes go idle.

### The login screen

`make lab-ssh` shows `fj-welcome`: flapjack's status (service, image,
nodes reporting, drift, Slurm daemons), the layout with each tentacle's and
node's live state (phase, applied generation, agent heartbeat, Slurm
state), and commands to try for template overlays, Nix modules, Slurm and
the REST API. Run `fj-welcome` again any time (`--brief` for status and
layout only); `touch ~/.hushlogin` turns it off.

### Slurm and its REST API

```sh
sinfo                                   # partitions compute, r1, r2
srun -N4 hostname
sbatch --wrap 'sleep 60; hostname'; squeue
fj-slurm-api ping                       # slurmrestd with a fresh JWT
fj-slurm-api nodes | jq '.nodes[] | {name, state}'
```

slurmrestd listens on the head's loopback and on its NAT address, which
the Mac forwards to `127.0.0.1:6820`. It only accepts JWTs:

```sh
# on the Mac
TOKEN=$(bin/flapjack lab ssh -- scontrol token lifespan=3600 | cut -d= -f2)
curl -H "X-SLURM-USER-NAME: flapjack" -H "X-SLURM-USER-TOKEN: $TOKEN" \
  http://127.0.0.1:6820/slurm/v0.0.38/diag
```

EPEL 9 ships Slurm 22.05 (API `v0.0.38`); `fj-slurm-api` finds the version
from the server's OpenAPI document. There is no slurmdbd, so the
accounting endpoints (`/slurmdb/`) are not loaded.

## Commands

```sh
make lab-up                       # build, then start head + 2 tentacles + 4 compute nodes
make lab-up RACKS=3 NODES=3       # shape it: LAYOUT RACKS NODES NODE_MEM POWER_ON
make lab-up LAYOUT=flat X86_BIOS=1  # the original layout: one network, optional x86 nodes
make lab-status                   # nodes, tentacles, Redfish BMCs, head node
make lab-ssh                      # shell on the head node (or: bin/flapjack lab ssh -- CMD)
bin/flapjack lab ssh --vm tentacle-r1   # shell on a tentacle
make lab-restart                  # rebuild; the head and tentacles pick up the new binary on boot
make lab-down                     # stop, keeping VM state (NVRAM, TPMs, disks)
make lab-destroy                  # delete the lab (downloads in ~/.flapjack/cache are kept)
make help                         # everything else
```

| Variable | Default | Meaning |
|---|---|---|
| `LAYOUT` | tentacles | `tentacles` (above) or `flat`: head and nodes on one provisioning network |
| `RACKS` | 2 | Racks (one tentacle each) |
| `NODES` | 2 | aarch64 nodes per rack |
| `X86_BIOS` | 0 | Flat layout: emulated x86_64 legacy BIOS nodes (rack 1) |
| `X86_SECURE` | 0 | Flat layout: emulated x86_64 UEFI Secure Boot nodes (rack 1) |
| `NODE_MEM` | 1536 (tentacles), 1024 (flat) | MiB per node |
| `POWER_ON` | true | Power nodes on once the head has built their iPXE; otherwise they wait for Redfish |
| `LAB_DIR` | `~/.flapjack/lab` | Lab state |

A lab keeps its layout: switching `LAYOUT` needs `make lab-destroy` first.
`flapjack lab up` also takes `--ssh-port`, `--seed-port`, `--redfish-port`
and `--rest-port`, to run a second lab next to the first in another
`--dir`, and `--switch-fps` (default 4000) and `--switch-mbps` (default
100), each lab network's frame and byte caps. Keep them modest: every lab
frame is work for the Mac's kernel, and at ~25,000 frames/s the lab has
hung macOS (see Findings). `~/.flapjack/lab/switch-stats.json` shows each
network's frames, drops and `waits` (frames the caps delayed).

**The safety watchdog.** While the lab runs, its daemon asks
mDNSResponder for `localhost` every 2 s (with `dns-sd`, which really goes
through the daemon). If two questions in a row go unanswered, it pauses
every switch, powers off every VM and writes the reason to
`safety-stop` in the lab directory; `lab status` shows it and the next
`lab up` reports it. That happens within ~10 s, long before macOS's own
watchdog (60 s for configd, then 180 s) would reset the Mac. It is a
backstop: if the kernel wedges the daemon too, it cannot run, which is
why the caps sit far below the rate that caused trouble.

## A tour

A fresh lab needs no manual steps. The head node is ready in about 80 s and
builds the node image in another 80 s. The nodes, which keep retrying
network boot, then boot it from RAM, and their agents apply the example
overlays. Everything is up about 3½ minutes after `make lab-up`.

On the head node (`make lab-ssh`):

```sh
flapjack nodes                             # applied generation, drift, agent heartbeat
flapjack events --type pki.                # node certificates, issued through the tentacles
ssh r2n01                                  # root on a node (cluster network)
ssh 10.98.0.11 status                      # a tentacle: service, staged images, certificate
flapjack overlay list                      # base (templates), site + rack-overrides (Nix)
flapjack overlay show r2n01                # every file Flapjack manages on r2n01
```

Change something and watch it arrive:

```sh
sudo vi /etc/flapjack/overlays/base/rootfs/etc/motd.ww
flapjack build --all                       # dry run: what would change where
flapjack switch --all -m "new motd"        # new generation; agents apply it at once
ssh r1n01 cat /etc/motd
flapjack generations r1n01
flapjack rollback r1n01 --reason "undo"
```

Try the cases Flapjack is built for:

- **Removal:** delete a file from an overlay and switch. It disappears from
  the nodes, or reverts to the image's copy if the image has one (try
  `/etc/motd`).
- **Drift:** on a node, `echo 1.2.3.4 evil >> /etc/hosts`. Within a minute the
  agent reverts it, and `flapjack events --type overlay.` shows
  `overlay.repaired`.
- **Exclusive directories:** `touch /etc/sudoers.d/rogue` on a node. It is
  deleted at the next check.
- **Report policy:** edit `/etc/motd` on a node. It is kept, and `flapjack
  nodes` shows `DRIFT 1`.
- **Nix precedence:** `sysctl vm.swappiness` is 10 on rack 1 and 1 on rack 2,
  where `rack-overrides` uses `lib.mkForce`. Break the assertion in
  `site/default.nix` (set swappiness to 500) and `flapjack build` refuses
  with your message.
- **Stateless reboot:** power-cycle a node through its BMC. It comes back
  configured in about 30 s.

```sh
PW=$(cat ~/.flapjack/lab/redfish-password)
curl -su admin:$PW -X POST -H 'Content-Type: application/json' \
  -d '{"ResetType":"ForceRestart"}' http://127.0.0.1:8100/redfish/v1/Systems/1/Actions/ComputerSystem.Reset
```

Node consoles are in `~/.flapjack/lab/vms/<vm>/console.log`. Every lab
network has its own capture: open `~/.flapjack/lab/r1.pcap` in Wireshark to
see rack 1's DHCP and HTTPS boot from its tentacle, `core.pcap` for the
head ↔ tentacle mTLS, `cluster.pcap` for Slurm (`prov.pcap` in the flat
layout).

## How it is built

| Piece | Implementation |
|---|---|
| Networks | Userspace learning Ethernet switches over connected Unix stream sockets (QEMU `stream` netdev), capped at 4,000 frames/s and 100 Mbit/s each, one per network: `core`, `r1`, `r2`…, `cluster` (or one `prov` in the flat layout). Every frame is written to `<network>.pcap` |
| Head node | Rocky Linux 9 aarch64 cloud image, 4 GiB. Core NIC `10.98.0.1/24` and cluster NIC `10.100.0.1/16` (flat: provisioning `10.99.0.1/16`); SSH and slurmrestd through ports forwarded to `127.0.0.1:2222` and `:6820` |
| Head-node setup | cloud-init only creates the `flapjack` user and the static addresses. On every boot `fj-sync` installs the Mac's current `flapjack` binary and runs `head-setup.sh` (embedded in the binary, idempotent). It installs iPXE builds, the node list (`flapjack apply`), the lab's `server.json`, `/etc/hosts` entries, a pinned static Nix and nixpkgs `lib`, `squashfs-tools`, EPEL with Slurm and munge, an SSH key authorized for root on the nodes, chrony, tentacle certificates, `flapjack.service` and the login screen. It installs the example overlays only into an empty `/etc/flapjack/overlays`, so your edits survive |
| Tentacles | Rocky 9 cloud image, 1 GiB, with NICs on the core and their rack. `fj-sync` runs `tentacle-setup.sh`: `tentacle.json` (DHCP on the rack NIC), a hardened `flapjack-tentacle.service` that waits for certificates, and the head's key, restricted to `install-certs` and `status` from `10.98.0.1` |
| Node image | `fj-lab-image.service` builds `rocky9-aarch64` (flat: `el9-aarch64`) on first boot, and again whenever the `flapjack` binary or `/etc/flapjack/images/rocky9-aarch64.json` changes, because the agent inside the image is that binary |
| Overlays | `base` (templates: hosts, motd, chrony, sshd, sudoers, root's `authorized_keys`), `site` and `rack-overrides` (Nix modules: typed sysctl options, a banner, a rack-2 `mkForce`). A fresh lab switches every node to generation 1 automatically |
| Nodes, fast | aarch64 under Apple's hypervisor (HVF), UEFI, `swtpm` TPM 2.0, no disk |
| Nodes, legacy | x86_64 under emulation (TCG), SeaBIOS with the iPXE option ROM |
| Nodes, Secure Boot | x86_64 under emulation, Secure Boot OVMF with SMM, TPM 2.0 |
| BMCs | One Redfish endpoint per node on `127.0.0.1:8100+`, reachable from the head node as `10.0.2.2:8100+`. Power goes to QEMU over QMP; inventory, BIOS settings and firmware versions are emulated, with staged changes applied on the next boot |
| Addresses | Tentacle layout: rack R's network is `10.1.R.0/24` (tentacle `.1`, node N `.1N`), node N's cluster address `10.100.R.1N`. Flat: rack R is `10.99.R.0/24`: aarch64 nodes from `.1`, BIOS nodes from `.101`, Secure Boot nodes from `.151`. MACs are `52:54:00:<rack>:<node>:<kind>` (cluster NICs `…:11`, tentacles `52:54:00:f0:<rack>:*`) and serials `FJLAB-<NAME>`, so they never change between runs |

State lives in `~/.flapjack/lab` and builds in `./bin`. `lab-down` keeps the
head disk, NVRAM and TPM state; `lab-destroy` deletes them but keeps the
download cache.

The x86_64 nodes boot iPXE and get their addresses, but there is no x86_64
node image yet (images are built for the head node's architecture), so they
wait at "image not built".

## Timings

Tentacle layout, M3 Max, warm download cache, with the first
(datagram, 200 Mbit/s) switch; expect staging and node boots to take
longer under the 4,000 frames/s cap:

| Step | Time |
|---|---|
| `make lab-up` to a ready head node (first boot: EPEL, Slurm, signed iPXE) | ~6 min |
| Node image (`rocky9-aarch64`, 147 MiB root filesystem) | ~1 min |
| Both tentacles staging it from the head | ~1 min |
| Image staged to all four nodes idle in Slurm | ~1 min |
| BMC power-cycle to the node back in Slurm (booted from its tentacle) | ~80 s |

Flat layout, measured earlier on the same Mac:

| Step | Time |
|---|---|
| `make lab-up` to a ready head node | ~80 s |
| Node image build | ~80 s |
| Image ready to all four nodes configured | ~40 s |
| Power-cycle to a configured node | ~30 s, mostly the initramfs downloading the 126 MiB root filesystem |
| Power-on to first DHCPDISCOVER | aarch64 UEFI 7.4 s, x86 BIOS 3.1 s, x86 Secure Boot 2.1 s |

## Findings that shaped the lab

- **edk2 network boot does not work under HVF.** Since the 2024 PixieFail
  fixes, edk2's network stack refuses to load without a hardware RNG.
  Apple's hypervisor provides neither the SMCCC TRNG nor `FEAT_RNG`, so the
  aarch64 firmware has no PXE or HTTP boot. aarch64 nodes therefore boot
  iPXE from a small read-only virtual FAT disk, standing in for iPXE flashed
  into the NIC, which brings its own network stack. That disk also holds an
  `autoexec.ipxe` that retries network boot forever, like a NIC set to retry
  PXE, so nodes powered on before the head node is ready still boot.
- **The aarch64 TPM needs `ppi=off`.** The TPM's physical-presence RAM
  region is smaller than Apple silicon's 16 KiB page, and HVF refuses to map
  it. Flapjack does not use PPI.
- **Secure Boot is x86-only here.** Homebrew's aarch64 edk2 has no
  Secure Boot build, so aarch64 lab nodes top out at the `tpm` tier.
- **macOS Unix datagram sockets** (the first switch) carry at most 2048 bytes (enough for
  1514-byte Ethernet frames) and default to a 4 KiB receive buffer. The
  switch raises its own buffer and counts drops.
- **The lab switch can hang macOS.** The first switch carried each frame
  as a Unix datagram addressed by path, so the kernel looked up a socket
  path for every frame, twice. Whenever two tentacles staged a node image
  from the head (~25,000 frames/s), mDNSResponder stopped answering within
  a second or two, configd's IPMonitor blocked on a DNS lookup, and
  macOS's userspace watchdog panicked or reset the Mac a few minutes
  later: three times. Kernel network buffers were not the problem (they
  barely moved), and a 200 Mbit/s byte cap did not help, because that is
  about the same frame rate. The switch now uses connected Unix stream
  sockets (QEMU's `stream` netdev: no lookup per frame, and a slow reader
  makes the writer wait), caps frames as well as bytes, gives each port its
  own bounded queue, and the daemon runs the safety watchdog above. A
  userspace program should not be able to do this to macOS; if you can
  reproduce it, it is worth a Feedback report to Apple.
- **Chunk files must be fsynced before they are renamed into place.** The
  head VM died in that panic mid-write, and XFS kept some renamed chunk
  files with no data. The staging store trusted them and served empty
  chunks until it learned to fsync, to treat an empty file as missing, and
  to replace a chunk whose size is wrong when it re-indexes.
- **Rocky's repo files need `$rltype`.** It is a dnf variable in the host's
  `/etc/dnf/vars`, which `dnf --installroot` does not read, so image builds
  pass `--setopt=varsdir=/etc/dnf/vars`.
- **slurmrestd 22.05 exits without slurmdbd** when it loads the accounting
  (`openapi/dbv*`) plugins, which it does by default. The lab loads only
  the `openapi/v*` ones.
- **Go's `embed` skips dot-directories** such as `.ssh` unless the pattern
  uses `all:`. The example overlays are embedded with `all:overlays`.
