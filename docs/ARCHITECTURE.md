# Flapjack architecture

Status: draft. This records the decisions made so far and the reasoning behind
them; sections marked *planned* have no code yet. For operating Flapjack, see
the [administrator guide](admin-guide.md).

## Goal

Flapjack is a declarative, security-first HPC cluster manager. It treats
bare-metal nodes as immutable, content-addressed workloads: a node is defined
by a spec (image digest, kernel, overlays, identity), booted quickly from a
distributed cache, verified before it is trusted with anything, and
continuously reconciled to that spec. It runs fully offline, scales across
racks without stateful "leader" nodes, and is extended through plugins rather
than forks.

Design priorities, in order: **security, boot and network speed,
repeatability, admin ergonomics.**

## Decisions

| Area | Decision | Why |
|---|---|---|
| Language | Go for server, CLI, rack cache and node agent (one static binary) | Ecosystem overlap with Warewulf, Kubernetes, containerd, OCI, DHCP, Redfish and Raft; static binaries make airgapped installs trivial. The agent protocol is protobuf/gRPC so the agent could move to Rust later. |
| License | Apache-2.0 | |
| Distros | EL first: RHEL, Rocky, Alma, CentOS Stream, Fedora | Vendor HPC stacks (NVIDIA, MOFED/DOCA, Lustre, GPFS, ISV codes) target EL. |
| Scale target | Tens of racks; developed against a handful of nodes | Rack caches are in scope early; peer-to-peer distribution comes later. |
| Firmware | UEFI and legacy BIOS both first-class | Mixed fleets are normal. Security guarantees differ per path; see [node identity](#node-identity). |
| BMC | Redfish and IPMI both first-class, behind one driver interface | Same reason. |
| Overlays | Warewulf-style overlays with pluggable engines (Go template, Nix modules) and bi-directional reconciliation | See [Overlays](#overlays). |
| k8s/k3s | Later: the same API types become CRDs and the server runs as an operator | Keep the state store behind an interface from day one. |

## Boot

```
UEFI:   firmware ── HTTP(S) Boot or PXE→TFTP ── iPXE (signed) ─┐
BIOS:   PXE ROM ── TFTP ── undionly.kpxe (iPXE) ───────────────┤
                                                               ▼
              Flapjack boot environment (kernel + initramfs + agent;
              a signed UKI on UEFI)
                • establishes node identity (see node identity)
                • fetches the image by digest from the nearest cache
                • verifies, assembles the root filesystem
                • applies the system overlay
                ── kexec or switch_root into the node's spec
```

- TFTP is used only to chainload iPXE, never for payloads.
- iPXE is built with an embedded CA and `imgverify` (always), so even
  legacy BIOS nodes verify the scripts, kernels and initrds they download;
  the initrd checks the root filesystem against a digest from the signed
  script ([design/tentacles.md](design/tentacles.md#signed-boot)).
- The boot environment is generic and changes rarely; real Linux userspace
  handles attestation and fetching instead of iPXE scripts. It also offers the
  last few overlay/image generations on the console for recovery, like the
  NixOS boot menu.

### Head-node service

`flapjack server` is the long-running service on a head node, installed as
`flapjack.service` by `flapjack server install --address 10.99.0.1/16`.
One process serves:

| Port | Bound to | Purpose |
|---|---|---|
| UDP 67 | the provisioning interface (`SO_BINDTODEVICE`) | DHCP: reservations only. An unknown MAC gets no reply and a rate-limited `boot.unknown` event |
| UDP 69 | provisioning address | TFTP, read-only, the iPXE binaries only (`undionly.kpxe`, `ipxe-x86_64.efi`, `ipxe-arm64.efi`) |
| TCP 443 | provisioning address | HTTPS boot (TLS 1.2, RSA boot CA, for iPXE): signed per-node scripts, iPXE for UEFI HTTP boot, images with per-boot tokens |
| TCP 8443 | provisioning address | Agents of racks without a tentacle: enrollment with a boot ticket, then mTLS with the node certificate |
| TCP 7443 | 127.0.0.1 | API: TLS always; a cluster certificate (admin, or the node's own) plus a token |
| TCP 80 | provisioning address | Only with `plainHTTP`: the iPXE binaries, nothing else |
| TCP 7444 | `tentacleListen` | Tentacles, mTLS from the cluster CA ([design/tentacles.md](design/tentacles.md)) |

DHCP picks the boot file from what the client says it is: iPXE gets its
node's script, UEFI HTTP boot gets iPXE over HTTPS, PXE ROMs get iPXE over
TFTP. There is no insecure mode: boot TLS, signed boot, mTLS agents, image
tokens and the API's certificate check can't be turned off. A node's
script carries its ticket and image tokens only inside its boot window,
which only authorized triggers open (`bootWindow: armed`, the default:
flapjack's own BMC power actions, the agent announcing a reboot, signed
by its key, an admin, or a BMC watcher that sees the node power on) or
DHCP does (`dhcp`). Each ticket enrollment revokes the node's earlier
certificates, so a node has one live identity. Every address is a fixed reservation from the node's interface, so
there is no lease database and a restarted server answers exactly as
before; relays (`giaddr`) are supported for routed racks. A node's script
is only served to the address reserved for that node.

A node whose class has no built image gets a script that says why and asks
again every 30 s, so building the image is enough to boot the cluster. The
script boots `vmlinuz` and `initrd.img` from `/var/lib/flapjack/images/<image>/`
with `BOOTIF`, `ip=dhcp`, the node name, server and generation digest on the
command line; if the image has `rootfs.squashfs`, dracut's livenet module
downloads it into RAM (`root=live:`) with a writable overlay on top.

The unit runs as the unprivileged `flapjackd` user with only
`CAP_NET_BIND_SERVICE` and `CAP_NET_RAW`, a read-only filesystem except
`/var/lib/flapjack`, and a `@system-service` syscall filter. `server install`
also writes `/etc/flapjack/server.json` and an admin token
(`/etc/flapjack/admin.token`, root only; the service keeps only its hash).
It is idempotent: rerunning it keeps the config and token and restarts the
service.

```
flapjack apply cluster.json   # classes and nodes (admin)
flapjack nodes                # NAME CLASS RACK PHASE MAC IP BMC
flapjack events --type boot.  # DHCP leases, scripts served, unknown MACs
journalctl -u flapjack -f
```

### Root filesystem modes

| Mode | Use |
|---|---|
| `tmpfs` | Warewulf-style: the whole image in RAM. Simplest. |
| `erofs` + overlayfs (tmpfs upper) | Default. Read-only, content-addressed image (EROFS/composefs, fs-verity), optionally lazy-loaded so only touched blocks cross the wire. |
| `erofs` + local NVMe cache | Large GPU images. Image chunks cached on disk by digest; reboots into the same digest fetch nothing. Disk is a cache, never the source of truth. |
| A/B stateful | Storage, login and infra nodes. Image written to alternate partitions with atomic switch and rollback; bootc is a candidate here. |

In every mode the booted image stays available read-only to the agent (the
*pristine* view), which overlay removal relies on.

### Node identity

A node proves who it is with its MAC plus a single-use boot ticket that the
head serves only in that node's boot script, from its reserved address,
inside a boot window. That proves the boot was one the head served to the
expected network position; it cannot stop an attacker who holds that
position at that moment. The certificate it earns lives only in RAM and
dies with the boot, each new enrollment revokes the node's earlier
certificates, and secrets are sealed to a key the node generated at
enrollment, so only that boot can open them. TPM-bound identity is not
built yet.

## Overlays

### Engines

Overlays are rendered on the server only. Nodes receive a plain file tree and
never run an overlay engine. Sources live in `/etc/flapjack/overlays/<name>/`
(a directory you can keep in git); a class lists the overlays its nodes get,
in order, and a later overlay's path replaces an earlier one's (the build
output warns when that happens).

**`template`**: a `rootfs/` tree, as in Warewulf. Files ending in `.ww` are Go
templates rendered per node; everything else is copied with its mode.
Templates see `.Node` (name, rack, IP, labels…), `.Nodes` (the whole
cluster), `.Class`, `.Server` and `.Domain`, plus Warewulf's `.Id`,
`.Hostname` and `.Ipaddr`. Functions: `Include` (a file from the overlay or
`/etc/flapjack/files`, nowhere else), `abort` (no file for this node),
`inRack`, `inClass`, `label`, `join`, `split` and friends. An optional
`overlay.json` sets per-path metadata (exact path or glob):

```json
{
  "paths": {
    "/etc/chrony.conf": {"onChange": ["systemctl try-restart chronyd"]},
    "/etc/sudoers.d/*": {"mode": "0440"},
    "/etc/motd": {"policy": "report"}
  },
  "directories": {"/root/.ssh": {"mode": "0700"}},
  "secrets": {"/etc/munge/munge.key": {"secret": "munge.key", "mode": "0400", "owner": "munge"}},
  "exclusive": ["/etc/sudoers.d"]
}
```

Directories in `rootfs/` are only containers: they are created as needed but
never chmod-ed or removed unless listed under `directories`.

**`nix`**: a `default.nix` NixOS-style module. All nix overlays of a class are
evaluated together with nixpkgs' `lib.evalModules`, once per render for all
nodes, so one overlay can declare typed options and another set them, with
`mkDefault`/`mkForce` precedence, `mkIf` conditions on the node, list and
text merging across modules, and assertions that fail the build with a
message. Modules receive `node`, `nodes`, `cluster` and `class`, and set:

```nix
files."/etc/sysctl.d/90-site.conf" = {
  text = "vm.swappiness = 10\n";    # or source = ./file; or secret = "name";
  mode = "0644"; owner = "root"; policy = "enforce";
  onChange = [ "sysctl --system" ];
};
directories."/var/spool/site".mode = "0750";
symlinks."/etc/localtime" = "/usr/share/zoneinfo/UTC";
exclusive = [ "/etc/slurm/conf.d" ];
assertions = [ { assertion = …; message = "…"; } ];
```

Evaluation is pure and confined: a static `nix` binary with `--store dummy://`
(no `/nix`, no daemon, no root, nothing built), and `restrict-eval` limiting
reads to the overlays being evaluated and nixpkgs' `lib`. A module cannot read
other files on the server or fetch anything. It takes milliseconds per class.
NixOS's own service modules are not reused because they assume `/nix/store`.

**Secrets** (`secret = "name"` or `overlay.json` `secrets`) are files in
`/etc/flapjack/secrets` (root-owned, readable only by the service). They never
pass through a template or Nix evaluation; their bytes become content like any
other file.

Both engines produce the same **manifest** (`internal/overlay`): a map of
absolute path → entry (kind, content digest or symlink target, mode, owner,
SELinux context, policy, `onChange`/`onRemove` hooks). Everything downstream
(signing, distribution, diff, apply) is engine-agnostic. Secrets are never
rendered into a manifest; entries reference them and the agent fills them in
after identity is established.

### Bi-directional reconciliation

Warewulf's `wwclient` only writes files. A file dropped from an overlay stays
on every node until reboot, or forever on stateful nodes. Flapjack instead
reconciles each node to an exact state.

**Downstream (server → node).** The agent keeps the manifest it last applied.
Applying generation N+1 over N:

1. Removes paths that are in N but not N+1, deepest first. If the booted
   image has its own version of a path the overlay had been shadowing (say
   `/etc/chrony.conf`), that version is restored instead of the path being
   deleted. Directories are removed only if empty, and never if the image ships
   them.
2. Converges every path in N+1: atomic write (temp file + fsync + rename),
   content verified against its digest, ownership before mode so setuid bits
   survive.
3. Prunes *exclusive* directories (for example `/etc/slurm`,
   `/etc/sudoers.d`, `/etc/yum.repos.d`): anything in them the manifest does
   not declare is deleted. Exclusive directories must be at least two levels
   deep.
4. Returns the de-duplicated `onChange`/`onRemove` hooks for the agent to run,
   for example `systemctl try-restart slurmd`.

Flapjack only ever deletes paths it recorded writing, or unmanaged paths
inside a directory explicitly declared exclusive. All filesystem access goes
through Go's `os.Root`, so a symlink planted on a node cannot redirect a write
or delete outside the target root.

**Per-path ownership policy:**

| Policy | Local edit between generations | Overlay changes the file | Path leaves the overlay |
|---|---|---|---|
| `enforce` (default) | Reverted on next apply; reported as drift | Overwritten | Removed (or image version restored) |
| `report` | Kept; reported as drift | Overwritten | Kept if edited, removed otherwise |
| `seed` | Kept; never reported | Updated only if untouched since Flapjack wrote it | Kept if edited, removed otherwise |

**Upstream (node → server).** The agent periodically verifies the node
against its manifest and reports drift: missing paths, changed content, mode
or owner, and unmanaged paths in exclusive directories. The server shows
drift as node status; for `enforce` paths the agent repairs it by re-applying
the same generation; `report` drift stays and is shown in `flapjack nodes`.
*Planned:* `flapjack overlay capture <node> <path>`
pulls a hand-edited file from a test node back into the overlay source as a
reviewable change, so tuning on a live node can be promoted instead of lost.

**Crash safety.** The agent records the incoming manifest as *pending* before
applying and as *applied* after. If it dies mid-apply, the next run treats the
union of both as "previously applied", so anything the interrupted run wrote
is still cleaned up when a later generation drops it. Apply is idempotent.

### Generations and the admin workflow

Like NixOS, every change a node receives is a numbered, immutable generation,
and the node's current generation is a pointer. `flapjack build` renders and
shows what would change without touching anything (`nixos-rebuild
dry-activate`); `flapjack switch` records a new generation for each node whose
result changed and its agent applies it within a second (`nixos-rebuild
switch`); `rollback` moves the pointer back, re-rendering nothing.

```
flapjack build --class compute           # dry run: per-node + ~ - per path
flapjack switch --class compute -m "chrony via head"
flapjack generations r1n01               # * marks current
flapjack diff r1n01 --from 3 --to 4
flapjack rollback r1n01 --reason "bad sysctl"          # previous generation
flapjack rollback r1n01 --to 2 --reason "known good"
flapjack overlay show r1n01              # every managed path, mode, owner, source overlay
flapjack nodes                           # applied generation, drift, agent heartbeat
flapjack events --type overlay.          # switch, applied, drift, repaired, rollback, hook_failed
```

Generations live in `/var/lib/flapjack/generations/<node>/<n>.json`; content
is stored by digest in `/var/lib/flapjack/content`. Switching to content
identical to the current generation records nothing. *Planned:* fold the
image digest and kernel into the same generation (today images are versioned
separately, below), and pin inputs in `flapjack.lock`.

### Node agent

`flapjack agent` runs on every node (`flapjack-agent.service`, installed in
the image). It long-polls `GET /agent/v1/manifest?have=N` on the head node, so
a switch reaches it at once, and:

1. resolves owner and group names against the node's `/etc/passwd`;
2. applies the new generation over the one it last applied (removing what
   left the overlay, restoring the image's own copy from the read-only
   `/run/rootfsbase` layer);
3. restores SELinux labels on what it wrote and runs the `onChange` /
   `onRemove` hooks;
4. every minute, verifies the node, repairs `enforce` drift (including
   unmanaged files in exclusive directories) and reports the rest.

It is a systemd `notify` service ordered before `sshd`, `chronyd`, `munge` and
`slurmd`, so at boot those start with their configuration in place; it
reports ready after 45 s regardless, so an unreachable server cannot block a
boot. Content requests are only answered for digests in the requesting node's
current generation, and a node is identified by its certificate and its
reserved address (see [node identity](#node-identity)).

### Images

`flapjack image build NAME` (root, on the head node) builds a stateless image
with `dnf --installroot`: base packages plus any in
`/etc/flapjack/images/NAME.json`, the agent, a generic initramfs with dracut's
`livenet` and `dmsquash-live`, SELinux labels, and a zstd squashfs. Builds
land in `images/NAME@<id>/` and `images/NAME` is a symlink to the current one;
`flapjack image list` shows versions and `flapjack image use NAME VERSION`
rolls back. Boot scripts name the exact version, so a rebuild during a boot
cannot mix one version's kernel with another's root filesystem. Nodes download
the root filesystem into RAM and run from an overlayfs on top of it.

## Data model

`api/v1alpha1` defines `NodeClass` (image, kernel, rootfs mode, overlays,
firmware spec, health policy) and `Node` (class, rack, topology block, BMC,
interfaces, serial; reported `status` with phase, generation, reason, and
the node's enrolled identity: its revocation floor and seal key). A `Generation` covers image,
kernel, boot arguments, overlays **and firmware/BIOS settings**, so a
firmware change is a new generation like any other. Phases form an enforced
lifecycle: a quarantined node can only leave through `BurnIn`, never straight
back to `Ready`. The types are plain structs designed to map onto Kubernetes
CRDs. *Planned:* label-selector overlay attachment.

## Platform features

On AI clusters the expensive failure is a node that is up but slow. One
degraded GPU or down-trained link can slow a 512-GPU job by a third without
crashing anything. These features exist to catch that, and to make the fixes
fast and repeatable.

| # | Feature | Package | Status |
|---|---|---|---|
| 1 | Health-gated admission, quarantine, stragglers, RMA evidence | `internal/health` | Complete: agents submit reports to the API, which applies the gate atomically. Collectors read real sysfs/procfs and parse `nvidia-smi`/`journalctl` output; validate on hardware |
| 2 | Topology discovery, cabling validation, Slurm topology | `internal/topology` | Complete, including multi-rail hosts; `ibnetdiscover -p` parser needs checking against your fabric's output |
| 3 | Firmware and BIOS in the generation | `internal/firmware`, `internal/bmc` | Complete over Redfish with task tracking and verified convergence; IPMI reports unsupported. In-band NIC settings (`mlxconfig`) planned |
| 4 | Model/data staging over the boot distribution layer | `internal/staging`, `internal/tlsutil` | Complete: HTTP or mTLS, retries, `stage ensure` for Slurm Prolog |
| 5 | Event timeline and change correlation | `internal/events` | Complete |
| 6 | Boot tickets and image tokens | `internal/attest` | Complete |
| 7 | AI-safe API: RBAC HTTP API and read-only MCP server | `internal/apiserver`, `internal/mcp` | Complete, with node-scoped agent tokens and a live read-only store for MCP |

### 1. Health gating

Checks run concurrently with per-check timeouts; a hung or panicking check
fails rather than stalling admission. Built in:

- **PCIe link**: width must match the maximum. GPUs lower link *speed* at idle,
  so for GPUs a speed below maximum is only a warning; for NICs it fails.
- **RDMA ports**: `ACTIVE` at or above the minimum rate, with error counters
  recorded.
- **GPUs**: count, uncorrectable ECC, row-remap pending (warn) or failed
  (fail), hardware slowdown, temperature.
- **Xid**: kernel log scan, classified so application faults (13, 31, 43)
  do not quarantine hardware but 48/64/74/79/95/119/120 do.
- **Memory**: catches DIMMs mapped out at POST.
- **Command / benchmark**: wraps `dcgmi diag`, NCCL tests or site scripts and
  extracts a metric for straggler detection.

`Gate` turns a report into a phase. Burn-in requires every listed check to
pass; in service, critical checks quarantine on first failure and others
after N consecutive failures.

`Admit` applies a report to the store: the verdict is computed from the
node's current status under the store lock, so concurrent reports cannot
interleave, and reports no newer than the last applied one are refused,
so a replayed or delayed "pass" cannot undo a quarantine. It fails closed:
a class that lists no checks requires every check in the report, and an
empty burn-in report quarantines. Agents run `flapjack health run
--report-to` with a node-scoped token, which can post only that node's
reports and nothing else. The verdict, not the caller, decides the phase,
so an agent can quarantine its own node but never release it. Reports and
phase changes land on the timeline as `health.pass|warn|fail` and
`node.phase`. `Stragglers` compares nodes against the fleet
median (so broken nodes cannot hide by dragging down a mean), and
`Regressed` compares a node against its own history to catch fleet-wide
decay. `WriteEvidence` packages report and raw tool output for an RMA ticket.

### 2. Topology

`Validate` classifies cabling against a blueprint as missing, miswired
(reporting where each end actually goes), wrong rate or unexpected; devices
outside the blueprint are ignored, so a one-rack blueprint can be checked
against a full fabric scan. `SlurmTree` assigns switch levels breadth-first
from the leaves (two- and three-tier fat trees) and `SlurmBlocks` renders
block topology for NVLink domains. Generated config comes from what is
cabled, so it never drifts from reality.

Host endpoints carry their HCA (`node01/mlx5_3:1`), so the eight rails of a
GPU node are distinct ports. A blueprint that names no HCAs for a host
matches whichever adapter is cabled, so single-rail blueprints need no
change. `CheckBlueprint` rejects a blueprint that uses one port twice. On
rail-optimized fabrics, `topology slurm --rail mlx5_0` builds the tree from
one rail, since Slurm expects each host under exactly one leaf. Port GUIDs
are kept from the scan for subnet-manager partitions.

### 3. Firmware

Specs pin component versions (exact names or globs such as `GPU* VBIOS`)
and BIOS attributes. Plans flash the BMC first, then BIOS, then devices,
reboot, and only then apply BIOS settings, because a BIOS flash can reset
them. Redfish BIOS values are sent with the JSON type the BMC reports, since
most BMCs reject `"4"` where they expect `4`. Drift with no image in the spec
is reported as unfixable instead of silently ignored.

Redfish `SimpleUpdate` is asynchronous: the BMC answers 202 with a Task.
The driver polls the Task (or TaskMonitor) until it reaches a terminal
state and fails on `Exception`, `Killed`, `Cancelled` or a `Critical`
status, so the following reboot never interrupts a flash in progress.
Polling retries through the BMC restarting. A task the BMC forgets (it
reset to activate its own image) is not trusted either way, and the outcome
is read from inventory. Updates target FirmwareInventory `@odata.id`s
recorded during inventory.

`Converger` (`flapjack firmware converge`) plans from live inventory,
applies each step, waits for the BMC and host after every reboot, then
re-reads inventory until only unfixable drift remains, failing with
`ErrNotConverged` otherwise. The command reads the node and class from the
API and records only changes that verifiably took effect, as
`firmware.flashed` and `bios.configured` change events
(`POST /v1/nodes/{name}/events`, admin only, and only those types), which
correlation can then rank. It refuses Ready nodes; drain first.

### 4. Staging

Artifacts are split into sha256-addressed chunks. Fetchers try rack peers,
then the rack cache, then the origin, rotating the starting peer per chunk to
spread load. Every chunk and the assembled artifact are verified; a tampered
chunk from one source just moves on to the next. The destination is replaced
atomically only after the whole artifact verifies. Digests are validated
before they become paths. Run on a rack cache with no destination, a fetch
pre-warms the cache.

Servers and clients can use mutual TLS (`stage serve --client-ca`, `stage
fetch --ca --cert --key`) so only enrolled nodes read chunks. Chunk bodies
are capped at the manifest's chunk size. A chunk gets several rounds over
all sources with exponential backoff, so a restarting rack cache does not
fail a job. `stage ensure` is the Slurm Prolog hook. It places named
artifacts under a directory, skips ones whose post-verification stamp
(digest, size, mtime) still matches, and serialises concurrent jobs on a
per-artifact lock, so a node downloads an artifact once.

### 5. Timeline

Events are JSON lines, one write each, with torn final lines tolerated.
`Correlate` groups changes by signature (type plus the values changed *to*),
then ranks them by coverage × precision. A change pushed to every node
explains everything and predicts nothing, so it ranks below one that hit
exactly the failing nodes.

### 6. Boot tickets

Boot tickets are HMACs bound to the node's MAC, expiring and single-use;
spent ones are kept on disk until they expire, so a restart cannot make a
ticket read from a node's `/proc/cmdline` good again. Image tokens gate
image downloads the same way.

### 7. API and MCP

The HTTP API stores only token hashes and compares them in constant time.
Reads need `viewer`; transitions need `operator`, require a reason and are
written to the timeline with the caller's name. It is TLS only, and every
request needs a cluster client certificate matching its token: an admin
certificate for admin tokens, the node's own for node-scoped tokens
(`"node": "<name>"`, which can only post their own health).

The MCP server (`flapjack mcp`, stdio) exposes six read-only tools:
`cluster_summary`, `list_nodes`, `get_node`, `explain_node`, `query_events`
and `correlate_failures`. It opens the store and event log
read-only. The store refuses writes and reloads whenever the API server
saves, so a long-running session never serves stale state. It negotiates
protocol versions 2024-11-05 through 2025-06-18. Results are bounded (list
limits, the newest events kept, a 512 KiB cap with a "narrow your query"
error), and a panicking tool becomes a tool error rather than a dead
session. Because it runs locally, it works with local models at airgapped
sites.

## Scale (*planned*)

See [design/tentacles.md](design/tentacles.md) for the fan-out control
plane: per-rack tentacles, a cluster CA with mTLS on every hop, and
head-signed generations, with a first implementation and a two-rack test.

- **Control plane:** 3–5 servers with embedded Raft state; no external database.
- **Rack caches:** stateless. Each serves DHCP (known MACs only, IPv4 and
  IPv6), HTTP boot and a content-addressed chunk cache. Any one can be lost;
  nodes fall back to a neighbouring rack or the control plane.
- **Networks:** boot over Ethernet management; the high-speed network
  (InfiniBand, Slingshot, RoCE) comes up from overlays after boot.

## Airgapped operation (*planned*)

One static binary plus an offline bundle (`flapjack bundle export|import`)
containing the boot environment, base images, overlays, signatures, dnf repo
snapshots and the Nix toolchain. An embedded OCI registry removes any need for
an external one. CI runs with network egress blocked to prove there are no
outbound calls.

## Testing

Unit tests cover every package without hardware; the Nix engine and QEMU
boot paths have their own tests. `flapjack lab` runs a whole cluster as VMs
on a Mac: a head node, network-booting nodes with TPMs, Redfish BMCs and a
packet capture of the provisioning network. See [testing/](testing/README.md)
and the [Mac lab](testing/mac-lab.md), including the findings that shaped it.

## Layout

```
api/v1alpha1/       declarative types: NodeClass, Node, Generation, phases
cmd/flapjack/       single static binary (CGO_ENABLED=0)
internal/overlay/   overlay manifests, diff, node-side apply/verify, state
internal/health/    checks, admission gate, stragglers, evidence bundles
internal/bmc/       Redfish and IPMI drivers, in-memory fake
internal/firmware/  firmware/BIOS drift, update plans
internal/topology/  fabric model, ibnetdiscover parser, cabling validation, Slurm topology
internal/events/    timeline and change correlation
internal/staging/   content-addressed chunk store, server, tiered fetcher
internal/attest/    boot tickets and image tokens
internal/dhcp/      DHCP server (reservations only, PXE/HTTP/iPXE boot files)
internal/tftp/      read-only TFTP server
internal/server/    head-node service: config, HTTP boot, overlays and agent API, systemd install
internal/render/    overlay engines: templates and Nix modules → manifests
internal/gens/      per-node overlay generations
internal/agent/     node agent: long-poll, apply, hooks, drift repair
internal/image/     stateless node images (dnf, dracut livenet, squashfs), versions
internal/lab/       QEMU test cluster on a Mac: switch, VMs, Redfish BMCs, head node
internal/store/     cluster state (one JSON file, group-committed writes)
internal/apiserver/ RBAC HTTP API
internal/mcp/       read-only MCP server
internal/sys/       command runner (real and fake)
internal/tlsutil/   shared TLS and mTLS configuration
internal/pki/       cluster CA, URI-SAN identities, identity-checked mTLS, signed generations
internal/tentacle/  per-rack relay and cache between agents and the head
internal/netsim/    in-process network with switches, link speeds and a wire tap, for topology tests
```
