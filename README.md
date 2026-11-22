<img src="assets/flapjack.png" width="128" height="128" alt="Flapjack logo: a flapjack octopus">

# flapjack

A declarative, security-first cluster manager for HPC and AI clusters.
Flapjack treats bare-metal nodes like containers: a node is an image plus
configuration plus an identity, it boots from the network into RAM, and it
is continuously kept equal to its definition. Reboot a node and you get back
exactly what it was defined to be.

It comes from running Warewulf, Bright/BCM, HPCM and Clusterware, keeping
what works (Warewulf's overlays, stateless nodes, one simple tool) and
fixing what hurts (files that never leave nodes, configuration drift,
upgrades nobody can roll back, and services that run as root and answer
anyone on the network).

> **Status:** early development. The boot pipeline, overlays, generations,
> node agent and images work end to end on a test cluster. See
> [what works today](#status).

## Core concepts

**One head-node service.** `flapjack.service` is a single static binary. It
answers DHCP for the nodes you declared (and nobody else), serves iPXE,
kernels and images, renders configuration, and hosts the API. It runs
unprivileged with two capabilities.

**Declarative nodes.** You describe **classes** (what a group of nodes runs:
an image and an ordered list of overlays) and **nodes** (one machine: name,
rack, MAC, IP, BMC, labels) in a JSON file and `flapjack apply` it. Keep that
file in git.

**Stateless images.** `flapjack image build` turns a list of EL packages
into a versioned, SELinux-labelled image. Nodes download it into RAM at boot,
so there is nothing on local disk to drift. Every build is kept, and rolling
back is moving a link.

**Overlays, with two engines.** Configuration lives in overlays, rendered per
node on the head node:

- **Templates:** a `rootfs/` tree of files, where `*.ww` files are per-node
  templates, as in Warewulf.
- **Nix modules:** NixOS-style modules with typed options, `mkDefault` and
  `mkForce` precedence, per-node conditions and assertions, evaluated
  together across overlays. You don't need NixOS or a Nix store, only a
  single static `nix` binary.

**Bi-directional reconciliation.** Remove a file from an overlay and it is
removed from the nodes, or the image's own copy is restored. Edit a managed
file by hand and the agent reverts it within a minute and records it.
Policies decide, per path, whether Flapjack enforces a file, only reports
changes to it, or seeds it once and leaves it to the node.

**Generations.** As in NixOS, every change a node receives is a numbered,
immutable generation. `build` shows what would change, `switch` applies it
everywhere in about a second, and `rollback` returns a node to any earlier
generation without rebuilding anything.

**Rack tentacles for large clusters.** Past a few racks, one head serving
every node becomes the bottleneck. A **tentacle** is a per-rack relay: the
same binary, run as `flapjack tentacle` on a machine in or next to the rack.
It keeps one connection to the head, caches what its rack needs, and relays
its nodes' status reports and enrollments. A `switch` then costs the head
one request per rack per file, not one per node, and the head's connection
count grows with racks rather than nodes. Optionally a tentacle also stages
the rack's images and runs its DHCP and boot, so a rack reboot pulls the
root filesystem across the core once, and nodes need no route to the head
at all.

A tentacle is a relay, never an authority:

- It holds no state. Losing one costs a cache; its rack keeps running what
  it has, and a replacement with the same certificate needs nothing
  restored.
- Every hop is mutual TLS from the cluster CA, and nodes verify each
  generation, boot script and image against the head's signature. A
  compromised tentacle can delay changes but cannot alter them, mint
  certificates, or act for any rack but the one its certificate names.
- Secrets reach it only sealed to each node's boot-time key
  (ML-KEM-768 + X25519), so it cannot read them.

**An audit trail.** DHCP leases, boots, switches, rollbacks, drift, repairs
and every admin action land on one event timeline, with who did it and why.

## How it works

```
 you ──► overlays + cluster.json ──► flapjack build / switch ──► generation N
                                                                     │
 power on ─► DHCP (known MACs only) ─► iPXE ─► kernel + image into RAM
         ─► flapjack agent ◄──── long-poll: generation N ────────────┘
                 │  applies it: writes, removes, restores, runs hooks
                 └─► reports applied generation and drift every minute
```

With tentacles, the head talks only to one tentacle per rack, and each rack
talks only to its tentacle:

```
                    head: store · render · signing · cluster CA
                     ▲ mTLS (management core)       ▲
             tentacle r1                     tentacle r2       stateless relays
   (cache · DHCP · boot · enroll)   (cache · DHCP · boot · enroll)
                     ▲ mTLS (rack network)          ▲
              r1n01 … r1nNN                  r2n01 … r2nNN
```

## Using Flapjack

```sh
# 1. Install the head node (EL9, provisioning NIC at 10.99.0.1/16)
sudo flapjack server install --address 10.99.0.1/16

# 2. Declare classes and nodes
flapjack apply cluster.json
flapjack nodes

# 3. Build the image the class names; nodes boot it as soon as it exists
sudo flapjack image build el9-compute

# 4. Write overlays in /etc/flapjack/overlays, then
flapjack build --class compute             # dry run: what changes on each node
flapjack switch --class compute -m "chrony from head node"

# 5. Day to day
flapjack generations r1n01
flapjack diff r1n01
flapjack rollback r1n01 --reason "bad sysctl"
flapjack events --type overlay.

# 6. Scale out: one tentacle per rack
sudo flapjack pki issue tentacle r1 --out /root/tentacle-r1  # copy to the rack's tentacle
flapjack tentacle                     # on it, configured by /etc/flapjack/tentacle.json
# then list the rack under "tentacles" in the head's server.json
```

A template overlay:

```
/etc/flapjack/overlays/base/rootfs/etc/hosts.ww
{{range .Nodes}}{{.IP}}  {{.Name}}.{{$.Domain}} {{.Name}}
{{end}}
```

A Nix overlay, overridden per rack by another:

```nix
# overlays/site/default.nix
{ lib, config, ... }: {
  options.site.swappiness = lib.mkOption { type = lib.types.int; default = 10; };
  config.files."/etc/sysctl.d/90-site.conf" = {
    text = "vm.swappiness = ${toString config.site.swappiness}\n";
    onChange = [ "sysctl --system" ];
  };
}

# overlays/rack2/default.nix
{ lib, node, ... }: lib.mkIf (node.rack == "r2") { site.swappiness = lib.mkForce 1; }
```

The [administrator guide](docs/admin-guide.md) covers all of this in
detail.

## Status

| Area | State |
|---|---|
| Head-node service: DHCP, TFTP, HTTP boot, API, hardened systemd unit | Working |
| Stateless EL9 images: build, versions, rollback | Working (head node's architecture) |
| Overlays: templates, Nix modules, secrets, policies, exclusive directories | Working |
| Generations: build, switch, diff, rollback | Working |
| Node agent: apply, hooks, SELinux labels, drift repair, reporting | Working |
| Signed iPXE boot, mTLS agents, sealed secrets, revocation | Working |
| Rack tentacles: per-rack relay, enrollment, sealed secrets, image staging, DHCP and boot | Working (tested in the Mac lab, not yet on hardware) |
| Health-gated admission, staging | Working |
| Firmware and BIOS over Redfish, topology validation, MCP server | CLI tools |
| TPM identity, HA control plane, offline bundles | Designed, not built |

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design and the reasoning
behind it.

## Documentation

- [Administrator guide](docs/admin-guide.md): install, configure and operate
  Flapjack
- [Overlays by example](docs/overlay-use-cases.md): templates or Nix for
  Slurm, PBS, Lmod, project environments, reserved nodes and RKE2
- [Architecture](docs/ARCHITECTURE.md): design decisions and feature status
- [Tentacles](docs/design/tentacles.md): the per-rack fan-out design, its
  security model and test topology; setup is in the
  [administrator guide](docs/admin-guide.md#16-racks-and-tentacles)
- [Testing](docs/testing/README.md): tests, and a
  [complete test cluster on a Mac](docs/testing/mac-lab.md) for learning
  Flapjack without hardware

## Building

Requires Go 1.26. There are no third-party dependencies.

```sh
make build    # bin/flapjack for this machine
make dist     # static Linux binaries for head nodes: bin/flapjack-linux-{amd64,arm64}
make test
```

## License

Apache-2.0. See [LICENSE](LICENSE).
