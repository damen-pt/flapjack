# Testing Flapjack

| What | Command | Needs |
|---|---|---|
| Unit tests | `make test` | Go 1.26 |
| Unit tests with the race detector | `make test-race` | Go 1.26 |
| Nix overlay engine tests | see below | Linux, a static `nix`, nixpkgs `lib/` |
| QEMU boot tests | `make test-lab` | macOS on Apple silicon, Homebrew `qemu` and `swtpm` |
| A whole test cluster | `make lab-up` | as above; see [mac-lab.md](mac-lab.md) |

## Unit tests

`go test ./...` covers every package without root, network access or
hardware. Hardware is faked where needed: an in-memory BMC (also served over
real Redfish), fake command output for `nvidia-smi`, `journalctl` and
`ibnetdiscover`, and temporary directories standing in for a node's root
filesystem. Highlights:

- `internal/overlay`: the bi-directional reconciler (removal, restore from
  the image, policies, exclusive directories, crash safety, symlink attacks).
- `internal/agent`: a real agent against a real server handler. It switches,
  removes files, repairs drift and rolls back, end to end.
- `internal/server`: boot scripts, per-node access control, build, switch,
  long-poll wake-up, rollback.
- `internal/dhcp`, `internal/tftp`: wire formats and the boot-file decision
  for every client type.
- `internal/render`: the template engine, and the Nix engine when available.

## Nix engine tests

The Nix tests skip unless both variables are set. They need Linux (the static
`nix` builds are Linux-only):

```sh
FLAPJACK_NIX=/usr/local/bin/nix FLAPJACK_NIXPKGS=/usr/local/share/flapjack/nixpkgs \
  go test -run Nix -v ./internal/render
```

From a Mac, cross-compile the test and run it on the lab's head node, which
has both installed:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c -o /tmp/render.test ./internal/render
bin/flapjack lab ssh -- 'cat > /tmp/render.test && chmod +x /tmp/render.test &&
  FLAPJACK_NIX=/usr/local/bin/nix FLAPJACK_NIXPKGS=/usr/local/share/flapjack/nixpkgs /tmp/render.test -test.v -test.run Nix' < /tmp/render.test
```

They check `mkDefault`/`mkForce` precedence, `mkIf` on node attributes, text
merging across modules, `source` files, secrets, assertions, and that
`restrict-eval` blocks reads outside the overlays.

## QEMU boot tests

`make test-lab` boots real VMs and checks that each firmware path reaches
DHCP: aarch64 UEFI with iPXE, x86_64 legacy BIOS, and x86_64 UEFI Secure
Boot. They need the iPXE build that `make lab-up` caches.

## The test cluster

[mac-lab.md](mac-lab.md) describes the full test cluster on a Mac: a head
node, racks of network-booting nodes, Redfish BMCs and a packet capture of
the provisioning network.
