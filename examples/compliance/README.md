# Compliance profiles on demand

This example is a Nix overlay that makes a compute node meet **CIS Level 1 or
Level 2, DISA STIG, PCI DSS 4.0 or HIPAA** when you put a label on it. The
node checks itself against the matching SCAP Security Guide profile, and the
results go to your log host. You don't reinstall or rebuild anything, and the
change takes effect without a reboot.

```json
{"name": "r2n01", "class": "compute-stig", "labels": {"compliance": "stig"}}
```

```sh
flapjack apply cluster.json
flapjack build r2n01            # dry run: every file it adds, plus warnings
flapjack switch r2n01 -m "STIG for the ITAR project"
```

To take a profile off, remove the label and switch again. The agent deletes
the files the overlay wrote and puts the image's own copies back.

## Contents

| Path | What it is |
|---|---|
| `overlays/compliance/` | The profiles. Copy it to `/etc/flapjack/overlays/` and leave it as it is |
| `overlays/compliance-site/` | Your site's settings: log host, cluster networks and exceptions. Edit this one |
| `images/el9-compliance.json` | The packages and services the profiles need in the image |
| `cluster.json` | Two classes and six nodes covering each profile and one combination |
| `compliance_test.go` | Renders the example the same way the head node does |

## Setup

1. **Image.** Merge the `packages` and `services` from
   `images/el9-compliance.json` into your compute image spec. Then run
   `sudo flapjack image build NAME` and reboot the nodes when it suits you.
   An overlay can't install packages: auditd, rsyslog-gnutls, AIDE,
   firewalld, USBGuard and the OpenSCAP scanner must already be in the
   image.
2. **Overlays.** Copy both overlay directories into
   `/etc/flapjack/overlays/`. Add `compliance` and then `compliance-site` to
   the end of the class's `overlays`. Both are Nix overlays, so the head
   needs the [Nix engine](../../docs/admin-guide.md#83-nix-modules).
3. **Site settings.** In `compliance-site/default.nix`, set:
   - `logHost`: your syslog server. Every profile needs it, because a
     stateless node keeps its logs and audit trail in RAM, and they are lost
     at reboot.
   - `trustedNetworks`: the provisioning and cluster networks, so MPI, Slurm
     and NFS traffic between nodes gets through the host firewall.
4. **Log host CA** (STIG, PCI DSS and HIPAA forward over TLS): put the PEM
   CA that signed the log host's certificate at
   `/etc/flapjack/secrets/compliance-log-ca.pem`.
5. **Kernel arguments.** Some profiles need kernel arguments, and these come
   from the class's `bootArgs`: `audit=1 audit_backlog_limit=8192` for CIS
   L2, PCI DSS and HIPAA, and STIG adds
   `pti=on vsyscall=none page_poison=1 slub_debug=P fips=1`. If any are
   missing, `flapjack build` lists them as a warning and the switch still
   goes ahead. Kernel arguments only change at a reboot, which is why
   `cluster.json` has a separate `compute-stig` class with all of them
   already set.

## Profiles

| Label | Benchmark | Checked against (SSG, RHEL 9) |
|---|---|---|
| `cis-l1` | CIS Red Hat Enterprise Linux 9, Level 1 Server | `cis_server_l1` |
| `cis-l2` | CIS RHEL 9, Level 2 Server (Level 1 plus auditing) | `cis` |
| `stig` | DISA STIG for RHEL 9 | `stig` |
| `pci-dss` | PCI DSS v4.0 | `pci-dss` |
| `hipaa` | HIPAA Security Rule technical safeguards | `hipaa` |

To apply several profiles, separate them with commas:
`"compliance": "cis-l2,hipaa"`. For each setting, the strictest value among
them wins: the shorter timeout, the longer password, the lower lockout
count. A typo in a label, such as `stg`, fails the build for that class
instead of quietly applying nothing.

What the profiles set, roughly from least strict to most:

| | cis-l1 | cis-l2 | pci-dss | hipaa | stig |
|---|---|---|---|---|---|
| Kernel sysctls (network, ptrace, dmesg, ASLR) | ✓ | ✓ | ✓ | ✓ | ✓ + BPF, kexec, perf, SysRq, user namespaces |
| SSH: root login, idle timeout (s) | no, 900 | no, 900 | no, 900 | no, 900 | no, 600 |
| Password length / history / max age (days) | 14 / 24 / 365 | 14 / 24 / 365 | 12 / 4 / 90 | 12 / – / – | 15 / 5 / 60 |
| Lockout: attempts / unlock (s) | 5 / 900 | 5 / 900 (root too) | 10 / 1800 | 5 / 900 | 3 / admin only |
| Shell timeout (s), umask | 900, 027 | 900, 027 | 900, – | 900, – | 600, 077 |
| Audit rules | | baseline, immutable | baseline, immutable | baseline | STIG, immutable |
| Remote logging | TCP | TCP | TLS | TLS | TLS |
| Crypto policy | DEFAULT:NO-SHA1 | DEFAULT:NO-SHA1 | DEFAULT:NO-SHA1 | DEFAULT:NO-SHA1 | FIPS |
| AIDE, host firewall, USBGuard | ✓ ✓ – | ✓ ✓ – | ✓ ✓ – | ✓ – – | ✓ ✓ ✓ |
| `/tmp`, `/dev/shm` nodev,nosuid,noexec | ✓ | ✓ | | | ✓ |
| Login banner | site | site | site | site | DoD standard notice |

`profiles.nix` holds the exact values, and `options.nix` documents every
setting.

## Exceptions

The site overlay can change a profile in two ways:

```nix
compliance.settings.ssh.maxAuthTries = 3;                                  # a floor: can only tighten
compliance.settings.ssh.permitRootLogin = lib.mkForce "prohibit-password"; # an exception: replaces the result
compliance.waivers.sshd_disable_root_login = "head manages nodes as root with keys only; SEC-412";
```

A waiver takes an SCAP Security Guide rule ID and the reason for the
exception. Each node gets the full list in `/etc/compliance/waivers`, and
the scan's tailoring file deselects exactly those rules. That way an
auditor sees every exception along with its reason, and the scan reports
only the gaps you haven't accepted. The example site overlay contains two
waivers: root login over SSH keys, which is how the head manages nodes, and
user namespaces on GPU nodes, which unprivileged Apptainer and Enroot need.

Some rules can't apply to a stateless node, and the overlay waives them
itself with a stated reason:

- separate `/var`, `/var/log` and `/var/log/audit` partitions
- the squashfs module, because the root filesystem is squashfs
- GRUB passwords and permissions, because nodes boot over iPXE
- GRUB kernel-argument rules, but only for arguments the class's `bootArgs`
  actually carry

## Evidence

Fifteen minutes after boot, and then daily, each node runs `oscap xccdf eval`
for each of its profiles. The daily start time is randomised over four hours,
so a large partition never scans all at once. Each scan sends one line to
syslog, which is forwarded to the log host:

```
compliance-scan: profile=stig pass=412 fail=3 waivers=21 exit=2 report=/var/log/compliance/stig-20261123T0412Z.html
```

The full ARF results and HTML reports stay on the node for 7 days, or until
it reboots. If a scan finds failures, `compliance-scan.service` exits
non-zero, so `systemctl --failed` or your monitoring shows which nodes are
out of compliance.

Flapjack keeps its own record as well:

- Every switch is a generation, with who made it and why
  (`flapjack generations NODE`).
- `flapjack diff` shows exactly which files a profile added.
- The agent reverts any hand edit to a managed file within a minute and
  logs an `overlay.repaired` event.

Taken together, this is the configuration-management evidence that CM-2,
CM-3 and CM-6 (the controls STIG and PCI DSS 2.2 draw on) ask for.

## What happens live, and what waits for a reboot

| Change | When the label is added | When it is removed |
|---|---|---|
| Files: SSH, PAM, sudo, logging, firewall, banners | At once (hooks reload the services) | At once, image copies restored |
| sysctls | At once | At the next reboot (the values stay set until then) |
| Audit rules with `-e 2` (CIS L2, PCI DSS, STIG) | At once, and then locked | At the next reboot |
| Kernel arguments, FIPS mode | At the next reboot, after you change the class | At the next reboot |

Nodes are stateless, so a reboot always gives you exactly what the node's
current generation defines.

## Limits

- **FIPS.** STIG sets the FIPS crypto policy and needs `fips=1`. Flapjack's
  image build doesn't add dracut's `fips` module yet, so the boot-time
  integrity self-test doesn't run. Don't claim FIPS 140-3 mode for an
  assessed system until the image builder adds that module.
- **Scope.** These profiles cover the operating system's technical controls,
  which is what a configuration file can do. They don't cover physical
  security, personnel, risk assessments, BAAs or PCI scoping. For HIPAA in
  particular, most of the rule is administrative and physical.
- **HPC trade-offs.** These are the settings most likely to break jobs:
  - `noexec` on `/tmp`: some installers and conda environments run code
    from there.
  - `DisableForwarding` (CIS): Jupyter and VS Code tunnels stop working.
  - No user namespaces (STIG): unprivileged containers stop working.
  - USBGuard (STIG): nothing to worry about on headless nodes.
  - The host firewall: only `trustedNetworks` get unrestricted access.

  Waive whatever your users depend on, and give the reason.
- **Rule IDs.** Waiver IDs come from SCAP Security Guide 0.1.7x. Check that
  they match the content shipped in your image with
  `oscap info /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml`.

## Testing

```sh
FLAPJACK_NIX=$(which nix) FLAPJACK_NIXPKGS=/path/to/nixpkgs go test ./examples/compliance
```

The test renders every profile, the combined `cis-l2,hipaa` node, the GPU
waiver and the strictest-wins merge. It also checks that a node with no
label gets no files, that a mistyped label fails the build, and that a
missing kernel argument produces a warning rather than an error.
