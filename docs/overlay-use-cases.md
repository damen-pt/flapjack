# Overlays by example: templates or Nix

The [administrator guide](admin-guide.md#8-overlays) explains how both
overlay engines work. This page covers when to use each one, with worked
examples for the stacks HPC sites usually run: Slurm, PBS, environment
modules, per-project environments, carving out nodes for one group, and
turning a compute node into a Kubernetes (RKE2) worker.

Neither engine runs on nodes. Both render on the head node and produce the
same signed manifest of plain files. Nodes and tentacles never need Nix.
Only the head does, and only if you use Nix overlays
([setup](admin-guide.md#83-nix-modules)).

## 1. Where each piece goes

| Piece | Lives in | Changes take effect |
|---|---|---|
| Packages and binaries: `slurmd`, `pbs_mom`, Lmod, `rke2-agent`, drivers | The image ([6](admin-guide.md#6-node-images)) | At the next reboot |
| Which image, which overlays, in what order | The class (`cluster.json`) | Overlays at the next `switch`; image at the next reboot |
| What makes one node differ from the rest of its class | The node's `rack` and `labels` (`cluster.json`) | At the next `switch` |
| Configuration files, users, mounts, hooks | Overlays | At the next `switch`, live, without a reboot |
| Keys and tokens | `/etc/flapjack/secrets` ([8.4](admin-guide.md#84-secrets)) | At the next `switch` |
| Cluster-wide service state: `slurmctld`, the PBS server, the RKE2 server | The head or your service nodes, not node overlays | Up to you |

The rule this page uses:

- **Template**: one overlay owns the file, and the file looks the same on
  every node apart from a few node values (name, IP, a label).
- **Nix**: more than one party has a say in the result: a site default, a
  class, a rack, a label. Or the values must be checked before they reach
  a node, or several files are generated from one list.

An overlay can only set a Nix option if an overlay in the same class
declares it. Setting `modules.paths` in a class without the `modules`
overlay fails the build with `The option 'modules' does not exist`.

## 2. Slurm

**Pieces.** The image installs `munge` and `slurm-slurmd`. The head runs
`slurmctld` and keeps the only `slurm.conf`. Compute nodes run slurmd in
configless mode, which fetches its configuration from `slurmctld`. Login
nodes only submit jobs, so they need `slurm.conf` itself but no slurmd.

**Template version.** One overlay per role:

```
overlays/slurm-compute/rootfs/etc/sysconfig/slurmd.ww
overlays/slurm-compute/rootfs/etc/systemd/system/slurmd.service.d/50-flapjack.conf
overlays/slurm-login/rootfs/etc/slurm/slurm.conf.ww      # {{Include "slurm/slurm.conf"}}
```

```
# slurmd.ww
SLURMD_OPTIONS="--conf-server {{with label .Node "head"}}{{.}}{{else}}head{{end}}:6817"
```

The munge key and the `slurm` user have to go into both overlays, or into a
third overlay that both classes list.

**Nix version.** This is what the lab ships:
[`overlays/slurm/default.nix`](../internal/lab/overlays/slurm/default.nix).
One module covers both roles with `lib.mkIf` on `node.labels.role`:

```nix
config = lib.mkMerge [
  (lib.mkIf (role == "compute" || role == "login") {
    files."/etc/munge/munge.key" = { secret = "munge.key"; owner = "munge"; mode = "0400"; };
  })
  (lib.mkIf (role == "compute") {
    files."/etc/sysconfig/slurmd".text = ''
      SLURMD_OPTIONS="--conf-server ${cfg.controller}:${toString cfg.port}"
    '';
  })
];
```

`slurm.controller` and `slurm.port` are typed options, so another overlay can
point a rack at a different controller without editing this file:

```nix
# overlays/rack-overrides/default.nix
{ lib, node, ... }:
lib.mkIf (node.rack == "r9") { slurm.controller = "10.100.9.1"; }
```

**Pick:** Nix. One feature with a different shape for each role, and a
controller address that some racks override.

The exception is `slurm.conf` on login nodes. That stays a template
(`login/rootfs/etc/slurm/slurm.conf.ww`) because it includes the head's live
copy from `/etc/flapjack/files`, and a Nix module can only read files inside
overlay directories.

## 3. PBS (OpenPBS / PBS Pro)

**Pieces.** The image installs `openpbs-execution`, or the PBS Pro MoM RPM.
The PBS server and scheduler run on the head. You register nodes with
`qmgr -c "create node r1n01"` on the server, not in a node file. Each node
needs `/etc/pbs.conf` and the MoM's `mom_priv/config`.

**Template version:**

```
overlays/pbs/
├── overlay.json
└── rootfs/
    ├── etc/pbs.conf.ww
    └── var/spool/pbs/mom_priv/config.ww
```

```
# etc/pbs.conf.ww: login nodes submit only, so they run no MoM.
PBS_SERVER=head
PBS_START_SERVER=0
PBS_START_SCHED=0
PBS_START_COMM=0
PBS_START_MOM={{if eq (label .Node "role") "login"}}0{{else}}1{{end}}
PBS_EXEC=/opt/pbs
PBS_HOME=/var/spool/pbs
```

```
# var/spool/pbs/mom_priv/config.ww: copy job output straight to the shared homes.
$clienthost head
$usecp *:/c/home/ /c/home/
```

```json
{
  "paths": {
    "/etc/pbs.conf": {"onChange": ["systemctl try-restart pbs"]},
    "/var/spool/pbs/mom_priv/config": {"mode": "0644", "onChange": ["systemctl try-restart pbs"]}
  }
}
```

**Pick:** template. Node-side PBS is two small files owned by one overlay,
and the node list lives on the PBS server. Reach for Nix only if PBS shares
settings with other overlays, for example the controller address in a
cluster that runs both PBS and Slurm classes.

## 4. HPC modules (Lmod)

**Pieces.** The image installs `Lmod`. Modulefiles and software live on
shared storage (say `/c/apps`, mounted the way the
[`home`](../internal/lab/overlays/home/default.nix) overlay mounts `/c/home`).
The overlay decides which module trees each node sees: everyone gets
`core`, GPU nodes also get `cuda`, and one rack of new CPUs gets an
optimised tree. GPU nodes carry a `gpu` label (`"gpu": "a100"`), and other
nodes have none.

**Template version.** One file, with a condition for every tree:

```
# overlays/modules/rootfs/etc/profile.d/z01-flapjack-modules.sh.ww
module use --append /c/apps/modulefiles/core
{{- if ne (label .Node "gpu") ""}}
module use --append /c/apps/modulefiles/cuda
{{- end}}
{{- if eq .Node.Rack "r7"}}
module use --append /c/apps/modulefiles/zen5
{{- end}}
```

It works, but every new tree means editing this one file, even when the
tree belongs to a different team's overlay.

**Nix version.** One module declares the list, and any overlay adds to it.
Lists from every module are joined:

```nix
# overlays/modules/default.nix
{ lib, config, ... }:
let cfg = config.modules;
in
{
  options.modules.paths = lib.mkOption {
    type = with lib.types; listOf str;
    default = [ ];
    description = "Module trees, in order. Every overlay's entries are joined.";
  };

  config = {
    modules.paths = lib.mkBefore [ "/c/apps/modulefiles/core" ];
    # z01 sorts after Lmod's z00_lmod.sh, so `module` exists.
    files."/etc/profile.d/z01-flapjack-modules.sh".text = ''
      # Managed by flapjack (overlay modules).
      ${lib.concatMapStrings (p: "module use --append ${p}\n") cfg.paths}
    '';
  };
}
```

```nix
# overlays/gpu/default.nix: owned by the GPU team, listed by the gpu class.
{ lib, node, ... }:
lib.mkIf ((node.labels.gpu or "") != "") {
  modules.paths = [ "/c/apps/modulefiles/cuda" ];
}
```

```nix
# overlays/rack-overrides/default.nix
{ lib, node, ... }:
lib.mkIf (node.rack == "r7") { modules.paths = [ "/c/apps/modulefiles/zen5" ]; }
```

**Pick:** Nix as soon as more than one team adds trees. A template is fine
for a single tree that is the same everywhere.

## 5. Custom environments per project or class

**Pieces.** A project (here "climate") buys nodes and wants its own
environment on them: larger limits, huge pages, `OMP_*` defaults and
Apptainer bind paths. The software is the same, so they use the same image
in a separate class.

```json
{"name": "climate", "image": "el9-compute", "rootfs": "tmpfs",
 "overlays": ["base", "site", "accounts", "home", "slurm", "env", "climate"]}
```

**Nix version.** `env` holds the site's defaults as options. `climate` only
lists what that project changes:

```nix
# overlays/env/default.nix
{ lib, config, ... }:
let cfg = config.env;
in
{
  options.env = {
    variables = lib.mkOption { type = with lib.types; attrsOf str; default = { }; };
    nofile = lib.mkOption { type = lib.types.ints.between 1024 1048576; default = 65536; };
    memlock = lib.mkOption { type = lib.types.str; default = "unlimited"; };
    hugepages = lib.mkOption { type = lib.types.ints.unsigned; default = 0; };
  };

  config = {
    files."/etc/profile.d/flapjack-env.sh".text = ''
      # Managed by flapjack (overlay env).
      ${lib.concatStrings (lib.mapAttrsToList (k: v: "export ${k}=${lib.escapeShellArg v}\n") cfg.variables)}
    '';
    files."/etc/security/limits.d/90-flapjack.conf".text = ''
      # Managed by flapjack (overlay env).
      * - nofile ${toString cfg.nofile}
      * - memlock ${cfg.memlock}
    '';
    # Adds to the site overlay's sysctl file, so the class must list site.
    site.sysctl."vm.nr_hugepages" = lib.mkIf (cfg.hugepages > 0) cfg.hugepages;
  };
}
```

```nix
# overlays/climate/default.nix
{ ... }:
{
  env.nofile = 1048576;
  env.hugepages = 4096;
  env.variables = {
    OMP_PROC_BIND = "close";
    OMP_PLACES = "cores";
    APPTAINER_BINDPATH = "/c/scratch,/c/data/era5";
  };
}
```

A typo such as `env.nofile = 10485760` fails `flapjack build` for the climate
class (it exceeds the option's range) and never reaches a node. The huge
pages land in the same `/etc/sysctl.d/90-flapjack.conf` the site overlay
writes, not in a second file that competes with it.

**Template version.** A `climate` overlay with its own `limits.d` and
`profile.d` files works if the project never shares settings with the site
defaults. Once it does, you end up copying the site's file and keeping two
versions in step by hand.

**Pick:** Nix. "Site defaults, project changes" is exactly what
`mkDefault` and options are for.

## 6. Setting nodes aside on demand

**Pieces.** For a few weeks, nodes r3n01–r3n08 belong to one group (a
security-sensitive project, or a reservation for a paper deadline). Only that
group may log in, and the nodes say so. The image and class stay the same;
a **label** marks the nodes.

```json
{"name": "r3n01", "class": "compute", "rack": "r3", "labels": {"role": "compute", "tenant": "genomics"}}
```

```sh
flapjack apply cluster.json
flapjack switch r3n01 r3n02 r3n03 r3n04 r3n05 r3n06 r3n07 r3n08 -m "reserve r3 for genomics"
```

It takes effect within seconds, with no reboot. To undo it, remove the label
and switch again: the agent deletes what the overlay wrote.

**Nix version:**

```nix
# overlays/tenant/default.nix
{ lib, config, node, ... }:
let
  cfg = config.tenants;
  tenant = node.labels.tenant or null;
in
{
  options.tenants = lib.mkOption {
    description = "Groups nodes can be reserved for. A node joins one with the `tenant` label.";
    default = { };
    type = lib.types.attrsOf (lib.types.submodule {
      options.gid = lib.mkOption { type = lib.types.ints.between 3000 3999; };
      options.members = lib.mkOption { type = with lib.types; listOf str; };
    });
  };

  config = lib.mkMerge [
    {
      tenants.genomics = { gid = 3001; members = [ "alice" "carol" ]; };
      assertions = [{
        assertion = tenant == null || cfg ? ${tenant};
        message = "node ${node.name}: tenant label '${toString tenant}' is not declared in tenants";
      }];
    }
    (lib.mkIf (tenant != null && cfg ? ${tenant}) {
      files."/etc/sysusers.d/flapjack-tenant.conf" = {
        text = ''
          # Managed by flapjack (overlay tenant).
          g ${tenant} ${toString cfg.${tenant}.gid}
          ${lib.concatMapStrings (u: "m ${u} ${tenant}\n") cfg.${tenant}.members}
        '';
        onChange = [ "systemd-sysusers" ];
      };
      files."/etc/ssh/sshd_config.d/50-tenant.conf" = {
        mode = "0600";
        text = ''
          # Managed by flapjack (overlay tenant): reserved for ${tenant}.
          AllowGroups ${tenant} wheel
        '';
        onChange = [ "systemctl try-reload-or-restart sshd" ];
      };
      files."/etc/motd.d/tenant".text = "This node is reserved for ${tenant}.\n";
    })
  ];
}
```

A label that names an undeclared group (`"tenant": "genomic"`) fails the
build for those nodes, so a typo can't lock everyone out.

**Scheduler side.** This controls who can log in. Who can run jobs is set
by the scheduler on the head: a Slurm partition with `AllowGroups=genomics`
and `Nodes=r3n[01-08]`, or a reservation, or a PBS queue with an ACL.
Flapjack doesn't manage the head's `slurm.conf`.

**Template version.** `{{if ne (label .Node "tenant") ""}}` around each file
works, but nothing checks the group name or GID, and the member list ends up
in a template rather than in data.

**Pick:** Nix. A label changes several files at once, and a validation step
is worth having when a mistake locks people out.

## 7. Swapping nodes between Slurm and RKE2

Some sites move nodes between a Slurm cluster and a Kubernetes (RKE2)
cluster as demand changes. Flapjack can do it two ways:

| | Live swap ([7.1](#71-live-swap-tested)) | Reboot swap ([7.2](#72-reboot-swap)) |
|---|---|---|
| What changes | The node's `role` label | The node's class, and so its image |
| Image | One image with both stacks, neither enabled | One image per role |
| Time, once the node is idle | 4 s to Slurm; 71 s to registered in RKE2 and 2 min 43 s to Ready in the lab, mostly image pulls | A full boot, plus the same image pulls |
| Node afterwards | Cleaned by hooks; kernel and RAM state carry over | Fresh boot, fresh enrollment, re-sealed secrets |

Both use the same overlays. In both, the scheduler the node is leaving must
let it go first: Slurm drains it, or Kubernetes evicts its pods. Flapjack
doesn't decide when a node is idle.

### 7.1 Live swap (tested)

The run below is from the [Mac lab](testing/mac-lab.md): Rocky 9 on aarch64,
RKE2 v1.33.13+rke2r2, the RKE2 server on the head node, and stateless nodes
(`rootfs: tmpfs`) with 4 GiB of RAM. Node `r2n02` was moved while a Slurm
job was running on it.

**Pieces.**

- **The head** runs the RKE2 server on the cluster network. The join token
  is a flapjack secret, so the server and the nodes read the same file:

  ```sh
  sudo sh -c 'umask 027; openssl rand -hex 32 > /etc/flapjack/secrets/rke2.token; chgrp flapjackd /etc/flapjack/secrets/rke2.token'
  sudo install -D -m 0600 /etc/flapjack/secrets/rke2.token /etc/rancher/rke2/token
  ```
  ```yaml
  # /etc/rancher/rke2/config.yaml on the head
  node-ip: 10.100.0.1
  advertise-address: 10.100.0.1
  tls-san: [10.100.0.1, head]
  token-file: /etc/rancher/rke2/token
  disable: [rke2-ingress-nginx, rke2-metrics-server]
  ```

- **One image with both stacks, neither enabled.** The overlay for the
  node's role starts its service. `/etc/flapjack/images/rocky9-flex.json`
  (the head's repositories include Rancher's from `rpm.rancher.io`, for
  `rke2-agent`):

  ```json
  {
    "packages": ["munge", "slurm", "slurm-slurmd", "nfs-utils", "rke2-agent"],
    "services": ["sshd", "chronyd", "NetworkManager", "munge"]
  }
  ```

  It built in 81 s at 190 MiB, against 158 MiB for the Slurm-only image.

- **A class with both overlays.** The `role` label picks which one is
  active:

  ```json
  {"name": "flex", "image": "rocky9-flex", "rootfs": "tmpfs",
   "overlays": ["base", "site", "rack-overrides", "fabric", "accounts", "home", "slurm", "rke2"]}
  ```

  Moving a node into this class is a class change, so it needs one reboot
  ([7.2](#72-reboot-swap)). Every swap after that is live.

- **One secret per node**, `rke2-node-<name>.password` (see the module).

**The Slurm overlay** turns slurmd on for its role and off when the node
leaves it. These are the changes to the lab's
[`slurm`](../internal/lab/overlays/slurm/default.nix) module, in the
`role == "compute"` block:

```nix
symlinks."/etc/systemd/system/multi-user.target.wants/slurmd.service" = "/usr/lib/systemd/system/slurmd.service";
files."/etc/sysconfig/slurmd" = {
  text = ''
    SLURMD_OPTIONS="--conf-server ${cfg.controller}:${toString cfg.port}"
  '';
  # restart, not try-restart: when the role arrives, slurmd isn't running yet.
  onChange = [ "systemctl daemon-reload && systemctl --no-block restart slurmd" ];
  onRemove = [ "systemctl stop slurmd" ];
};
```

**The fabric overlay** owns the cluster NIC's NetworkManager file. It gets a
`routes` option that other overlays add to. Nodes without routes render the
same file as before, so their NIC isn't bounced:

```nix
options.fabric.routes = lib.mkOption {
  type = with lib.types; listOf (strMatching "[0-9./]+,[0-9.]+");
  default = [ ];
  description = "Static routes on the cluster NIC, as prefix,gateway. Other overlays add to it.";
};
# in the keyfile's [ipv4] section:
#   address1=${nic.ip}/${toString cfg.prefixLength}${lib.concatImapStrings (i: r: "\nroute${toString i}=${r}") cfg.routes}
```

**The RKE2 overlay.** Each comment explains a problem found in testing:

```nix
# overlays/rke2/default.nix
{ lib, config, node, ... }:
let
  cfg = config.rke2;
  on = (node.labels.role or "") == "rke2";
  # Identical commands run once per apply, however many files ask for them.
  restart = "systemctl daemon-reload && systemctl --no-block restart rke2-agent";
  # Leaving the role: rke2-killall.sh stops the agent and its containers
  # and removes the CNI's interfaces and iptables rules. The killed
  # processes take a moment to let go of containerd's tmpfs. What canal and
  # kubelet wrote outside it goes too: 200 MiB of CNI binaries (RAM, on a
  # stateless node) and canal's kubeconfig, a service-account credential.
  # Anything left fails the hook, which shows up as overlay.hook_failed.
  stop = lib.concatStringsSep "; " [
    "/usr/bin/rke2-killall.sh >/dev/null 2>&1"
    "for i in $(seq 30); do umount -R /var/lib/rancher 2>/dev/null && break; sleep 1; done"
    "findmnt -rn -o TARGET | grep -q ^/var/lib/kubelet/ || rm -rf --one-file-system ${lib.concatStringsSep " " leftovers}"
    "systemctl daemon-reload"
    "! mountpoint -q /var/lib/rancher && ! ls -d ${lib.concatStringsSep " " leftovers} 2>/dev/null"
  ];
  leftovers = [ "/etc/cni" "/opt/cni" "/var/lib/cni" "/var/lib/kubelet" "/var/log/pods" "/var/log/containers" "/run/calico" ];
in
{
  options.rke2 = {
    server = lib.mkOption {
      type = lib.types.strMatching "https://.+:9345";
      default = "https://${node.labels.head or "head"}:9345";
      description = "The RKE2 server's registration address.";
    };
    proxy = lib.mkOption {
      type = with lib.types; nullOr str;
      default = null;
      description = "HTTP proxy for image pulls, for nodes without a route to a registry.";
    };
    stateSize = lib.mkOption {
      type = lib.types.strMatching "[0-9]+[kKmMgG%]";
      default = "75%";
      description = "Size limit of the tmpfs that holds containerd's images and RKE2's runtime. It only uses RAM as it fills.";
    };
    nodeLabels = lib.mkOption { type = with lib.types; attrsOf str; default = { }; };
    taints = lib.mkOption { type = with lib.types; listOf str; default = [ ]; };
  };

  config = lib.mkIf on {
    rke2.nodeLabels."topology.kubernetes.io/zone" = node.rack;

    files."/etc/rancher/rke2/config.yaml" = {
      mode = "0600";
      text = builtins.toJSON {   # JSON is valid YAML
        server = cfg.server;
        token-file = "/etc/rancher/rke2/token";
        node-name = node.name;
        node-ip = (lib.findFirst (i: i.network == "cluster") { ip = node.ip; } node.interfaces).ip;
        node-label = lib.mapAttrsToList (k: v: "${k}=${v}") cfg.nodeLabels;
        node-taint = cfg.taints;
      };
      onChange = [ restart ];
      onRemove = [ stop ];
    };
    # containerd stacks overlay mounts, which the kernel refuses on top of a
    # stateless node's overlayfs root: its state gets a tmpfs of its own.
    # systemd's default tmpfs size, half the RAM, is too small for canal's
    # images; when it fills, kubelet dies with SIGPIPE.
    files."/etc/systemd/system/var-lib-rancher.mount" = {
      text = ''
        # Managed by flapjack (overlay rke2).
        [Mount]
        What=tmpfs
        Where=/var/lib/rancher
        Type=tmpfs
        Options=mode=0755,size=${cfg.stateSize}
      '';
      # Reloading a mounted mount unit remounts it with the new size.
      onChange = [ "systemctl daemon-reload && systemctl reload-or-restart var-lib-rancher.mount" restart ];
      onRemove = [ stop ];
    };
    files."/etc/systemd/system/rke2-agent.service.d/50-flapjack.conf" = {
      text = ''
        # Managed by flapjack (overlay rke2).
        [Unit]
        RequiresMountsFor=/var/lib/rancher
      '';
      onChange = [ restart ];
    };
    files."/etc/rancher/rke2/token" = { secret = "rke2.token"; mode = "0600"; };
    # A stateless node would make a new node password at every boot, and the
    # server rejects a known name with a new password.
    files."/etc/rancher/node/password" = { secret = "rke2-node-${node.name}.password"; mode = "0600"; };
    files."/etc/sysconfig/rke2-agent" = lib.mkIf (cfg.proxy != null) {
      text = ''
        # Managed by flapjack (overlay rke2).
        HTTP_PROXY=${cfg.proxy}
        HTTPS_PROXY=${cfg.proxy}
        NO_PROXY=127.0.0.0/8,10.0.0.0/8,.svc,.cluster.local
      '';
      onChange = [ restart ];
    };
    # Canal's interfaces are not NetworkManager's.
    files."/etc/NetworkManager/conf.d/rke2-canal.conf" = {
      text = ''
        [keyfile]
        unmanaged-devices=interface-name:flannel*;interface-name:cali*
      '';
      onChange = [ "nmcli general reload conf" ];
    };
    symlinks."/etc/systemd/system/multi-user.target.wants/rke2-agent.service" = "/usr/lib/systemd/system/rke2-agent.service";
    site.sysctl."net.ipv4.ip_forward" = 1;
    # Pods reach the API server at a Service address (10.43.0.1), which
    # kube-proxy rewrites only after the kernel has found a route to it. The
    # cluster network has no default route, so add one for the Service range.
    fabric.routes = [ "10.43.0.0/16,${node.labels.head or "10.100.0.1"}" ];
  };
}
```

The lab's nodes can't reach the internet, so the lab also sets
`rke2.proxy = "http://10.100.0.1:3128"` (squid on the head). A site with a
local registry mirror would use RKE2's `registries.yaml` instead.

**Slurm → RKE2.** Drain, wait until nothing runs, then flip the label:

```sh
scontrol update nodename=r2n02 state=drain reason="swap to rke2"
until [ "$(sinfo -h -N -n r2n02 -o %T | head -1)" = drained ]; do sleep 5; done

# cluster.json: r2n02 "labels": {"role": "rke2", ...}
flapjack apply cluster.json
flapjack switch r2n02 -m "r2n02: slurm to rke2"

kubectl get node r2n02 -w          # Ready once canal's images are pulled
```

`draining` means jobs are still running; `drained` means none are left.
The switch removes the Slurm files, and `onRemove` stops slurmd. The RKE2
files arrive and `onChange` starts rke2-agent. Slurm keeps the node as
`drained*` (not responding) with your reason, so nothing is scheduled there.

**RKE2 → Slurm.** Evict the pods, flip the label back, resume:

```sh
kubectl drain r2n02 --ignore-daemonsets --delete-emptydir-data
# cluster.json: "role": "compute"
flapjack apply cluster.json
flapjack switch r2n02 -m "r2n02: rke2 to slurm"
kubectl delete node r2n02
scontrol update nodename=r2n02 state=resume
```

**What the test showed.** This is one uninterrupted run with the modules
above:

| Time (UTC) | Event | Elapsed |
|---|---|---|
| 06:29:19 | Job 16 (`sleep 60`) running on r2n02 | |
| 06:29:29 | `scontrol update ... state=drain` → `draining`; the job keeps running | |
| 06:30:18 | The job ends → `drained` | 49 s: the rest of the job |
| 06:30:18 | `apply` + `switch`, `role=rke2` | |
| 06:30:19 | Generation 16 applied: slurmd stopped, rke2-agent starting | 1 s |
| 06:31:29 | Registered with the RKE2 server | 71 s (RKE2's runtime image pulled through the proxy) |
| 06:33:01 | `Ready` (canal's images pulled, CNI installed) | 2 min 43 s |
| 06:33:13 | A test pod pinned to r2n02 `Succeeded` | |
| 06:33:14 | `kubectl drain r2n02` | |
| 06:33:32 | Drained; `apply` + `switch`, `role=compute` | 18 s (evicting CoreDNS) |
| 06:33:34 | Generation 17 applied, stop hook finished | 2 s |
| 06:33:35 | slurmd active | 3 s |
| 06:33:36 | `resume` → `idle`; `srun -w r2n02 hostname` runs | 4 s |

The image pulls dominate the time to Ready. They went through a proxy on a
lab switch limited to 100 Mb/s; a registry mirror on a real cluster network
is much faster. Every flapjack step took 1 to 2 seconds.

| On r2n02 | Slurm, before | RKE2, Ready | Slurm, after |
|---|---|---|---|
| Kubernetes iptables rules (`KUBE-`, `CNI-`, `cali`, `flannel`) | 0 | 173 | 0 |
| CNI interfaces | none | `cali…` | none |
| Container shims | 0 | 3 | 0 |
| `/var/lib/rancher` tmpfs | none | mounted | none |
| `/etc/cni`, `/opt/cni`, `/var/lib/cni`, `/var/lib/kubelet` | none | all four | none |
| RAM available (of 3.9 GiB) | 3,396 MiB | 565 MiB | 3,405 MiB |

No `overlay.hook_failed` events, and a job submitted to `r2n02` right
after the swap back ran normally.

**Found in testing.** Each of these broke the swap before the module above
handled it:

| Symptom | Cause | Fix in the module |
|---|---|---|
| `"overlayfs" snapshotter cannot be enabled` | containerd can't stack overlays on the node's overlayfs root | `/var/lib/rancher` on its own tmpfs |
| kubelet exits every minute with `signal: broken pipe`; image pulls fail with `no space left on device` | The tmpfs got systemd's default size, half the RAM. When it fills, RKE2 can't write kubelet's log and kubelet dies of SIGPIPE | `rke2.stateSize`, 75% by default; changing it remounts live |
| canal's `install-cni` crash-loops: `dial tcp 10.43.0.1:443: connect: network is unreachable` | No default route, so the kernel drops packets to Service addresses before kube-proxy's NAT sees them | `fabric.routes` gets the Service range |
| After the swap back, 673 MiB of RAM still held | The hook unmounted `/var/lib/rancher` before the processes `rke2-killall.sh` signalled had exited, and the hook still reported success | The stop hook retries for up to 30 s and fails if the mount remains |
| After the swap back, `/opt/cni` (212 MiB, in RAM) and `/etc/cni/net.d` with canal's `calico-kubeconfig` remain. On the next swap the node reports Ready before canal runs | `rke2-killall.sh` leaves CNI binaries, CNI config and kubelet state; only `rke2-uninstall.sh` removes them | The stop hook removes them, and fails if any remain |
| slurmd doesn't start when the role comes back | `try-restart` does nothing for a stopped service | `restart`, in the Slurm module |

**Sizing.** With canal, an RKE2 node holds about 2.2 GiB in
`/var/lib/rancher` (images and RKE2's runtime) before any workload, and on a
stateless node all of it is RAM. In the run above, a 3.9 GiB node had
565 MiB left once Ready. The same swap on 1.4 GiB nodes registered with the
server but never became Ready. Plan for about 3.5 GiB per node plus your
pods, or mount a local disk at `/var/lib/rancher` instead of the tmpfs.

**Limits.**

- A live swap cleans up what RKE2 created: containers, mounts, CNI links,
  iptables rules, CNI and kubelet files, and its tmpfs. It doesn't reset kernel modules
  (`br_netfilter`, `overlay`) or sysctls the overlays don't manage. For
  security-sensitive work, reboot after a node leaves RKE2. That reboot is
  the reboot swap below, in the same class.
- Both stacks are in every node's image, so there's more installed
  software, and more in RAM, than either role needs alone.
- Draining is the scheduler's job. A script that drains, waits for
  `drained`, then runs `apply` and `switch` is all the automation needed.

### 7.2 Reboot swap

Give each role its own image and class, and change the node's class. The
same `slurm` and `rke2` overlays work. Each role's image can enable its own
service, or leave that to the overlay as above.

```json
"classes": [
  {"name": "compute",     "image": "el9-compute", "rootfs": "tmpfs",
   "overlays": ["base", "site", "fabric", "accounts", "home", "slurm"]},
  {"name": "rke2-worker", "image": "el9-rke2",    "rootfs": "tmpfs",
   "overlays": ["base", "site", "fabric", "rke2"]}
]
```

Give `rke2-worker` nodes `"role": "rke2"`. The `rke2` overlay is gated on
that label, so it can also sit in a class that some nodes leave unused.

```sh
scontrol update nodename=r2n05 state=drain reason="to rke2"    # wait for drained
# cluster.json: "class": "rke2-worker", "role": "rke2"
flapjack apply cluster.json
flapjack build r2n05 -v                   # slurm files going, rke2 files coming
flapjack switch r2n05 -m "r2n05 to rke2"
ssh root@r2n05 systemctl reboot           # the agent announces it, which opens the boot window (3.7)
```

Between the switch and the reboot, the old image briefly has the new
class's files, and their hooks run against it. That's why the drain comes
first. `flapjack rollback` alone can't undo a class change, because the
image follows the class, not the generation.

**Template version.** A template could write `config.yaml`, but not the
rest. The node password has a different secret name on every node, while
`overlay.json` maps a path to one secret for all nodes. The route must be
added to another overlay's file, and the stop hook must run when the role
goes away. Each of those needs Nix.

**Pick:** Nix.

## 8. Summary

| Use case | Engine | Deciding reason |
|---|---|---|
| hosts, chrony, sshd, sudoers, motd | Template | One owner, static apart from node values |
| Slurm, compute and login | Nix | One feature, different shape per role; overridable controller |
| `slurm.conf` on login nodes | Template | Includes the head's live copy from `/etc/flapjack/files` |
| PBS MoM | Template | Two small files; the node list lives on the PBS server |
| Lmod module trees | Nix | Several overlays add to one list |
| Per-project environment | Nix | Site defaults with project changes, checked before they ship |
| Setting nodes aside (label) | Nix | One label changes several files; mistakes fail the build |
| Slurm ↔ RKE2, live or by reboot | Nix | Per-node secret, a route added to another overlay's file, stop hooks when the role goes |

| Change | Mechanism | Reboot |
|---|---|---|
| A setting for a whole class | Edit an overlay, `switch --class` | No |
| One node or a group of nodes differs from its class | Label in `cluster.json`, `apply`, `switch` | No |
| A node changes workload on an image that has both (Slurm ↔ RKE2) | `role` label, `apply`, `switch` | No |
| Different software on the node | Class with another image, `apply`, `switch`, reboot | Yes |
