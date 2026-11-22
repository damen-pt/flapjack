#!/bin/bash
# fj-welcome: the Flapjack lab head node's login screen. It shows
# flapjack's status, the lab's layout with each machine's live state, and
# commands to try. Installed by head-setup; run it again any time.
# Options: --no-color, --brief (status and layout only).

color=1 brief=
for a in "$@"; do
  case $a in
    --no-color) color= ;;
    --brief) brief=1 ;;
  esac
done
[ -t 1 ] || color=
if [ -n "$color" ]; then
  B=$'\e[1m' D=$'\e[2m' R=$'\e[0m' G=$'\e[32m' Y=$'\e[33m' E=$'\e[31m' C=$'\e[36m'
else
  B= D= R= G= Y= E= C=
fi
ok() { printf '%s●%s' "$G" "$R"; }
warn() { printf '%s●%s' "$Y" "$R"; }
bad() { printf '%s●%s' "$E" "$R"; }
dot() { # state → coloured dot
  case $1 in
    active|running|idle|alloc|mix|ok|up|reachable) ok ;;
    activating|inactive|waiting|unknown|unk|booting|comp|drng|drain|resv|"") warn ;;
    *) bad ;;
  esac
}
unit() { systemctl is-active "$1" 2>/dev/null || true; }

# ---- gather -----------------------------------------------------------
fj=$(unit flapjack)
nodes_json=$(timeout 5 flapjack nodes --json 2>/dev/null || echo '[]')
[ -n "$nodes_json" ] || nodes_json='[]'
images=$(ls -d /var/lib/flapjack/images/{{.Image}}@* 2>/dev/null | wc -l)
current=$(readlink /var/lib/flapjack/images/{{.Image}} 2>/dev/null)
node_field() { # NODE jq-expression
  jq -r --arg n "$1" ".[] | select(.name == \$n) | $2 // empty" <<<"$nodes_json" 2>/dev/null
}
agent_seen() { # NODE → "12s ago"
  local seen
  seen=$(node_field "$1" '.status.agent.seen')
  [ -n "$seen" ] || { echo "never"; return; }
  local s=$(( $(date +%s) - $(date -d "$seen" +%s 2>/dev/null || echo 0) ))
  if [ $s -lt 120 ]; then echo "${s}s ago"; else echo "$((s / 60))m ago"; fi
}
{{- if .Tentacles}}
declare -A slurm
if command -v sinfo >/dev/null; then
  while read -r n st; do slurm[$n]=$st; done < <(timeout 5 sinfo -h -N -o '%N %t' 2>/dev/null)
fi
{{- end}}

# ---- banner -----------------------------------------------------------
version=$(sha256sum /usr/local/bin/flapjack 2>/dev/null | cut -c1-12)
printf '\n%s  flapjack lab%s  %s· head node %s · flapjack build %s%s\n' "$B$C" "$R" "$D" "$(hostname -s)" "$version" "$R"
{{- if .Tentacles}}
printf '  %slayout: head + %d tentacles + %d compute + %d login nodes · Rocky Linux 9 · Slurm · NFS {{.HomeRoot}}%s\n\n' "$D" {{len .TentacleList}} {{.Compute}} {{len .Login}} "$R"
{{- else}}
printf '  %slayout: head + %d nodes on one provisioning network%s\n\n' "$D" {{len .Nodes}} "$R"
{{- end}}

# ---- status -----------------------------------------------------------
printf '%sStatus%s\n' "$B" "$R"
printf '  %s flapjack.service   %-10s' "$(dot "$fj")" "$fj"
if [ "$fj" = active ]; then
  printf ' %ssince %s%s' "$D" "$(systemctl show -p ActiveEnterTimestamp --value flapjack | cut -d' ' -f2-3)" "$R"
fi
echo
if [ "$images" -gt 0 ]; then
  printf '  %s image             %s %s(%d built)%s\n' "$(ok)" "${current:-{{.Image}}}" "$D" "$images" "$R"
elif [ "$(unit fj-lab-image)" = activating ]; then
  printf '  %s image             {{.Image}} is building %s(journalctl -fu fj-lab-image)%s\n' "$(warn)" "$D" "$R"
else
  printf '  %s image             {{.Image}} not built %s(sudo systemctl start fj-lab-image)%s\n' "$(bad)" "$D" "$R"
fi
total=$(jq length <<<"$nodes_json")
applied=$(jq '[.[] | select(.status.agent != null)] | length' <<<"$nodes_json")
drift=$(jq '[.[] | .status.agent.drift // [] | length] | add // 0' <<<"$nodes_json")
newest=$(jq '[.[] | .status.agent.applied // 0] | max // 0' <<<"$nodes_json")
printf '  %s nodes             %d declared, %d reporting, %d drifted paths, newest generation applied %d\n' \
  "$([ "$total" -gt 0 ] && [ "$applied" = "$total" ] && ok || warn)" "$total" "$applied" "$drift" "$newest"
{{- if .Tentacles}}
for u in munge slurmctld slurmrestd nfs-server; do
  s=$(unit $u)
  printf '  %s %-17s %s\n' "$(dot "$s")" "$u" "$s"
done
homes=$(ls -d {{.HomeRoot}}/*/ 2>/dev/null | wc -l)
clients=$(ss -Htn state established '( sport = :2049 )' 2>/dev/null | wc -l)
printf '  %s shared homes      {{.HomeRoot}}: %d users, NFS v4.2 to 10.100.0.0/16, %d client connections\n' \
  "$([ "$homes" -gt 0 ] && ok || warn)" "$homes" "$clients"
{{- end}}
if [ ! -e /var/lib/flapjack-lab-ready ]; then
  printf '  %s setup             still running %s(journalctl -fu fj-sync)%s\n' "$(warn)" "$D" "$R"
fi
echo

# ---- layout -----------------------------------------------------------
printf '%sLayout%s\n' "$B" "$R"
node_line() { # PREFIX NAME MGMT-IP CLUSTER-IP
  local phase gen seen sl
  phase=$(node_field "$2" '.status.phase')
  gen=$(node_field "$2" '.status.agent.applied')
  seen=$(agent_seen "$2")
  local a=down
  [ "$seen" != never ] && a=up
  printf '%s %s %-6s %-11s' "$1" "$(dot $a)" "$2" "$3"
  [ -n "$4" ] && printf ' %s%-13s%s' "$D" "$4" "$R"
  printf ' %-9s gen %-3s agent %-8s' "${phase:-?}" "${gen:--}" "$seen"
{{- if .Tentacles}}
  if [ -n "$5" ]; then
    printf ' %s' "$5" # a login node: no slurmd
  else
    sl=${slurm[$2]:-}
    printf ' slurm %s %s' "$(dot "${sl//[^a-z]/}")" "${sl:-unknown}"
  fi
{{- end}}
  echo
}
{{- if .Tentacles}}
printf '  %s fj-head   core %s · cluster %s · slurmctld · slurmrestd :6820 (Mac 127.0.0.1:{{.RESTPort}})\n' "$(dot "$fj")" "{{.HeadCore}}" "{{.HeadCluster}}"
printf '  │   %smanagement core 10.98.0.0/24: flapjack ↔ tentacles, mTLS%s\n' "$D" "$R"
{{- $nodes := .Nodes}}
{{- range $i, $t := .TentacleList}}
{{- $end := eq (len (slice $.TentacleList $i)) 1}}
status=$(timeout 4 ssh {{$t.CoreIP}} status 2>/dev/null)
tsvc=$(sed -n 's/.*service=\([a-z]*\).*/\1/p' <<<"$status")
timg=$(sed -n 's/.*images="\([^"]*\)".*/\1/p' <<<"$status")
if [ -z "$status" ]; then
  if ping -c1 -W1 {{$t.CoreIP}} >/dev/null 2>&1; then tsvc=booting; else tsvc=unreachable; fi
fi
printf '  {{if $end}}└{{else}}├{{end}}── %s {{$t.Name}}  core {{$t.CoreIP}} → rack {{$t.Rack}} {{$t.RackSubnet}} · DHCP, iPXE, images, agents · %s%s%s\n' \
  "$(dot "$tsvc")" "$D" "$tsvc${timg:+ · staged $timg}" "$R"
{{- range $nodes}}{{if eq .Rack $t.Rack}}
node_line '  {{if $end}} {{else}}│{{end}}    ├─' {{.Name}} {{.IP}} 'cluster {{.ClusterIP}}'{{if .SSHPort}} 'login · submit host · Mac ssh 127.0.0.1:{{.SSHPort}}'{{end}}
{{- end}}{{end}}
{{- end}}
printf '  %scluster network 10.100.0.0/16: fj-head + every node · Slurm, NFS {{.HomeRoot}}, ssh, jobs (no flapjack traffic)%s\n' "$D" "$R"
printf '  %srack networks reach only their tentacle: the nodes have no route to flapjack on the head%s\n' "$D" "$R"
{{- else}}
printf '  %s fj-head   provisioning {{.Address}}\n' "$(dot "$fj")"
{{- range .Nodes}}
node_line '  ├─' {{.Name}} {{.IP}} ''
{{- end}}
{{- end}}
echo
[ -n "$brief" ] && exit 0

# ---- things to try ------------------------------------------------------
cmd() { # COMMAND [WHAT IT DOES]; a long command puts its note on the next line
  if [ ${#1} -gt 52 ] && [ -n "$2" ]; then
    printf '  %s%s%s\n  %-52s %s%s%s\n' "$C" "$1" "$R" "" "$D" "$2" "$R"
  else
    printf '  %s%-52s%s %s%s%s\n' "$C" "$1" "$R" "$D" "$2" "$R"
  fi
}
sec() { printf '%s%s%s\n' "$B" "$1" "$R"; }

sec "Flapjack"
cmd "flapjack nodes" "phase, applied generation, drift, agent heartbeat"
cmd "flapjack events --since 30m" "DHCP, boots, enrollments, switches, drift"
{{- if .Tentacles}}
cmd "flapjack events --type pki." "node certificates issued through each tentacle"
cmd "ssh {{(index .TentacleList 0).CoreIP}} status" "a tentacle's service, staged images, certificate"
{{- end}}
cmd "ssh {{(index .Nodes 0).Name}}" "root on a node{{if .Tentacles}} (over the cluster network){{end}}"
echo

sec "Template overlays (Warewulf-style rootfs/ trees, *.ww templates)"
cmd "flapjack overlay list" "every overlay, its engine and the classes using it"
cmd "flapjack overlay show {{(index .Nodes 0).Name}}" "every file Flapjack manages on {{(index .Nodes 0).Name}}"
cmd "cat /etc/flapjack/overlays/base/rootfs/etc/hosts.ww" "one template, rendered per node"
cmd "sudo vi /etc/flapjack/overlays/base/rootfs/etc/motd.ww" "change the message of the day"
cmd "flapjack build --all" "dry run: what would change on each node"
cmd "flapjack switch --all -m 'new motd'" "a new generation; agents apply it at once"
cmd "ssh {{(index .Nodes 0).Name}} cat /etc/motd" ""
cmd "flapjack generations {{(index .Nodes 0).Name}}" "every generation the node received"
cmd "flapjack diff {{(index .Nodes 0).Name}}" "what the last switch changed"
cmd "flapjack rollback {{(index .Nodes 0).Name}} --reason undo" "back to the previous generation, no rebuild"
cmd "ssh {{(index .Nodes 0).Name}} 'echo 1.2.3.4 evil >> /etc/hosts'" "drift: reverted within a minute"
cmd "flapjack events --type overlay." "…and recorded as overlay.repaired"
echo

sec "NixOS-style modules (the nix engine: typed options, mkDefault / mkForce)"
cmd "cat /etc/flapjack/overlays/site/default.nix" "declares site.sysctl and site.banner"
cmd "cat /etc/flapjack/overlays/rack-overrides/default.nix" "lib.mkIf (node.rack == \"r2\"), lib.mkForce"
{{- $r2 := ""}}{{range .Nodes}}{{if and (eq .Rack "r2") (eq $r2 "")}}{{$r2 = .Name}}{{end}}{{end}}
cmd "ssh {{(index .Nodes 0).Name}} sysctl vm.swappiness" "10: site's lib.mkDefault"
{{- if $r2}}
cmd "ssh {{$r2}} sysctl vm.swappiness" "1: rack-overrides' lib.mkForce wins on r2"
{{- end}}
cmd "sudo sed -i 's/mkDefault 10/mkDefault 20/' \\" ""
cmd "    /etc/flapjack/overlays/site/default.nix" ""
cmd "flapjack build --all" "r1 changes to 20; r2 keeps its mkForce"
cmd "flapjack switch --all -m 'swappiness 20'" ""
cmd "sudo sed -i 's/mkDefault 20/mkDefault 500/' …" "breaks the assertion: build refuses with its message"
{{- if .Tentacles}}
cmd "cat /etc/flapjack/overlays/fabric/default.nix" "the cluster NIC, from node.interfaces in cluster.json"
cmd "cat /etc/flapjack/overlays/slurm/default.nix" "munge key (a secret), configless slurmd, users"
cmd "ssh {{(index .Nodes 0).Name}} cat /etc/sysconfig/slurmd" "rendered by the slurm module"
{{- end}}
echo
{{- if .Tentacles}}

sec "Slurm (slurmctld on fj-head; nodes are configless and fetch slurm.conf from it)"
cmd "sinfo" "partitions: compute{{range .TentacleList}}, {{.Rack}}{{end}}"
cmd "srun -N{{.Compute}} hostname" "one task on every node"
cmd "srun -p r2 -N2 uname -a" "a rack's partition"
cmd "sbatch --wrap 'sleep 60; hostname'; squeue" "a batch job"
cmd "scontrol show node {{(index .Nodes 0).Name}}" ""
echo

{{- if .Login}}
{{- $login := (index .Login 0).Name}}
{{- $u := (index .Users 0).Name}}
sec "Users and shared homes ({{range $i, $x := .Users}}{{if $i}}, {{end}}{{$x.Name}}{{end}}; homes in {{.HomeRoot}} over NFS)"
cmd "ssh {{$u}}@{{$login}}" "log in as a user on the login node"
cmd "ssh {{$u}}@{{$login}} 'sbatch --wrap \"hostname > ~/where.txt\"'" "submit from the login node"
cmd "cat {{.HomeRoot}}/{{$u}}/where.txt" "…written by a compute node into the shared home"
cmd "ssh {{$u}}@{{$login}} 'srun -N{{.Compute}} --chdir ~ pwd'" "every node sees the same home"
cmd "ssh r1n01 findmnt {{.HomeRoot}}" "automounted from fj-head over NFS v4.2"
cmd "sudo exportfs -v" "the export; root on nodes is squashed"
cmd "cat /etc/flapjack/overlays/accounts/default.nix" "users and UIDs, the same on every node (systemd-sysusers)"
cmd "cat /etc/flapjack/overlays/home/default.nix" "the automount, from typed options"
cmd "flapjack overlay show {{$login}}" "the login class: the compute overlays plus login"
echo

{{- end}}
sec "Slurm REST API (slurmrestd, JWT auth, also on the Mac at 127.0.0.1:{{.RESTPort}})"
cmd "fj-slurm-api ping" "GET /slurm/<version>/ping with a fresh token"
cmd "fj-slurm-api nodes | jq '.nodes[] | {name, state}'" ""
cmd "fj-slurm-api jobs | jq '.jobs[] | {job_id, name, job_state}'" ""
cmd "export \$(scontrol token lifespan=3600)" "a token for curl:"
cmd "curl -H \"X-SLURM-USER-NAME: \$USER\" -H \"X-SLURM-USER-TOKEN: \$SLURM_JWT\" \\" ""
cmd "    http://127.0.0.1:6820/openapi/v3 | jq '.paths | keys'" "every endpoint"
echo
{{- end}}
printf '%sRe-run: fj-welcome   ·   status only: fj-welcome --brief   ·   docs: docs/testing/mac-lab.md%s\n\n' "$D" "$R"
