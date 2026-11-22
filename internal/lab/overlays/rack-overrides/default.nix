# Per-rack policy on top of ../site: only rack r2 changes, and mkForce wins
# over site's mkDefault.
{ lib, node, ... }:
lib.mkIf (node.rack == "r2") {
  site.banner = "Flapjack lab (rack 2)";
  site.sysctl."vm.swappiness" = lib.mkForce 1;
}
