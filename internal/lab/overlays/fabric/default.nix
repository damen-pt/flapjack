# The cluster (job) network: each node's second NIC, with the static
# address cluster.json gives its "cluster" interface, as a NetworkManager
# keyfile. Addresses live in one place (flapjack apply); this module only
# turns them into configuration. Nodes without a cluster interface get
# nothing (lib.mkIf).
{ lib, config, node, ... }:
let
  cfg = config.fabric;
  nic = lib.findFirst (i: i.network == "cluster") null node.interfaces;
in
{
  options.fabric = {
    prefixLength = lib.mkOption {
      type = lib.types.ints.between 8 30;
      default = 16;
      description = "Prefix length of the cluster network.";
    };
    mtu = lib.mkOption {
      type = lib.types.ints.between 1280 9000;
      default = 1500;
      description = "MTU of the cluster NIC (the lab switch carries 1500).";
    };
  };

  config = lib.mkIf (nic != null) {
    files."/etc/NetworkManager/system-connections/cluster.nmconnection" = {
      mode = "0600";
      text = ''
        # Managed by flapjack (overlay fabric).
        [connection]
        id=cluster
        type=ethernet
        autoconnect=true
        autoconnect-priority=10

        [ethernet]
        mac-address=${lib.toUpper nic.mac}
        mtu=${toString cfg.mtu}

        [ipv4]
        method=manual
        address1=${nic.ip}/${toString cfg.prefixLength}

        [ipv6]
        method=disabled
      '';
      onChange = [ "nmcli connection reload && nmcli connection up cluster" ];
    };
  };
}
