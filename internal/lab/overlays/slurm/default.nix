# Slurm, configless. Compute nodes run slurmd with --conf-server: it
# fetches slurm.conf (and every other Slurm config file) from slurmctld, so
# the head's /etc/slurm/slurm.conf is the only copy. Login nodes only
# submit: they get the munge key here and slurm.conf from the login
# overlay. Every Slurm node gets the munge key (a flapjack secret, never in
# an overlay or the Nix store) and the slurm user with the head's IDs; job
# users come from the accounts overlay.
{ lib, config, node, nodes, ... }:
let
  cfg = config.slurm;
  inherit (lib) types mkOption;
  role = node.labels.role or "";
  computeNodes = lib.filter (n: n.labels.role or "" == "compute") nodes;
in
{
  options.slurm = {
    controller = mkOption {
      type = types.str;
      default = node.labels.head or "head";
      description = "slurmctld's address, on the cluster network.";
    };
    port = mkOption { type = types.port; default = 6817; };
  };

  config = lib.mkMerge [
    (lib.mkIf (role == "compute" || role == "login") {
      files."/etc/munge/munge.key" = {
        secret = "munge.key";
        owner = "munge";
        group = "munge";
        mode = "0400";
        onChange = [ "systemctl --no-block try-restart munge" ];
      };
      files."/etc/sysusers.d/flapjack-slurm.conf" = {
        text = ''
          # Managed by flapjack (overlay slurm).
          g slurm 450
          u slurm 450:slurm "Slurm" /var/lib/slurm /sbin/nologin
        '';
        onChange = [ "systemd-sysusers" ];
      };
    })

    (lib.mkIf (role == "compute") {
      files."/etc/sysconfig/slurmd" = {
        text = ''
          # Managed by flapjack (overlay slurm): configless slurmd.
          SLURMD_OPTIONS="--conf-server ${cfg.controller}:${toString cfg.port}"
        '';
        onChange = [ "systemctl --no-block try-restart slurmd" ];
      };
      # Keep retrying while the cluster NIC comes up or slurmctld restarts.
      files."/etc/systemd/system/slurmd.service.d/50-flapjack.conf" = {
        text = ''
          # Managed by flapjack (overlay slurm).
          [Unit]
          ConditionPathExists=
          Wants=network-online.target
          After=network-online.target munge.service flapjack-agent.service
          StartLimitIntervalSec=0

          [Service]
          Restart=on-failure
          RestartSec=10s
        '';
        onChange = [ "systemctl daemon-reload" ];
      };
      files."/etc/motd.d/slurm".text = ''
        Slurm: configless slurmd, controller ${cfg.controller}:${toString cfg.port}; ${toString (lib.length computeNodes)} compute nodes.
      '';
    })
  ];
}
