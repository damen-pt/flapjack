# Shared homes: /c/home, exported by the head over NFS v4.2 on the cluster
# network, automounted on first use. An automount rides out the cluster
# NIC coming up after the agent writes this file, and a file server
# restart; a plain mount at boot would not.
{ lib, config, node, ... }:
let
  cfg = config.home;
  # systemd names a mount unit after its path: /c/home -> c-home.
  unit = lib.replaceStrings [ "/" ] [ "-" ] (lib.removePrefix "/" cfg.root);
in
{
  options.home = {
    root = lib.mkOption { type = lib.types.str; default = "/c/home"; description = "Where homes are mounted."; };
    server = lib.mkOption {
      type = lib.types.str;
      default = node.labels.head or "head";
      description = "The NFS server, on the cluster network.";
    };
    export = lib.mkOption { type = lib.types.str; default = cfg.root; description = "The path the server exports."; };
    options = lib.mkOption {
      type = with lib.types; listOf str;
      default = [ "vers=4.2" "hard" "noatime" "_netdev" ];
    };
  };

  config = lib.mkIf (node.labels ? head) {
    files."/etc/systemd/system/${unit}.mount".text = ''
      # Managed by flapjack (overlay home).
      [Unit]
      Description=Shared homes from ${cfg.server}
      Wants=network-online.target
      After=network-online.target

      [Mount]
      What=${cfg.server}:${cfg.export}
      Where=${cfg.root}
      Type=nfs4
      Options=${lib.concatStringsSep "," cfg.options}
    '';
    files."/etc/systemd/system/${unit}.automount" = {
      text = ''
        # Managed by flapjack (overlay home).
        [Unit]
        Description=Shared homes from ${cfg.server} (on first use)

        [Automount]
        Where=${cfg.root}
        TimeoutIdleSec=0

        [Install]
        WantedBy=remote-fs.target
      '';
      # sshd and slurmd may read homes on NFS (SELinux), then mount.
      onChange = [ "setsebool use_nfs_home_dirs 1; systemctl daemon-reload && systemctl start --no-block ${unit}.automount" ];
    };
    symlinks."/etc/systemd/system/remote-fs.target.wants/${unit}.automount" = "/etc/systemd/system/${unit}.automount";
    # No directories entry for the root: systemd makes the mount point, and
    # the agent must never chmod the server's directory through NFS.
  };
}
