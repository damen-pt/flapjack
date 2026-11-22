# Cluster users, the same on every node and on the head, with the head's
# UIDs: jobs run as the submitting user's UID, and files on the shared
# /c/home must belong to the same people everywhere. A stateless node gets
# them from systemd-sysusers on every boot; nothing is written to an image.
#
# The lab's head creates the same users (internal/lab LabUsers); a test
# keeps the two lists equal.
{ lib, config, ... }:
let
  inherit (lib) types mkOption;
  cfg = config.accounts;
in
{
  options.accounts.users = mkOption {
    description = "Users by name. Homes under the shared root are on NFS; others are created locally.";
    default = { };
    type = types.attrsOf (types.submodule ({ name, ... }: {
      options = {
        uid = mkOption { type = types.ints.between 1000 59999; };
        home = mkOption { type = types.str; default = "${config.home.root}/${name}"; };
        shell = mkOption { type = types.str; default = "/bin/bash"; };
        description = mkOption { type = types.str; default = name; };
      };
    }));
  };

  config = {
    accounts.users = {
      # The lab's admin; its home stays local, like root's.
      flapjack = lib.mkDefault { uid = 1000; home = "/home/flapjack"; description = "Lab admin"; };
      alice = lib.mkDefault { uid = 2001; description = "Alice (user)"; };
      bob = lib.mkDefault { uid = 2002; description = "Bob (user)"; };
      carol = lib.mkDefault { uid = 2003; description = "Carol (user)"; };
      dave = lib.mkDefault { uid = 2004; description = "Dave (user)"; };
    };

    files."/etc/sysusers.d/flapjack-accounts.conf" = {
      text = "# Managed by flapjack (overlay accounts).\n" + lib.concatStrings (lib.mapAttrsToList (name: u:
        "u ${name} ${toString u.uid} \"${u.description}\" ${u.home} ${u.shell}\n") cfg.users);
      onChange = [ "systemd-sysusers && systemd-tmpfiles --create /etc/tmpfiles.d/flapjack-accounts.conf" ];
    };
    # Local homes only: the shared ones are the file server's.
    files."/etc/tmpfiles.d/flapjack-accounts.conf" = {
      text = "# Managed by flapjack (overlay accounts): local home directories.\n" + lib.concatStrings (lib.mapAttrsToList (name: u:
        "d ${u.home} 0700 ${name} ${name} -\n") (lib.filterAttrs (_: u: !lib.hasPrefix "${config.home.root}/" u.home) cfg.users));
      onChange = [ "systemd-sysusers && systemd-tmpfiles --create /etc/tmpfiles.d/flapjack-accounts.conf" ];
    };

    assertions =
      let uids = lib.mapAttrsToList (_: u: u.uid) cfg.users;
      in [{
        assertion = lib.length uids == lib.length (lib.unique uids);
        message = "accounts.users: every user needs its own uid";
      }];
  };
}
