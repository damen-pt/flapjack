# A NixOS-style module. It declares typed options with defaults; other
# modules (see ../rack-overrides) set them, with lib.mkDefault / lib.mkForce
# deciding who wins. Flapjack evaluates every nix overlay of a class
# together, per node, and turns `files`, `symlinks` and `directories` into
# the node's overlay.
{ lib, config, node, ... }:
let
  cfg = config.site;
in
{
  options.site = {
    banner = lib.mkOption {
      type = lib.types.str;
      default = "Flapjack lab";
      description = "Shown on the console login screen.";
    };
    sysctl = lib.mkOption {
      type = with lib.types; attrsOf (oneOf [ int str ]);
      default = { };
      description = "Kernel parameters for /etc/sysctl.d.";
    };
  };

  config = {
    site.sysctl = {
      "vm.swappiness" = lib.mkDefault 10;
      "net.core.somaxconn" = lib.mkDefault 4096;
    };

    files."/etc/sysctl.d/90-flapjack.conf" = {
      text = lib.concatStrings (lib.mapAttrsToList (k: v: "${k} = ${toString v}\n") cfg.sysctl);
      onChange = [ "sysctl --system" ];
    };

    files."/etc/issue".text = ''
      ${cfg.banner}: ${node.name} (rack ${node.rack})
      Kernel \r on \m
    '';

    assertions = [
      {
        assertion = cfg.sysctl."vm.swappiness" >= 0 && cfg.sysctl."vm.swappiness" <= 100;
        message = "site.sysctl.\"vm.swappiness\" must be between 0 and 100";
      }
    ];
  };
}
