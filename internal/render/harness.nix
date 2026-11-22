# Flapjack's Nix overlay engine. Evaluates every node's modules with the
# NixOS module system and returns plain data: files, directories, symlinks
# and exclusive directories per node. Nothing is built and nothing is
# copied to a store; Flapjack turns the result into manifests.
{ inputFile }:
let
  input = builtins.fromJSON (builtins.readFile inputFile);
  lib = import (input.nixpkgs + "/lib");
  inherit (lib) types mkOption;

  meta = {
    mode = mkOption { type = types.nullOr types.str; default = null; description = "Octal mode, e.g. \"0644\"."; };
    owner = mkOption { type = types.str; default = "root"; };
    group = mkOption { type = types.str; default = "root"; };
  };

  file = types.submodule {
    options = meta // {
      enable = mkOption { type = types.bool; default = true; };
      text = mkOption {
        type = types.nullOr types.lines;
        default = null;
        description = "File content. Definitions from several modules are joined with newlines.";
      };
      source = mkOption { type = types.nullOr types.path; default = null; description = "A file in the overlay directory."; };
      secret = mkOption { type = types.nullOr types.str; default = null; description = "A file in Flapjack's secrets directory."; };
      policy = mkOption { type = types.enum [ "enforce" "report" "seed" ]; default = "enforce"; };
      seContext = mkOption { type = types.nullOr types.str; default = null; };
      onChange = mkOption { type = types.listOf types.str; default = [ ]; };
      onRemove = mkOption { type = types.listOf types.str; default = [ ]; };
    };
  };

  flapjack = {
    options = {
      files = mkOption { type = types.attrsOf file; default = { }; description = "Managed files by absolute path."; };
      directories = mkOption { type = types.attrsOf (types.submodule { options = meta; }); default = { }; };
      symlinks = mkOption { type = types.attrsOf types.str; default = { }; description = "Symlinks: path → target."; };
      exclusive = mkOption { type = types.listOf types.str; default = [ ]; };
      assertions = mkOption {
        type = types.listOf (types.submodule {
          options.assertion = mkOption { type = types.bool; };
          options.message = mkOption { type = types.str; };
        });
        default = [ ];
      };
      warnings = mkOption { type = types.listOf types.str; default = [ ]; };
    };
  };

  evalNode = node:
    let
      c = (lib.evalModules {
        modules = [ flapjack ] ++ map (p: /. + p) input.modules;
        specialArgs = {
          inherit node;
          inherit (input) cluster class;
          nodes = input.cluster.nodes;
        };
      }).config;
      failed = map (a: a.message) (lib.filter (a: !a.assertion) c.assertions);
      strip = f: {
        inherit (f) text secret policy seContext onChange onRemove mode owner group;
        source = if f.source == null then null else toString f.source;
      };
    in
    if failed != [ ] then { errors = failed; }
    else {
      files = lib.mapAttrs (_: strip) (lib.filterAttrs (_: f: f.enable) c.files);
      inherit (c) directories symlinks exclusive warnings;
    };
in
lib.listToAttrs (map (n: lib.nameValuePair n.name (evalNode n)) input.nodes)
