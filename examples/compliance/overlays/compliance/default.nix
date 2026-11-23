# Compliance profiles for compute nodes, applied on demand.
#
# A node adopts profiles with a label in cluster.json:
#
#   "labels": {"compliance": "stig"}          one profile
#   "labels": {"compliance": "cis-l2,hipaa"}  several: the strictest value of each setting wins
#
# then `flapjack apply cluster.json && flapjack switch NODE`. It takes effect
# live, in seconds. Remove the label and switch again and the files go away
# (the agent restores the image's own copies); kernel state that cannot be
# unloaded live (immutable audit rules, sysctls, kernel arguments) is gone at
# the next reboot, because nodes are stateless.
#
# Layout:
#   options.nix   what can be set, and the "strictest wins" types
#   profiles.nix  CIS L1/L2, DISA STIG, PCI DSS 4 and HIPAA as settings
#   system.nix    settings → files: kernel, SSH, accounts, crypto, services
#   logging.nix   settings → auditd rules, remote logging (nodes keep nothing)
#   scan.nix      OpenSCAP verification against the matching SSG profile,
#                 with waivers as an XCCDF tailoring file
#
# A node with no compliance label gets nothing from this overlay.
{ ... }:
{
  imports = [ ./options.nix ./profiles.nix ./system.nix ./logging.nix ./scan.nix ];
}
