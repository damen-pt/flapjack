# The site's side of compliance: where logs go, which networks are the
# cluster's, and every exception with its reason. Keep it separate from the
# compliance overlay so the profiles stay as published and this file is the
# one the security officer reviews.
{ lib, node, ... }:
{
  compliance = {
    logHost = "loghost.cluster";
    trustedNetworks = [ "10.99.0.0/16" "10.100.0.0/16" ];

    # A floor above every profile (plain definitions only ever tighten).
    settings.ssh.maxAuthTries = 3;

    # An exception: mkForce replaces the strictest value. Flapjack's head
    # manages nodes as root over SSH keys; passwords stay refused.
    settings.ssh.permitRootLogin = lib.mkForce "prohibit-password";
    waivers.sshd_disable_root_login = "head node administers nodes as root with SSH keys only (PermitRootLogin prohibit-password); risk accepted SEC-412";

    # GPU partitions run Apptainer/Enroot unprivileged, which needs user
    # namespaces; STIG turns them off.
    settings.kernel.disableUserNamespaces = lib.mkIf ((node.labels.gpu or "none") != "none") (lib.mkForce false);
    waivers.sysctl_user_max_user_namespaces = lib.mkIf ((node.labels.gpu or "none") != "none")
      "unprivileged containers on GPU nodes (Apptainer, Enroot); seccomp and SELinux confine them; risk accepted SEC-430";
  };
}
