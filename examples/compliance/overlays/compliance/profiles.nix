# The profiles, as settings. Each is what its benchmark asks of a Linux
# compute node that a configuration file can satisfy; packages come from the
# image (../../images/el9-compliance.json) and kernel arguments from the
# class (bootArgs). Values follow the SCAP Security Guide's RHEL 9 profiles,
# which scan.nix then checks the node against:
#
#   cis-l1   CIS RHEL 9 Benchmark, Level 1 Server     (ssg: cis_server_l1)
#   cis-l2   CIS RHEL 9 Benchmark, Level 2 Server     (ssg: cis)
#   stig     DISA STIG for RHEL 9                     (ssg: stig)
#   pci-dss  PCI DSS v4.0                             (ssg: pci-dss)
#   hipaa    HIPAA Security Rule, 45 CFR 164.3xx      (ssg: hipaa)
#
# Profiles only add requirements. Combine them freely: the merge keeps the
# strictest value of every setting (options.nix).
{ lib, config, ... }:
let
  cfg = config.compliance;
  has = p: lib.elem p cfg.profiles;
  when = p: lib.mkIf (has p);

  cisL1 = {
    kernel.hardening = "baseline";
    kernel.disableIpForwarding = true;
    # squashfs is deliberately absent: it is the node's root filesystem.
    kernel.blacklistModules = [ "cramfs" "freevxfs" "hfs" "hfsplus" "jffs2" "udf" "usb-storage" "dccp" "sctp" "rds" "tipc" ];
    ssh = {
      hardening = true;
      maxAuthTries = 4;
      loginGraceTime = 60;
      idleTimeout = 900;
      maxSessions = 10;
      maxStartups = 10;
      permitRootLogin = "no";
      disableForwarding = true;
      banner = true;
    };
    accounts = {
      passwordMinLength = 14;
      passwordComplexity = true;
      passwordMaxDays = 365;
      passwordMinDays = 1;
      passwordWarnDays = 7;
      passwordHistory = 24;
      lockoutAttempts = 5;
      lockoutSeconds = 900;
      shellTimeout = 900;
      umask = "027";
      sudoHardening = true;
      disableCoreDumps = true;
    };
    logging.remote = true;
    crypto.policy = "DEFAULT:NO-SHA1";
    integrity.aide = true;
    services = {
      firewall = true;
      mask = [ "ctrl-alt-del.target" ];
      hardenTmp = true;
      hardenShm = true;
    };
  };

  # Level 2 adds auditing and locks it.
  cisL2 = {
    kernel.requiredArgs = [ "audit=1" "audit_backlog_limit=8192" ];
    audit.rules = "baseline";
    audit.immutable = true;
    accounts.lockoutRoot = true;
  };

  stig = {
    kernel = {
      hardening = "high";
      disableUserNamespaces = true;
      disableIpForwarding = true;
      blacklistModules = [ "atm" "can" "cramfs" "firewire-core" "sctp" "tipc" "bluetooth" "usb-storage" ];
      requiredArgs = [ "audit=1" "audit_backlog_limit=8192" "pti=on" "vsyscall=none" "page_poison=1" "slub_debug=P" "fips=1" ];
    };
    ssh = {
      hardening = true;
      idleTimeout = 600;
      permitRootLogin = "no";
      banner = true;
    };
    accounts = {
      passwordMinLength = 15;
      passwordComplexity = true;
      passwordMaxDays = 60;
      passwordMinDays = 1;
      passwordHistory = 5;
      lockoutAttempts = 3;
      lockoutSeconds = 0;
      lockoutRoot = true;
      shellTimeout = 600;
      umask = "077";
      maxLogins = 10;
      sudoHardening = true;
      sudoTimestamp = 0;
      disableCoreDumps = true;
    };
    audit = {
      rules = "stig";
      immutable = true;
      fullAction = "single";
    };
    logging = { remote = true; tls = true; };
    crypto = { policy = "FIPS"; fips = true; };
    integrity = { aide = true; usbguard = true; };
    services = {
      firewall = true;
      mask = [ "ctrl-alt-del.target" "debug-shell.service" "kdump.service" "systemd-coredump.socket" ];
      hardenTmp = true;
      hardenShm = true;
    };
  };

  # PCI DSS v4.0: 8.3.4 lockout ≤ 10 tries for ≥ 30 min, 8.3.6 length 12,
  # 8.3.7 last 4 passwords, 8.3.9 90-day change, 8.2.8 15-minute idle,
  # 10.x audit logs kept off the box, 11.5.2 change detection, 1.x firewall.
  pciDss = {
    kernel.hardening = "baseline";
    kernel.disableIpForwarding = true;
    kernel.requiredArgs = [ "audit=1" "audit_backlog_limit=8192" ];
    ssh = {
      hardening = true;
      idleTimeout = 900;
      permitRootLogin = "no";
      banner = true;
    };
    accounts = {
      passwordMinLength = 12;
      passwordComplexity = true;
      passwordMaxDays = 90;
      passwordHistory = 4;
      lockoutAttempts = 10;
      lockoutSeconds = 1800;
      shellTimeout = 900;
      sudoHardening = true;
      disableCoreDumps = true;
    };
    audit.rules = "baseline";
    audit.immutable = true;
    logging = { remote = true; tls = true; };
    crypto.policy = "DEFAULT:NO-SHA1";
    integrity.aide = true;
    services.firewall = true;
  };

  # HIPAA technical safeguards: 164.312(a)(2)(iii) automatic logoff,
  # (b) audit controls, (c) integrity, (d) authentication, (e) transmission
  # security. The rule names outcomes, not values; these are SSG's.
  hipaa = {
    kernel.hardening = "baseline";
    kernel.requiredArgs = [ "audit=1" "audit_backlog_limit=8192" ];
    ssh = {
      hardening = true;
      idleTimeout = 900;
      permitRootLogin = "no";
      banner = true;
    };
    accounts = {
      passwordMinLength = 12;
      passwordComplexity = true;
      lockoutAttempts = 5;
      lockoutSeconds = 900;
      shellTimeout = 900;
      sudoHardening = true;
      disableCoreDumps = true;
    };
    audit.rules = "baseline";
    logging = { remote = true; tls = true; };
    crypto.policy = "DEFAULT:NO-SHA1";
    integrity.aide = true;
    services.mask = [ "ctrl-alt-del.target" ];
  };

  dodBanner = ''
    You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
    By using this IS (which includes any device attached to this IS), you consent to the following conditions:
    -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
    -At any time, the USG may inspect and seize data stored on this IS.
    -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
    -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
    -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
  '';
  siteBanner = ''
    Authorized use only. Activity on this system is monitored and recorded;
    use constitutes consent to monitoring. Disconnect now if you are not authorized.
  '';
in
{
  config = {
    compliance.settings = lib.mkMerge [
      (when "cis-l1" cisL1)
      (when "cis-l2" cisL1)
      (when "cis-l2" cisL2)
      (when "stig" stig)
      (when "pci-dss" pciDss)
      (when "hipaa" hipaa)
    ];

    compliance.banner = lib.mkDefault (if has "stig" then dodBanner else siteBanner);

    assertions =
      let known = [ "cis-l1" "cis-l2" "stig" "pci-dss" "hipaa" ];
      in map (p: {
        assertion = lib.elem p known;
        message = "compliance: unknown profile '${p}' (known: ${lib.concatStringsSep ", " known})";
      }) cfg.profiles;
  };
}
