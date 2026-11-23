# Options of the compliance overlay.
#
# Profiles set `compliance.settings` at normal priority. Each setting has a
# type that merges several definitions by keeping the strictest, so
# "cis-l2,stig" gets the shorter timeout of the two and the longer password.
# null and false mean "not required"; that is every setting's default, so a
# node without profiles renders nothing.
#
# The site has two levers:
#   - a plain definition adds a floor:  compliance.settings.ssh.maxAuthTries = 3;
#   - lib.mkForce replaces the result:  compliance.settings.ssh.permitRootLogin = lib.mkForce "prohibit-password";
#     an exception, which belongs in compliance.waivers with the reason.
{ lib, config, node, ... }:
let
  inherit (lib) types mkOption;

  # A type whose definitions merge with `pick`; nulls are ignored.
  strictest = name: check: pick: lib.mkOptionType {
    name = "strictest-${name}";
    description = "${name} (strictest definition wins)";
    check = v: v == null || check v;
    merge = _loc: defs:
      let vs = lib.filter (v: v != null) (map (d: d.value) defs);
      in if vs == [ ] then null else lib.foldl' pick (lib.head vs) (lib.tail vs);
  };
  atMost = strictest "at most" lib.isInt lib.min;
  atLeast = strictest "at least" lib.isInt lib.max;
  required = strictest "required" lib.isBool (a: b: a || b);
  # An ordered enum, weakest first.
  ranked = order: strictest "one of ${lib.concatStringsSep ", " order}" (v: lib.elem v order)
    (a: b: if lib.lists.findFirstIndex (x: x == a) 0 order >= lib.lists.findFirstIndex (x: x == b) 0 order then a else b);
  # faillock's unlock_time: 0 means "only an admin unlocks", the strictest.
  unlockTime = strictest "seconds, 0 = never" lib.isInt (a: b: if a == 0 || b == 0 then 0 else lib.max a b);
  union = types.listOf types.str; # lists concatenate; renderers deduplicate

  opt = type: description: mkOption { inherit type description; default = null; };
  flag = description: mkOption { type = required; inherit description; default = false; };
  set = description: mkOption { type = union; inherit description; default = [ ]; };

  fromLabel = lib.filter (s: s != "") (map lib.trim (lib.splitString "," (node.labels.compliance or "")));
in
{
  options.compliance = {
    profiles = mkOption {
      type = types.listOf types.str;
      default = fromLabel;
      defaultText = "the node's `compliance` label, split on commas";
      description = "Active profiles. Known: cis-l1, cis-l2, stig, pci-dss, hipaa.";
    };

    arch = mkOption {
      type = types.enum [ "x86_64" "aarch64" ];
      default = node.labels.arch or "x86_64";
      description = "The node's architecture, for audit syscall rules. Defaults to the node's `arch` label.";
    };

    logHost = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = ''
        Where nodes send syslog and audit records (rsyslog, TCP; TLS on port
        6514 when settings.logging.tls). Every profile requires it: a
        stateless node's logs live in RAM and are gone at reboot.
      '';
    };
    logCaSecret = mkOption {
      type = types.str;
      default = "compliance-log-ca.pem";
      description = "Flapjack secret holding the CA that signed the log host's certificate.";
    };

    trustedNetworks = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "10.99.0.0/16" "10.100.0.0/16" ];
      description = ''
        CIDRs the host firewall accepts everything from: the provisioning
        and cluster (fabric) networks. MPI, Slurm and NFS between nodes use
        ports no profile could list. Everything else gets SSH only.
      '';
    };
    allowedTcpPorts = mkOption {
      type = types.listOf types.port;
      default = [ ];
      description = "Extra ports open to any source, besides SSH.";
    };

    banner = mkOption {
      type = types.str;
      description = "Pre-login banner for console and SSH.";
    };

    waivers = mkOption {
      type = types.attrsOf types.str;
      default = { };
      example = { sshd_disable_root_login = "head node manages nodes as root over SSH keys; ticket SEC-412"; };
      description = ''
        SCAP Security Guide rule IDs (without the xccdf_org.ssgproject.content_rule_
        prefix) the site does not meet, with the reason. They are deselected
        in the scan's tailoring file and listed in /etc/compliance/waivers,
        so an auditor sees every exception and why.
      '';
    };

    scan = {
      enable = mkOption {
        type = types.bool;
        default = config.compliance.profiles != [ ];
        description = "Scan with OpenSCAP at boot and daily, and log the result.";
      };
      onCalendar = mkOption { type = types.str; default = "daily"; };
      randomizedDelay = mkOption {
        type = types.str;
        default = "4h";
        description = "Spread scans so a large partition never scans at once.";
      };
    };

    settings = {
      kernel = {
        hardening = mkOption {
          type = ranked [ "none" "baseline" "high" ];
          default = "none";
          description = "baseline: network and memory sysctls every profile asks for; high: adds BPF, kexec, perf and SysRq lockdown (STIG).";
        };
        disableUserNamespaces = flag "user.max_user_namespaces = 0. Breaks unprivileged Apptainer, Podman and Enroot.";
        disableIpForwarding = flag "Nodes are not routers. Breaks Kubernetes workers.";
        blacklistModules = set "Kernel modules that may not load.";
        requiredArgs = set "Kernel arguments the profile needs; the class's bootArgs must carry them (warned at build).";
      };

      ssh = {
        hardening = flag "Protocol hygiene: no empty passwords, rhosts, host-based auth, user environment or X11; verbose logging.";
        maxAuthTries = opt atMost "MaxAuthTries.";
        loginGraceTime = opt atMost "LoginGraceTime, seconds.";
        idleTimeout = opt atMost "ClientAliveInterval, seconds (with ClientAliveCountMax 1).";
        maxSessions = opt atMost "MaxSessions.";
        maxStartups = opt atMost "MaxStartups (the first number).";
        permitRootLogin = mkOption { type = ranked [ "yes" "prohibit-password" "no" ]; default = "prohibit-password"; description = "PermitRootLogin."; };
        disableForwarding = flag "DisableForwarding: no TCP, agent or X11 forwarding. Breaks Jupyter-over-SSH tunnels.";
        banner = flag "Show the banner before login.";
      };

      accounts = {
        passwordMinLength = opt atLeast "pwquality minlen.";
        passwordComplexity = flag "One of each character class, no repeats or dictionary words.";
        passwordMaxDays = opt atMost "PASS_MAX_DAYS.";
        passwordMinDays = opt atLeast "PASS_MIN_DAYS.";
        passwordWarnDays = opt atLeast "PASS_WARN_AGE.";
        passwordHistory = opt atLeast "pam_pwhistory remember.";
        lockoutAttempts = opt atMost "pam_faillock deny.";
        lockoutSeconds = mkOption { type = unlockTime; default = null; description = "pam_faillock unlock_time; 0 = until an admin unlocks."; };
        lockoutRoot = flag "pam_faillock even_deny_root.";
        shellTimeout = opt atMost "TMOUT for interactive shells, seconds.";
        umask = mkOption { type = ranked [ "022" "027" "077" ]; default = "022"; description = "Default umask."; };
        maxLogins = opt atMost "Concurrent sessions per user (limits.conf maxlogins).";
        sudoHardening = flag "sudo: use_pty, an I/O-free log file.";
        sudoTimestamp = opt atMost "sudo timestamp_timeout, minutes (0: ask every time).";
        disableCoreDumps = flag "No core dumps (they can hold credentials and data).";
      };

      audit = {
        rules = mkOption {
          type = ranked [ "none" "baseline" "stig" ];
          default = "none";
          description = "baseline: identity, time, network, MAC, logins, permissions, mounts, modules, sudo; stig: adds privileged commands and execution as another user.";
        };
        immutable = flag "Lock the rules until reboot (-e 2). Rule changes then need a reboot.";
        fullAction = mkOption {
          type = ranked [ "syslog" "single" "halt" ];
          default = "syslog";
          description = "What auditd does when its log (in RAM) fills or fails.";
        };
      };

      logging = {
        remote = flag "Forward syslog and audit records to compliance.logHost.";
        tls = flag "Forward over TLS (port 6514).";
      };

      crypto = {
        policy = mkOption { type = ranked [ "DEFAULT" "DEFAULT:NO-SHA1" "FIPS" ]; default = "DEFAULT"; description = "System-wide crypto policy."; };
        fips = flag "FIPS 140 mode. Needs fips=1 in the class's bootArgs and an image built with dracut's fips module.";
      };

      integrity = {
        aide = flag "AIDE file integrity: a baseline at boot, a check daily.";
        usbguard = flag "USBGuard: allow only the USB devices present at boot.";
      };

      services = {
        firewall = flag "firewalld: cluster networks trusted, SSH from elsewhere.";
        mask = set "systemd units masked and stopped.";
        hardenTmp = flag "/tmp on its own tmpfs, nodev,nosuid,noexec. noexec breaks jobs that run code from /tmp.";
        hardenShm = flag "/dev/shm nodev,nosuid,noexec.";
      };
    };
  };
}
