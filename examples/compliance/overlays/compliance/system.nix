# Settings → files: kernel, SSH, accounts, crypto, integrity and services.
# Every file is conditional on the setting that needs it, so a node without
# profiles gets none of them. Hooks apply changes live; onRemove undoes what
# can be undone live, and a reboot undoes the rest.
{ lib, config, class, ... }:
let
  cfg = config.compliance;
  s = cfg.settings;
  on = v: v != null && v != false;
  str = toString;
  lines = ls: lib.concatStrings (map (l: l + "\n") ls);
  header = "# Managed by flapjack (overlay compliance: ${lib.concatStringsSep ", " cfg.profiles}).";
  # A setting line only when the setting is required.
  opt = v: line: lib.optional (on v) line;

  bootArgs = if class.bootArgs or null == null then [ ] else class.bootArgs;

  sysctlBaseline = {
    "kernel.randomize_va_space" = 2;
    "kernel.yama.ptrace_scope" = 1;
    "kernel.dmesg_restrict" = 1;
    "kernel.kptr_restrict" = 1;
    "fs.protected_hardlinks" = 1;
    "fs.protected_symlinks" = 1;
    "fs.suid_dumpable" = 0;
    "net.ipv4.conf.all.accept_redirects" = 0;
    "net.ipv4.conf.default.accept_redirects" = 0;
    "net.ipv4.conf.all.secure_redirects" = 0;
    "net.ipv4.conf.default.secure_redirects" = 0;
    "net.ipv4.conf.all.send_redirects" = 0;
    "net.ipv4.conf.default.send_redirects" = 0;
    "net.ipv4.conf.all.accept_source_route" = 0;
    "net.ipv4.conf.default.accept_source_route" = 0;
    "net.ipv4.conf.all.log_martians" = 1;
    "net.ipv4.conf.default.log_martians" = 1;
    "net.ipv4.conf.all.rp_filter" = 1;
    "net.ipv4.conf.default.rp_filter" = 1;
    "net.ipv4.icmp_echo_ignore_broadcasts" = 1;
    "net.ipv4.icmp_ignore_bogus_error_responses" = 1;
    "net.ipv4.tcp_syncookies" = 1;
    "net.ipv6.conf.all.accept_ra" = 0;
    "net.ipv6.conf.default.accept_ra" = 0;
    "net.ipv6.conf.all.accept_redirects" = 0;
    "net.ipv6.conf.default.accept_redirects" = 0;
    "net.ipv6.conf.all.accept_source_route" = 0;
    "net.ipv6.conf.default.accept_source_route" = 0;
  };
  sysctlHigh = {
    "kernel.unprivileged_bpf_disabled" = 1;
    "net.core.bpf_jit_harden" = 2;
    "kernel.kexec_load_disabled" = 1;
    "kernel.perf_event_paranoid" = 2;
    "kernel.sysrq" = 0;
    "kernel.core_pattern" = "|/bin/false";
  };
  sysctl =
    lib.optionalAttrs (s.kernel.hardening != "none") sysctlBaseline
    // lib.optionalAttrs (s.kernel.hardening == "high") sysctlHigh
    // lib.optionalAttrs s.kernel.disableIpForwarding { "net.ipv4.ip_forward" = 0; "net.ipv6.conf.all.forwarding" = 0; }
    // lib.optionalAttrs s.kernel.disableUserNamespaces { "user.max_user_namespaces" = 0; }
    // lib.optionalAttrs s.accounts.disableCoreDumps { "fs.suid_dumpable" = 0; };

  modules = lib.unique s.kernel.blacklistModules;
  masked = lib.unique s.services.mask;
  a = s.accounts;
  unit = name: "/etc/systemd/system/${name}";
  wants = target: name: { "/etc/systemd/system/${target}.wants/${name}" = "/usr/lib/systemd/system/${name}"; };
in
{
  # Only nodes with a profile; the site's floors alone render nothing.
  config = lib.mkIf (cfg.profiles != [ ]) (lib.mkMerge [
    (lib.mkIf (sysctl != { }) {
      # 99-: after the site's own sysctl files, so the profile wins.
      files."/etc/sysctl.d/99-compliance.conf" = {
        text = lines ([ header ] ++ lib.mapAttrsToList (k: v: "${k} = ${str v}") sysctl);
        onChange = [ "sysctl --system >/dev/null" ];
        onRemove = [ "sysctl --system >/dev/null" ];
      };
    })

    (lib.mkIf (modules != [ ]) {
      files."/etc/modprobe.d/compliance-blacklist.conf".text =
        lines ([ header ] ++ lib.concatMap (m: [ "install ${m} /bin/false" "blacklist ${m}" ]) modules);
    })

    {
      warnings =
        let missing = lib.filter (x: !lib.elem x bootArgs) (lib.unique s.kernel.requiredArgs);
        in lib.optional (missing != [ ])
          "compliance: class ${class.name} needs kernel arguments ${lib.concatStringsSep " " missing} in its bootArgs (profiles ${lib.concatStringsSep ", " cfg.profiles}); they apply at the next boot";
    }

    # SSH. sshd keeps the first value it reads, and 10- sorts before the
    # image's 50-redhat.conf and Flapjack's own 40-flapjack.conf.
    (lib.mkIf (s.ssh.hardening || on s.ssh.maxAuthTries || s.ssh.permitRootLogin != "prohibit-password") {
      files."/etc/ssh/sshd_config.d/10-compliance.conf" = {
        mode = "0600";
        text = lines ([ header ]
          ++ lib.optionals s.ssh.hardening [
            "PermitEmptyPasswords no"
            "IgnoreRhosts yes"
            "HostbasedAuthentication no"
            "PermitUserEnvironment no"
            "X11Forwarding no"
            "GSSAPIAuthentication no"
            "KerberosAuthentication no"
            "StrictModes yes"
            "UsePAM yes"
            "Compression no"
            "PrintLastLog yes"
            "LogLevel VERBOSE"
          ]
          ++ [ "PermitRootLogin ${s.ssh.permitRootLogin}" ]
          ++ opt s.ssh.maxAuthTries "MaxAuthTries ${str s.ssh.maxAuthTries}"
          ++ opt s.ssh.loginGraceTime "LoginGraceTime ${str s.ssh.loginGraceTime}"
          ++ opt s.ssh.idleTimeout "ClientAliveInterval ${str s.ssh.idleTimeout}"
          ++ opt s.ssh.idleTimeout "ClientAliveCountMax 1"
          ++ opt s.ssh.maxSessions "MaxSessions ${str s.ssh.maxSessions}"
          ++ opt s.ssh.maxStartups "MaxStartups ${str s.ssh.maxStartups}:30:${str (s.ssh.maxStartups * 6)}"
          ++ opt s.ssh.disableForwarding "DisableForwarding yes"
          ++ opt s.ssh.banner "Banner /etc/issue.net");
        onChange = [ "systemctl try-reload-or-restart sshd" ];
        onRemove = [ "systemctl try-reload-or-restart sshd" ];
      };
    })

    (lib.mkIf (s.ssh.banner || cfg.profiles != [ ]) {
      files."/etc/issue".text = cfg.banner;
      files."/etc/issue.net".text = cfg.banner;
    })

    # Accounts. login.defs and faillock.conf replace the image's copies,
    # which the agent puts back when the profile goes.
    (lib.mkIf (on a.passwordMaxDays || a.umask != "022") {
      files."/etc/login.defs".text = lines ([
        header
        "MAIL_DIR /var/spool/mail"
        "UMASK ${a.umask}"
        "HOME_MODE 0700"
        "PASS_MAX_DAYS ${str (if on a.passwordMaxDays then a.passwordMaxDays else 99999)}"
        "PASS_MIN_DAYS ${str (if on a.passwordMinDays then a.passwordMinDays else 0)}"
        "PASS_WARN_AGE ${str (if on a.passwordWarnDays then a.passwordWarnDays else 7)}"
        "UID_MIN 1000"
        "UID_MAX 60000"
        "SYS_UID_MIN 201"
        "SYS_UID_MAX 999"
        "SUB_UID_MIN 100000"
        "SUB_UID_MAX 600100000"
        "SUB_UID_COUNT 65536"
        "GID_MIN 1000"
        "GID_MAX 60000"
        "SYS_GID_MIN 201"
        "SYS_GID_MAX 999"
        "SUB_GID_MIN 100000"
        "SUB_GID_MAX 600100000"
        "SUB_GID_COUNT 65536"
        "ENCRYPT_METHOD SHA512"
        "SHA_CRYPT_MIN_ROUNDS 100000"
        "USERGROUPS_ENAB yes"
        "CREATE_HOME yes"
        "HMAC_CRYPTO_ALGO SHA512"
        "FAIL_DELAY 4"
      ]);
    })

    (lib.mkIf (on a.passwordMinLength || a.passwordComplexity) {
      files."/etc/security/pwquality.conf.d/50-compliance.conf".text = lines ([ header ]
        ++ opt a.passwordMinLength "minlen = ${str a.passwordMinLength}"
        ++ lib.optionals a.passwordComplexity [
          "dcredit = -1"
          "ucredit = -1"
          "lcredit = -1"
          "ocredit = -1"
          "minclass = 4"
          "difok = 8"
          "maxrepeat = 3"
          "maxclassrepeat = 4"
          "dictcheck = 1"
          "enforce_for_root"
        ]);
    })

    # PAM itself comes from authselect, which only switches features on.
    (lib.mkIf (on a.lockoutAttempts || on a.passwordHistory) {
      files."/etc/security/faillock.conf" = {
        text = lines ([ header "dir = /var/log/faillock" "audit" "silent" ]
          ++ opt a.lockoutAttempts "deny = ${str a.lockoutAttempts}"
          ++ [ "fail_interval = 900" ]
          ++ opt (a.lockoutSeconds != null) "unlock_time = ${str a.lockoutSeconds}"
          ++ opt a.lockoutRoot "even_deny_root");
        onChange = [ "(authselect current >/dev/null 2>&1 || authselect select local --force >/dev/null 2>&1 || authselect select minimal --force >/dev/null) && authselect enable-feature with-faillock >/dev/null && authselect enable-feature with-pwhistory >/dev/null" ];
        onRemove = [ "authselect disable-feature with-faillock >/dev/null; authselect disable-feature with-pwhistory >/dev/null; true" ];
      };
      files."/etc/security/pwhistory.conf".text = lines ([ header "enforce_for_root" ]
        ++ opt a.passwordHistory "remember = ${str a.passwordHistory}");
      directories."/var/log/faillock".mode = "0700";
    })

    (lib.mkIf (on a.shellTimeout || a.umask != "022") {
      files."/etc/profile.d/zz-compliance.sh".text = lines ([ header ]
        ++ opt a.shellTimeout "TMOUT=${str a.shellTimeout}; readonly TMOUT; export TMOUT"
        ++ opt (a.umask != "022") "umask ${a.umask}");
    })

    (lib.mkIf (on a.maxLogins || a.disableCoreDumps) {
      files."/etc/security/limits.d/50-compliance.conf".text = lines ([ header ]
        ++ opt a.disableCoreDumps "*    hard    core       0"
        ++ opt a.maxLogins "*    hard    maxlogins  ${str a.maxLogins}");
    })

    (lib.mkIf a.disableCoreDumps {
      files."/etc/systemd/coredump.conf.d/50-compliance.conf" = {
        text = lines [ header "[Coredump]" "Storage=none" "ProcessSizeMax=0" ];
        onChange = [ "systemctl daemon-reload" ];
      };
    })

    (lib.mkIf a.sudoHardening {
      files."/etc/sudoers.d/00-compliance" = {
        mode = "0440";
        text = lines ([ header "Defaults use_pty" "Defaults logfile=\"/var/log/sudo.log\"" "Defaults !visiblepw" ]
          ++ opt (a.sudoTimestamp != null) "Defaults timestamp_timeout=${str a.sudoTimestamp}");
      };
    })

    # Crypto. update-crypto-policies regenerates every back end from the
    # config file; running services pick it up when they restart.
    (lib.mkIf (s.crypto.policy != "DEFAULT") {
      files."/etc/crypto-policies/config" = {
        text = s.crypto.policy + "\n";
        onChange = [ "update-crypto-policies --no-reload" "systemctl try-reload-or-restart sshd" ];
        onRemove = [ "update-crypto-policies --no-reload" "systemctl try-reload-or-restart sshd" ];
      };
    })
    {
      warnings = lib.optional (s.crypto.fips && !lib.elem "fips=1" bootArgs)
        "compliance: FIPS policy on a kernel without fips=1: the node is not in FIPS mode until class ${class.name} boots with it";
    }

    # File integrity. The baseline is built from the booted image, so it is
    # the same on every node of a class, and checked daily.
    (lib.mkIf s.integrity.aide {
      files.${unit "compliance-aide-init.service"}.text = ''
        ${header}
        [Unit]
        Description=AIDE baseline of the booted image
        ConditionPathExists=!/var/lib/aide/aide.db.gz
        After=flapjack-agent.service

        [Service]
        Type=oneshot
        Nice=19
        IOSchedulingClass=idle
        ExecStart=/usr/sbin/aide --init
        ExecStartPost=/bin/mv -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
      '';
      files.${unit "compliance-aide-check.service"}.text = ''
        ${header}
        [Unit]
        Description=AIDE integrity check
        Requires=compliance-aide-init.service
        After=compliance-aide-init.service

        [Service]
        Type=oneshot
        Nice=19
        IOSchedulingClass=idle
        ExecStart=/usr/sbin/aide --check
      '';
      files.${unit "compliance-aide-check.timer"} = {
        text = ''
          ${header}
          [Unit]
          Description=Daily AIDE integrity check

          [Timer]
          OnBootSec=30min
          OnCalendar=daily
          RandomizedDelaySec=4h
          Persistent=false

          [Install]
          WantedBy=timers.target
        '';
        onChange = [ "systemctl daemon-reload && systemctl start --no-block compliance-aide-init.service compliance-aide-check.timer" ];
        onRemove = [ "systemctl stop compliance-aide-check.timer; systemctl daemon-reload" ];
      };
      symlinks."/etc/systemd/system/timers.target.wants/compliance-aide-check.timer" = unit "compliance-aide-check.timer";
    })

    (lib.mkIf s.integrity.usbguard {
      files.${unit "usbguard.service.d/50-compliance.conf"} = {
        text = ''
          ${header}
          # Allow the devices present at first start (keyboard, BMC virtual media), nothing new.
          [Service]
          ExecStartPre=/bin/sh -c 'test -s /etc/usbguard/rules.conf || (umask 077; /usr/bin/usbguard generate-policy > /etc/usbguard/rules.conf)'
        '';
        onChange = [ "systemctl daemon-reload && systemctl start usbguard" ];
        onRemove = [ "systemctl stop usbguard; systemctl daemon-reload" ];
      };
      symlinks = wants "multi-user.target" "usbguard.service";
    })

    # Host firewall: the cluster's own networks are trusted (MPI, Slurm,
    # NFS, the agent), everything else reaches SSH only.
    (lib.mkIf s.services.firewall {
      files."/etc/firewalld/zones/trusted.xml".text = ''
        <?xml version="1.0" encoding="utf-8"?>
        <!-- ${header} -->
        <zone target="ACCEPT">
          <short>Cluster</short>
        ${lib.concatMapStrings (n: "  <source address=\"${n}\"/>\n") cfg.trustedNetworks}</zone>
      '';
      files."/etc/firewalld/zones/public.xml" = {
        text = ''
          <?xml version="1.0" encoding="utf-8"?>
          <!-- ${header} -->
          <zone target="DROP">
            <short>Public</short>
            <service name="ssh"/>
          ${lib.concatMapStrings (p: "  <port protocol=\"tcp\" port=\"${str p}\"/>\n") cfg.allowedTcpPorts}</zone>
        '';
        onChange = [ "systemctl daemon-reload && systemctl start firewalld && firewall-cmd --reload >/dev/null" ];
        onRemove = [ "systemctl stop firewalld" ];
      };
      symlinks = wants "multi-user.target" "firewalld.service";
      assertions = [{
        assertion = cfg.trustedNetworks != [ ];
        message = "compliance: the host firewall needs compliance.trustedNetworks (the provisioning and cluster networks), or traffic between nodes is dropped";
      }];
    })

    (lib.mkIf (masked != [ ]) {
      files."/etc/compliance/masked-units" = {
        text = lines ([ header ] ++ masked);
        onChange = [ "systemctl mask --now ${lib.concatStringsSep " " masked} >/dev/null 2>&1; true" ];
        onRemove = [ "systemctl unmask ${lib.concatStringsSep " " masked} >/dev/null 2>&1; true" ];
      };
    })

    # Stateless nodes have no partitions to mount with options, so /tmp
    # becomes its own tmpfs and /dev/shm is remounted.
    (lib.mkIf s.services.hardenTmp {
      files.${unit "tmp.mount.d/50-compliance.conf"} = {
        text = lines [ header "[Mount]" "Options=mode=1777,strictatime,nosuid,nodev,noexec,size=50%" ];
        onChange = [ "systemctl daemon-reload && systemctl start tmp.mount" ];
      };
      symlinks = wants "local-fs.target" "tmp.mount";
    })
    (lib.mkIf s.services.hardenShm {
      files.${unit "compliance-shm.service"} = {
        text = ''
          ${header}
          [Unit]
          Description=Mount /dev/shm nodev,nosuid,noexec
          DefaultDependencies=no
          After=local-fs.target

          [Service]
          Type=oneshot
          RemainAfterExit=yes
          ExecStart=/bin/mount -o remount,nodev,nosuid,noexec /dev/shm
          ExecStop=/bin/mount -o remount,exec /dev/shm

          [Install]
          WantedBy=multi-user.target
        '';
        onChange = [ "systemctl daemon-reload && systemctl restart compliance-shm.service" ];
        onRemove = [ "mount -o remount,exec /dev/shm; systemctl daemon-reload" ];
      };
      symlinks."/etc/systemd/system/multi-user.target.wants/compliance-shm.service" = unit "compliance-shm.service";
    })
  ]);
}
