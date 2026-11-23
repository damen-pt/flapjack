# Audit and logging. A stateless node keeps its logs in RAM and loses them
# at reboot, so every profile forwards syslog and the audit trail to
# compliance.logHost, and auditd's own log is capped (8 MiB × 5).
{ lib, config, ... }:
let
  cfg = config.compliance;
  s = cfg.settings;
  lines = ls: lib.concatStrings (map (l: l + "\n") ls);
  header = "# Managed by flapjack (overlay compliance: ${lib.concatStringsSep ", " cfg.profiles}).";
  rules = s.audit.rules;

  # Both ABIs, as every benchmark asks. arm64's native table has only the
  # *at() forms of the old file calls, so auditctl would reject them there.
  legacy = [ "open" "creat" "chmod" "chown" "lchown" "rename" "unlink" "rmdir" ];
  syscall = key: calls: filter: lib.concatMap (arch:
    let cs = if arch == "b64" && cfg.arch == "aarch64" then lib.subtractLists legacy calls else calls;
    in lib.optional (cs != [ ]) "-a always,exit -F arch=${arch} -S ${lib.concatStringsSep "," cs}${filter} -k ${key}") [ "b32" "b64" ];
  user = " -F auid>=1000 -F auid!=unset";
  watch = key: perm: paths: map (p: "-w ${p} -p ${perm} -k ${key}") paths;

  baseline = lib.concatLists [
    (syscall "time-change" [ "adjtimex" "settimeofday" "clock_settime" ] "")
    (watch "time-change" "wa" [ "/etc/localtime" ])
    (watch "identity" "wa" [ "/etc/passwd" "/etc/group" "/etc/shadow" "/etc/gshadow" "/etc/security/opasswd" "/etc/nsswitch.conf" "/etc/pam.conf" "/etc/pam.d" ])
    (syscall "system-locale" [ "sethostname" "setdomainname" ] "")
    (watch "system-locale" "wa" [ "/etc/issue" "/etc/issue.net" "/etc/hosts" "/etc/hostname" "/etc/sysconfig/network" "/etc/NetworkManager" ])
    (watch "MAC-policy" "wa" [ "/etc/selinux" "/usr/share/selinux" ])
    (watch "logins" "wa" [ "/var/log/lastlog" "/var/log/faillock" ])
    (watch "session" "wa" [ "/var/run/utmp" "/var/log/wtmp" "/var/log/btmp" ])
    (syscall "perm_mod" [ "chmod" "fchmod" "fchmodat" ] user)
    (syscall "perm_mod" [ "chown" "fchown" "lchown" "fchownat" ] user)
    (syscall "perm_mod" [ "setxattr" "lsetxattr" "fsetxattr" "removexattr" "lremovexattr" "fremovexattr" ] user)
    (syscall "access" [ "creat" "open" "openat" "truncate" "ftruncate" ] " -F exit=-EACCES${user}")
    (syscall "access" [ "creat" "open" "openat" "truncate" "ftruncate" ] " -F exit=-EPERM${user}")
    (syscall "mounts" [ "mount" "umount2" ] user)
    (syscall "delete" [ "unlink" "unlinkat" "rename" "renameat" "rmdir" ] user)
    (watch "scope" "wa" [ "/etc/sudoers" "/etc/sudoers.d" ])
    (watch "actions" "wa" [ "/var/log/sudo.log" ])
    (syscall "modules" [ "init_module" "finit_module" "delete_module" ] "")
    (watch "modules" "x" [ "/usr/bin/kmod" ])
    (watch "audit" "wa" [ "/etc/audit" "/etc/rsyslog.conf" "/etc/rsyslog.d" ])
  ];

  # Every setuid/setgid program on an EL9 node, and running anything as
  # another user (sudo, su, setuid).
  privileged = [
    "/usr/bin/chage" "/usr/bin/chcon" "/usr/bin/chfn" "/usr/bin/chsh" "/usr/bin/crontab" "/usr/bin/gpasswd"
    "/usr/bin/mount" "/usr/bin/newgrp" "/usr/bin/passwd" "/usr/bin/setfacl" "/usr/bin/chacl" "/usr/bin/su"
    "/usr/bin/sudo" "/usr/bin/umount" "/usr/bin/kmod" "/usr/sbin/pam_timestamp_check" "/usr/sbin/semanage"
    "/usr/sbin/setfiles" "/usr/sbin/setsebool" "/usr/sbin/unix_chkpwd" "/usr/sbin/userhelper" "/usr/sbin/usermod"
    "/usr/sbin/postdrop" "/usr/sbin/postqueue" "/usr/libexec/openssh/ssh-keysign" "/usr/sbin/init"
    "/usr/sbin/poweroff" "/usr/sbin/reboot" "/usr/sbin/shutdown"
  ];
  stigExtra = lib.concatLists [
    (map (p: "-a always,exit -F path=${p} -F perm=x${user} -k privileged") privileged)
    (syscall "execpriv" [ "execve" ] " -C uid!=euid -F euid=0")
    (syscall "execpriv" [ "execve" ] " -C gid!=egid -F egid=0")
    (syscall "perm_mod" [ "lremovexattr" "removexattr" "fremovexattr" "fsetxattr" "lsetxattr" "setxattr" ] " -F auid=0")
    (syscall "delete" [ "rename" "unlink" "rmdir" "renameat" "unlinkat" ] " -F auid=0")
    (watch "privileged" "wa" [ "/var/log/sudo.log" "/etc/sudoers" ])
  ];

  fullAction = lib.toUpper s.audit.fullAction;
  caPath = "/etc/pki/rsyslog/compliance-ca.pem";
  forward =
    if s.logging.tls then ''
      global(DefaultNetstreamDriverCAFile="${caPath}")
      *.* action(type="omfwd" target="${toString cfg.logHost}" port="6514" protocol="tcp"
                 StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="x509/name"
                 StreamDriverPermittedPeers="${toString cfg.logHost}"
                 queue.type="LinkedList" queue.size="100000" queue.filename="compliance-fwd"
                 queue.maxDiskSpace="64m" queue.saveOnShutdown="on" action.resumeRetryCount="-1")
    '' else ''
      *.* action(type="omfwd" target="${toString cfg.logHost}" port="514" protocol="tcp"
                 queue.type="LinkedList" queue.size="100000" queue.filename="compliance-fwd"
                 queue.maxDiskSpace="64m" queue.saveOnShutdown="on" action.resumeRetryCount="-1")
    '';
in
{
  # Only nodes with a profile; the site's floors alone render nothing.
  config = lib.mkIf (cfg.profiles != [ ]) (lib.mkMerge [
    (lib.mkIf (rules != "none") {
      # Replaces the image's audit.rules, so its own -D cannot clear ours.
      files."/etc/audit/rules.d/audit.rules" = {
        mode = "0600";
        text = lines ([ header "-D" "-b 8192" "--backlog_wait_time 60000" "-f 1" ]
          ++ baseline
          ++ lib.optionals (rules == "stig") stigExtra
          ++ lib.optional s.audit.immutable "-e 2");
        onChange = [ "augenrules --load >/dev/null" ];
        onRemove = [ "augenrules --load >/dev/null 2>&1; true" ];
      };
      files."/etc/audit/auditd.conf" = {
        mode = "0640";
        text = lines [
          header
          "local_events = yes"
          "write_logs = yes"
          "log_file = /var/log/audit/audit.log"
          "log_group = root"
          "log_format = ENRICHED"
          "flush = INCREMENTAL_ASYNC"
          "freq = 50"
          "max_log_file = 8"
          "num_logs = 5"
          "priority_boost = 4"
          "name_format = hostname"
          "max_log_file_action = ROTATE"
          "space_left = 25%"
          "space_left_action = SYSLOG"
          "verify_email = yes"
          "action_mail_acct = root"
          "admin_space_left = 10%"
          "admin_space_left_action = ${fullAction}"
          "disk_full_action = ${fullAction}"
          "disk_error_action = ${fullAction}"
          "tcp_listen_queue = 5"
          "tcp_max_per_addr = 1"
          "tcp_client_max_idle = 0"
          "transport = TCP"
          "distribute_network = no"
          "q_depth = 2000"
          "overflow_action = SYSLOG"
          "max_restarts = 10"
          "plugin_dir = /etc/audit/plugins.d"
          "end_of_event_timeout = 2"
        ];
        onChange = [ "service auditd restart >/dev/null" ];
        onRemove = [ "service auditd restart >/dev/null" ];
      };
      directories."/var/log/audit".mode = "0700";
    })

    (lib.mkIf s.logging.remote {
      # Audit records into syslog, so one encrypted stream carries both.
      files."/etc/audit/plugins.d/syslog.conf" = lib.mkIf (rules != "none") {
        mode = "0640";
        text = lines [ header "active = yes" "direction = out" "path = /sbin/audisp-syslog" "type = always" "args = LOG_INFO LOG_LOCAL6" "format = string" ];
        onChange = [ "service auditd restart >/dev/null" ];
        onRemove = [ "service auditd restart >/dev/null" ];
      };
      files."/etc/rsyslog.d/90-compliance-forward.conf" = {
        text = header + "\n" + forward;
        onChange = [ "systemctl restart rsyslog" ];
        onRemove = [ "systemctl restart rsyslog" ];
      };
      files.${caPath} = lib.mkIf s.logging.tls {
        secret = cfg.logCaSecret;
        mode = "0644";
        onChange = [ "systemctl restart rsyslog" ];
      };
      files."/etc/systemd/journald.conf.d/50-compliance.conf" = {
        text = lines [ header "[Journal]" "ForwardToSyslog=yes" "Compress=yes" "SystemMaxUse=256M" "RuntimeMaxUse=256M" ];
        onChange = [ "systemctl restart systemd-journald" ];
        onRemove = [ "systemctl restart systemd-journald" ];
      };
      assertions = [{
        assertion = cfg.logHost != null;
        message = "compliance: profiles ${lib.concatStringsSep ", " cfg.profiles} need compliance.logHost; a stateless node keeps its logs and audit trail only in RAM";
      }];
    })
  ]);
}
