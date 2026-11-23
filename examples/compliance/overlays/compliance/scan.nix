# Verification. Configuration is only half of compliance; the other half is
# evidence. Each node scans itself with OpenSCAP against the SCAP Security
# Guide profile that matches each of its profiles, at boot and daily, and
# logs one summary line per profile (forwarded to the log host). Full ARF
# results and HTML reports stay in /var/log/compliance until reboot.
#
# Waivers become an XCCDF tailoring file: the scan deselects exactly the
# rules the site has accepted, and the waivers file says why. Rules that
# cannot apply to a stateless, netbooted node are waived here, with reasons.
{ lib, config, class, ... }:
let
  cfg = config.compliance;
  lines = ls: lib.concatStrings (map (l: l + "\n") ls);
  header = "# Managed by flapjack (overlay compliance: ${lib.concatStringsSep ", " cfg.profiles}).";
  bootArgs = if class.bootArgs or null == null then [ ] else class.bootArgs;

  ssg = {
    "cis-l1" = "cis_server_l1";
    "cis-l2" = "cis";
    "stig" = "stig";
    "pci-dss" = "pci-dss";
    "hipaa" = "hipaa";
  };
  known = lib.filter (p: ssg ? ${p}) cfg.profiles;
  rule = id: "xccdf_org.ssgproject.content_rule_${id}";
  tailored = p: "xccdf_org.flapjack_profile_${lib.replaceStrings [ "-" ] [ "_" ] p}_tailored";

  stateless = "stateless node: the root filesystem is RAM over the image; nothing on the node persists to partition";
  netboot = "no bootloader on the node: it boots the head's signed iPXE script, and kernel arguments come from the class's bootArgs";
  # Kernel-argument rules read GRUB's config; the argument itself is checked
  # against the class at build time, so the rule is waived only when present.
  argRules = {
    "audit=1" = "grub2_audit_argument";
    "audit_backlog_limit=8192" = "grub2_audit_backlog_limit_argument";
    "pti=on" = "grub2_pti_argument";
    "vsyscall=none" = "grub2_vsyscall_argument";
    "page_poison=1" = "grub2_page_poison_argument";
    "slub_debug=P" = "grub2_slub_debug_argument";
  };

  script = ''
    #!/bin/sh
    ${header}
    # Scan this node against each active profile; one log line per profile.
    set -u
    ds=$(ls /usr/share/xml/scap/ssg/content/ssg-*9-ds.xml 2>/dev/null | head -n 1)
    if [ -z "$ds" ]; then
      logger -t compliance-scan -p authpriv.err "no SCAP Security Guide datastream: add scap-security-guide to the image"
      exit 1
    fi
    out=/var/log/compliance
    mkdir -p -m 0700 "$out"
    find "$out" -type f -mtime +7 -delete
    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    rc=0
    for p in ${lib.concatStringsSep " " known}; do
      case $p in
        ${lib.concatMapStrings (p: "${p}) profile=${tailored p} ;;\n    ") known}esac
      oscap xccdf eval --profile "$profile" --tailoring-file /etc/compliance/tailoring.xml \
        --results-arf "$out/$p-$stamp.arf.xml" --report "$out/$p-$stamp.html" "$ds" > "$out/$p-$stamp.txt" 2>&1
      code=$?
      pass=$(grep -c '^Result[[:space:]]*pass$' "$out/$p-$stamp.txt")
      fail=$(grep -c '^Result[[:space:]]*fail$' "$out/$p-$stamp.txt")
      waived=$(grep -c . /etc/compliance/waivers)
      logger -t compliance-scan -p authpriv.notice "profile=$p pass=$pass fail=$fail waivers=$waived exit=$code report=$out/$p-$stamp.html"
      [ "$code" -le 2 ] || rc=$code
      [ "$fail" -eq 0 ] || rc=2
    done
    exit $rc
  '';
in
{
  config = lib.mkMerge [
    {
      compliance.waivers = lib.mkIf (cfg.profiles != [ ]) ({
        partition_for_tmp = stateless;
        partition_for_var = stateless;
        partition_for_var_log = stateless;
        partition_for_var_log_audit = stateless;
        partition_for_var_tmp = stateless;
        partition_for_home = "homes are on the shared file system";
        kernel_module_squashfs_disabled = "the node's root filesystem is a squashfs image";
        grub2_password = netboot;
        grub2_uefi_password = netboot;
        file_owner_grub2_cfg = netboot;
        file_groupowner_grub2_cfg = netboot;
        file_permissions_grub2_cfg = netboot;
        aide_build_database = "built from the booted image at every boot (compliance-aide-init.service)";
      } // lib.listToAttrs (map (a: lib.nameValuePair argRules.${a} "${a} is in class ${class.name}'s bootArgs; ${netboot}")
        (lib.filter (a: argRules ? ${a} && lib.elem a bootArgs) (lib.attrNames argRules))));
    }

    (lib.mkIf (cfg.profiles != [ ]) {
      files."/etc/compliance/profiles".text = lines ([ header ] ++ cfg.profiles);
      files."/etc/compliance/waivers".text = lines (lib.mapAttrsToList (r: why: "${r}: ${why}") cfg.waivers);
      files."/etc/motd.d/compliance".text = ''
        Compliance: ${lib.concatStringsSep ", " cfg.profiles}. ${toString (lib.length (lib.attrNames cfg.waivers))} waivers in /etc/compliance/waivers; scans in /var/log/compliance.
      '';
    })

    (lib.mkIf (cfg.scan.enable && known != [ ]) {
      files."/etc/compliance/tailoring.xml".text = ''
        <?xml version="1.0" encoding="UTF-8"?>
        <!-- ${header} -->
        <xccdf:Tailoring xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2" id="xccdf_org.flapjack_tailoring_compliance">
          <xccdf:benchmark href="ssg-ds.xml"/>
          <xccdf:version time="2026-01-01T00:00:00">1</xccdf:version>
        ${lib.concatMapStrings (p: ''
          <xccdf:Profile id="${tailored p}" extends="xccdf_org.ssgproject.content_profile_${ssg.${p}}">
            <xccdf:title>${p}, with flapjack waivers</xccdf:title>
        ${lib.concatMapStrings (r: "    <xccdf:select idref=\"${rule r}\" selected=\"false\"/>\n") (lib.attrNames cfg.waivers)}  </xccdf:Profile>
        '') known}</xccdf:Tailoring>
      '';
      files."/usr/local/sbin/compliance-scan" = { mode = "0755"; text = script; };
      files."/etc/systemd/system/compliance-scan.service".text = ''
        ${header}
        [Unit]
        Description=OpenSCAP compliance scan (${lib.concatStringsSep ", " known})
        After=flapjack-agent.service compliance-aide-init.service

        [Service]
        Type=oneshot
        Nice=19
        IOSchedulingClass=idle
        ExecStart=/usr/local/sbin/compliance-scan
      '';
      files."/etc/systemd/system/compliance-scan.timer" = {
        text = ''
          ${header}
          [Unit]
          Description=OpenSCAP compliance scan

          [Timer]
          OnBootSec=15min
          OnCalendar=${cfg.scan.onCalendar}
          RandomizedDelaySec=${cfg.scan.randomizedDelay}

          [Install]
          WantedBy=timers.target
        '';
        onChange = [ "systemctl daemon-reload && systemctl start compliance-scan.timer" ];
        onRemove = [ "systemctl stop compliance-scan.timer; systemctl daemon-reload" ];
      };
      symlinks."/etc/systemd/system/timers.target.wants/compliance-scan.timer" = "/etc/systemd/system/compliance-scan.timer";
    })
  ];
}
