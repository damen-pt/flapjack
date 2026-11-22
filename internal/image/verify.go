package image

import (
	"os"
	"path/filepath"
)

// The flapjack-verify dracut module. With signed boot the kernel command
// line (from a signed script) carries flapjack.rootfs=sha256:…, and this
// hook, in the signed initrd, hashes the live image dracut downloaded and
// refuses to switch root to anything else. iPXE checks the kernel and
// initrd; it cannot check a root filesystem dracut fetches later, so the
// check has to live here. The image sits in RAM by then, so what is
// hashed is what gets mounted.

const verifyModuleDir = "usr/lib/dracut/modules.d/90flapjack-verify"

const verifyModuleSetup = `#!/bin/bash
# flapjack: verify the live root filesystem against flapjack.rootfs=.
check() { return 0; }
depends() { echo dmsquash-live; }
install() {
    inst_multiple sha256sum cat
    inst_hook pre-pivot 10 "$moddir/flapjack-verify-rootfs.sh"
}
`

// VerifyHook is sourced by dracut at pre-pivot. FLAPJACK_SYSFS lets tests
// point it at a fake /sys.
const VerifyHook = `#!/bin/sh
# flapjack: refuse a live root filesystem that does not hash to
# flapjack.rootfs= (set by the head in a signed boot script).
type getarg >/dev/null 2>&1 || . /lib/dracut-lib.sh

flapjack_verify_rootfs() {
    want=$(getarg flapjack.rootfs=)
    [ -n "$want" ] || return 0
    want=${want#sha256:}
    found=0
    for bf in "${FLAPJACK_SYSFS:-/sys}"/block/loop*/loop/backing_file; do
        [ -r "$bf" ] || continue
        f=$(cat "$bf")
        f=${f% (deleted)}
        case "$f" in
            */squashfs/*|*/overlayfs/*) continue ;; # files inside the image, not the image
        esac
        dev=${bf%/loop/backing_file}
        src=$f
        [ -r "$src" ] || src=/dev/${dev##*/}
        found=1
        got=$(sha256sum < "$src")
        got=${got%% *}
        if [ "$got" = "$want" ]; then
            info "flapjack: root filesystem verified (sha256:$want)"
            return 0
        fi
        warn "flapjack: live image $f hashes to sha256:$got, not sha256:$want"
    done
    [ "$found" = 1 ] || warn "flapjack: flapjack.rootfs= is set but no live image was found to verify"
    return 1
}

flapjack_verify_rootfs || die "flapjack: refusing a root filesystem the head did not sign for"
`

// installVerifyModule puts the dracut module into the image so initramfs
// can add it.
func installVerifyModule(root string) error {
	dir := filepath.Join(root, verifyModuleDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "module-setup.sh"), []byte(verifyModuleSetup), 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "flapjack-verify-rootfs.sh"), []byte(VerifyHook), 0o755)
}
