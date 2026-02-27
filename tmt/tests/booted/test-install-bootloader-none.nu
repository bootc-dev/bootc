# number: 38
# tmt:
#   summary: Test bootc install with --bootloader=none
#   duration: 30m
#
use std assert
use tap.nu

let target_image = (tap get_target_image)

def main [] {
    tap begin "install with --bootloader=none"

    truncate -s 10G disk.img

    setenforce 0

    systemd-run -p MountFlags=slave -qdPG -- /bin/sh -c $"
set -xeuo pipefail
bootc usr-overlay
if test -d /sysroot/ostree; then mount --bind /usr/share/empty /sysroot/ostree; fi
rm -vrf /usr/lib/bootupd/updates
rm -vrf /usr/lib/bootc/bound-images.d
# Install with --bootloader=none - skips bootloader management
bootc install to-disk --disable-selinux --via-loopback --filesystem xfs --bootloader=none --source-imgref ($target_image) ./disk.img
"

    rm -f disk.img

    tap ok
}
