# number: 37
# tmt:
#   summary: Test bootc install to-filesystem without /boot directory
#   duration: 30m
#
use std assert
use tap.nu

let target_image = (tap get_target_image)

def main [] {
    tap begin "install to-filesystem without /boot"

    mkdir /var/mnt
    truncate -s 10G disk.img
    mkfs.ext4 disk.img
    mount -o loop disk.img /var/mnt

    setenforce 0

    systemd-run -p MountFlags=slave -qdPG -- /bin/sh -c $"
set -xeuo pipefail
bootc usr-overlay
if test -d /sysroot/ostree; then mount --bind /usr/share/empty /sysroot/ostree; fi
rm -vrf /usr/lib/bootupd/updates
rm -vrf /usr/lib/bootc/bound-images.d
# Install to filesystem without /boot - skips bootloader management
bootc install to-filesystem --disable-selinux --bootloader=none --source-imgref ($target_image) /var/mnt
"

    umount /var/mnt
    rm -f disk.img

    tap ok
}
