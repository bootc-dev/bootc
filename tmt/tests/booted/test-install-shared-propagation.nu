# number: 63
# tmt:
#   summary: Install from a shared mount namespace without leaking the storage bind mount
#   duration: 30m
# extra:
#   # bootloader=none is not supported for composefs (see test-install-no-boot-dir.nu)
#   fixme_skip_if_composefs: true
#
# Regression test for https://github.com/bootc-dev/bootc/issues/2455
#
# Installing with --source-imgref skips bootc's own mount namespace unshare,
# so on a host where / is shared (the systemd default) the bind mount made
# for podman onto /run/bootc/storage used to propagate back and stay mounted.
# run_install already uses MountFlags=slave, which hides that, so make /
# shared again inside that namespace before installing.

use std assert
use tap.nu

def main [] {
    tap begin "install to-filesystem with shared mount propagation"

    bootc image copy-to-storage
    let target_image = "containers-storage:localhost/bootc"

    mkdir /var/mnt
    truncate -s 10G disk.img
    mkfs.ext4 disk.img
    mount -o loop disk.img /var/mnt

    setenforce 0

    tap run_install $"mount --make-rshared /
bootc install to-filesystem --disable-selinux --bootloader=none --source-imgref ($target_image) /var/mnt
if findmnt /run/bootc/storage; then echo 'error: /run/bootc/storage mount leaked'; exit 1; fi"

    umount -l /var/mnt
    rm -f disk.img

    tap ok
}
