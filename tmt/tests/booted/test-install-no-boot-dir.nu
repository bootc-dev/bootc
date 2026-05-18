# number: 37
# tmt:
#   summary: Test bootc install to-filesystem without /boot directory
#   duration: 30m
# extra:
#   # bootloader=none is not supported for composefs and this test fails
#   # when trying to install bootloader for composefs. For ostree, the
#   # bootloader installation is simply skipped
#   fixme_skip_if_composefs: true

use std assert
use tap.nu

def main [] {
    tap begin "install to-filesystem without /boot"

    # Copy the booted image to container storage for use as install source
    bootc image copy-to-storage
    let target_image = "containers-storage:localhost/bootc"

    mkdir /var/mnt
    truncate -s 10G disk.img
    mkfs.ext4 disk.img
    mount -o loop disk.img /var/mnt

    setenforce 0
    
    tap run_install $"bootc install to-filesystem --disable-selinux --bootloader=none --source-imgref ($target_image) /var/mnt"

    umount /var/mnt
    rm -f disk.img

    tap ok
}
