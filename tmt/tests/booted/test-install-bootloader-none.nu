# number: 38
# tmt:
#   summary: Test bootc install with --bootloader=none
#   duration: 30m
#
use std assert
use tap.nu

def main [] {
    tap begin "install with --bootloader=none"

    # Copy the booted image to container storage for use as install source
    bootc image copy-to-storage
    let target_image = "containers-storage:localhost/bootc"

    truncate -s 10G disk.img

    setenforce 0

    tap run_install $"bootc install to-disk --disable-selinux --via-loopback --filesystem xfs --bootloader=none --source-imgref ($target_image) ./disk.img"

    rm -f disk.img

    tap ok
}
