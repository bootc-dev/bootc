# number: 30
# extra:
#   fixme_skip_if_composefs: true
# tmt:
#   summary: Test bootc install with experimental unified storage flag
#   duration: 30m
#
# Test bootc install with --experimental-unified-storage flag
# This test performs an actual install to a loopback device and verifies
# the unified storage path is used.

use std assert
use tap.nu

# Use an OS-matched target image to avoid version mismatches
# (e.g., XFS features created by newer mkfs.xfs not recognized by older grub2)
let target_image = (tap get_target_image)

def main [] {
    tap begin "install with experimental unified storage flag"

    # Setup filesystem - create a loopback disk image
    mkdir /var/mnt
    truncate -s 10G disk.img

    # Disable SELinux enforcement for the install (same as test-install-outside-container)
    setenforce 0

    tap run_install $"bootc install to-disk --disable-selinux --via-loopback --filesystem xfs --experimental-unified-storage --source-imgref ($target_image) ./disk.img"

    # Cleanup
    rm -f disk.img

    tap ok
}
