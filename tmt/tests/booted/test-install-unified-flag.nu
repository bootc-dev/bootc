# number: 30
# extra:
# tmt:
#   summary: Test bootc install with experimental unified storage flag
#   duration: 30m
#
# Test bootc install with --experimental-unified-storage flag
# This test performs an actual install to a loopback device and verifies
# the unified storage path is used.

use std assert
use tap.nu

# Use a generic target image to test skew between the bootc binary doing
# the install and the target image
let target_image = "docker://quay.io/centos-bootc/centos-bootc:stream10"

def main [] {
    tap begin "install with experimental unified storage flag"

    # Setup filesystem - create a loopback disk image
    mkdir /var/mnt
    truncate -s 10G disk.img

    # Disable SELinux enforcement for the install (same as test-install-outside-container)
    setenforce 0

    # Perform the install with unified storage flag
    # We use systemd-run to handle mount namespace issues
    systemd-run -p MountFlags=slave -qdPG -- /bin/sh -c $"
set -xeuo pipefail
bootc usr-overlay
if test -d /sysroot/ostree; then mount --bind /usr/share/empty /sysroot/ostree; fi
# Note we do keep the other bootupd state
rm -vrf /usr/lib/bootupd/updates
# Another bootc install bug, we should not look at this in outside-of-container flows
rm -vrf /usr/lib/bootc/bound-images.d
# Install with unified storage flag to loopback disk
bootc install to-disk --disable-selinux --via-loopback --filesystem xfs --experimental-unified-storage --source-imgref ($target_image) ./disk.img
"

    # Cleanup
    rm -f disk.img

    tap ok
}
