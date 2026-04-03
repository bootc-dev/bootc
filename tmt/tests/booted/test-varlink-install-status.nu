# number: 40
# extra:
#   fixme_skip_if_composefs: true
# tmt:
#   summary: Varlink install-to-disk then query sysroot status
#   duration: 30m
#
# Perform a loopback install, then use the varlink IPC interface to
# query the installed sysroot status via GetStatusForSysroot.
# This verifies the end-to-end flow: install via CLI, then query
# deployment metadata (image digest, stateroot, ostree commit) via
# the varlink API.

use std assert
use tap.nu

let target_image = (tap get_target_image)

def main [] {
    tap begin "varlink: install and query sysroot status"

    # --- Phase 1: Loopback install ---
    truncate -s 10G disk.img
    setenforce 0

    let base_args = $"bootc install to-disk --disable-selinux --via-loopback --source-imgref ($target_image)"

    let install_cmd = if (tap is_composefs) {
        let st = bootc status --json | from json
        let bootloader = ($st.status.booted.composefs.bootloader | str downcase)
        $"($base_args) --composefs-backend --bootloader=($bootloader) --filesystem ext4 ./disk.img"
    } else {
        $"($base_args) --filesystem xfs ./disk.img"
    }

    tap run_install $install_cmd

    # --- Phase 2: Mount the installed sysroot ---
    let mnt = "/var/mnt/installed"
    mkdir $mnt

    # Find the root partition in the loopback image
    let lodev = (losetup --find --show --partscan ./disk.img | str trim)
    # Give the kernel a moment to create partition devices
    udevadm settle
    # Use lsblk to find the largest partition (the root fs)
    let root_part = (lsblk -ln -o NAME,SIZE,TYPE $lodev
        | lines
        | where {|l| $l | str contains "part" }
        | last
        | split row " "
        | first
        | str trim)
    mount $"/dev/($root_part)" $mnt

    # --- Phase 3: Query the installed sysroot status ---
    let status = (bootc status --json --sysroot $mnt | from json)
    assert equal ($status.apiVersion) "org.containers.bootc/v1" "apiVersion should match"
    assert equal ($status.kind) "BootcHost" "kind should be BootcHost"

    # A non-booted sysroot has no staged/booted; deployments are in otherDeployments
    assert ($status.status.staged? == null) "staged should be null for non-booted sysroot"
    assert ($status.status.booted? == null) "booted should be null for non-booted sysroot"
    let deployments = $status.status.otherDeployments
    assert (($deployments | length) > 0) "should have at least one deployment"

    let primary = ($deployments | first)

    # Verify the primary deployment has image metadata
    assert ($primary.image? != null) "deployment should have image info"
    assert ($primary.image.image? != null) "deployment should have image reference"
    assert ($primary.image.imageDigest? != null) "deployment should have image digest"
    let digest = $primary.image.imageDigest
    assert ($digest | str starts-with "sha256:") $"digest should start with sha256:, got ($digest)"

    # Verify ostree metadata is present
    assert ($primary.ostree? != null) "deployment should have ostree info"
    assert ($primary.ostree.stateroot? != null) "deployment should have stateroot"
    assert ($primary.ostree.checksum? != null) "deployment should have ostree checksum"

    print $"Verified: stateroot=($primary.ostree.stateroot) digest=($digest)"

    # --- Phase 4: Also verify plain status still works ---
    let plain = (bootc status --json | from json)
    assert equal ($plain.kind) "BootcHost" "plain bootc status should also work"

    # --- Cleanup ---
    umount $mnt
    losetup -d $lodev
    rm -f disk.img

    tap ok
}
