# number: 40
# tmt:
#   summary: Test Anaconda installation of bootc images via liveimg
#   duration: 45m
#   require:
#     - qemu-img
#     - virt-install
#     - libvirt
#
# This test validates that bootc images can be installed via Anaconda's
# liveimg kickstart directive. This is a critical integration test for:
# https://github.com/bootc-dev/bootc/pull/1969
#
# The test:
# 1. Checks if KVM is available (skips if not)
# 2. Exports the current bootc image to tar format
# 3. Uses virt-install to boot an Anaconda installer with a kickstart
#    that installs from the tar using liveimg
# 4. Verifies the installation completed successfully
#
use std assert
use tap.nu

def main [] {
    tap begin "Anaconda liveimg installation test"

    # Check for KVM availability - this test requires hardware virtualization
    if not ("/dev/kvm" | path exists) {
        print "SKIP: /dev/kvm not available - hardware virtualization required"
        print "ok # SKIP no KVM available"
        return
    }

    # Verify KVM is accessible
    let kvm_access = (do { cat /dev/null > /dev/kvm } | complete)
    if $kvm_access.exit_code != 0 {
        print "SKIP: /dev/kvm not accessible - check permissions"
        print "ok # SKIP KVM not accessible"
        return
    }

    print "=== KVM is available ==="

    let td = mktemp -d
    cd $td

    # Copy the currently booted image to podman storage for export
    print "=== Copying booted image to containers-storage ==="
    bootc image copy-to-storage

    # Verify the image is in storage
    let images = podman images --format json | from json
    let bootc_img = $images | where Names != null | where { |img|
        $img.Names | any { |t| $t == "localhost/bootc:latest" }
    }
    assert (($bootc_img | length) > 0) "Expected localhost/bootc image in podman storage"

    # Create output disk for the installation
    let output_disk = $"($td)/anaconda-test.raw"

    # Determine installer type based on current OS
    let os_release = open /etc/os-release
        | lines
        | parse "{key}={value}"
        | reduce -f {} { |it, acc| $acc | upsert $it.key ($it.value | str replace -a '"' '') }

    let installer_type = if ($os_release.ID? == "centos") {
        "centos-stream-10"
    } else if ($os_release.ID? == "fedora") {
        "fedora"
    } else {
        "centos-stream-10"  # Default fallback
    }

    print $"=== Using installer type: ($installer_type) ==="

    # Run the anaconda xtask test
    # The xtask handles all the complexity of:
    # - Exporting the container to tar
    # - Downloading/caching the installer ISO
    # - Creating kickstart with liveimg directive
    # - Running virt-install with virtiofs for tar access
    # - Monitoring installation progress
    # - Verifying the installation
    print "=== Running cargo xtask anaconda ==="

    let result = (do {
        cargo xtask anaconda
            --installer-type $installer_type
            --timeout 10
            localhost/bootc:latest
            $output_disk
    } | complete)

    print $"Exit code: ($result.exit_code)"
    if ($result.stdout | str length) > 0 {
        print $"stdout: ($result.stdout)"
    }
    if ($result.stderr | str length) > 0 {
        print $"stderr: ($result.stderr)"
    }

    assert ($result.exit_code == 0) "cargo xtask anaconda failed"

    # Verify the output disk was created
    assert ($output_disk | path exists) "Output disk was not created"

    # Check disk size is reasonable (at least 1GB of actual data)
    let disk_size = ls $output_disk | get size | first
    print $"Output disk size: ($disk_size)"
    assert ($disk_size > 1000000000) "Output disk seems too small"

    print "=== Anaconda installation test passed ==="
    tap ok
}
