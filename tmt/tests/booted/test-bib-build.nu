# number: 33
# tmt:
#   summary: Test building a qcow2 disk image with bootc-image-builder
#   duration: 45m
#   require:
#     - qemu-img
#
# This test validates that bootc-image-builder (bib) can successfully
# create disk images from the current booted image. This is a critical
# integration test to catch regressions like:
# https://github.com/bootc-dev/bootc/issues/1907
#
# The key scenario tested here is a partition layout where /boot is a
# directory on the root filesystem (NOT a separate partition), but
# /boot/efi IS a separate mount point. The bug was that when bootc
# checked /boot, it found "efi" as a directory entry and failed to
# recognize it was actually a mount point on a different device.
#
use std assert
use tap.nu

const BIB_IMAGE = "quay.io/centos-bootc/bootc-image-builder:latest"

def main [] {
    tap begin "bootc-image-builder qcow2 build test"

    let td = mktemp -d
    cd $td

    # Copy the currently booted image to podman storage
    print "=== Copying booted image to containers-storage ==="
    bootc image copy-to-storage
    
    # Verify the image is in storage
    let images = podman images --format json | from json
    let bootc_img = $images | where Names != null | where { |img| 
        $img.Names | any { |t| $t == "localhost/bootc:latest" }
    }
    assert (($bootc_img | length) > 0) "Expected localhost/bootc image in podman storage"

    # Build a derived image that:
    # 1. Removes bound images (bib runs isolated)
    # 2. Embeds a disk.yaml that creates a layout WITHOUT a separate /boot partition
    #    This triggers the bug from issue #1907 where /boot is a directory on root
    #    and /boot/efi is a mount point
    print "=== Building derived image with no-/boot-partition layout ==="
    'FROM localhost/bootc
RUN rm -rf /usr/lib/bootc/bound-images.d/*
RUN mkdir -p /usr/lib/bootc-image-builder && cat > /usr/lib/bootc-image-builder/disk.yaml << "DISKEOF"
# Partition layout without a separate /boot partition.
# This mimics the CentOS Automotive ukiboot layout and triggers issue #1907.
# The key is that /boot is a directory on root, but /boot/efi is a mount point.
.common:
  partitioning:
    guids:
      - &bios_boot_partition_guid "21686148-6449-6E6F-744E-656564454649"
      - &efi_system_partition_guid "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
      - &filesystem_data_guid "0FC63DAF-8483-4772-8E79-3D69D8477DE4"

partition_table:
  type: "gpt"
  partitions:
    - size: "1 MiB"
      bootable: true
      type: *bios_boot_partition_guid
    - size: "501 MiB"
      type: *efi_system_partition_guid
      payload_type: "filesystem"
      payload:
        type: vfat
        mountpoint: "/boot/efi"
        label: "EFI-SYSTEM"
        fstab_options: "umask=0077,shortname=winnt"
        fstab_freq: 0
        fstab_passno: 2
    - size: "4 GiB"
      type: *filesystem_data_guid
      payload_type: "filesystem"
      payload:
        type: xfs
        label: "root"
        mountpoint: "/"
        fstab_options: "ro"
DISKEOF
' | save Dockerfile
    podman build -t localhost/bootc-bib-test .

    # Create output directory for bib
    mkdir output

    # Run bootc-image-builder to create a qcow2
    # We use --local to pull from local containers-storage
    # The embedded disk.yaml will be used for partitioning
    print "=== Running bootc-image-builder ==="
    let bib_image = $BIB_IMAGE
    # Note: we disable SELinux labeling since we're running in a test VM
    # and use unconfined_t to avoid permission issues
    podman run --rm --privileged -v /var/lib/containers/storage:/var/lib/containers/storage --security-opt label=type:unconfined_t -v ./output:/output $bib_image --type qcow2 --local localhost/bootc-bib-test

    # Verify output was created
    print "=== Verifying output ==="
    let disk_path = "output/qcow2/disk.qcow2"
    assert ($disk_path | path exists) $"Expected disk image at ($disk_path)"

    # Check the disk has reasonable virtual size (at least 4GB as per disk.yaml)
    # Note: qcow2 files are sparse, so file size != virtual size
    # We use qemu-img to get the actual virtual disk size
    let info = qemu-img info --output=json $disk_path | from json
    let virtual_size = $info | get virtual-size
    print $"Disk image virtual size: ($virtual_size | into filesize)"
    # The disk.yaml specifies ~4.5 GiB total, so virtual size should be at least 4 GiB
    assert ($virtual_size > 4000000000) "Disk image virtual size seems too small"

    # Also print file size for reference (qcow2 is sparse/compressed)
    let file_size = ls $disk_path | get size | first
    print $"Disk image file size: ($file_size)"

    print "=== Success: bootc-image-builder created disk image ==="
    tap ok
}
