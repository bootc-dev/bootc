# number: 32
# tmt:
#   summary: Test multi-device ESP detection for to-existing-root
#   duration: 45m
#
# Test that bootc install to-existing-root can find and use ESP partitions
# when the root filesystem spans multiple backing devices (e.g., LVM across disks).
#
# Two scenarios are tested:
# 1. Single ESP: Only one backing device has an ESP partition
# 2. Dual ESP: Both backing devices have ESP partitions
#
# This validates the fix for https://github.com/bootc-dev/bootc/issues/481

use std assert
use tap.nu

# Use the currently booted image (copied to container storage)
const target_image = "localhost/bootc"

# ESP partition type GUID
const ESP_TYPE = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
# Linux LVM partition type GUID
const LVM_TYPE = "E6D6D379-F507-44C2-A23C-238F2A3DF928"

# Cleanup function for LVM and loop devices
def cleanup [vg_name: string, loop1: string, loop2: string, mountpoint: string] {
    # Unmount if mounted
    do { umount $mountpoint } | complete | ignore
    do { rmdir $mountpoint } | complete | ignore

    # Deactivate and remove LVM
    do { lvchange -an $"($vg_name)/test_lv" } | complete | ignore
    do { lvremove -f $"($vg_name)/test_lv" } | complete | ignore
    do { vgchange -an $vg_name } | complete | ignore
    do { vgremove -f $vg_name } | complete | ignore

    # Remove PVs and detach loop devices
    if ($loop1 | path exists) {
        do { pvremove -f $loop1 } | complete | ignore
        do { losetup -d $loop1 } | complete | ignore
    }
    if ($loop2 | path exists) {
        do { pvremove -f $loop2 } | complete | ignore
        do { losetup -d $loop2 } | complete | ignore
    }
}

# Create a disk with GPT, optional ESP, and LVM partition
# Returns the loop device path
def setup_disk_with_partitions [
    disk_path: string,
    with_esp: bool,
    disk_size: string = "5G"
] {
    # Create disk image
    truncate -s $disk_size $disk_path

    # Setup loop device
    let loop = (losetup -f --show $disk_path | str trim)

    # Create partition table
    if $with_esp {
        # GPT with ESP (512MB) + LVM partition
        $"label: gpt\nsize=512M, type=($ESP_TYPE)\ntype=($LVM_TYPE)\n" | sfdisk $loop

        # Reload partition table (partx is part of util-linux)
        partx -u $loop
        sleep 1sec

        # Format ESP
        mkfs.vfat -F 32 $"($loop)p1"
    } else {
        # GPT with only LVM partition (full disk)
        $"label: gpt\ntype=($LVM_TYPE)\n" | sfdisk $loop

        # Reload partition table (partx is part of util-linux)
        partx -u $loop
        sleep 1sec
    }

    $loop
}

# Validate that an ESP partition has bootloader files installed
def validate_esp [esp_partition: string] {
    let esp_mount = "/var/mnt/esp_check"
    mkdir $esp_mount
    mount $esp_partition $esp_mount

    # Check for EFI directory with bootloader files
    let efi_dir = $"($esp_mount)/EFI"
    if not ($efi_dir | path exists) {
        umount $esp_mount
        rmdir $esp_mount
        error make {msg: $"ESP validation failed: EFI directory not found on ($esp_partition)"}
    }

    # Verify there's actual content in EFI (not just empty)
    let efi_contents = (ls $efi_dir | length)
    umount $esp_mount
    rmdir $esp_mount

    if $efi_contents == 0 {
        error make {msg: $"ESP validation failed: EFI directory is empty on ($esp_partition)"}
    }
}

# Run bootc install to-existing-root from within the container image under test
def run_install [mountpoint: string] {
    (podman run
        --rm
        --privileged
        -v $"($mountpoint):/target"
        -v /dev:/dev
        -v /usr/share/empty:/usr/lib/bootc/bound-images.d
        --pid=host
        --security-opt label=type:unconfined_t
        $target_image
        bootc install to-existing-root
            --disable-selinux
            --acknowledge-destructive
            --target-no-signature-verification
            /target)
}

# Test scenario 1: Single ESP on first device
def test_single_esp [] {
    tap begin "multi-device ESP detection tests"

    # Copy the currently booted image to container storage for podman to use
    bootc image copy-to-storage

    print "Starting single ESP test"

    let vg_name = "test_single_esp_vg"
    let mountpoint = "/var/mnt/test_single_esp"
    let disk1 = "/var/tmp/disk1_single.img"
    let disk2 = "/var/tmp/disk2_single.img"

    # Setup disks
    # DISK1: ESP + LVM partition
    # DISK2: Full LVM partition (no ESP)
    let loop1 = (setup_disk_with_partitions $disk1 true)
    let loop2 = (setup_disk_with_partitions $disk2 false)

    try {
        # Create LVM spanning both devices
        # Use partition 2 from disk1 (after ESP) and partition 1 from disk2 (full disk)
        pvcreate $"($loop1)p2" $"($loop2)p1"
        vgcreate $vg_name $"($loop1)p2" $"($loop2)p1"
        lvcreate -l "100%FREE" -n test_lv $vg_name

        let lv_path = $"/dev/($vg_name)/test_lv"

        # Create filesystem and mount
        mkfs.ext4 -q $lv_path
        mkdir $mountpoint
        mount $lv_path $mountpoint

        # Create boot directory
        mkdir $"($mountpoint)/boot"

        # Show block device hierarchy
        lsblk --pairs --paths --inverse --output NAME,TYPE $lv_path

        run_install $mountpoint

        # Validate ESP was installed correctly
        validate_esp $"($loop1)p1"
    } catch {|e|
        cleanup $vg_name $loop1 $loop2 $mountpoint
        rm -f $disk1 $disk2
        error make {msg: $"Single ESP test failed: ($e)"}
    }

    # Cleanup
    cleanup $vg_name $loop1 $loop2 $mountpoint
    rm -f $disk1 $disk2

    print "Single ESP test completed successfully"
    tmt-reboot
}

# Test scenario 2: ESP on both devices
def test_dual_esp [] {
    print "Starting dual ESP test"

    let vg_name = "test_dual_esp_vg"
    let mountpoint = "/var/mnt/test_dual_esp"
    let disk1 = "/var/tmp/disk1_dual.img"
    let disk2 = "/var/tmp/disk2_dual.img"

    # Setup disks
    # DISK1: ESP + LVM partition
    # DISK2: ESP + LVM partition
    let loop1 = (setup_disk_with_partitions $disk1 true)
    let loop2 = (setup_disk_with_partitions $disk2 true)

    try {
        # Create LVM spanning both devices
        # Use partition 2 from both disks (after ESP)
        pvcreate $"($loop1)p2" $"($loop2)p2"
        vgcreate $vg_name $"($loop1)p2" $"($loop2)p2"
        lvcreate -l "100%FREE" -n test_lv $vg_name

        let lv_path = $"/dev/($vg_name)/test_lv"

        # Create filesystem and mount
        mkfs.ext4 -q $lv_path
        mkdir $mountpoint
        mount $lv_path $mountpoint

        # Create boot directory
        mkdir $"($mountpoint)/boot"

        # Show block device hierarchy
        lsblk --pairs --paths --inverse --output NAME,TYPE $lv_path

        run_install $mountpoint

        # Validate both ESPs were installed correctly
        validate_esp $"($loop1)p1"
        validate_esp $"($loop2)p1"
    } catch {|e|
        cleanup $vg_name $loop1 $loop2 $mountpoint
        rm -f $disk1 $disk2
        error make {msg: $"Dual ESP test failed: ($e)"}
    }

    # Cleanup
    cleanup $vg_name $loop1 $loop2 $mountpoint
    rm -f $disk1 $disk2

    print "Dual ESP test completed successfully"
    tap ok
}

def main [] {
    # See https://tmt.readthedocs.io/en/stable/stories/features.html#reboot-during-test
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => test_single_esp,
        "1" => test_dual_esp,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
