# number: 32
# tmt:
#   summary: Test multi-device ESP detection for to-existing-root
#   duration: 60m
#
# Test that bootc install to-existing-root can find and use ESP partitions
# when the root filesystem spans multiple backing devices (e.g., LVM across disks).
#
# Five scenarios are tested across three reboot cycles:
#
# Reboot 0:
#   1. Single ESP: Only one of two backing devices has an ESP partition
#
# Reboot 1:
#   2. Dual ESP: Both backing devices have ESP partitions
#   3. Three devices, partial ESP: Three disks, ESP on disk1+disk3 only
#
# Reboot 2:
#   4. Single device (no LVM): ESP + root partition on a single disk
#   5. No ESP anywhere: Two disks with no ESP; install should fail gracefully
#
# This validates the fix for https://github.com/bootc-dev/bootc/issues/481

use std assert
use tap.nu

const target_image = "localhost/bootc"

# ESP partition type GUID
const ESP_TYPE = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
# Linux LVM partition type GUID
const LVM_TYPE = "E6D6D379-F507-44C2-A23C-238F2A3DF928"
# Linux root (x86-64) partition type GUID
const ROOT_TYPE = "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709"

# Cleanup function for LVM and loop devices
def cleanup [vg_name: string, loops: list<string>, mountpoint: string] {
    # Unmount if mounted
    do { umount $mountpoint } | complete | ignore
    do { rmdir $mountpoint } | complete | ignore

    # Deactivate and remove LVM
    do { lvchange -an $"($vg_name)/test_lv" } | complete | ignore
    do { lvremove -f $"($vg_name)/test_lv" } | complete | ignore
    do { vgchange -an $vg_name } | complete | ignore
    do { vgremove -f $vg_name } | complete | ignore

    # Remove PVs and detach loop devices
    for loop in $loops {
        if ($loop | path exists) {
            do { pvremove -f $loop } | complete | ignore
            do { losetup -d $loop } | complete | ignore
        }
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

# Create a disk with GPT, ESP, and a root partition (no LVM)
# Returns the loop device path
def setup_disk_with_root [
    disk_path: string,
    disk_size: string = "5G"
] {
    truncate -s $disk_size $disk_path
    let loop = (losetup -f --show $disk_path | str trim)

    # GPT with ESP (512MB) + root partition
    $"label: gpt\nsize=512M, type=($ESP_TYPE)\ntype=($ROOT_TYPE)\n" | sfdisk $loop
    partx -u $loop
    sleep 1sec

    mkfs.vfat -F 32 $"($loop)p1"
    mkfs.ext4 -q $"($loop)p2"

    $loop
}

# Simple cleanup for non-LVM scenarios (single loop device, no VG)
def cleanup_simple [loop: string, mountpoint: string] {
    do { umount $mountpoint } | complete | ignore
    do { rmdir $mountpoint } | complete | ignore

    if ($loop | path exists) {
        do { losetup -d $loop } | complete | ignore
    }
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
        -v /run/udev:/run/udev:ro
        -v /usr/share/empty:/usr/lib/bootc/bound-images.d
        --pid=host
        --security-opt label=type:unconfined_t
        --env BOOTC_BOOTLOADER_DEBUG=1
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
        cleanup $vg_name [$loop1, $loop2] $mountpoint
        rm -f $disk1 $disk2
        error make {msg: $"Single ESP test failed: ($e)"}
    }

    # Cleanup
    cleanup $vg_name [$loop1, $loop2] $mountpoint
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
        cleanup $vg_name [$loop1, $loop2] $mountpoint
        rm -f $disk1 $disk2
        error make {msg: $"Dual ESP test failed: ($e)"}
    }

    # Cleanup
    cleanup $vg_name [$loop1, $loop2] $mountpoint
    rm -f $disk1 $disk2

    print "Dual ESP test completed successfully"
}

# Test scenario 3: Three devices, ESP on disk1 and disk3 only
def test_three_devices_partial_esp [] {
    print "Starting three devices partial ESP test"

    let vg_name = "test_three_dev_vg"
    let mountpoint = "/var/mnt/test_three_dev"
    let disk1 = "/var/tmp/disk1_three.img"
    let disk2 = "/var/tmp/disk2_three.img"
    let disk3 = "/var/tmp/disk3_three.img"

    # Setup disks
    # DISK1: ESP + LVM partition
    # DISK2: Full LVM partition (no ESP)
    # DISK3: ESP + LVM partition
    let loop1 = (setup_disk_with_partitions $disk1 true)
    let loop2 = (setup_disk_with_partitions $disk2 false)
    let loop3 = (setup_disk_with_partitions $disk3 true)

    try {
        # Create LVM spanning all three devices
        pvcreate $"($loop1)p2" $"($loop2)p1" $"($loop3)p2"
        vgcreate $vg_name $"($loop1)p2" $"($loop2)p1" $"($loop3)p2"
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

        # Validate ESP installed on disk1 and disk3, disk2 has no ESP
        validate_esp $"($loop1)p1"
        validate_esp $"($loop3)p1"
    } catch {|e|
        cleanup $vg_name [$loop1, $loop2, $loop3] $mountpoint
        rm -f $disk1 $disk2 $disk3
        error make {msg: $"Three devices partial ESP test failed: ($e)"}
    }

    # Cleanup
    cleanup $vg_name [$loop1, $loop2, $loop3] $mountpoint
    rm -f $disk1 $disk2 $disk3

    print "Three devices partial ESP test completed successfully"
}

# Test scenario 4: Single device with ESP + root partition (no LVM)
def test_single_device_no_lvm [] {
    print "Starting single device no LVM test"

    let mountpoint = "/var/mnt/test_no_lvm"
    let disk1 = "/var/tmp/disk1_nolvm.img"

    let loop1 = (setup_disk_with_root $disk1 "10G")

    try {
        # Mount root partition directly (no LVM)
        mkdir $mountpoint
        mount $"($loop1)p2" $mountpoint

        # Create boot directory
        mkdir $"($mountpoint)/boot"

        # Show block device hierarchy
        lsblk --pairs --paths --inverse --output NAME,TYPE $"($loop1)p2"

        run_install $mountpoint

        # Validate ESP was installed correctly
        validate_esp $"($loop1)p1"
    } catch {|e|
        cleanup_simple $loop1 $mountpoint
        rm -f $disk1
        error make {msg: $"Single device no LVM test failed: ($e)"}
    }

    # Cleanup
    cleanup_simple $loop1 $mountpoint
    rm -f $disk1

    print "Single device no LVM test completed successfully"
}

# Test scenario 5: No ESP on any device (install should fail gracefully)
def test_no_esp_failure [] {
    print "Starting no ESP failure test"

    let vg_name = "test_no_esp_vg"
    let mountpoint = "/var/mnt/test_no_esp"
    let disk1 = "/var/tmp/disk1_noesp.img"
    let disk2 = "/var/tmp/disk2_noesp.img"

    # Setup disks - neither has ESP
    let loop1 = (setup_disk_with_partitions $disk1 false)
    let loop2 = (setup_disk_with_partitions $disk2 false)

    try {
        # Create LVM spanning both devices
        pvcreate $"($loop1)p1" $"($loop2)p1"
        vgcreate $vg_name $"($loop1)p1" $"($loop2)p1"
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

        # Run install and expect it to fail
        let result = (do {
            run_install $mountpoint
        } | complete)

        assert ($result.exit_code != 0) "Expected install to fail with no ESP partitions"
        # Verify the failure is ESP-related, not an unrelated podman/runtime error
        let combined = $"($result.stdout)\n($result.stderr)"
        assert ($combined | str contains "ESP") $"Expected ESP-related error message, got: ($combined | str substring 0..200)"
        print $"Install failed as expected with exit code ($result.exit_code)"
    } catch {|e|
        cleanup $vg_name [$loop1, $loop2] $mountpoint
        rm -f $disk1 $disk2
        error make {msg: $"No ESP failure test failed: ($e)"}
    }

    # Cleanup
    cleanup $vg_name [$loop1, $loop2] $mountpoint
    rm -f $disk1 $disk2

    print "No ESP failure test completed successfully"
    tap ok
}

def main [] {
    # This test requires a UEFI-booted host because it creates ESP partitions
    # and expects bootupd to install a UEFI bootloader.  On BIOS systems,
    # bootupd would try to install GRUB for i386-pc which needs a BIOS Boot
    # Partition instead of an ESP.
    if not ("/sys/firmware/efi" | path exists) {
        print "SKIP: multi-device ESP test requires UEFI boot"
        tap ok
        return
    }

    # This test exercises bootupd-based bootloader installation which only
    # supports GRUB today.  Skip when the image uses systemd-boot.
    if (tap is_composefs) {
        let st = bootc status --json | from json
        if ($st.status.booted.composefs.bootloader | str downcase) == "systemd" {
            print "SKIP: multi-device ESP test not supported with systemd-boot"
            tap ok
            return
        }
    }

    # See https://tmt.readthedocs.io/en/stable/stories/features.html#reboot-during-test
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => test_single_esp,
        "1" => { test_dual_esp; test_three_devices_partial_esp; tmt-reboot },
        "2" => { test_single_device_no_lvm; test_no_esp_failure },
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
