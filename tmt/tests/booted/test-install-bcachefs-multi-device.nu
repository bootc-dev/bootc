# number: 68
# tmt:
#   summary: Test install to-filesystem on a multi-device bcachefs root
#   duration: 30m
#   require:
#     - dosfstools
# extra:
#   # Only covered with systemd-boot, see below, and a UKI brings its own
#   # kernel arguments
#   skip_if_ostree: true
#   fixme_skip_if_uki: true
#
# A bcachefs filesystem on several devices is mounted with a colon-separated
# source such as `/dev/loop0:/dev/loop1:/dev/loop2p2`. That names no single
# block device, and findmnt reports no UUID for it. Installing to one, bootc
# has to
#
# - find the ESP on whichever device's disk carries it: here the last one,
#   the other two being whole-disk members without a partition table;
# - take the UUID for the default `root=UUID=` argument from the devices.
#
# With systemd-boot, the kernels and the boot entries are on the ESP, so no
# bootloader has to read bcachefs. GRUB loads them from /boot, which would
# have to be a separate filesystem that it can read; that isn't covered here.
#
# Booting a disk installed inside the VM isn't possible here, so the test
# stops at inspecting what was installed. bcachefs is not in the mainline
# kernel: the test is skipped without the module or bcachefs-tools.

use std assert
use tap.nu

const ESP_TYPE = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
const DISKS = ["/var/tmp/bcachefs-a.img" "/var/tmp/bcachefs-b.img" "/var/tmp/bcachefs-c.img"]
const ROOT = "/var/mnt/bcachefs-root"
const ESP = "/var/mnt/bcachefs-esp"

def cleanup [loops: list<string>] {
    for mnt in [$ESP $ROOT] {
        do { umount -l $mnt } | complete | ignore
    }
    for loop in $loops {
        do { losetup -d $loop } | complete | ignore
    }
    rm -f ...$DISKS
}

def install_and_check [loops: list<string>] {
    let esp_part = $"($loops.2)p1"
    let devices = [$loops.0 $loops.1 $"($loops.2)p2"]

    $"label: gpt\nsize=1G, type=($ESP_TYPE)\ntype=linux\n" | sfdisk $loops.2
    udevadm settle
    mkfs.vfat -F 32 $esp_part
    bcachefs format --quiet ...$devices
    udevadm settle
    let uuid = (blkid --probe --match-tag UUID --output value $devices.0 | str trim)

    mkdir $ROOT
    mount -t bcachefs ($devices | str join ":") $ROOT
    findmnt --output SOURCE,FSTYPE,UUID $ROOT

    (podman run --rm --privileged --pid=host
        --security-opt label=type:unconfined_t
        -v /dev:/dev -v /run/udev:/run/udev:ro
        -v /usr/share/empty:/usr/lib/bootc/bound-images.d
        -v $"($ROOT):/target"
        localhost/bootc
        bootc install to-filesystem --disable-selinux /target)

    assert ($"($ROOT)/composefs" | path exists) "No composefs repository in the bcachefs root"

    mkdir $ESP
    mount -o ro $esp_part $ESP
    assert (glob $"($ESP)/EFI/systemd/*.efi" | is-not-empty) $"systemd-boot is not on ($esp_part)"
    let entries = (glob $"($ESP)/loader/entries/*.conf")
    assert ($entries | is-not-empty) $"No boot entries on ($esp_part)"
    for entry in $entries {
        let options = (open --raw $entry | lines | where { |l| $l | str starts-with "options " } | first)
        print $"($entry): ($options)"
        assert ($options | str contains $"root=UUID=($uuid)") $"($entry) doesn't mount the root by its UUID ($uuid)"
    }
}

def main [] {
    tap begin "install to-filesystem on a multi-device bcachefs root"

    if (which bcachefs | is-empty) or (do { modprobe bcachefs } | complete).exit_code != 0 {
        print "SKIP: needs bcachefs-tools and a kernel with bcachefs"
        tap ok
        return
    }
    let st = bootc status --json | from json
    let bootloader = $st.status.booted.composefs.bootloader | str downcase
    if $bootloader != "systemd" {
        print $"SKIP: only covered with systemd-boot, not ($bootloader)"
        tap ok
        return
    }

    bootc image copy-to-storage

    let loops = ($DISKS | each { |disk|
        truncate -s 5G $disk
        losetup --find --show --partscan $disk | str trim
    })
    try {
        install_and_check $loops
    } catch { |e|
        cleanup $loops
        error make {msg: $"Multi-device bcachefs install failed: ($e)"}
    }
    cleanup $loops

    tap ok
}
