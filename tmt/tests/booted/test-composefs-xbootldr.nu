# number: 61
# tmt:
#   summary: Test composefs with systemd-boot and an XBOOTLDR partition
#   duration: 60m
#   require:
#     - dosfstools
#   adjust:
#     - when: seal_state == sealed
#       enabled: false
#       because: the derived images are built in the VM, which has no keys to sign their UKIs for Secure Boot
# extra:
#   skip_if_ostree: true
#
# With systemd-boot, bootc writes the UKIs, the BLS entries and their kernels
# to a VFAT XBOOTLDR partition next to the ESP when there is one, so that a
# small ESP (e.g. Windows' 100 MB one) only holds the bootloader. Systems
# whose entries are on the ESP, e.g. from a bootc that didn't use XBOOTLDR
# partitions, keep them there.
#
# Booting a disk installed inside the VM isn't possible here, so the VM's own
# disk is given that layout instead:
#
# 1. Split the ESP in half, and put an empty VFAT XBOOTLDR partition in the
#    second half. bootc's entries, UKIs and kernels stay on the ESP.
# 2. Switch to a derived image: since the booted deployment's entries are on
#    the ESP, its entries and binaries go there too.
# 3. Move bootc's files to the XBOOTLDR partition, as if it had been
#    installed there, and upgrade to a newer build of that image, which goes
#    back to the base image's initramfs: GC must keep that one, and drop
#    nothing in use.
# 4. Roll back.
# 5. The rollback worked, and bootc wrote nothing to the ESP.

use std assert
use tap.nu

const XBOOTLDR_TYPE = "BC13C2FF-59E6-4262-A352-B275FD6F7172"
const ESP_TYPE = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
const SECTOR_SIZE = 512
const STATE_FILE = "/var/xbootldr-test.json"
const DERIVED_IMAGE = "localhost/bootc-xbootldr-derived"
const MARKER = "/usr/share/bootc-xbootldr-marker"
const BOOTC_PREFIX = "bootc_"
# What bootc owns on the partition holding the boot entries
const BOOTC_GLOBS = ["loader/entries*/bootc_*.conf" "EFI/Linux/bootc*"]
# Keys of BLS entries that refer to files on the same partition
const ENTRY_FILE_KEYS = ["linux" "initrd" "efi" "uki"]

def partitions [disk: string] {
    (sfdisk --json $disk | from json).partitiontable.partitions
}

def partition_of_type [disk: string, type: string] {
    partitions $disk | where { |p| ($p.type | str upcase) == $type } | first
}

def partition_number [node: string] {
    $node | str replace -r '.*[^0-9]' '' | into int
}

# The path of an existing mount of `dev`, or a new one.
def find_or_mount [dev: string, name: string] {
    let existing = (findmnt -rn -o TARGET -S $dev | lines)
    if ($existing | is-not-empty) {
        return ($existing | first)
    }
    let path = $"/var/mnt/($name)"
    mkdir $path
    mount $dev $path
    $path
}

def bootc_files [dir: string] {
    $BOOTC_GLOBS | each { |g| glob $"($dir)/($g)" } | flatten
}

# The files the BLS entries refer to, relative to the partition they're on.
def referenced_files [dir: string] {
    glob $"($dir)/loader/entries*/*.conf"
    | each { |f| open $f | lines | parse -r '^(?<key>\S+)\s+(?<path>\S+)' }
    | flatten
    | where key in $ENTRY_FILE_KEYS
    | get path
    | uniq
}

# The UKIs and kernel directories bootc keeps on `dir`, as entries refer to
# them.
def bootc_binaries [dir: string] {
    let ukis = (glob $"($dir)/EFI/Linux/bootc/($BOOTC_PREFIX)*.efi")
    let kernel_dirs = (glob $"($dir)/EFI/Linux/($BOOTC_PREFIX)*" --no-file)
    $ukis | append $kernel_dirs | each { |p| $p | str replace $dir "" }
}

# The mounted ESP and XBOOTLDR partition
def mounted_partitions [] {
    let state = (open $STATE_FILE)
    { esp: (find_or_mount $state.esp "esp"), xbootldr: (find_or_mount $state.xbootldr "xbootldr") }
}

# Check that the entries, UKIs and kernels are all on the `holder` partition
# ("esp" or "xbootldr"), that GC left nothing unreferenced there, and that
# nothing of bootc's is on the other one.
def assert_layout [holder: string] {
    let mounted = (mounted_partitions)
    let dir = ($mounted | get $holder)
    let other = ($mounted | reject $holder | values | first)

    let entries = (glob $"($dir)/loader/entries/*.conf")
    print $"BLS entries on the ($holder) partition: ($entries)"
    assert ($entries | is-not-empty) $"No BLS entries on the ($holder) partition"

    let referenced = (referenced_files $dir)
    print $"Referenced files: ($referenced)"
    for f in $referenced {
        assert ($"($dir)($f)" | path exists) $"($f) is not on the ($holder) partition"
    }
    let referenced_binaries = ($referenced | each { |f|
        if ($f | str ends-with ".efi") { $f } else { $f | path dirname }
    } | uniq)
    let on_disk = (bootc_binaries $dir)
    print $"Binaries on the ($holder) partition: ($on_disk)"
    assert equal ($on_disk | sort) ($referenced_binaries | sort) $"Binaries on the ($holder) partition don't match the BLS entries"

    let elsewhere = (bootc_files $other)
    assert ($elsewhere | is-empty) $"bootc files outside the ($holder) partition: ($elsewhere)"
    assert ($"($mounted.esp)/loader/loader.conf" | path exists) "loader.conf is missing from the ESP"
    assert (not ($"($mounted.xbootldr)/loader/loader.conf" | path exists)) "loader.conf was written to the XBOOTLDR partition"
}

def move_to_xbootldr [] {
    let mounted = (mounted_partitions)
    for f in (bootc_files $mounted.esp) {
        let dest = $"($mounted.xbootldr)($f | str replace $mounted.esp "")"
        mkdir ($dest | path dirname)
        ^mv $f $dest
    }
    sync
}

# Split the ESP in half, with a new, empty XBOOTLDR partition in the second
# half.
def make_xbootldr [] {
    let root_part = (findmnt -n -o SOURCE /sysroot | str trim)
    let disk = $"/dev/(lsblk -n -o PKNAME $root_part | str trim)"
    let esp = (partition_of_type $disk $ESP_TYPE)
    let esp_nr = (partition_number $esp.node)
    let esp_uuid = (blkid -s UUID -o value $esp.node | str trim)
    let esp_partuuid = (blkid -s PARTUUID -o value $esp.node | str trim)
    print $"Disk ($disk), ESP ($esp.node) \(($esp.size) sectors\)"
    let new_esp_sectors = ($esp.size / 2 / 2048 | math floor) * 2048
    assert (($new_esp_sectors * $SECTOR_SIZE) >= 512 * 1024 * 1024) "ESP too small to split"

    let esp_backup = "/var/tmp/esp-backup"
    /usr/bin/cp -a -T (find_or_mount $esp.node "esp") $esp_backup
    for unit in [boot.automount efi.automount boot.mount efi.mount] {
        do { systemctl stop $unit } | complete | ignore
    }
    for t in (findmnt -rn -o TARGET -S $esp.node | lines) {
        umount $t
    }

    let xbootldr_start = $esp.start + $new_esp_sectors
    let xbootldr_sectors = $esp.size - $new_esp_sectors
    let used_nrs = (partitions $disk | each { |p| partition_number $p.node })
    let xbootldr_nr = (1..128 | where { |n| $n not-in $used_nrs } | first)
    # See test-composefs-separate-boot.nu: the root filesystem is mounted, so
    # update the kernel's partitions one at a time while holding the disk's
    # lock against systemd-udevd.
    let script = '
        set -euo pipefail
        disk=$1 esp_nr=$2 esp_spec=$3 xbootldr_nr=$4 xbootldr_spec=$5
        echo "$esp_spec" | sfdisk --lock=no --no-reread -N "$esp_nr" "$disk"
        echo "$xbootldr_spec" | sfdisk --lock=no --no-reread -N "$xbootldr_nr" "$disk"
        partx -u --nr "$esp_nr" "$disk"
        partx -a --nr "$xbootldr_nr" "$disk"
    '
    (udevadm lock $"--device=($disk)" bash -c $script bash $disk $esp_nr
        $"start=($esp.start), size=($new_esp_sectors), type=($ESP_TYPE)"
        $xbootldr_nr $"start=($xbootldr_start), size=($xbootldr_sectors), type=($XBOOTLDR_TYPE)")
    udevadm settle
    let xbootldr = (partitions $disk | where start == $xbootldr_start | first).node
    for p in [[node sectors]; [$esp.node $new_esp_sectors] [$xbootldr $xbootldr_sectors]] {
        let sysfs = $"/sys/class/block/($p.node | path basename)/size"
        assert ($sysfs | path exists) $"The kernel doesn't know ($p.node)"
        assert equal (open --raw $sysfs | str trim | into int) $p.sectors $"The kernel's size of ($p.node)"
    }
    # systemd-boot reports the ESP it was started from by its PARTUUID, which
    # bootc looks the XBOOTLDR partition up from
    assert equal (blkid -s PARTUUID -o value $esp.node | str trim) $esp_partuuid "The ESP's PARTUUID changed"
    print $"New ESP ($esp.node), XBOOTLDR ($xbootldr)"

    # Keep the ESP's filesystem UUID, in case something refers to it
    mkfs.vfat -F 32 -n EFI-SYSTEM -i ($esp_uuid | str replace "-" "") $esp.node
    mkfs.vfat -F 32 -n XBOOTLDR $xbootldr
    udevadm settle

    /usr/bin/cp -r -T $esp_backup (find_or_mount $esp.node "esp")
    rm -rf $esp_backup

    { esp: $esp.node, xbootldr: $xbootldr } | to json | save -f $STATE_FILE
    sync
}

# A derived image with a marker. With `own_initramfs`, a traditional
# kernel install gets its own copy of the initramfs (zero padding is ignored
# when unpacking it), so GC has a kernel directory to drop.
def build_derived [marker: string, --own-initramfs] {
    let initramfs_step = if $own_initramfs {
        "RUN for f in /usr/lib/modules/*/initramfs.img; do if test -f $f; then head -c 512 /dev/zero >> $f; fi; done"
    } else {
        ""
    }
    let containerfile = (tap make_uki_containerfile $"
        FROM localhost/bootc as base
        ($initramfs_step)
        RUN echo ($marker) > ($MARKER)
    ")
    $containerfile | podman build -t $DERIVED_IMAGE -f - .
}

def assert_marker [expected: string] {
    assert ($MARKER | path exists) "Not booted into the derived image"
    assert equal (open $MARKER | str trim) $expected
}

def assert_staged_on [holder: string] {
    let dir = (mounted_partitions | get $holder)
    assert (glob $"($dir)/loader/entries.staged/*.conf" | is-not-empty) $"No staged entries on the ($holder) partition"
}

def first_boot [] {
    tap begin "composefs with systemd-boot and an XBOOTLDR partition"

    let bootloader = ((bootc status --json | from json).status.booted.composefs.bootloader | str downcase)
    if $bootloader != "systemd" {
        print $"Only systemd-boot uses an XBOOTLDR partition, not ($bootloader); skipping"
        tap ok
        return
    }

    make_xbootldr
    tmt-reboot
}

def second_boot [] {
    assert_layout esp
    bootc status

    bootc image copy-to-storage
    build_derived v1 --own-initramfs
    bootc switch --transport containers-storage $DERIVED_IMAGE
    assert_staged_on esp
    assert_layout esp
    tmt-reboot
}

def third_boot [] {
    assert_marker v1
    assert_layout esp

    move_to_xbootldr
    assert_layout xbootldr
    bootc status

    build_derived v2
    bootc upgrade
    assert_staged_on xbootldr
    tmt-reboot
}

def fourth_boot [] {
    assert_marker v2
    assert_layout xbootldr

    bootc rollback
    assert (bootc status --json | from json).status.rollbackQueued
    tmt-reboot
}

def fifth_boot [] {
    assert_marker v1
    assert_layout xbootldr
    tap ok
}

def main [] {
    # See https://tmt.readthedocs.io/en/stable/stories/features.html#reboot-during-test
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => first_boot,
        "1" => second_boot,
        "2" => third_boot,
        "3" => fourth_boot,
        "4" => fifth_boot,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
