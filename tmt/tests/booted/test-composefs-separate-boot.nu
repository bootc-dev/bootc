# tmt:
#   summary: Test composefs with GRUB and a separate /boot partition
#   duration: 60m
#   require:
#     - dosfstools
#     - e2fsprogs
# extra:
#   skip_if_ostree: true
#   fixme_skip_if_uki: true
#
# Disk images from e.g. image-builder have a separate /boot partition, which
# the VMs these tests run in don't have. With GRUB, the boot partition holds
# GRUB's configuration, the BLS entries and the kernels, is mounted on /boot
# (by a systemd.mount-extra karg from bootc install, or e.g. an fstab entry),
# and /sysroot/boot is empty.
#
# Booting a disk installed inside the VM isn't possible here, so the VM's own
# disk is given that layout instead, as `bootc install` would have made it:
#
# 1. Split the ESP into a smaller ESP and an ext4 XBOOTLDR partition, and move
#    everything in /sysroot/boot there: the BLS entries then refer to the
#    kernels relative to the boot partition, get the systemd.mount-extra karg,
#    and GRUB finds its configuration there by the filesystem UUID in
#    bootuuid.cfg.
# 2. Switch to a derived image with its own initramfs, so that its kernel
#    and initramfs are written to the boot partition too.
# 3. Upgrade to a newer build of that image, which goes back to the base
#    image's initramfs: GC must keep that one, and drop nothing in use.
# 4. Roll back.
# 5. The rollback worked, and nothing was written to /sysroot/boot.

use std assert
use tap.nu

const XBOOTLDR_TYPE = "BC13C2FF-59E6-4262-A352-B275FD6F7172"
const ESP_TYPE = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
# The size the VM's ESP is shrunk to; the boot partition gets the rest of it
const NEW_ESP_SIZE_MIB = 256
const SECTOR_SIZE = 512
const PHYSICAL_BOOT = "/sysroot/boot"
const STATE_FILE = "/var/separate-boot-test.json"
const DERIVED_IMAGE = "localhost/bootc-separate-boot-derived"
const MARKER = "/usr/share/bootc-separate-boot-marker"
const KERNEL_DIR_PREFIX = "bootc_composefs-"

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

# The kernel directories the BLS entries refer to, relative to the boot
# partition.
def referenced_kernel_dirs [boot: string] {
    glob $"($boot)/loader/entries*/*.conf"
    | each { |f| open $f | lines | where { |l| $l | str starts-with "linux " } }
    | flatten
    | each { |l| $l | str replace -r '^linux\s+' '' | path dirname }
    | uniq
}

# Check that everything is on the boot partition mounted on /boot, that the
# entries refer to kernels there, that GC left no unreferenced kernels, and
# that /sysroot/boot is still empty.
def assert_boot_layout [] {
    let state = (open $STATE_FILE)
    # systemd-gpt-auto-generator also sets up an automount on /boot for the
    # XBOOTLDR partition, under the systemd.mount-extra mount
    let boot_src = (findmnt -J -l -o SOURCE,FSTYPE -M /boot | from json).filesystems
        | where fstype != "autofs" | get source
    assert equal $boot_src [$state.boot] "/boot is not the boot partition"
    assert (ls -a $PHYSICAL_BOOT | is-empty) $"($PHYSICAL_BOOT) is not empty"

    let entries = (glob /boot/loader/entries/*.conf)
    print $"BLS entries: ($entries)"
    assert ($entries | is-not-empty) "No BLS entries on /boot"

    let referenced = (referenced_kernel_dirs /boot)
    print $"Referenced kernel directories: ($referenced)"
    for d in $referenced {
        assert ($d | str starts-with $"/($KERNEL_DIR_PREFIX)") $"Kernel path not relative to the boot partition: ($d)"
    }
    let on_disk = (glob $"/boot/($KERNEL_DIR_PREFIX)*" | each { |d| $"/($d | path basename)" })
    print $"Kernel directories on /boot: ($on_disk)"
    assert equal ($on_disk | sort) ($referenced | sort) "Kernel directories on /boot don't match the BLS entries"
}

# Move /sysroot/boot to a new boot partition carved out of the ESP.
def make_separate_boot [] {
    let root_part = (findmnt -n -o SOURCE /sysroot | str trim)
    let disk = $"/dev/(lsblk -n -o PKNAME $root_part | str trim)"
    let esp = (partition_of_type $disk $ESP_TYPE)
    let esp_nr = (partition_number $esp.node)
    let esp_uuid = (blkid -s UUID -o value $esp.node | str trim)
    let root_uuid = (blkid -s UUID -o value $root_part | str trim)
    print $"Disk ($disk), ESP ($esp.node) \(($esp.size) sectors\), root ($root_part)"
    assert (($esp.size * $SECTOR_SIZE) > ($NEW_ESP_SIZE_MIB * 3 * 1024 * 1024)) "ESP too small to split"

    let esp_backup = "/var/tmp/esp-backup"
    /usr/bin/cp -a -T (find_or_mount $esp.node "esp") $esp_backup
    for unit in [boot.automount efi.automount boot.mount efi.mount] {
        do { systemctl stop $unit } | complete | ignore
    }
    for t in (findmnt -rn -o TARGET -S $esp.node | lines) {
        umount $t
    }

    let new_esp_sectors = $NEW_ESP_SIZE_MIB * 1024 * 1024 / $SECTOR_SIZE
    let boot_start = $esp.start + $new_esp_sectors
    let boot_sectors = $esp.size - $new_esp_sectors
    let used_nrs = (partitions $disk | each { |p| partition_number $p.node })
    let boot_nr = (1..128 | where { |n| $n not-in $used_nrs } | first)
    # The root filesystem is mounted, so the kernel can't reread the whole
    # partition table, and partx updates it one partition at a time. But
    # systemd-udevd (v259 and newer) also syncs the kernel's partitions with
    # BLKPG when a disk it watches is closed after writing, racing with partx:
    # hold the disk's BSD lock, which it honors, until the kernel is updated.
    let script = '
        set -euo pipefail
        disk=$1 esp_nr=$2 esp_spec=$3 boot_nr=$4 boot_spec=$5
        echo "$esp_spec" | sfdisk --lock=no --no-reread -N "$esp_nr" "$disk"
        echo "$boot_spec" | sfdisk --lock=no --no-reread -N "$boot_nr" "$disk"
        partx -u --nr "$esp_nr" "$disk"
        partx -a --nr "$boot_nr" "$disk"
    '
    (udevadm lock $"--device=($disk)" bash -c $script bash $disk $esp_nr
        $"start=($esp.start), size=($new_esp_sectors), type=($ESP_TYPE)"
        $boot_nr $"start=($boot_start), size=($boot_sectors), type=($XBOOTLDR_TYPE)")
    udevadm settle
    let boot = (partitions $disk | where start == $boot_start | first).node
    for p in [[node sectors]; [$esp.node $new_esp_sectors] [$boot $boot_sectors]] {
        let sysfs = $"/sys/class/block/($p.node | path basename)/size"
        assert ($sysfs | path exists) $"The kernel doesn't know ($p.node)"
        assert equal (open --raw $sysfs | str trim | into int) $p.sectors $"The kernel's size of ($p.node)"
    }
    print $"New ESP ($esp.node), boot ($boot)"

    # Keep the ESP's filesystem UUID, in case something refers to it
    mkfs.vfat -F 32 -n EFI-SYSTEM -i ($esp_uuid | str replace "-" "") $esp.node
    mkfs.ext4 -q -L boot $boot
    udevadm settle
    let boot_uuid = (blkid -s UUID -o value $boot | str trim)

    let esp_dir = (find_or_mount $esp.node "esp")
    /usr/bin/cp -a -T $esp_backup $esp_dir
    rm -rf $esp_backup

    # Move everything in /sysroot/boot to the boot partition
    mount -o remount,rw /sysroot
    let boot_dir = (find_or_mount $boot "boot")
    /usr/bin/cp -a -T $PHYSICAL_BOOT $boot_dir
    for f in (ls -a $PHYSICAL_BOOT | get name) {
        rm -rf $f
    }

    # The kernels are now relative to the boot partition, which systemd
    # mounts on /boot
    let mount_karg = $"systemd.mount-extra=UUID=($boot_uuid):/boot:ext4:defaults"
    for f in (glob $"($boot_dir)/loader/entries/*.conf") {
        # Read it all before overwriting it
        let entry = (open --raw $f | lines | each { |l|
            if ($l | str starts-with "options ") {
                $"($l) ($mount_karg)"
            } else {
                $l | str replace -r '^(linux|initrd)(\s+)/boot/' '$1$2/'
            }
        } | str join "\n")
        print $"($f):\n($entry)"
        assert ($entry | str contains $"linux /($KERNEL_DIR_PREFIX)") $"Unexpected entry ($f)"
        $"($entry)\n" | save -f $f
    }

    # GRUB finds its configuration by filesystem UUID (see bootupd's static
    # GRUB configs)
    let uuid_files = (glob $"($esp_dir)/EFI/*/bootuuid.cfg" | append (glob $"($boot_dir)/grub2/bootuuid.cfg"))
    print $"Pointing ($uuid_files) at ($boot_uuid)"
    assert ($uuid_files | is-not-empty) "No bootuuid.cfg found"
    for f in $uuid_files {
        let content = (open --raw $f)
        assert ($content | str contains $root_uuid) $"($f) doesn't refer to the root filesystem: ($content)"
        $content | str replace --all $root_uuid $boot_uuid | save -f $f
    }

    { boot: $boot } | to json | save -f $STATE_FILE
    sync
}

# A derived image with a marker. With `own_initramfs`, its initramfs differs
# from the base image's (zero padding is ignored when unpacking it), so it
# gets its own copy on the boot partition.
def build_derived [marker: string, --own-initramfs] {
    let initramfs_step = if $own_initramfs {
        "RUN for f in /usr/lib/modules/*/initramfs.img; do head -c 512 /dev/zero >> $f; done\n"
    } else {
        ""
    }
    $"FROM localhost/bootc\n($initramfs_step)RUN echo ($marker) > ($MARKER)\n" | podman build -t $DERIVED_IMAGE -f - .
}

def assert_marker [expected: string] {
    assert ($MARKER | path exists) "Not booted into the derived image"
    assert equal (open $MARKER | str trim) $expected
}

def first_boot [] {
    tap begin "composefs with GRUB and a separate /boot"

    let st = bootc status --json | from json
    let cfs = $st.status.booted.composefs
    let bootloader = ($cfs.bootloader | str downcase)
    if $bootloader != "grub" or ($cfs.bootType | str downcase) != "bls" {
        print $"Only GRUB with BLS entries is covered, not ($bootloader) ($cfs.bootType); skipping"
        tap ok
        return
    }
    if not ("/sys/firmware/efi" | path exists) {
        print "Only UEFI is covered; skipping"
        tap ok
        return
    }

    make_separate_boot
    tmt-reboot
}

def second_boot [] {
    assert_boot_layout
    bootc status

    bootc image copy-to-storage
    build_derived v1 --own-initramfs
    bootc switch --transport containers-storage $DERIVED_IMAGE
    assert (glob /boot/loader/entries.staged/*.conf | is-not-empty) "No staged entries on /boot"
    tmt-reboot
}

def third_boot [] {
    assert_marker v1
    assert_boot_layout

    build_derived v2
    bootc upgrade
    assert (glob /boot/loader/entries.staged/*.conf | is-not-empty) "No staged entries on /boot"
    tmt-reboot
}

def fourth_boot [] {
    assert_marker v2
    assert_boot_layout

    bootc rollback
    assert (bootc status --json | from json).status.rollbackQueued
    tmt-reboot
}

def fifth_boot [] {
    assert_marker v1
    assert_boot_layout
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
