# number: 23
# tmt:
#   summary: Execute tests for installing outside of a container
#   duration: 30m
#
use std assert
use tap.nu

# Use the locally-built image which has updated bootupd with compatible
# EFI update metadata. Export to OCI layout on a writable path since
# containers-storage: transport can't work when the root fs is read-only
# (composefs), and install-outside-container tests run directly on the host.
bootc image copy-to-storage
skopeo copy containers-storage:localhost/bootc oci:/var/tmp/bootc-oci
let target_image = "oci:/var/tmp/bootc-oci"

# Keep the policy observed from the image we are actually testing.  In
# particular, do not infer it from the fact that the target is ext4: an
# unsealed UKI is a valid result on an fs-verity-capable filesystem.
let source_status = bootc status --json | from json
let source_composefs = $source_status.status.booted.composefs?
let source_is_uki = $source_composefs != null and (($source_composefs.bootType | str downcase) == "uki")
let source_cmdline = (open /proc/cmdline | str trim | split row " ")
let source_composefs_args = ($source_cmdline | where { |arg|
    ($arg | str starts-with "composefs=") or ($arg | str starts-with "composefs.digest=")
})
let source_requests_missing_verity = if $source_is_uki {
    assert (($source_composefs_args | length) > 0) "source UKI must have a composefs kernel argument"
    let requested = ($source_composefs_args | any { |arg|
        ($arg | str starts-with "composefs=?") or ($arg | str starts-with "composefs.digest=?")
    })
    assert equal $source_composefs.missingVerityAllowed $requested "bootc status must reflect the source UKI composefs policy"
    $requested
} else {
    false
}

# setup filesystem
mkdir /var/mnt
truncate -s 10G disk.img
mkfs.ext4 disk.img
mount -o loop disk.img /var/mnt

# attempt to install to filesystem without specifying a source-imgref
let result = bootc install to-filesystem /var/mnt e>| find "--source-imgref must be defined"
assert not equal $result null
umount /var/mnt

# And using systemd-run here breaks our install_t so we disable SELinux enforcement
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

def discover_target_partitions [loop: string] {
    mut last_listing = ""
    for attempt in 1..20 {
        # partscan creates the kernel partition devices synchronously, but
        # lsblk's udev-backed LABEL cache can lag behind filesystem creation.
        udevadm settle
        let listed = (do { lsblk --json --tree --paths --output PATH,LABEL,TYPE $loop } | complete)
        $last_listing = $listed.stdout
        if $listed.exit_code == 0 {
            let parsed = (try { $listed.stdout | from json } catch { null })
            if $parsed != null {
                let partitions = ($parsed.blockdevices.0.children? | default [])
                let esp = ($partitions | where type == "part" and label == "EFI-SYSTEM" | get path)
                let root = ($partitions | where type == "part" and label == "root" | get path)
                if (($esp | length) == 1 and ($root | length) == 1) {
                    return { esp: ($esp | first), root: ($root | first) }
                }

                # Query the filesystem superblocks directly as a fallback for
                # a stale lsblk LABEL cache.  blkid -p does not consult udev.
                let direct = ($partitions | each { |partition|
                    let label = (do { blkid -p -s LABEL -o value $partition.path } | complete)
                    $partition | upsert label ($label.stdout | str trim)
                })
                let direct_esp = ($direct | where type == "part" and label == "EFI-SYSTEM" | get path)
                let direct_root = ($direct | where type == "part" and label == "root" | get path)
                if (($direct_esp | length) == 1 and ($direct_root | length) == 1) {
                    return { esp: ($direct_esp | first), root: ($direct_root | first) }
                }
            }
        }
        if $attempt < 20 {
            sleep 100ms
        }
    }
    error make { msg: $"target partition labels did not become visible after 20 attempts; last lsblk JSON: ($last_listing)" }
}

# Inspect the disk produced by this test, rather than the running system.
# The installer creates an architecture-specific BIOS/boot partition before
# the ESP, so locate partitions by their discoverable labels instead of using
# fixed partition numbers.
if $source_is_uki {
    let loop = (losetup --find --show --partscan ./disk.img | str trim)
    let partitions = try {
        discover_target_partitions $loop
    } catch {|err|
        do { losetup -d $loop } | complete | ignore
        error make { msg: $"installed target partition discovery failed: ($err)" }
    }
    let esp = $partitions.esp
    let root = $partitions.root

    let target_root = "/var/mnt/plan23-target"
    let target_esp = "/var/mnt/plan23-esp"
    mkdir $target_root
    mkdir $target_esp
    mount -o ro $root $target_root
    mount -o ro $esp $target_esp

    # Always tear down the temporary mounts and loop device, while retaining
    # the original assertion/inspection error for tmt to report.
    let inspection_error = try {
        let meta = $"($target_root)/composefs/meta.json"
        assert ($meta | path exists) "installed target must contain composefs/meta.json"
        assert (not (which objcopy | is-empty)) "binutils package must provide objcopy"

        # lsattr reads the typed ext4 FS_VERITY_FL attribute.  This is
        # deliberately not a check of the composefs metadata JSON (which only
        # describes the hash algorithm), and works on bases without the
        # separately packaged fsverity utility.
        let attributes = (do { lsattr -d $meta } | complete)
        assert equal $attributes.exit_code 0 "could not read target metadata fs-verity attribute"
        let flags = ($attributes.stdout | split row " " | first)
        let has_verity = ($flags | str contains "V")
        if $source_requests_missing_verity {
            assert (not $has_verity) "an unsealed source UKI must not make target composefs metadata require fs-verity"
        } else {
            assert $has_verity "a strict source UKI must produce fs-verity-protected target composefs metadata"
        }

        let ukis = (glob $"($target_esp)/EFI/Linux/bootc/*.efi")
        assert (($ukis | length) > 0) "installed target ESP must contain a composefs UKI"
        let inspect_dir = "/var/tmp/plan23-uki-cmdline"
        mkdir $inspect_dir
        for uki in $ukis {
            let dump = $"($inspect_dir)/($uki | path basename).cmdline"
            # Some objcopy versions open the input for writing even when only
            # dumping a section. Keep the installed ESP read-only.
            let uki_copy = $"($inspect_dir)/($uki | path basename)"
            cp $uki $uki_copy
            let dump_result = (do { objcopy --dump-section $".cmdline=($dump)" $uki_copy } | complete)
            assert equal $dump_result.exit_code 0 $"could not inspect installed UKI ($uki): ($dump_result.stderr)"
            let cmdline = (open --raw $dump | into binary | decode utf-8 | str replace -a (char nul) "" | str trim | split row " ")
            let args = ($cmdline | where { |arg|
                ($arg | str starts-with "composefs=") or ($arg | str starts-with "composefs.digest=")
            })
            assert (($args | length) > 0) $"installed UKI ($uki) must have a composefs kernel argument"
            let requests_missing = ($args | each { |arg|
                ($arg | str starts-with "composefs=?") or ($arg | str starts-with "composefs.digest=?")
            })
            assert (($requests_missing | uniq | length) == 1) $"installed UKI ($uki) contains inconsistent composefs policies"
            assert equal ($requests_missing | first) $source_requests_missing_verity $"installed UKI ($uki) policy must match the initial UKI"
        }
        print $"Verified installed target policy: missing-verity=($source_requests_missing_verity), metadata-verity=($has_verity)"
        null
    } catch {|err| $err }

    do { umount $target_esp } | complete | ignore
    do { umount $target_root } | complete | ignore
    do { losetup -d $loop } | complete | ignore
    if $inspection_error != null {
        error make { msg: $"installed target inspection failed: ($inspection_error)" }
    }
}

tap ok
