#!/bin/bash
set -euo pipefail

boot_sector_size=440
esp_typeguid=c12a7328-f81f-11d2-ba4b-00a0c93ec93b
bios_typeguid=21686148-6449-6e6f-744e-656564454649
prep_typeguid=9e1a2d38-c612-4316-aa26-8b49521e5a8b

# This is implementation details of Ignition; in the future, we should figure
# out a way to ask Ignition directly whether there's a filesystem with label
# "root" being set up.
ignition_cfg=/run/ignition.json
root_part=/dev/disk/by-label/root
boot_part=/dev/disk/by-label/boot
esp_part=/dev/disk/by-label/EFI-SYSTEM
bios_part=/dev/disk/by-partlabel/BIOS-BOOT
prep_part=/dev/disk/by-partlabel/PowerPC-PReP-boot
saved_data=/run/ignition-ostree-transposefs
saved_root=${saved_data}/root
saved_boot=${saved_data}/boot
saved_esp=${saved_data}/esp
saved_bios=${saved_data}/bios
saved_prep=${saved_data}/prep
zram_dev=${saved_data}/zram_dev
partstate_root=/run/ignition-ostree-rootfs-partstate.sh

is_rhcos9() {
    source /etc/os-release
    [ "${ID}" == "rhcos" ] && [ "${RHEL_VERSION%%.*}" -eq 9 ]
}

# Print jq query string for wiped filesystems with label $1
query_fslabel() {
    echo ".storage?.filesystems? // [] | map(select(.label == \"$1\" and .wipeFilesystem == true))"
}

# Print jq query string for partitions with type GUID $1
query_parttype() {
    echo ".storage?.disks? // [] | map(.partitions?) | flatten | map(select(has(\"typeGuid\") and (.typeGuid | ascii_downcase == \"$1\")))"
}

# Print partition labels for partitions with type GUID $1
get_partlabels_for_parttype() {
    jq -r "$(query_parttype $1) | .[].label" "${ignition_cfg}"
}

# Mounts device to directory, with extra logging of the src device
mount_verbose() {
    local srcdev=$1; shift
    local destdir=$1; shift
    local mode=${1:-ro}
    echo "Mounting ${srcdev} ${mode} ($(realpath "$srcdev")) to $destdir"
    mkdir -p "${destdir}"
    mount -o "${mode}" "${srcdev}" "${destdir}"
}

# A copy of this exists in ignition-ostree-growfs.sh.
# Sometimes, for some reason the by-label symlinks aren't updated. Detect these
# cases, and explicitly `udevadm trigger`.
# See: https://bugzilla.redhat.com/show_bug.cgi?id=1908780
udev_trigger_on_label_mismatch() {
    local label=$1; shift
    local expected_dev=$1; shift
    local actual_dev
    expected_dev=$(realpath "${expected_dev}")
    # We `|| :` here because sometimes /dev/disk/by-label/$label is missing.
    # We've seen this on Fedora kernels with debug enabled (common in `rawhide`).
    # See https://github.com/coreos/fedora-coreos-tracker/issues/1092
    actual_dev=$(realpath "/dev/disk/by-label/$label" || :)
    if [ "$actual_dev" != "$expected_dev" ]; then
        echo "Expected /dev/disk/by-label/$label to point to $expected_dev, but points to $actual_dev; triggering udev"
        udevadm trigger --settle "$expected_dev"
    fi
}

# Print partition offset for device node $1
get_partition_offset() {
    local devpath=$(udevadm info --query=path "$1")
    cat "/sys${devpath}/start"
}

# copied from generator-lib.sh
karg() {
    local name="$1" value="${2:-}"
    local cmdline=( $(</proc/cmdline) )
    for arg in "${cmdline[@]}"; do
        if [[ "${arg%%=*}" == "${name}" ]]; then
            value="${arg#*=}"
        fi
    done
    echo "${value}"
}

mount_and_restore_filesystem_by_label() {
    local label=$1; shift
    local mountpoint=$1; shift
    local saved_fs=$1; shift
    local new_dev
    new_dev=$(jq -r "$(query_fslabel "${label}") | .[0].device // \"\"" "${ignition_cfg}")
    # in the autosave-xfs path, it's not driven by the Ignition config so we
    # don't expect a new device there
    if [ -n "${new_dev}" ]; then
        udev_trigger_on_label_mismatch "${label}" "${new_dev}"
    fi
    mount_verbose "/dev/disk/by-label/${label}" "${mountpoint}" rw
    find "${saved_fs}" -mindepth 1 -maxdepth 1 -exec mv -t "${mountpoint}" {} +
}

mount_and_save_filesystem_by_label() {
    local label=$1; shift
    local saved_fs=$1; shift
    local fs=/dev/disk/by-label/${label}
    if [[ -f /run/coreos/secure-execution ]]; then
        local roothash_karg=${label}fs.roothash
        local roothash=$(karg "${roothash_karg}")
        if [ -z "${roothash}" ]; then
          echo "Missing kernel argument ${roothash_karg}; aborting"
          exit 1
        fi
        local roothash_part=/dev/disk/by-partlabel/${label}hash
        veritysetup open "${fs}" "${label}" "${roothash_part}" "${roothash}"
        fs=/dev/mapper/${label}
    fi
    mount_verbose "${fs}" /var/tmp/mnt
    cp -aT /var/tmp/mnt "${saved_fs}"
    umount /var/tmp/mnt
    if [[ -f /run/coreos/secure-execution ]]; then
        veritysetup close "${label}"
    fi
}

# This implements https://github.com/coreos/fedora-coreos-tracker/issues/1183.
should_autosave_rootfs() {
    local fstype
    fstype=$(lsblk -no FSTYPE "${root_part}")
    if [ "$fstype" != xfs ]; then
        echo "Filesystem is not XFS (found $fstype); skipping" >&2
        echo 0
        return
    fi
    local agcount
    # This runs xfs_info on the unmounted filesystem, because mounting an
    # XFS filesystem that has grown an excessive number of allocation groups
    # can be very slow.
    eval $(xfs_info "${root_part}" | grep -o 'agcount=[0-9]*')
    # This is roughly ~700GiB currently (based on initial ag sizing at build time)
    # which ensures we grow only on "large" root filesystems.
    # Specifically for e.g. OpenShift, this ensures we don't reprovision on default
    # worker node root filesystems.
    local threshold
    threshold=400
    if [ "$agcount" -lt "${threshold}" ]; then
        echo "autosave-xfs: ${root_part} agcount=$agcount is lower than threshold=${threshold}" >&2
        echo 0
        return
    else
        echo "autosave-xfs: ${root_part} agcount=$agcount meets threshold=${threshold}" >&2
        echo 1
    fi
}

ensure_zram_dev() {
    if test -d "${saved_data}"; then
        return 0
    fi
    mem_available=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
    # Just error out early if we don't even have 1G to work with. This
    # commonly happens if you `cosa run` but forget to add `--memory`. That
    # way you get a nicer error instead of the spew of EIO errors from `cp`.
    # The amount we need is really dependent on a bunch of factors, but just
    # ballpark it at 3G.
    if [ "${mem_available}" -lt $((1*1024*1024)) ] && [ "${wipes_root}" != 0 ]; then
        echo "Root reprovisioning requires at least 3G of RAM" >&2
        exit 1
    fi
    modprobe zram num_devices=0
    read dev < /sys/class/zram-control/hot_add
    # disksize is set arbitrarily large, as zram is capped by mem_limit
    echo 10G > /sys/block/zram"${dev}"/disksize
    # Limit zram to 90% of available RAM: we want to be greedy since the
    # boot breaks anyway, but we still want to leave room for everything
    # else so it hits ENOSPC and doesn't invoke the OOM killer
    echo $(( mem_available * 90 / 100 ))K > /sys/block/zram"${dev}"/mem_limit
    mkfs.xfs -q /dev/zram"${dev}"
    mkdir "${saved_data}"
    mount -t xfs /dev/zram"${dev}" "${saved_data}"
    # save the zram device number created for when called to cleanup
    echo "${dev}" > "${zram_dev}"
}

print_zram_mm_stat() {
    echo "zram usage:"
    read dev < "${zram_dev}"
    cat /sys/block/zram"${dev}"/mm_stat
}

# In Secure Execution case user is not allowed to modify partition table
check_and_set_secex_config() {
    if [[ -f /run/coreos/secure-execution ]]; then
        local wr=$(jq "$(query_fslabel root) | length" "${ignition_cfg}")
        local wb=$(jq "$(query_fslabel boot) | length" "${ignition_cfg}")
        if [ "${wr}${wb}" != "00" ]; then
            echo "Modifying bootfs and rootfs is not supported in Secure Execution mode"
            exit 1
        fi
        # Cached config isn't merged, so reset it and recheck again, just to make sure
        ignition_cfg=/usr/lib/ignition/base.d/01-secex.ign
    fi
}

# We could have done this during 'detect' below, but other cases also request
# info from config, so just check cached one and reset to secex.ign now
check_and_set_secex_config

case "${1:-}" in
    detect)
        # Mounts are not in a private namespace so we can mount ${saved_data}
        wipes_root=$(jq "$(query_fslabel root) | length" "${ignition_cfg}")
        wipes_boot=$(jq "$(query_fslabel boot) | length" "${ignition_cfg}")
        creates_esp=$(jq "$(query_parttype ${esp_typeguid}) | length" "${ignition_cfg}")
        creates_bios=$(jq "$(query_parttype ${bios_typeguid}) | length" "${ignition_cfg}")
        creates_prep=$(jq "$(query_parttype ${prep_typeguid}) | length" "${ignition_cfg}")
        if [ "${wipes_root}${wipes_boot}${creates_esp}${creates_bios}${creates_prep}" = "00000" ]; then
            exit 0
        fi
        echo "Detected partition replacement in fetched Ignition config: /run/ignition.json"
        # verify all ESP, BIOS, and PReP partitions have non-null unique labels
        unique_esp=$(jq -r "$(query_parttype ${esp_typeguid}) | [.[].label | values] | unique | length" "${ignition_cfg}")
        unique_bios=$(jq -r "$(query_parttype ${bios_typeguid}) | [.[].label | values] | unique | length" "${ignition_cfg}")
        unique_prep=$(jq -r "$(query_parttype ${prep_typeguid}) | [.[].label | values] | unique | length" "${ignition_cfg}")
        if [ "${creates_esp}" != "${unique_esp}" -o "${creates_bios}" != "${unique_bios}" -o "${creates_prep}" != "${unique_prep}" ]; then
            echo "Found duplicate or missing ESP, BIOS-BOOT, or PReP labels in config" >&2
            exit 1
        fi

        ensure_zram_dev

        if [ "${wipes_root}" != "0" ]; then
            mkdir "${saved_root}"
        fi
        if [ "${wipes_boot}" != "0" ]; then
            mkdir "${saved_boot}"
        fi
        if [ "${creates_esp}" != "0" ]; then
            mkdir "${saved_esp}"
        fi
        if [ "${creates_bios}" != "0" ]; then
            mkdir "${saved_bios}"
        fi
        if [ "${creates_prep}" != "0" ]; then
            mkdir "${saved_prep}"
        fi
        ;;
    autosave-xfs)
        should_autosave=$(should_autosave_rootfs)
        if [ "${should_autosave}" = "1" ]; then
            wipes_root=1
            ensure_zram_dev
            # in the in-place reprovisioning case, the rootfs was already saved
            if [ ! -d "${saved_root}" ]; then
                mkdir "${saved_root}"
                echo "Moving rootfs to RAM..."
                mount_and_save_filesystem_by_label root "${saved_root}"
                print_zram_mm_stat
            fi
            mkfs.xfs "${root_part}" -L root -f
            # for tests
            touch /run/ignition-ostree-autosaved-xfs.stamp
        fi
        ;;
    save)
        # Mounts happen in a private mount namespace since we're not "offically" mounting
        if [ -d "${saved_root}" ]; then
            echo "Moving rootfs to RAM..."
            mount_and_save_filesystem_by_label root "${saved_root}"
            # also store the state of the partition
            lsblk "${root_part}" --nodeps --pairs -b --paths -o NAME,TYPE,SIZE > "${partstate_root}"
        fi
        if [ -d "${saved_boot}" ]; then
            echo "Moving bootfs to RAM..."
            mount_and_save_filesystem_by_label boot "${saved_boot}"
        fi
        if [ -d "${saved_esp}" ]; then
            echo "Moving EFI System Partition to RAM..."
            mount_verbose "${esp_part}" /sysroot/boot/efi
            cp -aT /sysroot/boot/efi "${saved_esp}"
        fi
        if [ -d "${saved_bios}" ]; then
            echo "Moving BIOS Boot partition and boot sector to RAM..."
            # save partition
            cat "${bios_part}" > "${saved_bios}/partition"
            # save boot sector
            bios_disk=$(lsblk --noheadings --output PKNAME --paths "${bios_part}")
            dd if="${bios_disk}" of="${saved_bios}/boot-sector" bs="${boot_sector_size}" count=1 status=none
            # store partition start offset so we can check it later
            get_partition_offset "${bios_part}" > "${saved_bios}/start"
        fi
        if [ -d "${saved_prep}" ]; then
            echo "Moving PReP partition to RAM..."
            cat "${prep_part}" > "${saved_prep}/partition"
        fi
        print_zram_mm_stat
        ;;
    restore)
        # Mounts happen in a private mount namespace since we're not "offically" mounting
        if [ -d "${saved_root}" ]; then
            echo "Restoring rootfs from RAM..."
            mount_and_restore_filesystem_by_label root /sysroot "${saved_root}"
            chcon -v system_u:object_r:root_t:s0 /sysroot  # the root of the fs itself
            echo "Enabling fs-verity again..."
            find /sysroot/composefs/objects -type f -exec fsverity enable {} \;
            # chattr +i $(ls -d /sysroot/ostree/deploy/*/deploy/*/)
        fi
        if [ -d "${saved_boot}" ]; then
            echo "Restoring bootfs from RAM..."
            mount_and_restore_filesystem_by_label boot /sysroot/boot "${saved_boot}"
            chcon -v system_u:object_r:boot_t:s0 /sysroot/boot # the root of the fs itself
            # chcon -v --reference "${saved_boot}" /sysroot/boot  # the root of the fs itself
        fi
        if [ -d "${saved_esp}" ]; then
            echo "Restoring EFI System Partition from RAM..."
            get_partlabels_for_parttype "${esp_typeguid}" | while read label; do
                # Don't use mount_and_restore_filesystem_by_label because:
                # 1. We're mounting by partlabel, not FS label
                # 2. We need to copy the contents to each partition, not move
                #    them once
                # 3. We don't need the by-label symlink to be correct and
                #    nothing later in boot will be mounting the filesystem
                mountpoint="/mnt/esp-${label}"
                mount_verbose "/dev/disk/by-partlabel/${label}" "${mountpoint}" rw
                find "${saved_esp}" -mindepth 1 -maxdepth 1 -exec cp -at "${mountpoint}" {} +
            done
        fi
        if [ -d "${saved_bios}" ]; then
            echo "Restoring BIOS Boot partition and boot sector from RAM..."
            expected_start=$(cat "${saved_bios}/start")
            get_partlabels_for_parttype "${bios_typeguid}" | while read label; do
                cur_part="/dev/disk/by-partlabel/${label}"
                # boot sector hardcodes the partition start; ensure it matches
                cur_start=$(get_partition_offset "${cur_part}")
                if [ "${cur_start}" != "${expected_start}" ]; then
                    echo "Partition ${cur_part} starts at ${cur_start}; expected ${expected_start}" >&2
                    exit 1
                fi
                # copy partition contents
                cat "${saved_bios}/partition" > "${cur_part}"
                # copy boot sector
                cur_disk=$(lsblk --noheadings --output PKNAME --paths "${cur_part}")
                cat "${saved_bios}/boot-sector" > "${cur_disk}"
            done
        fi
        if [ -d "${saved_prep}" ]; then
            echo "Restoring PReP partition from RAM..."
            get_partlabels_for_parttype "${prep_typeguid}" | while read label; do
                cat "${saved_prep}/partition" > "/dev/disk/by-partlabel/${label}"
            done
        fi
        ;;
    cleanup)
        # Mounts are not in a private namespace so we can unmount ${saved_data}
        if [ -d "${saved_data}" ]; then
            read dev < "${zram_dev}"
            umount "${saved_data}"
            rm -rf "${saved_data}" "${partstate_root}"
            # After unmounting, make sure zram device state is stable before we remove it.
            # See https://github.com/openshift/os/issues/1149
            # Should remove when https://bugzilla.redhat.com/show_bug.cgi?id=2172058 is fixed.
            # Seems the previous workaround https://github.com/coreos/fedora-coreos-config/pull/2226
            # can not completely resolve the race issue, try in loop with a small sleep for el9 + !x86_64.
            if [ $(uname -m) != x86_64 ] && is_rhcos9; then
                for x in {0..10}; do
                    if ! echo "${dev}" > /sys/class/zram-control/hot_remove 2>/dev/null; then
                        sleep 0.1
                    else
                        dev=
                        break
                    fi
                done
                # try it one last time and let it possibly fail
                if [ -n "${dev}" ]; then
                    echo "${dev}" > /sys/class/zram-control/hot_remove
                fi
            else
                echo "${dev}" > /sys/class/zram-control/hot_remove
            fi
        fi
        ;;
    *)
        echo "Unsupported operation: ${1:-}" 1>&2; exit 1
        ;;
esac
