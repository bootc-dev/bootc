#!/bin/bash
set -euo pipefail

# This script is run by ignition-ostree-growfs.service. It grows the root
# partition, unless it determines that either the rootfs was moved or the
# partition was already resized (e.g. via Ignition).

# In the IBM Secure Execution case we use Ignition to grow and reencrypt rootfs
# see overlay.d/05core/usr/lib/dracut/modules.d/35coreos-ignition/coreos-diskful-generator
if [[ -f /run/coreos/secure-execution ]]; then
    exit 0
fi

# This is copied from ignition-ostree-transposefs.sh.
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

# This is also similar to bits from transposefs.sh.
ignition_cfg=/run/ignition.json
expected_dev=$(jq -r '.storage?.filesystems? // [] | map(select(.label == "root")) | .[0].device // ""' "${ignition_cfg}")
if [ -n "${expected_dev}" ]; then
    udev_trigger_on_label_mismatch root "${expected_dev}"
fi

# If root reprovisioning was triggered, this file contains state of the root
# partition *before* ignition-disks.
saved_partstate=/run/ignition-ostree-rootfs-partstate.sh

# We run before the rootfs is mounted at /sysroot, but we still need to mount it
# (in a private namespace) since XFS and Btrfs can only do resizing online (EXT4
# can do either).
path=/sysroot
src=/dev/disk/by-label/root
mount "${src}" "${path}"

if [ ! -f "${saved_partstate}" ]; then
    partition=$(realpath /dev/disk/by-label/root)
else
    # The rootfs was reprovisioned. Our rule in this case is: we only grow if
    # the partition backing the rootfs is the same and its size didn't change
    # (IOW, it was an in-place reprovisioning; e.g. LUKS or xfs -> btrfs).
    source "${saved_partstate}"
    if [ "${TYPE}" != "part" ]; then
        # this really should never happen; but play nice
        echo "$0: original rootfs blockdev not of type 'part'; not auto-growing"
        exit 0
    fi
    partition=$(realpath "${NAME}")
    if [ "${SIZE}" != "$(lsblk --nodeps -bno SIZE "${partition}")" ]; then
        echo "$0: original root partition changed size; not auto-growing"
        exit 0
    fi
    if ! lsblk -no MOUNTPOINT "${partition}" | grep -q '^/sysroot$'; then
        echo "$0: original root partition no longer backing rootfs; not auto-growing"
        exit 0
    fi
fi

# Go through each blockdev in the hierarchy and verify we know how to grow them
lsblk -no TYPE "${partition}" | while read dev; do
    case "${dev}" in
        part|crypt) ;;
        *) echo "error: Unsupported blockdev type ${dev}" 1>&2; exit 1 ;;
    esac
done

# Get the filesystem type before extending the partition.  This matters
# because the partition, once extended, might include leftover superblocks
# from the previous contents of the disk (notably ZFS), causing blkid to
# refuse to return any filesystem type at all.
eval $(blkid -p -o export "${src}")
ROOTFS_TYPE=${TYPE:-}
case "${ROOTFS_TYPE}" in
    xfs|ext4|btrfs) ;;
    *) echo "error: Unsupported filesystem for ${path}: '${ROOTFS_TYPE}'" 1>&2; exit 1 ;;
esac

# Now, go through the hierarchy, growing everything. Note we go one device at a
# time using --nodeps, because ordering is buggy in el8:
# https://bugzilla.redhat.com/show_bug.cgi?id=1940607
current_blkdev=${partition}
while true; do
    eval "$(lsblk --paths --nodeps --pairs -o NAME,TYPE,PKNAME "${current_blkdev}")"
    MAJMIN=$(echo $(lsblk -dno MAJ:MIN "${NAME}"))
    case "${TYPE}" in
        part)
            eval $(udevadm info --query property --export "${current_blkdev}" | grep ^DM_ || :)
            if [ -n "${DM_MPATH:-}" ]; then
                PKNAME=/dev/mapper/${DM_MPATH}
                partnum=${DM_PART}
                # Since growpart does not understand device mapper, we have to use sfdisk.
                echo ", +" | sfdisk --no-reread --no-tell-kernel --force -N "${partnum}" "${PKNAME}"
                udevadm settle || : # Wait for udev-triggered kpartx to update mappings
            elif [[ "${PKNAME}" = /dev/dasd* ]]; then
                echo "partition is on DASD device; skipping growpart"
            else
                partnum=$(cat "/sys/dev/block/${MAJMIN}/partition")
                # XXX: ideally this'd be idempotent and we wouldn't `|| :`
                growpart "${PKNAME}" "${partnum}" || :
            fi
            # If this is a 512e disk, then ensure the partition end is 4K
            # aligned to be compatible with LUKS. If it's a 4Kn disk, `size`
            # necessarily must be 4K aligned (note the sysfs value is always
            # reported in 512b sizes). We should be able to drop this once
            # https://github.com/util-linux/util-linux/issues/2140 is fixed.
            size=$(cat "/sys/dev/block/${MAJMIN}/size")
            phy_sec=$(blockdev --getpbsz "${PKNAME}")
            if [ "$((size % 8))" != 0 ] && [ "${phy_sec:-}" = 4096 ]; then
                size=$(((size >> 3) << 3))  # round down to nearest 4K boundary
                echo ", ${size}" | sfdisk --no-reread --force -N "${partnum}" "${PKNAME}"
                partx --update --nr "${partnum}" "${PKNAME}"
            fi
            ;;
        crypt)
            # lsblk doesn't print PKNAME of crypt devices with --nodeps
            PKNAME=/dev/$(ls "/sys/dev/block/${MAJMIN}/slaves")
            LUKS_DUMP=$(cryptsetup luksDump "$PKNAME" --dump-json-metadata)
            if jq -e '[.tokens[].type] | index("clevis")' <<< "$LUKS_DUMP"; then
                # XXX: yuck... we need to expose this sanely in clevis
                (. /usr/bin/clevis-luks-common-functions
                 eval $(udevadm info --query=property --export "${NAME}")
                 clevis_luks_unlock_device "${PKNAME}" | cryptsetup resize -d- "${DM_NAME}"
                )
            elif jq -e '.segments["0"].encryption | startswith("paes")' <<< "$LUKS_DUMP"; then
                # CEX LUKS volume: https://github.com/coreos/ignition/issues/1693
                cryptsetup resize root --key-file /etc/luks/cex.key
            else
                echo "$LUKS_DUMP"
                echo "error: unknown LUKS device"
                exit 1
            fi
            ;;
        # already checked
        *) echo "unreachable" 1>&2; exit 1 ;;
    esac
    holders="/sys/dev/block/${MAJMIN}/holders"
    [ -d "${holders}" ] || break
    nholders="$(ls "${holders}" | wc -l)"
    if [ "${nholders}" -eq 0 ]; then
        break
    elif [ "${nholders}" -gt 1 ]; then
        # this shouldn't happen since we've checked the partition types already
        echo "error: Unsupported block device with multiple children: ${NAME}" 1>&2
        exit 1
    fi
    current_blkdev=/dev/$(ls "${holders}")
done

# Wipe any filesystem signatures from the extended partition that don't
# correspond to the FS type we detected earlier.
wipefs -af -t "no${ROOTFS_TYPE}" "${src}"

# TODO: Add XFS to https://github.com/systemd/systemd/blob/master/src/partition/growfs.c
# and use it instead.
case "${ROOTFS_TYPE}" in
    xfs) xfs_growfs "${path}" ;;
    ext4) resize2fs "${src}" ;;
    btrfs) btrfs filesystem resize max ${path} ;;
esac

# The ignition-ostree-transposefs-xfsauto.service unit needs to know if we
# actually run. This is also useful for tests.
touch /run/ignition-ostree-growfs.stamp
