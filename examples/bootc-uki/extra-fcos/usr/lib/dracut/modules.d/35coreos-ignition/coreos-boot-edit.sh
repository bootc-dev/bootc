#!/bin/bash
set -euo pipefail

# For a description of how this is used, see `coreos-boot-edit.service`.

IFS=" " read -r -a cmdline <<< "$(</proc/cmdline)"
karg() {
    local name="$1" value="${2:-}"
    for arg in "${cmdline[@]}"; do
        if [[ "${arg%%=*}" == "${name}" ]]; then
            value="${arg#*=}"
        fi
    done
    echo "${value}"
}

# Mount /boot. Note that we mount /boot but we don't unmount it because we
# are run in a systemd unit with MountFlags=slave so it is unmounted for us.
bootmnt=/sysroot/boot
bootdev=/dev/disk/by-label/boot
mount -o rw ${bootdev} ${bootmnt}

# Clean up firstboot networking config files if the user copied them into the
# installed system (most likely by using `coreos-installer install --copy-network`).
firstboot_network_dir_basename="coreos-firstboot-network"
initramfs_firstboot_network_dir="${bootmnt}/${firstboot_network_dir_basename}"
rm -vrf ${initramfs_firstboot_network_dir}

# If root is specified, assume rootmap is already configured. Otherwise,
# append rootmap kargs to the BLS configs.
root=$(karg root)
if [ -z "${root}" ]; then
    rdcore rootmap /sysroot --boot-mount ${bootmnt}
    echo "Prepared rootmap"
fi

# This does a few things:
# 1. it puts the boot UUID in /run/coreos/bootfs_uuid which is used by the real
#    root for mounting the bootfs in this boot
# 2. it adds a boot=UUID= karg which is used by the real root for mounting the
#    bootfs in subsequent boots
# 3. it create a .root_uuid stamp file on the bootfs or fails if one exists
# 4. it adds GRUB bootuuid.cfg dropins so that GRUB selects the boot filesystem
#    by UUID
rdcore bind-boot /sysroot ${bootmnt}

# relabel files rdcore created; ideally in the future rdcore does this itself
coreos-relabel /boot/.root_uuid
if [ -e /sysroot/boot/grub2/bootuuid.cfg ]; then
    coreos-relabel /boot/grub2/bootuuid.cfg
fi
