# number: 23
# tmt:
#   summary: Execute tests for installing outside of a container
#   duration: 30m
#
use std assert
use tap.nu

# Use the locally-built image which has updated bootupd with compatible
# EFI update metadata, matching the pattern used by test-32/37/38.
bootc image copy-to-storage
let target_image = "containers-storage:localhost/bootc"

# setup filesystem
mkdir /var/mnt
truncate -s 10G disk.img
mkfs.ext4 disk.img
mount -o loop disk.img /var/mnt

# attempt to install to filesystem without specifying a source-imgref
let result = bootc install to-filesystem /var/mnt e>| find "--source-imgref must be defined"
assert not equal $result null
umount /var/mnt

# Mask off the bootupd state to reproduce https://github.com/bootc-dev/bootc/issues/1778
# Also it turns out that installation outside of containers dies due to `error: Multiple commit objects found`
# so we mask off /sysroot/ostree
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

tap ok
