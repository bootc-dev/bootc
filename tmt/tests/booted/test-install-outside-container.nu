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

tap ok
