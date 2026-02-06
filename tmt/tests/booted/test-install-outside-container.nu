# number: 23
# tmt:
#   summary: Execute tests for installing outside of a container
#   duration: 30m
#
use std assert
use tap.nu

# In this test we install a generic image mainly because it keeps
# this test in theory independent of starting from a bootc host,
# but also because it's useful to test "skew" between the bootc binary
# doing the install and the target image.
let target_image = "docker://quay.io/centos-bootc/centos-bootc:stream9"

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

let st = bootc status --json | from json
let bootloader = ($st.status.booted.composefs.bootloader | str downcase)

let install_cmd = if (tap is_composefs) {
    $"bootc install to-disk --disable-selinux --via-loopback --composefs-backend --bootloader=($bootloader) --filesystem ext4 --source-imgref ($target_image) ./disk.img"
} else {
    $"bootc install to-disk --disable-selinux --via-loopback --filesystem xfs --source-imgref ($target_image) ./disk.img"
}

systemd-run -p MountFlags=slave -qdPG -- /bin/sh -c $"
set -xeuo pipefail
bootc usr-overlay
if test -d /sysroot/ostree; then mount --bind /usr/share/empty /sysroot/ostree; fi
# Note we do keep the other bootupd state
rm -vrf /usr/lib/bootupd/updates
# Another bootc install bug, we should not look at this in outside-of-container flows
rm -vrf /usr/lib/bootc/bound-images.d
($install_cmd)
"

tap ok
