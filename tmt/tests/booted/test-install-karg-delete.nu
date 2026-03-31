# number: 40
# tmt:
#   summary: Test bootc install --karg-delete
#   duration: 30m
# extra:
#   fixme_skip_if_composefs: true
#
use std assert
use tap.nu
#
# Use an OS-matched target image to avoid version mismatches
let target_image = (tap get_target_image)

# setup filesystem
mkdir /var/mnt
truncate -s 10G disk.img
mkfs.ext4 disk.img
mount -o loop disk.img /var/mnt

# Mask off the bootupd state to reproduce https://github.com/bootc-dev/bootc/issues/1778
# Also it turns out that installation outside of containers dies due to `error: Multiple commit objects found`
# so we mask off /sysroot/ostree
# And using systemd-run here breaks our install_t so we disable SELinux enforcement
setenforce 0

mkdir /etc/bootc/install
{ install: { kargs: ["foo=bar"] } } | to toml | save /etc/bootc/install/99-test.toml

tap run_install $"bootc install to-filesystem --disable-selinux --bootloader none --source-imgref ($target_image) --karg-delete localtestkarg --karg-delete foo /var/mnt"


# Verify the karg is gone from the bootloader entries
let entries = (glob /var/mnt/boot/loader/entries/*.conf
    | each { open $in | lines }
    | flatten)

let localtestkarg_found = ($entries | find "localtestkarg" | is-empty)
assert $localtestkarg_found "Found localtestkarg in bootloader entries, but it should have been deleted"

let foo_found = ($entries | find "foo" | is-empty)
assert $foo_found "Found foo in bootloader entries, but it should have been deleted"

# Clean up
umount /var/mnt
rm -rf disk.img

tap ok
