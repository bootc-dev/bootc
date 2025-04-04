use std assert
use tap.nu

# setup filesystem
mkdir /var/mnt
truncate -s 100M disk.img
mkfs.ext4 disk.img
mount -o loop disk.img /var/mnt

# attempt to install to filesystem without specifying a source-imgref
let result = bootc install to-filesystem /var/mnt e>| ansi strip
assert equal $result "ERROR Installing to filesystem: Either --source-imgref must be defined or this command must be executed inside a podman container."

tap ok
