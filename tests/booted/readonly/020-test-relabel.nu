use std assert
use tap.nu

tap begin "Relabel"

let td = mktemp -d -p /var/tmp
cd $td

mkdir etc/ssh
touch etc/shadow etc/ssh/ssh_config
bootc internals relabel --as-path /etc $"(pwd)/etc"

def assert_labels_equal [p] {
    let base = (getfattr --only-values -n security.selinux $"/($p)")
    let target = (getfattr --only-values -n security.selinux $p)
    assert equal $base $target
}

for path in ["etc", "etc/shadow", "etc/ssh/ssh_config"] {
    assert_labels_equal $path
}

cd /
rm -rf $td

tap ok
