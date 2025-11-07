use std assert
use tap.nu

tap begin "initramfs"

if (not ("/usr/lib/bootc/initramfs-setup" | path exists)) {
    print "No initramfs support"
} else if (not (open /proc/cmdline | str contains composefs)) {
    print "No composefs in cmdline"
} else {
    # journalctl --grep exits with 1 if no entries found, so we need to handle that
    let result = (do { journalctl -b -t bootc-root-setup.service --grep=OK } | complete)
    if $result.exit_code == 0 {
        print $result.stdout
    } else {
        print "# TODO composefs: No bootc-root-setup.service journal entries found"
    }
}

tap ok
