use std assert
use tap.nu

tap begin "verify there's not an empty /etc/resolv.conf in the image"

let st = bootc status --json | from json

# Detect composefs by checking if composefs field is present
let is_composefs = ($st.status.booted.composefs? != null)
if $is_composefs {
    print "# TODO composefs: skipping test - ostree commands don't work with composefs"
} else {
    let booted_ostree = $st.status.booted.ostree.checksum;

    # ostree ls should probably have --json and a clean way to not error on ENOENT
    let resolvconf = ostree ls $booted_ostree /usr/etc | split row (char newline) | find resolv.conf
    if ($resolvconf | length) > 0 {
        let parts = $resolvconf | first | split row -r '\s+'
        let ty = $parts | first | split chars | first
        # If resolv.conf exists in the image, currently require it in our
        # test suite to be a symlink (which is hopefully to the systemd/stub-resolv.conf)
        assert equal $ty 'l'
        print "resolv.conf is a symlink"
    } else {
        print "No resolv.conf found in commit"
    }
}

tap ok
