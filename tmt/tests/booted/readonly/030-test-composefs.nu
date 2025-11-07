use std assert
use tap.nu

tap begin "composefs integration smoke test"

# Detect composefs by checking if composefs field is present
let st = bootc status --json | from json
let is_composefs = ($st.status.booted.composefs? != null)
let expecting_composefs = ($env.BOOTC_variant? | default "" | find "composefs") != null
if $expecting_composefs {
    assert $is_composefs
}

if $is_composefs {
    # When already on composefs, we can only test read-only operations
    print "# TODO composefs: skipping pull test - cfs oci pull requires write access to sysroot"
    bootc internals cfs --help
} else {
    # When not on composefs, run the full test including initialization
    bootc internals test-composefs
    bootc internals cfs --help
    bootc internals cfs oci pull docker://busybox busybox
    test -L /sysroot/composefs/streams/refs/busybox
}

tap ok
