use std assert
use tap.nu

tap begin "composefs repo always present"

let st = bootc status --json | from json
let is_composefs = (tap is_composefs)

# The composefs repository must always exist on a booted bootc system,
# regardless of whether the system was booted via composefs or classic ostree.
# This is a regression guard for the composefs-first fetch pipeline.

print "# Checking /sysroot/composefs directory structure"

assert ("/sysroot/composefs" | path exists) "/sysroot/composefs must exist"
assert (("/sysroot/composefs" | path type) == "dir") "/sysroot/composefs must be a directory"

assert ("/sysroot/composefs/objects" | path exists) "/sysroot/composefs/objects must exist"
assert (("/sysroot/composefs/objects" | path type) == "dir") "/sysroot/composefs/objects must be a directory"

print $"# /sysroot/composefs exists with objects directory \(is_composefs: ($is_composefs)\)"

if $is_composefs {
    # On a composefs-native boot, the streams/refs tree must also be populated.
    print "# Checking composefs streams/refs structure (composefs-native boot)"

    assert ("/sysroot/composefs/streams" | path exists) "/sysroot/composefs/streams must exist on composefs boot"
    assert (("/sysroot/composefs/streams" | path type) == "dir") "/sysroot/composefs/streams must be a directory"

    let oci_refs = (ls /sysroot/composefs/streams/refs/oci/ | where type == "symlink")
    let n_refs = ($oci_refs | length)
    print $"# Found ($n_refs) OCI image ref symlinks under /sysroot/composefs/streams/refs/oci/"
    assert ($n_refs > 0) "At least one OCI image ref symlink must exist under /sysroot/composefs/streams/refs/oci/ on a composefs-native booted system"
}

tap ok
