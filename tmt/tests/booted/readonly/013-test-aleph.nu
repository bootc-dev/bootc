use std assert
use tap.nu

tap begin "verify bootc aleph file contents"

let aleph_path = "/sysroot/.bootc-aleph.json"
let aleph = open $aleph_path

# Verify required fields exist and are non-empty
assert ($aleph.kernel | is-not-empty) "kernel field should be non-empty"
assert ($aleph.selinux | is-not-empty) "selinux field should be non-empty"

# Cross-check aleph fields against the booted image from bootc status
let st = bootc status --json | from json
let booted = $st.status.booted

# Verify the digest field matches the booted image digest
assert ($aleph.digest | is-not-empty) "digest field should be non-empty"
let booted_digest = $booted.image.imageDigest
assert equal $aleph.digest $booted_digest "digest should match the booted image digest"

# Verify the target-image field matches the booted image reference
let target_image = $aleph | get "target-image"
assert ($target_image | is-not-empty) "target-image field should be non-empty"
let booted_imgref = $booted.image.image.image
assert equal $target_image $booted_imgref "target-image should match the booted image reference"

# The image field is optional (skipped when source is a /tmp path),
# but if present it should be non-empty.
let image = $aleph.image? | default null
if $image != null {
    assert ($image | is-not-empty) "image field, if present, should be non-empty"
    let booted_imgref = $booted.image.image.image
    # The booted imgref contain the full digested pullspec
    # so we only check the beginning of the string
    assert ($image | str starts-with $booted_imgref) "image should match the booted image reference"

}

# The labels field may be absent if empty (skip_serializing_if), but if
# present it should be a record and contain the bootc marker label.
let labels = $aleph.labels? | default null
if $labels != null {
    # Verify labels is a record (table-like key-value structure)
    assert (($labels | describe) =~ "record") "labels should be a record"
    # A bootc image should always carry the containers.bootc label
    let bootc_label = $labels | get "containers.bootc"
    assert ($bootc_label | is-not-empty) "containers.bootc label should be present"
}

tap ok
