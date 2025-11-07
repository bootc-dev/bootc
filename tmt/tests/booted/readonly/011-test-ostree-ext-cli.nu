# Verify our wrapped "bootc internals ostree-container" calling into
# the legacy ostree-ext CLI.
use std assert
use tap.nu

tap begin "verify bootc wrapping ostree-ext"

# Parse the status and get the booted image
let st = bootc status --json | from json
# Detect composefs by checking if composefs field is present
let is_composefs = ($st.status.booted.composefs? != null)
if $is_composefs {
    print "# TODO composefs: skipping test - ostree-container commands don't work with composefs"
} else {
    let booted = $st.status.booted.image
    # Then verify we can extract its metadata via the ostree-container code.
    let metadata = bootc internals ostree-container image metadata --repo=/ostree/repo $"($booted.image.transport):($booted.image.image)" | from json
    assert equal $metadata.mediaType "application/vnd.oci.image.manifest.v1+json"
}

tap ok
