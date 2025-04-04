# Verify our wrapped "bootc internals ostree-container" calling into
# the legacy ostree-ext CLI.
use std assert
use tap.nu

tap begin "verify bootc wrapping ostree-ext"

# Parse the status and get the booted image
let st = bootc status --json | from json
let booted = $st.status.booted.image
# Then verify we can extract its metadata via the ostree-container code.
let metadata = bootc internals ostree-container image metadata --repo=/ostree/repo $"($booted.image.transport):($booted.image.image)" | from json
assert equal $metadata.mediaType "application/vnd.oci.image.manifest.v1+json"
