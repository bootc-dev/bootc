# number: 43
# tmt:
#   summary: Error on bootc switch to image with identical fs-verity digest
#   duration: 10m
#
# Verify that `bootc switch` errors out when the target image produces the
# same composefs fs-verity digest as an existing deployment.  The simplest
# way to produce two registry images with identical content is to tag the
# same local image under a second name.
use std assert
use tap.nu

if not (tap is_composefs) {
    exit 0
}

tap begin "bootc switch to same-digest image must error"

# Copy the booted image into podman storage so we can retag it.
bootc image copy-to-storage

# Tag the same image under a second name — identical bits, so the composefs
# EROFS digest will be the same as the currently booted deployment.
podman tag localhost/bootc localhost/bootc-same-digest

# bootc switch should refuse: the target produces the same fs-verity digest
# as the booted deployment.
let result = do { bootc switch --transport containers-storage localhost/bootc-same-digest } | complete
assert ($result.exit_code != 0) "Expected bootc switch to fail for same-digest image"

tap ok
