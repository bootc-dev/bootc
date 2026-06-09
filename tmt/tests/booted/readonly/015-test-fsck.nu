use std assert
use tap.nu

tap begin "Run fsck"

let is_composefs = (tap is_composefs)

if $is_composefs {
    print "# TODO composefs: skipping low-level fsck - requires ostree-booted host"
} else {
    # Run the full fsck suite (low-level checks + image metadata).
    bootc internals fsck
}

# Image metadata check runs on all backends — it's a no-op when unified
# storage is not enabled, so this is always safe to run.
bootc internals fsck images

tap ok
