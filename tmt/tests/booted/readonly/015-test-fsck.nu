use std assert
use tap.nu

tap begin "Run fsck"

# Detect composefs by checking if composefs field is present
let st = bootc status --json | from json
let is_composefs = (tap is_composefs)

if $is_composefs {
    print "# TODO composefs: skipping test - fsck requires ostree-booted host"
} else {
    # That's it, just ensure we've run a fsck on our basic install.
    bootc internals fsck
}

tap ok
