use std assert
use tap.nu

tap begin "verify bootc-owned container storage"

# Detect composefs by checking if composefs field is present
let st = bootc status --json | from json
let is_composefs = ($st.status.booted.composefs? != null)

if $is_composefs {
    print "# TODO composefs: skipping test - /usr/lib/bootc/storage doesn't exist with composefs"
} else {
    # Just verifying that the additional store works
    podman --storage-opt=additionalimagestore=/usr/lib/bootc/storage images

    # And verify this works
    bootc image cmd list -q o>/dev/null
}

tap ok
