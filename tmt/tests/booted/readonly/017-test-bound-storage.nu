# Verify that we have host container storage with bcvk
use std assert
use tap.nu
use ../bootc_testlib.nu

if not (bootc_testlib have_hostexports) {
    print "No host exports, skipping"
    exit 0
}

bootc status
let st = bootc status --json | from json
let is_composefs = (tap is_composefs)
if $is_composefs {
    # TODO we don't have imageDigest yet in status
    exit 0
}

# If we have --bind-storage-ro, then verify it 
if ($env.BOOTC_upgrade_image? != null) {
    let booted = $st.status.booted
    let imgref = $booted.image.image.image
    let digest = $booted.image.imageDigest
    let imgref_untagged = $imgref | split row ':' | first
    let digested_imgref = $"($imgref_untagged)@($digest)"
    systemd-run -dqP /bin/env
    podman inspect $digested_imgref
}

tap ok
