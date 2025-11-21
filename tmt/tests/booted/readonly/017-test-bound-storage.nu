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
let is_composefs = ($st.status.booted.composefs? != null)
if is_composefs {
    # TODO we don't have imageDigest yet in status
    exit 0
}

let booted = $st.status.booted
let imgref = $booted.image.image.image
let digest = $booted.image.imageDigest
let imgref_untagged = $imgref | split row ':' | first
let digested_imgref = $"($imgref_untagged)@($digest)"
systemd-run -dqP /bin/env
podman inspect $digested_imgref

tap ok