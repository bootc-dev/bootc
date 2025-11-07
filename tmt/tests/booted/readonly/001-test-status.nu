use std assert
use tap.nu

tap begin "verify bootc status output formats"

let st = bootc status --json | from json
assert equal $st.apiVersion org.containers.bootc/v1

let st = bootc status --json --format-version=0 | from json
assert equal $st.apiVersion org.containers.bootc/v1

let st = bootc status --format=yaml | from yaml
assert equal $st.apiVersion org.containers.bootc/v1
# Detect composefs by checking if composefs field is present
let is_composefs = ($st.status.booted.composefs? != null)
if not $is_composefs {
    assert ($st.status.booted.image.timestamp != null)
} # else { TODO composefs: timestamp is not populated with composefs }
let ostree = $st.status.booted.ostree
if $ostree != null {
    assert ($ostree.stateroot != null)
}

let st = bootc status --json --booted | from json
assert equal $st.apiVersion org.containers.bootc/v1
# Detect composefs by checking if composefs field is present
let is_composefs = ($st.status.booted.composefs? != null)
if not $is_composefs {
    assert ($st.status.booted.image.timestamp != null)
} # else { TODO composefs: timestamp is not populated with composefs }
assert (($st.status | get rollback | default null) == null)
assert (($st.status | get staged | default null) == null)

tap ok
