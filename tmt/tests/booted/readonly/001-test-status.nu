use std assert
use tap.nu

tap begin "verify bootc status output formats"

# Verify /sysroot is not writable initially (read-only operations should not make it writable)
let is_writable = (do -i { /bin/test -w /sysroot } | complete | get exit_code) == 0
assert (not $is_writable) "/sysroot should not be writable initially"

# Double-check with findmnt
let mnt = (findmnt /sysroot -J | from json)
let opts = ($mnt.filesystems.0.options | split row ",")
assert ($opts | any { |o| $o == "ro" }) "/sysroot should be mounted read-only"

let st = bootc status --json | from json
# Detect composefs by checking if composefs field is present
let is_composefs = (tap is_composefs)

assert equal $st.apiVersion org.containers.bootc/v1

let st = bootc status --json --format-version=0 | from json
assert equal $st.apiVersion org.containers.bootc/v1

let st = bootc status --format=yaml | from yaml
assert equal $st.apiVersion org.containers.bootc/v1
if not $is_composefs {
    assert ($st.status.booted.image.timestamp != null)
} # else { TODO composefs: timestamp is not populated with composefs }
let ostree = $st.status.booted.ostree
if $ostree != null {
    assert ($ostree.stateroot != null)
}

let st = bootc status --json --booted | from json
assert equal $st.apiVersion org.containers.bootc/v1
if not $is_composefs {
    assert ($st.status.booted.image.timestamp != null)
} # else { TODO composefs: timestamp is not populated with composefs }
assert (($st.status | get rollback | default null) == null)
assert (($st.status | get staged | default null) == null)

# Verify /sysroot is still not writable after bootc status (regression test for PR #1718)
let is_writable = (do -i { /bin/test -w /sysroot } | complete | get exit_code) == 0
assert (not $is_writable) "/sysroot should remain read-only after bootc status"

tap ok
