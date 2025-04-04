use std assert
use tap.nu

tap begin "verify bootc status output formats"

let st = bootc status --json | from json
assert equal $st.apiVersion org.containers.bootc/v1

let st = bootc status --json --format-version=0 | from json
assert equal $st.apiVersion org.containers.bootc/v1

let st = bootc status --format=yaml | from yaml
assert equal $st.apiVersion org.containers.bootc/v1
assert ($st.status.booted.image.timestamp != null)

let st = bootc status --json --booted | from json
assert equal $st.apiVersion org.containers.bootc/v1
assert ($st.status.booted.image.timestamp != null)
assert (($st.status | get rollback | default null) == null)
assert (($st.status | get staged | default null) == null)

tap ok
