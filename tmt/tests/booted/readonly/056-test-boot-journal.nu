# Verify that bootc-log-boot.service records the booted image in the journal.
#
# See: https://github.com/bootc-dev/bootc/issues/452
use std assert
use tap.nu

tap begin "verify booted image journal entry"

const BOOT_JOURNAL_ID = "66797517e29842bfa048064146ec92c2"

# The unit is ordered before multi-user.target, but this test may run before
# boot finishes. Wait for the boot transaction to complete. The exit status is
# non-zero on a degraded system; 014-test-no-failed-units reports that case.
do { systemctl is-system-running --wait } | complete | ignore

let entries = (
    journalctl -b -o json $"MESSAGE_ID=($BOOT_JOURNAL_ID)"
    | lines
    | each { from json }
)

if not (tap is_composefs) {
    # The generator only enables the unit on composefs boots for now.
    assert equal ($entries | length) 0 "no boot journal entry expected on ostree"
    tap ok
    exit 0
}

# Result=success alone also matches a unit that never ran, so check that the
# main process actually exited, and exited cleanly.
let unit = "bootc-log-boot.service"
let exited = (systemctl show -P ExecMainExitTimestampMonotonic $unit | str trim)
assert not equal $exited "0" $"($unit) should have run this boot"
let status = (systemctl show -P ExecMainStatus $unit | str trim)
assert equal $status "0" $"($unit) should have exited successfully"

assert equal ($entries | length) 1 "expected exactly one boot journal entry for this boot"
let entry = $entries | first
print $"# MESSAGE: ($entry.MESSAGE)"
print ($entry | select -i BOOTC_BACKEND BOOTC_DEPLOYMENT BOOTC_IMAGE BOOTC_TRANSPORT BOOTC_MANIFEST_DIGEST BOOTC_ARCHITECTURE BOOTC_VERSION BOOTC_TIMESTAMP | to json)

let st = bootc status --json | from json
let booted = $st.status.booted

assert equal $entry.BOOTC_BACKEND "composefs"
assert equal $entry.BOOTC_DEPLOYMENT $booted.composefs.verity
assert equal $entry.BOOTC_IMAGE $booted.image.image.image
assert equal $entry.BOOTC_TRANSPORT $booted.image.image.transport
assert equal $entry.BOOTC_MANIFEST_DIGEST $booted.image.imageDigest
assert equal $entry.BOOTC_ARCHITECTURE $booted.image.architecture

tap ok
