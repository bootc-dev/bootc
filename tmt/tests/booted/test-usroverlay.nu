# number: 23
# tmt:
#   summary: Execute tests for bootc usrover
#   duration: 30m
#
# Verify that bootc usroverlay works
use std assert
use tap.nu
use bootc_testlib.nu

def usr_is_writable []: nothing -> bool {
    (do -i { /bin/test -w /usr } | complete | get exit_code) == 0
}

# Status should initially report no overlay in JSON
let status_before = bootc status --json | from json
assert ($status_before.status.usrOverlay? == null)

# We should start out in a non-writable state on each boot
assert (not (usr_is_writable))

def initial_run [] {
    bootc usroverlay
    assert (usr_is_writable)

    # After `usroverlay`, status JSON should report a transient read/write overlay
    let status_after = bootc status --json | from json
    let overlay = $status_after.status.usrOverlay
    assert ($overlay.accessMode == "readWrite")
    assert ($overlay.persistence == "transient")

    bootc_testlib reboot
}

def second_boot [] {
    # After reboot, /usr overlay should be gone
    let status_after_reboot = bootc status --json | from json
    assert ($status_after_reboot.status.usrOverlay? == null)
    # And /usr should not be writable
    assert (not (usr_is_writable))

    # Mount a read-only /usr overlay
    bootc usroverlay --read-only
    assert (not (usr_is_writable))

    # After `usroverlay --read-only`, status should report a transient read-only overlay
    let status_after_readonly = bootc status --json | from json
    let overlay = $status_after_readonly.status.usrOverlay
    assert ($overlay.accessMode == "readOnly")
    assert ($overlay.persistence == "transient")
}

def main [] {
    # See https://tmt.readthedocs.io/en/stable/stories/features.html#reboot-during-test
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => initial_run,
        "1" => second_boot,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
