# number: 23
# tmt:
#   summary: Execute tests for bootc usrover
#   duration: 30m
#
# Verify that bootc usroverlay works
use std assert
use tap.nu
use bootc_testlib.nu

# Status should initially report no overlay in JSON
let status_json_before = bootc status --json | from json
assert ($status_json_before.status.usrOverlay? == null)

# We should start out in a non-writable state on each boot
let is_writable = (do -i { /bin/test -w /usr } | complete | get exit_code) == 0
assert (not $is_writable)

def initial_run [] {
    bootc usroverlay
    let is_writable = (do -i { /bin/test -w /usr } | complete | get exit_code) == 0
    assert ($is_writable)

    # After `usroverlay`, status JSON should report a transient read/write overlay
    let status_json_after = bootc status --json | from json
    let overlay = $status_json_after.status.usrOverlay
    assert ($overlay.accessMode == "readWrite")
    assert ($overlay.persistence == "transient")

    bootc_testlib reboot
}

# The second boot; verify we're in the derived image
def second_boot [] {
    # After reboot, usr overlay should be gone
    let status_after_reboot = bootc status --json | from json
    assert ($status_after_reboot.status.usrOverlay? == null)
}

def main [] {
    # See https://tmt.readthedocs.io/en/stable/stories/features.html#reboot-during-test
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => initial_run,
        "1" => second_boot,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
