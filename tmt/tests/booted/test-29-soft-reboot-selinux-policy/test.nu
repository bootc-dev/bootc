# number: 29
# tmt:
#   summary: Test soft reboot with SELinux policy changes
#   duration: 30m
#
# Verify that soft reboot is blocked when SELinux policies differ
use std assert
use ../tap.nu

let soft_reboot_capable = "/usr/lib/systemd/system/soft-reboot.target" | path exists
if not $soft_reboot_capable {
    echo "Skipping, system is not soft reboot capable"
    return
}

# Check if SELinux is enabled
let selinux_enabled = "/sys/fs/selinux/enforce" | path exists
if not $selinux_enabled {
    echo "Skipping, SELinux is not enabled"
    return
}

# This code runs on *each* boot.
bootc status

# Run on the first boot
def initial_build [] {
    tap begin "Test soft reboot with SELinux policy change"

    # Use the pre-built image from the framework
    let image = $env.BOOTC_TEST_IMAGE_BOOTC_DERIVED_POLICY

    # Verify soft reboot preparation hasn't happened yet
    assert (not ("/run/nextroot" | path exists))

    # Try to soft reboot - this should fail because policies differ
    bootc switch --soft-reboot=auto --transport registry $image
    let st = bootc status --json | from json

    # Verify staged deployment exists
    assert ($st.status.staged != null) "Expected staged deployment to exist"

    # The staged deployment should NOT be soft-reboot capable because policies differ
    assert (not $st.status.staged.softRebootCapable) "Expected soft reboot to be blocked due to SELinux policy difference, but softRebootCapable is true"

    # Verify soft reboot preparation didn't happen
    assert (not ("/run/nextroot" | path exists)) "Soft reboot should not be prepared when policies differ"

    # Do a full reboot
    tmt-reboot
}

# The second boot; verify we're in the derived image
def second_boot [] {
    tap begin "Verify deployment with different SELinux policy"

    # Verify we're in the new deployment
    let st = bootc status --json | from json
    let booted = $st.status.booted.image
    assert ($booted.image.image | str contains "bootc-derived-policy") $"Expected booted image to contain 'bootc-derived-policy', got: ($booted.image.image)"

    tap ok
}

def main [] {
    # See https://tmt.readthedocs.io/en/stable/stories/features.html#reboot-during-test
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => initial_build,
        "1" => second_boot,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
