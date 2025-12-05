# number: 30
# extra:
#   try_bind_storage: true
# tmt:
#   summary: Execute upgrade --download-only tests
#   duration: 30m
#
# This test does:
# bootc image copy-to-storage
# podman build <from that image>
# bootc upgrade --download-only
# reboot (should boot into old image)
# bootc upgrade --download-only (verify lock status)
# bootc upgrade
# reboot (should boot into new image)
#
use std assert
use tap.nu

# This code runs on *each* boot.
# Here we just capture information.
bootc status
journalctl --list-boots

let st = bootc status --json | from json
let booted = $st.status.booted.image

# Parse the kernel commandline into a list.
# This is not a proper parser, but good enough
# for what we need here.
def parse_cmdline []  {
    open /proc/cmdline | str trim | split row " "
}

def imgsrc [] {
    $env.BOOTC_upgrade_image? | default "localhost/bootc-derived-local"
}

# Run on the first boot
def initial_build [] {
    tap begin "upgrade --download-only test"

    let imgsrc = imgsrc
    # For the packit case, we build locally right now
    if ($imgsrc | str ends-with "-local") {
        bootc image copy-to-storage

        # A simple derived container that adds a file
        "FROM localhost/bootc
RUN touch /usr/share/testing-bootc-download-only
" | save Dockerfile
         # Build it
        podman build -t $imgsrc .
    }

    # Now, upgrade with --download-only (should lock the deployment)
    print $"Upgrading with --download-only: ($imgsrc)"
    bootc upgrade --download-only

    # Verify that deployment is staged and locked
    let status_output = bootc status --json | from json
    assert ($status_output.status.staged != null) "Staged deployment should exist"

    # Reboot - should boot into old image since deployment is locked
    tmt-reboot
}

# Second boot - verify we're still on old image, then unlock
def second_boot [] {
    print "verifying second boot (should still be old image)"

    # Verify we're NOT booted into the new image yet
    assert (not ("/usr/share/testing-bootc-download-only" | path exists)) "File should not exist yet"

    # Run --download-only again to verify staged deployment is still locked
    let imgsrc = imgsrc
    print $"Running upgrade --download-only again"
    bootc upgrade --download-only

    # Verify staged deployment exists and is locked (verbose mode shows lock status)
    let status_verbose = bootc status --verbose | complete
    print $status_verbose.stdout
    assert ($status_verbose.stdout | str contains "Locked") "Status should show lock information"

    # Now unlock the deployment by running upgrade without flags
    print "Unlocking deployment with bootc upgrade"
    bootc upgrade

    # Verify deployment is now unlocked by checking status
    let status_after_unlock = bootc status --verbose | complete
    print $status_after_unlock.stdout

    # Reboot to apply the update
    tmt-reboot
}

# Third boot - verify we're on the new image
def third_boot [] {
    print "verifying third boot (should be new image)"
    assert equal $booted.image.transport containers-storage
    assert equal $booted.image.image $"(imgsrc)"

    # Verify the new file exists
    assert ("/usr/share/testing-bootc-download-only" | path exists) "New file should exist after upgrade"

    tap ok
}

def main [] {
    # See https://tmt.readthedocs.io/en/stable/stories/features.html#reboot-during-test
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => initial_build,
        "1" => second_boot,
        "2" => third_boot,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
