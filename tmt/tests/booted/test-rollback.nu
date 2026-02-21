# number: 36
# tmt:
#   summary: Test bootc rollback functionality
#   duration: 30m
#
# This test verifies bootc rollback functionality:
# 1. Captures the initial deployment state
# 2. Switches to a different image
# 3. Verifies the switch was successful
# 4. Performs bootc rollback
# 5. Reboots and verifies we're back to the original deployment

use std assert
use tap.nu
use bootc_testlib.nu

bootc status
journalctl --list-boots

let st = bootc status --json | from json
let booted = $st.status.booted.image

def imgsrc [] {
    $env.BOOTC_upgrade_image? | default "localhost/bootc-derived-local"
}

# Run on the first boot - capture initial state and switch to new image
def initial_switch [] {
    tap begin "bootc rollback test"

    print "=== Initial boot - capturing state and switching image ==="

    # Store initial deployment information for later verification
    let initial_st = bootc status --json | from json
    let initial_image = $initial_st.status.booted.image

    $initial_image | to json | save /var/bootc-initial-state.json

    let imgsrc = imgsrc

    if ($imgsrc | str ends-with "-local") {
        bootc image copy-to-storage

        print "Building derived container"
        "FROM localhost/bootc
RUN echo 'This is the rollback target image' > /usr/share/bootc-rollback-marker
" | save Dockerfile

        podman build -t $imgsrc .
        print $"Built derived image: ($imgsrc)"
    }

    print $"Switching to ($imgsrc)"
    bootc switch --transport containers-storage $imgsrc

    print "Switch completed, rebooting to new image..."
    tmt-reboot
}

# Check that we successfully switched to the new image and then rollback
def second_boot_rollback [] {
    print "=== Second boot - verifying switch and performing rollback ==="

    # Verify we're running the new image
    assert equal $booted.image.image $"(imgsrc)"
    print "Successfully switched to new image"

    assert ("/usr/share/bootc-rollback-marker" | path exists)
    print "New image artifacts verified"

    print "Performing bootc rollback..."
    bootc rollback

    print "Rollback initiated, rebooting to previous deployment..."
    tmt-reboot
}

def back_to_first_depl [boot_count] {
    print $"=== ($boot_count) boot - verifying rollback success ==="

    # Load the original state we saved and verify we're back to the original image
    let original_state = cat /var/bootc-initial-state.json | from json

    assert equal $booted.image $original_state.image
    print $"Successfully rolled back to original image: ($booted.image.image)"

    if ("/usr/share/bootc-rollback-marker" | path exists) {
        error make { msg: "Rollback target marker still present - rollback may have failed" }
    }
}

# Verify that rollback was successful and we're back to original deployment
def third_boot_verify [] {
    back_to_first_depl Third

    # Finally test a double rollback, to make sure the rollback state is queued then unqueued
    bootc rollback
    bootc rollback

    tmt-reboot
}

def fourth_boot_verify [] {
    back_to_first_depl Fourth
    tap ok
}

def main [] {
    # See https://tmt.readthedocs.io/en/stable/stories/features.html#reboot-during-test
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => initial_switch,
        "1" => second_boot_rollback,
        "2" => third_boot_verify,
        "3" => fourth_boot_verify,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
