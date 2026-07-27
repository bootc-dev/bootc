# number: 47
# tmt:
#   summary: Execute download-only switch tests
#   duration: 40m
#
# This test does:
# bootc image copy-to-storage
# podman build <from that image> (v1)
# bootc switch <into that image> (v1)
# Verify we boot into the new image (v1)
# podman build updated image (v2)
# bootc switch --download-only <to v2> (stage v2 in download-only mode)
# reboot (should still boot into v1, staged deployment discarded)
# verify staged deployment is null (discarded on reboot)
# bootc switch --download-only <to v2> (re-stage v2 in download-only mode)
# bootc switch --from-downloaded (clear download-only mode without fetching from image source)
# reboot (should boot into v2)
#
use std assert
use tap.nu
use bootc_testlib.nu

# This code runs on *each* boot.
# Here we just capture information.
bootc status
journalctl --list-boots

let st = bootc status --json | from json
let booted = $st.status.booted.image

def imgsrc [] {
    $env.BOOTC_upgrade_image? | default "localhost/bootc-derived-local"
}

# Run on the first boot - build v1 and switch to it
def initial_build [] {
    tap begin "download-only switch test"

    let imgsrc = imgsrc
    # This test only works in local mode
    assert ($imgsrc | str ends-with "-local") "This test requires local mode"

    bootc image copy-to-storage

    # Create test file v1 on host
    "v1" | save testing-bootc-switch-apply

    # A simple derived container (v1) that adds a file
    let dockerfile = $"FROM localhost/bootc as base
COPY testing-bootc-switch-apply /usr/share/testing-bootc-switch-apply
"
    (tap make_uki_containerfile $dockerfile) | save Dockerfile
    # Build it
    podman build -t $imgsrc .

    # Now, switch into the new image
    print $"Applying ($imgsrc)"
    bootc switch --transport containers-storage ($imgsrc)
    tmt-reboot
}

# Check we have the updated image (v1), then test --download-only with switch
def second_boot [] {
    print "verifying second boot - should be on v1"
    assert equal $booted.image.transport containers-storage
    assert equal $booted.image.image $"(imgsrc)"

    # Verify the v1 file exists
    assert ("/usr/share/testing-bootc-switch-apply" | path exists) "v1 file should exist"
    let v1_content = open /usr/share/testing-bootc-switch-apply | str trim
    assert equal $v1_content "v1"

    # Build v2 - a different derived image with a different tag
    let imgsrc = imgsrc
    let v2_image = $"($imgsrc)-v2"
    # Create test file v2 on host
    "v2" | save --force testing-bootc-switch-apply

    let dockerfile = $"FROM localhost/bootc as base
COPY testing-bootc-switch-apply /usr/share/testing-bootc-switch-apply
"
    (tap make_uki_containerfile $dockerfile) | save --force Dockerfile
    podman build -t $v2_image .

    # Now switch with --download-only (should set deployment to download-only mode)
    print $"Switching with --download-only to v2"
    bootc switch --download-only --transport containers-storage ($v2_image)

    # Verify deployment is staged and in download-only mode
    let status_json = bootc status --json | from json
    assert ($status_json.status.staged != null) "Staged deployment should exist"
    assert ($status_json.status.staged.downloadOnly) "Staged deployment should be in download-only mode"

    # Reboot - should still boot into v1 since deployment is in download-only mode
    tmt-reboot
}

# Third boot - verify still on v1, staged deployment discarded, re-stage and clear download-only mode
def third_boot [] {
    print "verifying third boot - should still be on v1 (download-only deployment was discarded)"

    # Verify we're still on v1
    let v1_content = open /usr/share/testing-bootc-switch-apply | str trim
    assert equal $v1_content "v1" "Should still be on v1 after download-only reboot"

    # Verify that the staged deployment was discarded on reboot, as is expected for download-only deployments
    let status_before = bootc status --json | from json
    assert ($status_before.status.staged == null) "Staged deployment should be discarded after rebooting with a download-only deployment"

    # Re-run switch --download-only to re-stage the deployment
    let imgsrc = imgsrc
    let v2_image = $"($imgsrc)-v2"
    print "Re-staging with switch --download-only"
    bootc switch --download-only --transport containers-storage ($v2_image)

    # Verify via JSON that deployment is in download-only mode again
    let status_json = bootc status --json | from json
    assert ($status_json.status.staged != null) "Staged deployment should exist"
    assert ($status_json.status.staged.downloadOnly) "Staged deployment should be in download-only mode"

    # Now clear download-only mode by running switch --from-downloaded (without fetching from image source)
    print "Clearing download-only mode with bootc switch --from-downloaded"
    bootc switch --from-downloaded

    # Verify via JSON that deployment is not in download-only mode
    let status_after_json = bootc status --json | from json
    assert (not $status_after_json.status.staged.downloadOnly) "Staged deployment should not be in download-only mode"

    # Reboot to apply the update
    tmt-reboot
}

# Fourth boot - verify we're on v2
def fourth_boot [] {
    print "verifying fourth boot - should be on v2"
    assert equal $booted.image.transport containers-storage

    let imgsrc = imgsrc
    let v2_image = $"($imgsrc)-v2"
    assert equal $booted.image.image $v2_image

    # Verify v2 file content
    let v2_content = open /usr/share/testing-bootc-switch-apply | str trim
    assert equal $v2_content "v2" "Should be on v2 after clearing download-only and reboot"

    tap ok
}

def main [] {
    # See https://tmt.readthedocs.io/en/stable/stories/features.html#reboot-during-test
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => initial_build,
        "1" => second_boot,
        "2" => third_boot,
        "3" => fourth_boot,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
