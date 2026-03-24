# number: 39
# tmt:
#   summary: Test bootc upgrade --tag functionality with containers-storage
#   duration: 30m
#
# This test verifies:
# - bootc upgrade --tag switches to different tags of the same image
# - bootc upgrade --check --tag verifies tag availability
# Test using containers-storage transport to avoid registry dependency
use std assert
use tap.nu

# This code runs on *each* boot
bootc status
let st = bootc status --json | from json
let booted = $st.status.booted.image

# Run on the first boot
def initial_build [] {
    tap begin "upgrade --tag test"

    let td = mktemp -d
    cd $td

    # Copy bootc image to local storage
    bootc image copy-to-storage

    # Build v1 image
    "FROM localhost/bootc
RUN echo v1 content > /usr/share/bootc-tag-test.txt
" | save Dockerfile
    podman build -t localhost/bootc-tag-test:v1 .

    # Verify v1 content
    let v = podman run --rm localhost/bootc-tag-test:v1 cat /usr/share/bootc-tag-test.txt | str trim
    assert equal $v "v1 content"

    # Switch to v1
    bootc switch --transport containers-storage localhost/bootc-tag-test:v1

    # Build v2 image (different content) - use --force to overwrite Dockerfile
    "FROM localhost/bootc
RUN echo v2 content > /usr/share/bootc-tag-test.txt
" | save --force Dockerfile
    podman build -t localhost/bootc-tag-test:v2 .

    # Verify v2 content
    let v = podman run --rm localhost/bootc-tag-test:v2 cat /usr/share/bootc-tag-test.txt | str trim
    assert equal $v "v2 content"

    tmt-reboot
}

# Second boot: verify we're on v1, then upgrade to v2 using --tag
def second_boot [] {
    print "verifying second boot (v1)"

    # Should be on v1
    assert equal $booted.image.transport containers-storage
    assert equal $booted.image.image "localhost/bootc-tag-test:v1"

    # Verify v1 content
    let t = open /usr/share/bootc-tag-test.txt | str trim
    assert equal $t "v1 content"

    # Test upgrade --check --tag v2
    let check_output = bootc upgrade --check --tag v2
    print $"Check output: ($check_output)"

    # Now upgrade to v2 using --tag
    bootc upgrade --tag v2

    # Verify we staged an update
    let st = bootc status --json | from json
    assert ($st.status.staged != null)
    let staged = $st.status.staged.image
    assert equal $staged.image.image "localhost/bootc-tag-test:v2"

    tmt-reboot
}

# Third boot: verify we're on v2
def third_boot [] {
    print "verifying third boot (v2)"

    # Should be on v2 now
    assert equal $booted.image.transport containers-storage
    assert equal $booted.image.image "localhost/bootc-tag-test:v2"

    # Verify v2 content
    let t = open /usr/share/bootc-tag-test.txt | str trim
    assert equal $t "v2 content"

    tap ok
}

def main [] {
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => initial_build,
        "1" => second_boot,
        "2" => third_boot,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
