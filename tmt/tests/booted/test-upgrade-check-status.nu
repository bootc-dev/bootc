# number: 37
# tmt:
#   summary: Verify upgrade --check populates cached update in status
#   duration: 30m
# extra:
#   fixme_skip_if_composefs: true
#
# TODO: The composefs backend does not yet persist cachedUpdate metadata
# from `upgrade --check`. Remove the skip once that is implemented.
#
# This test verifies that `bootc upgrade --check` caches registry
# metadata and that `bootc status` renders the cached update.
# Flow:
# 1. Build derived image v1, switch to it, reboot
# 2. Build v2, run `bootc upgrade --check`, verify status shows v2 as cached update
# 3. Build v3, run `bootc upgrade --check` again, verify status now shows v3
use std assert
use tap.nu

# This code runs on *each* boot.
bootc status
let st = bootc status --json | from json
let booted = $st.status.booted.image

def imgsrc [] {
    "localhost/bootc-test-check"
}

# Run on the first boot - build v1 and switch to it
def initial_build [] {
    tap begin "upgrade --check cached update in status"

    bootc image copy-to-storage

    # A simple derived container that adds a file with a version label
    "FROM localhost/bootc
LABEL org.opencontainers.image.version=v1
RUN echo v1 > /usr/share/test-upgrade-check
" | save Dockerfile
    podman build -t (imgsrc) .

    # Switch into the derived image
    bootc switch --transport containers-storage (imgsrc)
    tmt-reboot
}

# Second boot: verify on v1, then test upgrade --check with v2 and v3
def second_boot [] {
    print "verifying second boot - should be on v1"
    assert equal $booted.image.transport containers-storage
    assert equal $booted.image.image (imgsrc)

    let v1_content = open /usr/share/test-upgrade-check | str trim
    assert equal $v1_content "v1"

    let booted_digest = $booted.imageDigest
    print $"booted digest: ($booted_digest)"

    # Initially there should be no cached update
    let initial_status = bootc status --json | from json
    assert ($initial_status.status.booted.cachedUpdate == null) "No cached update initially"

    # Build v2 with same tag - this is a newer image
    "FROM localhost/bootc
LABEL org.opencontainers.image.version=v2
RUN echo v2 > /usr/share/test-upgrade-check
" | save --force Dockerfile
    podman build -t (imgsrc) .

    # Run upgrade --check (metadata only, no deployment)
    print "Running bootc upgrade --check for v2"
    bootc upgrade --check

    # Verify status now shows cached update
    let status_after_v2 = bootc status --json | from json
    assert ($status_after_v2.status.booted.cachedUpdate != null) "cachedUpdate should be populated after upgrade --check"

    let v2_cached = $status_after_v2.status.booted.cachedUpdate
    print $"v2 cached digest: ($v2_cached.imageDigest)"
    assert ($v2_cached.imageDigest != $booted_digest) "Cached update digest should differ from booted"

    # Verify human-readable output contains update info
    let human_output = bootc status --format humanreadable
    print $"Human output:\n($human_output)"
    assert ($human_output | str contains "UpdateVersion:") "Human-readable output should show UpdateVersion line"
    assert ($human_output | str contains "UpdateDigest:") "Human-readable output should show UpdateDigest line"

    # Now build v3 - another update on the same tag
    "FROM localhost/bootc
LABEL org.opencontainers.image.version=v3
RUN echo v3 > /usr/share/test-upgrade-check
" | save --force Dockerfile
    podman build -t (imgsrc) .

    # Run upgrade --check again
    print "Running bootc upgrade --check for v3"
    bootc upgrade --check

    # Verify status now shows v3 as the cached update (not v2)
    let status_after_v3 = bootc status --json | from json
    assert ($status_after_v3.status.booted.cachedUpdate != null) "cachedUpdate should still be populated"

    let v3_cached = $status_after_v3.status.booted.cachedUpdate
    print $"v3 cached digest: ($v3_cached.imageDigest)"
    assert ($v3_cached.imageDigest != $booted_digest) "v3 cached digest should differ from booted"
    assert ($v3_cached.imageDigest != $v2_cached.imageDigest) "v3 cached digest should differ from v2"

    # Verify human-readable output updated to v3
    let human_output_v3 = bootc status --format humanreadable
    assert ($human_output_v3 | str contains "UpdateVersion:") "Human-readable output should show UpdateVersion line after v3 check"
    assert ($human_output_v3 | str contains $v3_cached.imageDigest) "Human-readable output should show v3 digest"

    tap ok
}

def main [] {
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => initial_build,
        "1" => second_boot,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
