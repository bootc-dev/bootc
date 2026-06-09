# number: 44
# tmt:
#   summary: Readonly tests after onboarding to unified storage via set-unified
#   duration: 30m
#
# Two-boot test:
#   Boot 0: copy-to-storage + switch to containers-storage transport + reboot.
#           This sidesteps any registry dependency so set-unified can work
#           fully offline without STORAGE_OPTS/skopeo complexity.
#   Boot 1: set-unified (takes the containers-storage fast path), verify,
#           then run the full readonly suite.

use std assert
use tap.nu
use bootc_testlib.nu

def main [] {
    # This test onboards a freshly-installed system to unified storage and then
    # exercises new-binary-only functionality (copy-to-storage, set-unified,
    # `bootc internals fsck images`).  In an upgrade run the first boot is the
    # older, published base image which lacks these subcommands, so skip the
    # whole test there rather than crashing on the pre-upgrade binary.
    if ($env.BOOTC_test_upgrade_image? | default "" | is-not-empty) {
        tap begin "skipping unified-storage onboarding test in upgrade run"
        tap ok
        return
    }

    bootc_testlib initial_status_and_checks
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => first_boot,
        "1" => second_boot,
        $o => { error make { msg: $"Unexpected TMT_REBOOT_COUNT ($o)" } },
    }
}

# Derived image: FROM the booted base (exported to the default containers-storage
# as localhost/bootc by `bootc image copy-to-storage` below) plus a trivial RUN so
# it has a genuinely different fs-verity digest.  The `as base` stage name is
# required by make_uki_containerfile, which appends sealed-UKI build stages that
# reference `base` when running on a UKI composefs system.
const DERIVED_DOCKERFILE = '
FROM localhost/bootc as base

RUN echo unified > /etc/unified-test
'

def first_boot [] {
    tap begin "copy booted image to containers-storage and switch transport"

    # Export the booted image into the default /var/lib/containers as
    # localhost/bootc (IMAGE_DEFAULT) so the podman build below can use it as the
    # FROM base without any registry pull.
    bootc image copy-to-storage

    # Build a derived image.  A different fs-verity digest is mandatory: composefs
    # `bootc switch` errors on any digest collision with an existing deployment
    # (the intentional same-fs-verity guard), so we must switch to a genuinely
    # different image.  This also leaves the original booted image as the rollback
    # on the next boot, which exercises set-unified's reconcile-of-non-booted logic.
    #
    # On UKI composefs the derived image needs a sealed UKI; make_uki_containerfile
    # appends the necessary build stages when running on a UKI system (no-op
    # otherwise, including on ostree).
    (tap make_uki_containerfile $DERIVED_DOCKERFILE) | save --force Dockerfile
    podman build -t localhost/bootc-unified-test .

    # Switch to containers-storage transport so the next boot's set-unified sees
    # transport=containers-storage and onboards the image from /var/lib/containers
    # (via image_exists_in_host_storage -> pull_from_host_storage) without network.
    bootc switch --transport containers-storage localhost/bootc-unified-test

    tmt-reboot
}

def second_boot [] {
    tap begin "readonly tests after onboarding to unified storage"

    # Detect the sysroot filesystem type.  On ext4 (no reflink support) we
    # must pass --enabled-with-copy; on xfs/btrfs reflinks are available and we
    # default to requiring them (the stricter path).
    let sysroot_fstype = (findmnt -n -o FSTYPE /sysroot | str trim)
    let set_unified_args = if $sysroot_fstype == "ext4" {
        print $"# sysroot is ext4 — using --enabled-with-copy for set-unified"
        ["--enabled-with-copy"]
    } else {
        print $"# sysroot is ($sysroot_fstype) — reflinks required"
        []
    }

    # Now booted from containers-storage transport — set-unified will copy
    # from /var/lib/containers into bootc storage without any network access.
    bootc image set-unified full ...$set_unified_args

    bootc_testlib verify_unified_storage

    # Verify that the synthesized ostree commit (composefs→ostree path) is
    # equivalent to the commit the classic tar-pipeline would produce for
    # the same image.  This is the most natural place to run this check:
    # the booted image is still in /var/lib/containers/storage (copied there
    # in first_boot via `bootc image copy-to-storage`), so the classic
    # re-import works fully offline without any network access.
    #
    # See: PR #2236 TODO "add equivalence/diff testing of this versus the
    # current ostree-ext container backend".
    bootc_testlib verify_synthesis_equivalence

    let tests = (ls booted/readonly/*-test-*.nu | get name | sort)
    for test_file in $tests {
        print $"Running ($test_file)..."
        nu $test_file
    }

    tap ok
}
