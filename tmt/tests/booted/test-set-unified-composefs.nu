# number: 47
# extra:
#   fixme_skip_if_composefs: true
# tmt:
#   summary: Runtime set-unified composefs then verify persistence across reboot
#   duration: 30m

use std assert
use tap.nu
use bootc_testlib.nu

# Multi-boot test:
#   Boot 0 (first_boot): run `bootc image set-unified composefs`.  This is a
#           flag-only operation: it writes `[composefs] unified=true` to the
#           ostree repo config but does NOT fetch, synthesize, or stage anything.
#           fsck reports ok=true with the live image in pending=true state.
#           After asserting the pending state and the sync no-op, we run
#           `bootc upgrade` which re-fetches the image, synthesizes the
#           composefs-backed commit, and stages a new deployment.  Then reboot.
#   Boot 1 (second_boot): now booted into the synthesized deployment; run
#           `bootc_testlib verify_bound_only` which asserts ok=true, binding=
#           "bound-only", and every live image is composefs-backed, synthesized,
#           and has no issues (pending=false).

# Per-boot status capture (runs on every boot)
bootc status

def main [] {
    bootc_testlib initial_status_and_checks
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => first_boot,
        "1" => second_boot,
        $o => { error make { msg: $"Unexpected TMT_REBOOT_COUNT ($o)" } },
    }
}

def first_boot [] {
    tap begin "bind ostree-composefs (flag-only) and activate via bootc upgrade"

    # Enable the ostree↔composefs binding for the booted image.
    # This is a flag-only operation: it writes [composefs] unified=true to the
    # ostree repo config but does NOT fetch, synthesize, or stage anything.
    bootc image set-unified composefs

    # The binding flag must now be set in the repo config.
    let cfg_val = (^ostree config --repo /sysroot/ostree/repo get composefs.unified | str trim)
    assert equal $cfg_val "true" "ostree repo config composefs.unified must be true after set-unified composefs"

    # fsck must report ok=true and binding="bound-only".  The live image must
    # have pending=true because the booted commit is not yet synthesized.
    let fsck = (bootc internals fsck images --json | from json)
    assert ($fsck.ok) "fsck: ok must be true immediately after set-unified composefs"
    assert equal $fsck.binding "bound-only" "fsck: binding must be bound-only"
    let live = ($fsck.images | where isLive == true)
    assert (($live | length) > 0) "fsck: at least one live image must be present"
    for img in $live {
        assert ($img.pending) $"($img.name): must be pending (booted classic commit, not yet synthesized)"
        assert (not $img.ostreeCommitSynthesized) $"($img.name): ostreeCommitSynthesized must be false while pending"
    }

    # bootc image sync must be a no-op (BoundOnly: nothing to reconcile).
    let sync_out = (bootc image sync | complete)
    assert equal $sync_out.exit_code 0 "bootc image sync must exit 0 on a bound-only system"
    assert ($sync_out.stdout | str contains "nothing to reconcile") \
        $"bootc image sync must print 'nothing to reconcile', got: ($sync_out.stdout)"

    # OS image must NOT be visible via the bootc additional store.
    let podman_out = (podman --storage-opt=additionalimagestore=/usr/lib/bootc/storage images --format "{{.Repository}}" | str trim)
    print $"Images via podman additional store (should be empty/absent): ($podman_out)"

    # Run `bootc upgrade` to fetch the image, synthesize the composefs-backed
    # ostree commit, and stage the new deployment.  Because the binding is now
    # active but the booted commit is still classic (non-synthesized), bootc
    # upgrade will detect the mismatch and stage even though the manifest digest
    # is unchanged.
    let upgrade_out = (bootc upgrade | complete)
    assert equal $upgrade_out.exit_code 0 $"bootc upgrade must exit 0, got: ($upgrade_out.stderr)"
    assert (not ($upgrade_out.stdout | str contains "No update available")) \
        $"bootc upgrade must NOT print 'No update available' after set-unified composefs; got: ($upgrade_out.stdout)"

    # Confirm a staged deployment now exists.
    let staged_check = (bootc status --json | from json | get status.staged?)
    assert ($staged_check != null) "A staged deployment must exist after bootc upgrade"

    tmt-reboot
}

def second_boot [] {
    tap begin "verify bound-only state after reboot onto synthesized deployment"

    # The synthesized deployment is now live; verify the full bound-only state.
    # This asserts ok=true, binding=bound-only, every live image is in composefs,
    # ostreeCommitSynthesized=true, and has no issues (pending=false).
    bootc_testlib verify_bound_only

    tap ok
}
