# A simple nushell "library" for bootc test helpers

# Run standard per-boot checks that should pass on every boot in every test.
#
# Call this at the start of every boot function (first_boot, second_boot, etc.)
# to ensure consistent baseline verification across all tests.  Currently runs:
#
#   - `bootc internals fsck images`: verifies that every image bootc has
#     committed to (composefs GC tag) is also present in containers-storage.
#     This is a no-op when unified storage is not enabled, so it is always
#     safe to call regardless of the system configuration.
export def initial_status_and_checks [] {
    bootc internals fsck images
}

# Asserts the system is in a unified storage state and performs common verifications
export def verify_unified_storage [] {
    use std assert

    # 1. Asserts `/usr/lib/bootc/storage` path exists
    assert ("/usr/lib/bootc/storage" | path exists) "/usr/lib/bootc/storage must exist"

    # 2. Asserts `bootc image list --format json | from json | where image_type == "unified"` has at least 1 entry
    let images = bootc image list --format json | from json
    let unified_images = $images | where image_type == "unified"
    assert (($unified_images | length) > 0) "Expected at least one image with type 'unified'"

    # 3. Asserts `/sysroot/composefs/bootc.json` exists
    assert ("/sysroot/composefs/bootc.json" | path exists) "/sysroot/composefs/bootc.json must exist"

    # 4. Calls `bootc internals fsck images` (via `bootc_testlib initial_status_and_checks`)
    initial_status_and_checks

    # Verify bootc status --json storage field
    let st = bootc status --json | from json
    let storage_unified = $st.status.storage?.unified? | default "disabled"
    assert ($storage_unified != "disabled") $"status JSON: storage.unified must not be disabled, got ($storage_unified)"

    # Verify fsck --json output
    let fsck_json = bootc internals fsck images --json | from json
    assert ($fsck_json.unifiedStorageEnabled) "fsck JSON: unifiedStorageEnabled must be true"
    assert ($fsck_json.ok) "fsck JSON: ok must be true"
    # reflinksSupported may be true or false depending on filesystem
    assert ("reflinksSupported" in $fsck_json) "fsck JSON: reflinksSupported field must be present"
    # Must have checked at least one image — guards against the "0 image(s) OK"
    # silent-pass bug where the live-deployment filter skips everything.
    assert (($fsck_json.images | length) > 0) "fsck JSON: at least one image must be checked (not silently skipped)"

    # 5. On composefs-native boot (`tap is_composefs`): asserts `/sysroot/composefs/streams` exists and has at least one OCI ref symlink
    if (tap is_composefs) {
        assert ("/sysroot/composefs/streams" | path exists) "/sysroot/composefs/streams must exist"
        let oci_refs = (ls /sysroot/composefs/streams/refs/oci/ | where type == "symlink")
        assert (($oci_refs | length) > 0) "At least one OCI ref must exist under /sysroot/composefs/streams/refs/oci/"
    }
}

# Verify that the composefs→ostree synthesis path produces an ostree commit
# equivalent to the classic tar-pipeline ostree-ext ImageImporter, for the same
# image, by importing it BOTH ways into a scratch ostree repo and running
# `ostree diff`.
#
# This addresses the TODO from PR #2236: "add equivalence/diff testing of this
# versus the current ostree-ext container backend".
#
# The check is fully self-contained and independent of host boot/deployment
# state: we drive both backends explicitly via `bootc internals ostree-container
# image pull`, once classically and once with `--composefs-unified` (which runs
# `import_from_composefs_repo`).  The image under test is the currently booted
# image, which on a unified system is available locally in containers-storage,
# so both imports run fully offline.
#
# Both imports target a fresh scratch ostree repo (not the system repo) so we
# never perturb the booted system's refs/objects.
#
# Equivalence policy: we assert the two commits have an empty `ostree diff`
# (identical file content AND per-file metadata: mode/uid/gid/xattrs), EXCEPT
# for a small allowlist of paths with known, understood divergences.  `ostree
# diff` ignores commit-level metadata (timestamp, manifest digest).  Any
# divergence outside the allowlist hard-fails the test (and prints the full
# diff), so this still catches regressions in either backend.
#
# Known allowlisted divergences (verified against the real image on a booted
# CentOS Stream 10 root):
#
#   * /usr/lib, /usr/lib/bootc, /usr/lib/bootc/kargs.d — directory MODE differs
#     (classic 0755 vs synth 0770).  The image genuinely ships these as 0770
#     (a bootc-generated layer sets them group-writable).  The composefs
#     synthesis path is CORRECT here; the CLASSIC ImageImporter is the buggy
#     one: its `checkout_at(UnionFiles)` merge step (store.rs) does not update
#     directory metadata when a later OCI layer re-specifies an existing dir,
#     so the later 0770 is silently lost and 0755 from the first layer wins.
#     Allowlisted until the classic path is fixed; see PR #2236 discussion.
#
#   * /proc — SELinux label differs (classic `mnt_t` vs synth `default_t`).
#     /proc is an empty mountpoint placeholder relabeled by the kernel at
#     runtime, so this is benign.  synth's `default_t` matches the image's own
#     embedded policy; classic's `mnt_t` leaks in from the importing host's
#     booted-deployment policy (used as the SEPolicy seed).
export def verify_synthesis_equivalence [] {
    use std assert

    let st = bootc status --json | from json

    # The booted image is our test subject.  Require an ostree-based unified
    # deployment with a known image reference; skip cleanly otherwise.
    if ($st.status.booted?.image? == null) {
        print "# verify_synthesis_equivalence: skipping — no booted image reference"
        return
    }
    let img_transport = $st.status.booted.image.image.transport
    let img_name = $st.status.booted.image.image.image
    # `image pull` takes an OstreeImageReference: <sigverify>:<transport>:<name>.
    let imgref = $"ostree-unverified-image:($img_transport):($img_name)"
    print $"# verify_synthesis_equivalence: image under test = ($imgref)"

    # Both the classic and the --composefs-unified pulls write the SAME ostree
    # ref (store::ref_for_image), so to avoid one clobbering the other we import
    # into two separate throwaway repos, then pull the synthesized commit into
    # the classic repo so `ostree diff` (single-repo) can compare them.  Neither
    # repo is the system repo, so the booted system is never perturbed.
    # Place scratch repos on persistent storage under /var (the booted root /tmp
    # is typically a small tmpfs that can't hold a full OS image twice).
    let scratch = (mktemp -d -p /var/tmp)
    let classic_repo = $"($scratch)/classic"
    let synth_repo = $"($scratch)/synth"
    ostree --repo=($classic_repo) init --mode=bare
    ostree --repo=($synth_repo) init --mode=bare
    # These are throwaway repos; disable the min-free-space guard so a full-size
    # OS image import doesn't trip it (we delete the whole tree at the end).
    ostree --repo=($classic_repo) config set core.min-free-space-percent 0
    ostree --repo=($synth_repo) config set core.min-free-space-percent 0

    # Both pulls print "... => <commit>" on success; parse the commit checksum
    # from that line (the ref name is prefix-stripped by `ostree refs`, so the
    # stdout is the most robust source of the resulting commit).
    def commit_from_pull [out: string] {
        $out | lines | where {|l| ($l | str contains "=>")} | last | split row "=>" | last | str trim
    }

    # Import 1: classic tar pipeline (writes ref_for_image automatically).
    print "# verify_synthesis_equivalence: classic import..."
    let classic_out = (bootc internals ostree-container image pull ($classic_repo) $imgref | complete)
    assert ($classic_out.exit_code == 0) $"classic import failed: ($classic_out.stderr)"
    let classic_commit = (commit_from_pull $classic_out.stdout)

    # Import 2: composefs→ostree synthesis.
    print "# verify_synthesis_equivalence: composefs-unified import..."
    let synth_out = (bootc internals ostree-container image pull ($synth_repo) $imgref --composefs-unified | complete)
    assert ($synth_out.exit_code == 0) $"composefs-unified import failed: ($synth_out.stderr)"
    let synth_commit = (commit_from_pull $synth_out.stdout)

    print $"# verify_synthesis_equivalence: classic=($classic_commit) synth=($synth_commit)"

    # Confirm the synthesized commit really carries the synthesis marker, so a
    # silent fallthrough to the classic path can't make this pass vacuously.
    let meta = (ostree --repo=($synth_repo) show $"--print-metadata-key=ostree-ext.composefs-synthesized" $synth_commit | complete)
    assert ($meta.exit_code == 0) "synthesized commit must carry ostree-ext.composefs-synthesized metadata"

    # Bring the synthesized commit into the classic repo for a single-repo diff.
    ostree --repo=($classic_repo) pull-local ($synth_repo) $synth_commit

    # ostree diff: empty stdout + exit 0 means the trees are byte-for-byte and
    # metadata-for-metadata identical.  Lines are `<A|D|M>    <path>`.
    let diff_result = (ostree --repo=($classic_repo) diff $classic_commit $synth_commit | complete)
    let diff_output = ($diff_result.stdout | str trim)

    rm -rf $scratch

    if ($diff_output | is-empty) {
        print "# verify_synthesis_equivalence: PASS — classic and synthesized commits are identical"
        return
    }

    # Always log the full diff for the record.
    print "# verify_synthesis_equivalence: ostree diff (non-empty — checking against allowlist):"
    print $diff_output

    # Paths with known, understood divergences (see the function doc comment).
    # Any differing path NOT in this set is an unexpected regression and fails.
    let allowlist = [
        "/proc"
        "/usr/lib"
        "/usr/lib/bootc"
        "/usr/lib/bootc/kargs.d"
    ]

    # Parse `<A|D|M>    <path>` lines into the set of differing paths.
    let diff_paths = ($diff_output | lines
        | where {|l| ($l | str trim | is-not-empty)}
        | each {|l| ($l | str trim | split row -r " +" | last)})

    let unexpected = ($diff_paths | where {|p| ($p not-in $allowlist)})

    if (($unexpected | length) > 0) {
        let summary = ($unexpected | str join "\n")
        print "# verify_synthesis_equivalence: FAIL — unexpected (non-allowlisted) divergences:"
        print $summary
        error make {msg: $"verify_synthesis_equivalence: classic and composefs-synthesized commits differ outside the known allowlist:\n($summary)\n\nFull diff:\n($diff_output)"}
    }

    print "# verify_synthesis_equivalence: PASS — only known allowlisted divergences present"
}

# Asserts the system is in a bound-only storage state and performs consistency checks.
#
# Delegates to `bootc internals fsck images --json` as the single authoritative
# consistency gate.  Verifies that:
#   - fsck reports ok=true
#   - the binding is "bound-only"
#   - unifiedStorageEnabled is false
#   - at least one live image is present
#   - every live image is in composefs, has a synthesized ostree commit,
#     has no issues, and is NOT pending (i.e. fully activated bound-only mode)
export def verify_bound_only [] {
    use std assert
    let f = bootc internals fsck images --json | from json
    assert ($f.ok) "fsck: ok must be true"
    assert equal $f.binding "bound-only" "fsck: binding must be bound-only"
    assert (not $f.unifiedStorageEnabled) "fsck: unifiedStorageEnabled must be false"
    let live = ($f.images | where isLive == true)
    assert (($live | length) > 0) "fsck: expected at least one live bound image"
    for img in $live {
        assert ($img.inComposefs) $"($img.name): must be in composefs"
        assert ($img.ostreeCommitSynthesized) $"($img.name): ostree commit must be synthesized"
        assert (($img.issues | length) == 0) $"($img.name): unexpected issues: ($img.issues)"
        assert (not $img.pending) $"($img.name): must not be pending after reboot onto synthesized deployment"
    }
}

# This is a workaround for what must be a systemd bug
# that seems to have appeared in C10S
# TODO diagnose and fill in here
export def reboot [] {
    # Allow more delay for bootc to settle
    sleep 120sec

    tmt-reboot
}

# True if we're running in bcvk with `--bind-storage-ro` and
# we can expect to be able to pull container images from the host.
# See xtask.rs
export def have_hostexports [] {
    $env.BCVK_EXPORT? == "1"
}

# Parse the kernel commandline into a list.
# This is not a proper parser, but good enough
# for what we need here.
export def parse_cmdline []  {
    open /proc/cmdline | str trim | split row " "
}

# If the BOOTC_test_upgrade_image environment variable is set, performs
# an upgrade to that image and reboots on the first boot. On the second
# boot (after the upgrade), verifies we're running the upgraded image
# and returns so the caller can proceed with its tests.
#
# This enables an "upgrade test" flow: boot from a published base image,
# upgrade to the image under test, reboot, then run verification tests.
#
# Note: This uses BOOTC_test_upgrade_image (the image to upgrade *into*),
# which is distinct from BOOTC_upgrade_image (the synthetic upgrade image
# used by existing upgrade tests like test-image-upgrade-reboot).
#
# Returns without doing anything if BOOTC_test_upgrade_image is not set.
export def maybe_upgrade [] {
    use std assert

    let upgrade_image = $env.BOOTC_test_upgrade_image? | default ""
    if $upgrade_image == "" {
        return
    }

    match $env.TMT_REBOOT_COUNT? {
        null | "0" => {
            if not (have_hostexports) {
                error make { msg: "BOOTC_test_upgrade_image is set but host exports (--bind-storage-ro) are not available" }
            }
            # Save the pre-upgrade bootc version so post-upgrade tests
            # can detect known incompatibilities with older versions.
            let pre_ver = (bootc --version | parse "bootc {v}" | get 0.v)
            $pre_ver | save /var/bootc-pre-upgrade-version
            print $"Pre-upgrade bootc version: ($pre_ver)"

            print $"Upgrade image specified: ($upgrade_image)"
            print "Performing upgrade switch..."
            bootc switch --transport containers-storage $upgrade_image
            print "Switch complete, rebooting..."
            tmt-reboot
        },
        "1" => {
            print $"Second boot after upgrade to ($upgrade_image)"
            let st = bootc status --json | from json
            let booted = $st.status.booted.image
            assert equal $booted.image.transport "containers-storage"
            assert equal $booted.image.image $upgrade_image
            print "Upgrade verified, continuing with tests..."
        },
        $o => {
            # For higher reboot counts, just continue - the caller
            # may have its own reboot logic
        },
    }
}
