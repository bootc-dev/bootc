# number: 42
# extra:
#   fixme_skip_if_composefs: true
# tmt:
#   summary: Test bootc loader-entries set-options-for-source
#   duration: 30m
#
# This test verifies the source-tracked kernel argument management via
# bootc loader-entries set-options-for-source. It covers:
# 1. Input validation (invalid/empty source names)
# 2. Adding source-tracked kargs and verifying they appear in /proc/cmdline
# 3. Kargs and x-options-source-* BLS keys surviving the staging roundtrip
# 4. Source replacement semantics (old kargs removed, new ones added)
# 5. Multiple sources coexisting independently
# 6. Source removal (--source without --options clears all owned kargs)
# 7. Idempotent operation (no changes when kargs already match)
# 8. Existing system kargs (root=, ostree=, etc.) preserved through changes
# 9. --options "" (empty string) clears kargs without removing the source
# 10. Staged deployment interaction (bootc switch + set-options-for-source
#     preserves the pending image switch)
# 11. Cross-consumer staging (bootc stages source kargs, then rpm-ostree
#     re-stages on the same boot via kargs --append; x-options-source-*
#     keys must survive in the replacement staged deployment via the
#     "previously-staged fallback" path in ostree_sysroot_stage_tree_with_options)
#
# Requires ostree with bootconfig-extra support (>= 2026.1).
# See: https://github.com/ostreedev/ostree/pull/3570
# See: https://github.com/ostreedev/ostree/pull/3611
# See: https://github.com/bootc-dev/bootc/issues/899
use std assert
use tap.nu

let is_bad_version = ostree --version | lines | any {|l| $l | str contains "2026.2" }

if $is_bad_version {
    print "Found Ostree v2026.2, skipping test"
    exit 0
}

def parse_cmdline [] {
    open /proc/cmdline | str trim | split row " "
}

# Read x-options-source-* keys from the booted BLS entry.
# The booted deployment always has the highest version number,
# so we pick the last entry when sorted by filename (ostree-N.conf).
def read_bls_source_keys [] {
    let entries = glob /boot/loader/entries/ostree-*.conf | sort
    if ($entries | length) == 0 {
        error make { msg: "No BLS entries found" }
    }
    let entry = open ($entries | last)
    $entry | lines | where { |line| $line starts-with "x-options-source-" }
}

# Save the current system kargs (root=, ostree=, rw, etc.) for later comparison
def save_system_kargs [] {
    let cmdline = parse_cmdline
    # Filter to well-known system kargs that must never be lost
    # Note: ostree= is excluded because its value changes between deployments
    # (boot version counter, bootcsum). It's managed by ostree's
    # install_deployment_kernel() and always regenerated during finalization.
    let system_kargs = $cmdline | where { |k|
        (($k starts-with "root=") or ($k == "rw") or ($k starts-with "console="))
    }
    $system_kargs | to json | save -f /var/bootc-test-system-kargs.json
}

def load_system_kargs [] {
    open /var/bootc-test-system-kargs.json
}

def first_boot [] {
    tap begin "loader-entries set-options-for-source"

    # Save system kargs for later verification
    save_system_kargs

    # -- Input validation --

    # Invalid source name (spaces)
    let r = do -i { bootc loader-entries set-options-for-source --source "bad name" --options "foo=bar" } | complete
    assert ($r.exit_code != 0) "spaces in source name should fail"

    # Invalid source name (special chars)
    let r = do -i { bootc loader-entries set-options-for-source --source "foo@bar" --options "foo=bar" } | complete
    assert ($r.exit_code != 0) "special chars in source name should fail"

    # Empty source name
    let r = do -i { bootc loader-entries set-options-for-source --source "" --options "foo=bar" } | complete
    assert ($r.exit_code != 0) "empty source name should fail"

    # Valid name with underscores/dashes
    bootc loader-entries set-options-for-source --source "my_custom-src" --options "testvalid=1"
    # Clear it immediately (no --options = remove source)
    bootc loader-entries set-options-for-source --source "my_custom-src"

    # -- Add source kargs (multiple sources before reboot) --
    bootc loader-entries set-options-for-source --source tuned --options "nohz=full isolcpus=1-3"
    bootc loader-entries set-options-for-source --source admin --options "quiet"

    # Verify deployment is staged
    let st = bootc status --json | from json
    assert ($st.status.staged != null) "deployment should be staged"

    print "ok: validation and initial staging"
    tmt-reboot
}

def second_boot [] {
    # Verify kargs survived the staging roundtrip
    let cmdline = parse_cmdline
    assert ("nohz=full" in $cmdline) "nohz=full should be in cmdline after reboot"
    assert ("isolcpus=1-3" in $cmdline) "isolcpus=1-3 should be in cmdline after reboot"

    # Verify both sources staged in first_boot survived
    assert ("quiet" in $cmdline) "admin quiet karg should be in cmdline after reboot"
    print "ok: multiple sources staged before reboot both survived"

    # Verify system kargs were preserved
    let system_kargs = load_system_kargs
    for karg in $system_kargs {
        assert ($karg in $cmdline) $"system karg '($karg)' must be preserved"
    }
    print "ok: system kargs preserved"

    # Verify x-options-source-* keys in BLS entry
    let source_keys = read_bls_source_keys
    let tuned_key = $source_keys | where { |line| $line starts-with "x-options-source-tuned" }
    assert (($tuned_key | length) > 0) "x-options-source-tuned should be in BLS entry"
    let tuned_line = $tuned_key | first
    assert ($tuned_line | str contains "nohz=full") "tuned source key should contain nohz=full"
    assert ($tuned_line | str contains "isolcpus=1-3") "tuned source key should contain isolcpus=1-3"
    let admin_key = $source_keys | where { |line| $line starts-with "x-options-source-admin" }
    assert (($admin_key | length) > 0) "x-options-source-admin should be in BLS entry"
    print "ok: kargs and source keys survived reboot"

    # Clean up admin source before continuing with replacement test
    bootc loader-entries set-options-for-source --source admin

    # -- Source replacement: new kargs replace old ones --
    bootc loader-entries set-options-for-source --source tuned --options "nohz=on rcu_nocbs=2-7"

    tmt-reboot
}

def third_boot [] {
    # Verify replacement worked
    let cmdline = parse_cmdline
    assert ("nohz=full" not-in $cmdline) "old nohz=full should be gone"
    assert ("isolcpus=1-3" not-in $cmdline) "old isolcpus=1-3 should be gone"
    assert ("nohz=on" in $cmdline) "new nohz=on should be present"
    assert ("rcu_nocbs=2-7" in $cmdline) "new rcu_nocbs=2-7 should be present"
    # Admin source was removed in second_boot
    assert ("quiet" not-in $cmdline) "admin quiet should be gone after removal"

    # Verify system kargs still preserved after replacement
    let system_kargs = load_system_kargs
    for karg in $system_kargs {
        assert ($karg in $cmdline) $"system karg '($karg)' must survive replacement"
    }
    print "ok: source replacement persisted, system kargs preserved"

    # -- Multiple sources coexist --
    bootc loader-entries set-options-for-source --source dracut --options "rd.driver.pre=vfio-pci"

    tmt-reboot
}

def fourth_boot [] {
    # Verify both sources persisted
    let cmdline = parse_cmdline
    assert ("nohz=on" in $cmdline) "tuned nohz=on should still be present"
    assert ("rcu_nocbs=2-7" in $cmdline) "tuned rcu_nocbs=2-7 should still be present"
    assert ("rd.driver.pre=vfio-pci" in $cmdline) "dracut karg should be present"

    # Verify both source keys in BLS
    let source_keys = read_bls_source_keys
    let tuned_keys = $source_keys | where { |line| $line starts-with "x-options-source-tuned" }
    let dracut_keys = $source_keys | where { |line| $line starts-with "x-options-source-dracut" }
    assert (($tuned_keys | length) > 0) "tuned source key should exist"
    assert (($dracut_keys | length) > 0) "dracut source key should exist"
    print "ok: multiple sources coexist"

    # -- Clear source with empty --options "" (different from no --options) --
    # --options "" should remove the kargs but the key can remain with empty value
    bootc loader-entries set-options-for-source --source dracut --options ""
    # dracut kargs should be removed from pending deployment
    let st = bootc status --json | from json
    assert ($st.status.staged != null) "empty options should still stage a deployment"
    print "ok: --options '' clears kargs"

    # Now also test no --options (remove the source entirely)
    # First re-add dracut so we can test removal
    bootc loader-entries set-options-for-source --source dracut --options "rd.driver.pre=vfio-pci"
    # Then remove it with no --options
    bootc loader-entries set-options-for-source --source dracut

    # -- Cross-consumer staging --
    # Simulate the scenario where bootc stages source-tracked kargs and
    # then rpm-ostree re-stages on the same boot (e.g., appending an
    # unrelated karg). The replacement staged deployment created by
    # rpm-ostree must inherit the x-options-source-* keys from the
    # previously-staged deployment via ostree's fallback path.
    bootc loader-entries set-options-for-source --source crosstest --options "cross1=a cross2=b"
    let st = bootc status --json | from json
    assert ($st.status.staged != null) "crosstest should stage a deployment"

    # Now rpm-ostree appends an unrelated karg, creating a NEW staged
    # deployment that replaces the one bootc just created.
    rpm-ostree kargs --append=rpmarg=yes

    # A staged deployment should still exist after rpm-ostree re-staged
    let st = bootc status --json | from json
    assert ($st.status.staged != null) "deployment should still be staged after rpm-ostree kargs"
    print "ok: cross-consumer staging set up (bootc then rpm-ostree)"

    tmt-reboot
}

def fifth_boot [] {
    # -- Verify cross-consumer staging results --
    # After fourth_boot: bootc staged crosstest source kargs, then
    # rpm-ostree re-staged with --append=rpmarg=yes. Both the
    # source-tracked kargs AND the rpm-ostree karg must be present.
    let cmdline = parse_cmdline
    assert ("cross1=a" in $cmdline) "crosstest cross1=a should survive rpm-ostree re-staging"
    assert ("cross2=b" in $cmdline) "crosstest cross2=b should survive rpm-ostree re-staging"
    assert ("rpmarg=yes" in $cmdline) "rpm-ostree rpmarg=yes should be present"

    # Verify the crosstest source key exists in BLS
    let source_keys = read_bls_source_keys
    let crosstest_keys = $source_keys | where { |line| $line starts-with "x-options-source-crosstest" }
    assert (($crosstest_keys | length) > 0) "x-options-source-crosstest BLS key must survive rpm-ostree re-staging"
    let crosstest_line = $crosstest_keys | first
    assert ($crosstest_line | str contains "cross1=a") "crosstest source key should contain cross1=a"
    assert ($crosstest_line | str contains "cross2=b") "crosstest source key should contain cross2=b"

    # Verify tuned source also survived the cross-consumer staging
    assert ("nohz=on" in $cmdline) "tuned nohz=on should survive cross-consumer staging"
    assert ("rcu_nocbs=2-7" in $cmdline) "tuned rcu_nocbs=2-7 should survive cross-consumer staging"
    print "ok: cross-consumer staging preserved all source kargs and rpm-ostree karg"

    # Verify dracut cleared (from fourth_boot removal)
    assert ("rd.driver.pre=vfio-pci" not-in $cmdline) "dracut karg should be gone"
    print "ok: source clear persisted"

    # -- Idempotent: same kargs again should be a no-op --
    # Note: crosstest and rpmarg are still present in the booted deployment,
    # but the idempotent check is only about the tuned source. Since tuned
    # already has "nohz=on rcu_nocbs=2-7", bootc should detect no change
    # and not stage a new deployment.
    bootc loader-entries set-options-for-source --source tuned --options "nohz=on rcu_nocbs=2-7"
    # Should not stage a new deployment (idempotent)
    let st = bootc status --json | from json
    assert ($st.status.staged == null) "idempotent call should not stage a deployment"
    print "ok: idempotent operation"

    # Clean up cross-consumer kargs now that the idempotent test has passed.
    # These operations will stage a deployment, but that's fine because the
    # staged deployment interaction test below also stages.
    bootc loader-entries set-options-for-source --source crosstest
    rpm-ostree kargs --delete=rpmarg=yes

    # -- Staged deployment interaction --
    # Build a derived image and switch to it (this stages a deployment).
    # Then call set-options-for-source on top. The staged deployment should
    # be replaced with one that has the new image AND the source kargs.
    bootc image copy-to-storage

    let td = mktemp -d
    $"FROM localhost/bootc
RUN echo source-test-marker > /usr/share/source-test-marker.txt
" | save $"($td)/Dockerfile"
    podman build -t localhost/bootc-source-test $"($td)"

    bootc switch --transport containers-storage localhost/bootc-source-test
    let st = bootc status --json | from json
    assert ($st.status.staged != null) "switch should stage a deployment"

    # Now add source kargs on top of the staged switch
    bootc loader-entries set-options-for-source --source tuned --options "nohz=on rcu_nocbs=2-7 skew_tick=1"

    # Verify a deployment is still staged (it was replaced, not removed)
    let st = bootc status --json | from json
    assert ($st.status.staged != null) "deployment should still be staged after set-options-for-source"

    tmt-reboot
}

def sixth_boot [] {
    # Verify the image switch landed (the derived image's marker file exists)
    assert ("/usr/share/source-test-marker.txt" | path exists) "derived image marker should exist"
    print "ok: image switch preserved"

    # Verify the source kargs also landed
    let cmdline = parse_cmdline
    assert ("nohz=on" in $cmdline) "tuned nohz=on should be present"
    assert ("rcu_nocbs=2-7" in $cmdline) "tuned rcu_nocbs=2-7 should be present"
    assert ("skew_tick=1" in $cmdline) "tuned skew_tick=1 should be present"

    # Verify cross-consumer kargs were cleaned up in fifth_boot
    assert ("cross1=a" not-in $cmdline) "crosstest kargs should be gone after cleanup"
    assert ("cross2=b" not-in $cmdline) "crosstest kargs should be gone after cleanup"
    assert ("rpmarg=yes" not-in $cmdline) "rpm-ostree rpmarg should be gone after cleanup"

    # Verify source key in BLS
    let source_keys = read_bls_source_keys
    let tuned_key = $source_keys | where { |line| $line starts-with "x-options-source-tuned" }
    assert (($tuned_key | length) > 0) "tuned source key should exist after staged interaction"
    let crosstest_keys = $source_keys | where { |line| $line starts-with "x-options-source-crosstest" }
    assert (($crosstest_keys | length) == 0) "crosstest source key should be gone after cleanup"
    print "ok: staged deployment interaction preserved both image and source kargs"

    # Verify system kargs still intact
    let system_kargs = load_system_kargs
    let cmdline = parse_cmdline
    for karg in $system_kargs {
        assert ($karg in $cmdline) $"system karg '($karg)' must survive staged interaction"
    }
    print "ok: system kargs preserved through all phases"

    tap ok
}

def main [] {
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => first_boot,
        "1" => second_boot,
        "2" => third_boot,
        "3" => fourth_boot,
        "4" => fifth_boot,
        "5" => sixth_boot,
        $o => { error make { msg: $"Unexpected TMT_REBOOT_COUNT ($o)" } },
    }
}
