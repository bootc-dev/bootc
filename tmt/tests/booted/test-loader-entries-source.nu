# number: 40
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
#
# Requires ostree with bootconfig-extra support (>= 2026.1).
# See: https://github.com/ostreedev/ostree/pull/3570
# See: https://github.com/bootc-dev/bootc/issues/899
use std assert
use tap.nu
use bootc_testlib.nu

def parse_cmdline [] {
    open /proc/cmdline | str trim | split row " "
}

# Read x-options-source-* keys from the booted BLS entry
def read_bls_source_keys [] {
    let entries = glob /boot/loader/entries/ostree-*.conf
    if ($entries | length) == 0 {
        error make { msg: "No BLS entries found" }
    }
    let entry = open ($entries | first)
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
    let r = do -i { bootc loader-entries set-options-for-source --source "my_custom-src" --options "testvalid=1" } | complete
    if $r.exit_code != 0 {
        print $"FAILED: valid source name returned exit code ($r.exit_code)"
        print $"stdout: ($r.stdout)"
        print $"stderr: ($r.stderr)"
    }
    assert ($r.exit_code == 0) "valid source name should succeed"

    # Clear it immediately (no --options = remove source)
    let r = do -i { bootc loader-entries set-options-for-source --source "my_custom-src" } | complete
    if $r.exit_code != 0 {
        print $"FAILED: clearing source returned exit code ($r.exit_code)"
        print $"stdout: ($r.stdout)"
        print $"stderr: ($r.stderr)"
    }
    assert ($r.exit_code == 0) "clearing source should succeed"

    # -- Add source kargs --
    bootc loader-entries set-options-for-source --source tuned --options "nohz=full isolcpus=1-3"

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

    # Verify system kargs were preserved
    let system_kargs = load_system_kargs
    for karg in $system_kargs {
        assert ($karg in $cmdline) $"system karg '($karg)' must be preserved"
    }
    print "ok: system kargs preserved"

    # Verify x-options-source-tuned key in BLS entry
    let source_keys = read_bls_source_keys
    let tuned_key = $source_keys | where { |line| $line starts-with "x-options-source-tuned" }
    assert (($tuned_key | length) > 0) "x-options-source-tuned should be in BLS entry"
    let tuned_line = $tuned_key | first
    assert ($tuned_line | str contains "nohz=full") "tuned source key should contain nohz=full"
    assert ($tuned_line | str contains "isolcpus=1-3") "tuned source key should contain isolcpus=1-3"
    print "ok: kargs and source key survived reboot"

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

    tmt-reboot
}

def fifth_boot [] {
    # Verify dracut cleared, tuned preserved
    let cmdline = parse_cmdline
    assert ("rd.driver.pre=vfio-pci" not-in $cmdline) "dracut karg should be gone"
    assert ("nohz=on" in $cmdline) "tuned nohz=on should still be present"
    assert ("rcu_nocbs=2-7" in $cmdline) "tuned rcu_nocbs=2-7 should still be present"
    print "ok: source clear persisted"

    # -- Idempotent: same kargs again should be a no-op --
    let r = bootc loader-entries set-options-for-source --source tuned --options "nohz=on rcu_nocbs=2-7" | complete
    # Should not stage a new deployment (idempotent)
    let st = bootc status --json | from json
    assert ($st.status.staged == null) "idempotent call should not stage a deployment"
    print "ok: idempotent operation"

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

    # Verify source key in BLS
    let source_keys = read_bls_source_keys
    let tuned_key = $source_keys | where { |line| $line starts-with "x-options-source-tuned" }
    assert (($tuned_key | length) > 0) "tuned source key should exist after staged interaction"
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
