# number: 43
# tmt:
#   summary: Test bootc loader-entries set-options-for-source on composefs
#   duration: 30m
#
# This test verifies source-tracked kernel argument management on composefs-
# booted systems. The composefs path directly modifies BLS entry files on
# /boot rather than staging a new ostree deployment. It covers:
# 1. Input validation (invalid/empty source names)
# 2. Adding source-tracked kargs and verifying they appear in /proc/cmdline
# 3. Source keys (x-options-source-*) in BLS entry files
# 4. Source replacement semantics (old kargs removed, new ones added)
# 5. Multiple sources coexisting independently
# 6. Source removal (--source without --options clears all owned kargs)
# 7. Idempotent operation (no changes when kargs already match)
# 8. Existing system kargs preserved through changes
#
# This test is composefs-specific. It exits 0 (skip) on ostree-booted systems.
# The UKI boot type is also skipped since kargs are embedded in the PE binary.
#
# See: https://github.com/bootc-dev/bootc/issues/899
use std assert
use tap.nu

# Skip if not composefs-booted
if not (tap is_composefs) {
    print "Not a composefs system, skipping"
    exit 0
}

# Skip if UKI boot type — kargs are embedded in the PE binary
let st = bootc status --json | from json
let boot_type = $st.status.booted.composefs?.bootType? | default "bls"
if ($boot_type | str downcase) == "uki" {
    print "UKI boot type, skipping (kargs embedded in PE binary)"
    exit 0
}

def parse_cmdline [] {
    open /proc/cmdline | str trim | split row " "
}

# Read x-options-source-* keys from the booted BLS entry.
# On composefs, entries are named bootc_*.conf (not ostree-*.conf).
def read_bls_source_keys [] {
    let entries = glob /boot/loader/entries/bootc_*.conf | sort
    if ($entries | length) == 0 {
        error make { msg: "No composefs BLS entries found" }
    }
    let entry = open ($entries | last)
    $entry | lines | where { |line| $line starts-with "x-options-source-" }
}

# Save the current system kargs for later comparison
def save_system_kargs [] {
    let cmdline = parse_cmdline
    let system_kargs = $cmdline | where { |k|
        (($k starts-with "root=") or ($k == "rw") or ($k starts-with "console="))
    }
    $system_kargs | to json | save -f /var/bootc-test-system-kargs.json
}

def load_system_kargs [] {
    open /var/bootc-test-system-kargs.json
}

def first_boot [] {
    tap begin "composefs loader-entries set-options-for-source"

    save_system_kargs

    # -- Input validation (same as ostree test) --

    let r = do -i { bootc loader-entries set-options-for-source --source "bad name" --options "foo=bar" } | complete
    assert ($r.exit_code != 0) "spaces in source name should fail"

    let r = do -i { bootc loader-entries set-options-for-source --source "foo@bar" --options "foo=bar" } | complete
    assert ($r.exit_code != 0) "special chars in source name should fail"

    let r = do -i { bootc loader-entries set-options-for-source --source "" --options "foo=bar" } | complete
    assert ($r.exit_code != 0) "empty source name should fail"

    # Valid name with underscores/dashes
    bootc loader-entries set-options-for-source --source "my_custom-src" --options "testvalid=1"
    # Clear it immediately
    bootc loader-entries set-options-for-source --source "my_custom-src"

    # -- Add source kargs --
    # On composefs, this directly modifies the BLS entry (no staging)
    bootc loader-entries set-options-for-source --source tuned --options "nohz=full isolcpus=1-3"

    # Verify the BLS entry was updated immediately (composefs writes directly)
    let source_keys = read_bls_source_keys
    let tuned_key = $source_keys | where { |line| $line starts-with "x-options-source-tuned" }
    assert (($tuned_key | length) > 0) "x-options-source-tuned should be in BLS entry immediately"
    print "ok: source key written to BLS entry"

    # Add a second source
    bootc loader-entries set-options-for-source --source admin --options "quiet"

    # Verify both source keys present
    let source_keys = read_bls_source_keys
    let admin_key = $source_keys | where { |line| $line starts-with "x-options-source-admin" }
    assert (($admin_key | length) > 0) "x-options-source-admin should be in BLS entry"
    print "ok: multiple sources written"

    print "ok: validation and initial BLS update"
    tmt-reboot
}

def second_boot [] {
    # Verify kargs survived reboot
    let cmdline = parse_cmdline
    assert ("nohz=full" in $cmdline) "nohz=full should be in cmdline after reboot"
    assert ("isolcpus=1-3" in $cmdline) "isolcpus=1-3 should be in cmdline after reboot"
    assert ("quiet" in $cmdline) "admin quiet karg should be in cmdline after reboot"
    print "ok: kargs survived reboot"

    # Verify system kargs preserved
    let system_kargs = load_system_kargs
    for karg in $system_kargs {
        assert ($karg in $cmdline) $"system karg '($karg)' must be preserved"
    }
    print "ok: system kargs preserved"

    # Verify source keys in BLS entry
    let source_keys = read_bls_source_keys
    let tuned_key = $source_keys | where { |line| $line starts-with "x-options-source-tuned" }
    assert (($tuned_key | length) > 0) "x-options-source-tuned should be in BLS entry"
    let tuned_line = $tuned_key | first
    assert ($tuned_line | str contains "nohz=full") "tuned source key should contain nohz=full"
    assert ($tuned_line | str contains "isolcpus=1-3") "tuned source key should contain isolcpus=1-3"
    print "ok: source keys persisted across reboot"

    # -- Source replacement: new kargs replace old ones --
    # Clean up admin source first
    bootc loader-entries set-options-for-source --source admin

    # Replace tuned kargs
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
    assert ("quiet" not-in $cmdline) "admin quiet should be gone after removal"

    # Verify system kargs still preserved
    let system_kargs = load_system_kargs
    for karg in $system_kargs {
        assert ($karg in $cmdline) $"system karg '($karg)' must survive replacement"
    }
    print "ok: source replacement persisted, system kargs preserved"

    # -- Multiple sources coexist --
    bootc loader-entries set-options-for-source --source dracut --options "rd.driver.pre=vfio-pci"

    # -- Idempotent: same kargs again should be a no-op --
    # On composefs, idempotency means the BLS file is not rewritten
    bootc loader-entries set-options-for-source --source tuned --options "nohz=on rcu_nocbs=2-7"
    # (No easy way to detect no-write on composefs, but the command should succeed silently)
    print "ok: idempotent operation succeeded"

    # -- Source removal --
    bootc loader-entries set-options-for-source --source dracut

    # Verify dracut removed, tuned preserved (check BLS immediately)
    let source_keys = read_bls_source_keys
    let dracut_keys = $source_keys | where { |line| $line starts-with "x-options-source-dracut" }
    assert (($dracut_keys | length) == 0) "dracut source key should be gone after removal"
    let tuned_keys = $source_keys | where { |line| $line starts-with "x-options-source-tuned" }
    assert (($tuned_keys | length) > 0) "tuned source key should still exist"
    print "ok: source removal and coexistence verified"

    tmt-reboot
}

def fourth_boot [] {
    # Final verification after reboot
    let cmdline = parse_cmdline
    assert ("rd.driver.pre=vfio-pci" not-in $cmdline) "dracut karg should be gone"
    assert ("nohz=on" in $cmdline) "tuned nohz=on should still be present"
    assert ("rcu_nocbs=2-7" in $cmdline) "tuned rcu_nocbs=2-7 should still be present"

    # Verify system kargs intact through all phases
    let system_kargs = load_system_kargs
    for karg in $system_kargs {
        assert ($karg in $cmdline) $"system karg '($karg)' must survive all phases"
    }
    print "ok: all phases completed, system kargs preserved"

    tap ok
}

def main [] {
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => first_boot,
        "1" => second_boot,
        "2" => third_boot,
        "3" => fourth_boot,
        $o => { error make { msg: $"Unexpected TMT_REBOOT_COUNT ($o)" } },
    }
}
