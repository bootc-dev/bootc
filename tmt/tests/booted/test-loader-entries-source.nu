# number: 42
# tmt:
#   summary: Test bootc loader-entries set-options-for-source
#   duration: 45m
#
# This test verifies the source-tracked kernel argument management via
# bootc loader-entries set-options-for-source on both the ostree and the
# composefs backend. It covers:
# 1. Input validation (invalid/empty source names)
# 2. Adding source-tracked kargs and verifying they appear in /proc/cmdline
# 3. Kargs and x-options-source-* BLS keys surviving the staging roundtrip
# 4. `bootc rollback` boots without the change, and re-applying it works
# 5. Source replacement semantics (old kargs removed, new ones added)
# 6. Multiple sources coexisting independently
# 7. Source removal (--source without --options clears all owned kargs)
# 8. Idempotent operation (no changes when kargs already match)
# 9. Existing system kargs (root=, ostree=, composefs=, etc.) preserved
# 10. --options "" (empty string) clears kargs without removing the source
# 11. Staged deployment interaction (bootc switch + set-options-for-source
#     preserves the pending image switch and the source's ownership key)
# 12. ostree only: cross-consumer staging (bootc stages source kargs, then
#     rpm-ostree re-stages on the same boot via kargs --append; the
#     x-options-source-* keys must survive in the replacement staged
#     deployment, see ostreedev/ostree#3611)
#
# On ostree this requires bootconfig-extra support (ostree >= 2026.1).
# On composefs the UKI boot type is skipped since the kargs are embedded in
# the PE binary.
# See: https://github.com/ostreedev/ostree/pull/3570
# See: https://github.com/ostreedev/ostree/pull/3611
# See: https://github.com/bootc-dev/bootc/issues/899
use std assert
use tap.nu

let composefs = tap is_composefs

if $composefs {
    let st = bootc status --json | from json
    let boot_type = $st.status.booted.composefs?.bootType? | default "bls"
    if ($boot_type | str downcase) == "uki" {
        print "UKI boot type, skipping (kargs embedded in PE binary)"
        exit 0
    }
} else {
    let is_bad_version = ostree --version | lines | any {|l| $l | str contains "2026.2" }
    if $is_bad_version {
        print "Found Ostree v2026.2, skipping test"
        exit 0
    }
}

def parse_cmdline [] {
    open /proc/cmdline | str trim | split row " "
}

# The BLS entry the kernel was booted from.  Its options are all on the
# command line (the bootloader only adds to it); take the largest such set,
# because a kernel-argument change on composefs keeps the deployment's
# previous entry as its rollback and that one differs only by the arguments
# it lacks.  The boot partition is not necessarily mounted at /boot on
# composefs systems, so look under /sysroot/boot as well.
def booted_bls_entry [] {
    let cmdline = parse_cmdline
    let entries = if (tap is_composefs) {
        [/boot/loader/entries /sysroot/boot/loader/entries]
            | each { |d| glob $"($d)/bootc_*.conf" }
            | flatten
    } else {
        glob /boot/loader/entries/ostree-*.conf
    }
    let matching = $entries | each { |e|
        let options = open $e
            | lines
            | where { |line| $line starts-with "options " }
            | first
            | str replace "options " ""
            | str trim
            | split row " "
        if ($options | all { |o| $o in $cmdline }) {
            { path: $e, score: ($options | length) }
        } else {
            null
        }
    } | compact
    if ($matching | is-empty) {
        error make { msg: "No BLS entry matches /proc/cmdline" }
    }
    $matching | sort-by score | last | get path
}

# The x-options-source-* lines of the booted BLS entry
def read_bls_source_keys [] {
    open (booted_bls_entry) | lines | where { |line| $line starts-with "x-options-source-" }
}

# Value of an x-options-source-* line, or "" for a tombstoned source.
def source_key_value [line: string] {
    $line | str replace --regex '^x-options-source-\S+\s*' '' | str trim
}

# The x-options-source-* lines for one source
def source_keys [name: string] {
    read_bls_source_keys | where { |line| $line starts-with $"x-options-source-($name)" }
}

# Whether `name` owns nothing: removed on composefs, tombstoned on ostree
def assert_source_gone [name: string] {
    let keys = source_keys $name
    if (tap is_composefs) {
        assert (($keys | length) == 0) $"($name) source key should be gone"
    } else {
        assert (($keys | length) == 1) $"($name) source key should remain as a tombstone"
        assert ((source_key_value ($keys | first)) == "") $"($name) source key should be empty"
    }
}

# Save the current system kargs (root=, rw, etc.) for later comparison.
# The ostree= / composefs= arguments are excluded because they change
# between deployments.
def save_system_kargs [] {
    let cmdline = parse_cmdline
    let system_kargs = $cmdline | where { |k|
        (($k starts-with "root=") or ($k == "rw") or ($k starts-with "console="))
    }
    $system_kargs | to json | save -f /var/bootc-test-system-kargs.json
}

def assert_system_kargs [phase: string] {
    let cmdline = parse_cmdline
    for karg in (open /var/bootc-test-system-kargs.json) {
        assert ($karg in $cmdline) $"system karg '($karg)' must survive ($phase)"
    }
}

def assert_staged [expected: bool, msg: string] {
    let st = bootc status --json | from json
    assert (($st.status.staged != null) == $expected) $msg
}

def first_boot [] {
    tap begin "loader-entries set-options-for-source"

    save_system_kargs

    # -- Input validation --
    let r = do -i { bootc loader-entries set-options-for-source --source "bad name" --options "foo=bar" } | complete
    assert ($r.exit_code != 0) "spaces in source name should fail"

    let r = do -i { bootc loader-entries set-options-for-source --source "foo@bar" --options "foo=bar" } | complete
    assert ($r.exit_code != 0) "special chars in source name should fail"

    let r = do -i { bootc loader-entries set-options-for-source --source "" --options "foo=bar" } | complete
    assert ($r.exit_code != 0) "empty source name should fail"

    # Valid name with underscores/dashes, then clear it (no --options = remove source)
    bootc loader-entries set-options-for-source --source "my_custom-src" --options "testvalid=1"
    bootc loader-entries set-options-for-source --source "my_custom-src"

    # -- Add source kargs (multiple sources before reboot) --
    bootc loader-entries set-options-for-source --source tuned --options "nohz=full isolcpus=1-3"
    bootc loader-entries set-options-for-source --source admin --options "quiet"

    assert_staged true "deployment should be staged"

    print "ok: validation and initial staging"
    tmt-reboot
}

def second_boot [] {
    let cmdline = parse_cmdline
    assert ("nohz=full" in $cmdline) "nohz=full should be in cmdline after reboot"
    assert ("isolcpus=1-3" in $cmdline) "isolcpus=1-3 should be in cmdline after reboot"
    assert ("quiet" in $cmdline) "admin quiet karg should be in cmdline after reboot"
    print "ok: multiple sources staged before reboot both survived"

    assert_system_kargs "the staging roundtrip"

    let tuned_keys = source_keys tuned
    assert (($tuned_keys | length) > 0) "x-options-source-tuned should be in BLS entry"
    let tuned_line = $tuned_keys | first
    assert ($tuned_line | str contains "nohz=full") "tuned source key should contain nohz=full"
    assert ($tuned_line | str contains "isolcpus=1-3") "tuned source key should contain isolcpus=1-3"
    assert ((source_keys admin | length) > 0) "x-options-source-admin should be in BLS entry"
    print "ok: kargs and source keys survived reboot"

    # -- Rollback: the previous entry, without the change, is the rollback --
    let st = bootc status --json | from json
    assert ($st.status.rollback != null) "kargs change must leave a rollback"
    bootc rollback
    let st = bootc status --json | from json
    assert ($st.status.rollbackQueued == true) "rollback should be queued"
    print "ok: rollback queued"

    tmt-reboot
}

def third_boot [] {
    let cmdline = parse_cmdline
    assert ("nohz=full" not-in $cmdline) "nohz=full must be gone after rollback"
    assert ("isolcpus=1-3" not-in $cmdline) "isolcpus=1-3 must be gone after rollback"
    assert ("quiet" not-in $cmdline) "quiet must be gone after rollback"
    assert ((source_keys tuned | length) == 0) "rolled back entry must not have the tuned key"
    assert ((source_keys admin | length) == 0) "rolled back entry must not have the admin key"
    assert_system_kargs "rollback"

    let st = bootc status --json | from json
    assert ($st.status.rollback != null) "the kargs entry should now be the rollback"
    print "ok: rollback booted without the source kargs"

    # Re-apply and continue with the change in place
    bootc loader-entries set-options-for-source --source tuned --options "nohz=full isolcpus=1-3"
    bootc loader-entries set-options-for-source --source admin --options "quiet"
    assert_staged true "re-applied kargs should be staged"

    tmt-reboot
}

def fourth_boot [] {
    let cmdline = parse_cmdline
    assert ("nohz=full" in $cmdline) "nohz=full should be back after re-applying"
    assert ("isolcpus=1-3" in $cmdline) "isolcpus=1-3 should be back after re-applying"
    assert ("quiet" in $cmdline) "quiet should be back after re-applying"
    assert ((source_keys tuned | length) > 0) "tuned source key should be back"
    print "ok: re-applied kargs and keys survived reboot"

    # Clean up admin source before continuing with replacement test
    bootc loader-entries set-options-for-source --source admin

    # -- Source replacement: new kargs replace old ones --
    bootc loader-entries set-options-for-source --source tuned --options "nohz=on rcu_nocbs=2-7"

    tmt-reboot
}

def fifth_boot [] {
    let cmdline = parse_cmdline
    assert ("nohz=full" not-in $cmdline) "old nohz=full should be gone"
    assert ("isolcpus=1-3" not-in $cmdline) "old isolcpus=1-3 should be gone"
    assert ("nohz=on" in $cmdline) "new nohz=on should be present"
    assert ("rcu_nocbs=2-7" in $cmdline) "new rcu_nocbs=2-7 should be present"
    assert ("quiet" not-in $cmdline) "admin quiet should be gone after removal"
    assert_system_kargs "replacement"
    print "ok: source replacement persisted, system kargs preserved"

    # -- Multiple sources coexist --
    bootc loader-entries set-options-for-source --source dracut --options "rd.driver.pre=vfio-pci"

    tmt-reboot
}

def sixth_boot [] {
    let cmdline = parse_cmdline
    assert ("nohz=on" in $cmdline) "tuned nohz=on should still be present"
    assert ("rcu_nocbs=2-7" in $cmdline) "tuned rcu_nocbs=2-7 should still be present"
    assert ("rd.driver.pre=vfio-pci" in $cmdline) "dracut karg should be present"
    assert ((source_keys tuned | length) > 0) "tuned source key should exist"
    assert ((source_keys dracut | length) > 0) "dracut source key should exist"
    print "ok: multiple sources coexist"

    # -- Clear source with empty --options "" (different from no --options) --
    # --options "" removes the kargs but the key can remain with an empty value
    bootc loader-entries set-options-for-source --source dracut --options ""
    assert_staged true "empty options should still stage a deployment"
    print "ok: --options '' clears kargs"

    # Now also test no --options (remove the source entirely)
    bootc loader-entries set-options-for-source --source dracut --options "rd.driver.pre=vfio-pci"
    bootc loader-entries set-options-for-source --source dracut

    if not (tap is_composefs) {
        # -- Cross-consumer staging --
        # bootc stages source-tracked kargs and then rpm-ostree re-stages on
        # the same boot, appending an unrelated karg.  The replacement staged
        # deployment must inherit the x-options-source-* keys from the
        # previously staged one via ostree's fallback path.
        bootc loader-entries set-options-for-source --source crosstest --options "cross1=a cross2=b"
        assert_staged true "crosstest should stage a deployment"

        rpm-ostree kargs --append=rpmarg=yes
        assert_staged true "deployment should still be staged after rpm-ostree kargs"
        print "ok: cross-consumer staging set up (bootc then rpm-ostree)"
    }

    tmt-reboot
}

def seventh_boot [] {
    let cmdline = parse_cmdline

    if not (tap is_composefs) {
        assert ("cross1=a" in $cmdline) "crosstest cross1=a should survive rpm-ostree re-staging"
        assert ("cross2=b" in $cmdline) "crosstest cross2=b should survive rpm-ostree re-staging"
        assert ("rpmarg=yes" in $cmdline) "rpm-ostree rpmarg=yes should be present"

        let crosstest_keys = source_keys crosstest
        assert (($crosstest_keys | length) > 0) "x-options-source-crosstest BLS key must survive rpm-ostree re-staging"
        let crosstest_line = $crosstest_keys | first
        assert ($crosstest_line | str contains "cross1=a") "crosstest source key should contain cross1=a"
        assert ($crosstest_line | str contains "cross2=b") "crosstest source key should contain cross2=b"
        print "ok: cross-consumer staging preserved all source kargs and rpm-ostree karg"
    }

    assert ("nohz=on" in $cmdline) "tuned nohz=on should still be present"
    assert ("rcu_nocbs=2-7" in $cmdline) "tuned rcu_nocbs=2-7 should still be present"
    assert ("rd.driver.pre=vfio-pci" not-in $cmdline) "dracut karg should be gone"
    assert_source_gone dracut
    print "ok: source clear persisted"

    # -- Idempotent: same kargs again should be a no-op --
    # tuned already has "nohz=on rcu_nocbs=2-7", so nothing is staged even
    # though other arguments follow its own on the options line.
    bootc loader-entries set-options-for-source --source tuned --options "nohz=on rcu_nocbs=2-7"
    assert_staged false "idempotent call should not stage a deployment"
    print "ok: idempotent operation"

    if not (tap is_composefs) {
        # Clean up the cross-consumer kargs.  These stage a deployment, and
        # the image switch below re-stages on top of it: the switch must
        # build on the staged kargs, not the booted ones, or this removal
        # would be silently undone (verified in eighth_boot).
        bootc loader-entries set-options-for-source --source crosstest
        rpm-ostree kargs --delete=rpmarg=yes
    }

    # -- Staged deployment interaction --
    # Switch to a derived image (this stages a deployment), then change a
    # source on top.  The staged deployment must keep the new image and get
    # the new kargs, and its entry must carry the x-options-source-tuned key;
    # without the latter, tuned's kargs could never be removed again.
    bootc image copy-to-storage

    let td = mktemp -d
    $"FROM localhost/bootc
RUN echo source-test-marker > /usr/share/source-test-marker.txt
" | save $"($td)/Dockerfile"
    podman build -t localhost/bootc-source-test $"($td)"

    bootc switch --transport containers-storage localhost/bootc-source-test
    assert_staged true "switch should stage a deployment"

    bootc loader-entries set-options-for-source --source tuned --options "nohz=on rcu_nocbs=2-7 skew_tick=1"
    assert_staged true "deployment should still be staged after set-options-for-source"

    tmt-reboot
}

def eighth_boot [] {
    let marker = open /usr/share/source-test-marker.txt | str trim
    assert equal $marker "source-test-marker"
    print "ok: image switch preserved"

    let cmdline = parse_cmdline
    assert ("nohz=on" in $cmdline) "tuned nohz=on should be present"
    assert ("rcu_nocbs=2-7" in $cmdline) "tuned rcu_nocbs=2-7 should be present"
    assert ("skew_tick=1" in $cmdline) "tuned skew_tick=1 should be present"

    if not (tap is_composefs) {
        assert ("cross1=a" not-in $cmdline) "crosstest kargs should be gone after cleanup"
        assert ("cross2=b" not-in $cmdline) "crosstest kargs should be gone after cleanup"
        assert ("rpmarg=yes" not-in $cmdline) "rpm-ostree rpmarg should be gone after cleanup"
        assert_source_gone crosstest
    }

    let tuned_keys = source_keys tuned
    assert (($tuned_keys | length) > 0) "x-options-source-tuned must be carried into the new entry"
    let tuned_val = source_key_value ($tuned_keys | first)
    assert ($tuned_val | str contains "skew_tick=1") $"tuned key should own skew_tick=1, got '($tuned_val)'"
    assert_system_kargs "the staged interaction"
    print "ok: staged deployment interaction preserved both image and source kargs"

    # Remove the source: this only works if its key was carried into the
    # new entry.
    bootc loader-entries set-options-for-source --source tuned
    assert_staged true "source removal should stage a deployment"

    tmt-reboot
}

def ninth_boot [] {
    let cmdline = parse_cmdline
    assert ("nohz=on" not-in $cmdline) "tuned nohz=on should be gone after removal"
    assert ("rcu_nocbs=2-7" not-in $cmdline) "tuned rcu_nocbs=2-7 should be gone after removal"
    assert ("skew_tick=1" not-in $cmdline) "tuned skew_tick=1 should be gone after removal"
    assert_source_gone tuned
    assert_system_kargs "all phases"
    print "ok: source removal after switch persisted, system kargs preserved"

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
        "6" => seventh_boot,
        "7" => eighth_boot,
        "8" => ninth_boot,
        $o => { error make { msg: $"Unexpected TMT_REBOOT_COUNT ($o)" } },
    }
}
