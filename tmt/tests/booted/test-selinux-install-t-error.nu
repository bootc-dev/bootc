# number: 71
# tmt:
#   summary: Verify bootc explains a failure to enter install_t and logs it to the journal
#   duration: 10m
#   adjust:
#     - when: running_env != image_mode
#       enabled: false
#       because: these tests require features only available in image mode
# extra:
#   fixme_skip_if_composefs: true
#
# A wrapper script in a systemd unit runs as unconfined_service_t, so bootc
# re-executes a relabeled copy of itself from $TMPDIR, which fails on a noexec
# mount.
use std assert
use tap.nu

if not ("/sys/fs/selinux/enforce" | path exists) or ((open /sys/fs/selinux/enforce | str trim) != "1") {
    print "Skipping, SELinux is not enforcing"
    return
}

const message_id = "6ef49a449e1140d8835ada26ce80e0b9"
const wrapper = "/run/bootc-test-wrapper.sh"
const noexec_tmpdir = "/run/bootc-test-noexec-tmp"

tap begin "bootc explains a failure to enter install_t"

mkdir $noexec_tmpdir
^mount -t tmpfs -o noexec,nosuid,nodev tmpfs $noexec_tmpdir
"#!/bin/bash
exec bootc status --format=json
" | save --force $wrapper
chmod 0755 $wrapper
^chcon -t bin_t $wrapper

let r = ^systemd-run --wait --pipe --quiet --collect $"--setenv=TMPDIR=($noexec_tmpdir)" $wrapper | complete
print $"stderr: ($r.stderr)"
assert ($r.exit_code != 0) "Expected wrapped bootc status to fail; does the base policy now include the unconfined_service_t -> install_t transition?"
assert ($r.stderr | str contains "without install_t") $"Expected the install_t explanation, got: ($r.stderr)"
assert ($r.stderr | str contains "execve: Permission denied") $"Expected the execve failure, got: ($r.stderr)"

let entries = ^journalctl -b -o json $"MESSAGE_ID=($message_id)" | lines | each { from json }
assert (($entries | length) > 0) $"Expected a journal entry with MESSAGE_ID=($message_id)"
let entry = $entries | last
assert ($entry.BOOTC_SELINUX_CONTEXT | str contains "unconfined_service_t") $"Expected BOOTC_SELINUX_CONTEXT to name the domain, got: ($entry.BOOTC_SELINUX_CONTEXT)"
assert equal $entry.PRIORITY "3"

tap ok
