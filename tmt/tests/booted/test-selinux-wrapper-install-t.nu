# number: 68
# tmt:
#   summary: Verify a policy module lets bootc enter install_t from a wrapper service
#   duration: 30m
#   adjust:
#     - when: running_env != image_mode
#       enabled: false
#       because: these tests require features only available in image mode
# extra:
#   fixme_skip_if_composefs: true
#
# When systemd runs bootc via a wrapper (e.g. a shell script in ExecStart=),
# the wrapper runs as unconfined_service_t. The base policy has no transition
# from there to install_t when executing /usr/bin/bootc (install_exec_t), so
# bootc falls back to re-executing a relabeled copy of itself from $TMPDIR.
# If $TMPDIR is mounted noexec (as e.g. the DISA STIG requires for /tmp), that
# fails with "execve: Permission denied".
#
# This test verifies that failure on the base image, then verifies that adding
# a small policy module in a derived image fixes it. The module is also the
# workaround users can ship in their own derived images until the base policy
# includes these rules.
#
# See https://github.com/bootc-dev/bootc/issues/2186
# and https://github.com/fedora-selinux/selinux-policy/pull/3327
use std assert
use tap.nu

if not ("/sys/fs/selinux/enforce" | path exists) or ((open /sys/fs/selinux/enforce | str trim) != "1") {
    print "Skipping, SELinux is not enforcing"
    return
}

# This code runs on *each* boot.
# Here we just capture information.
bootc status

const wrapper = "/run/bootc-test-wrapper.sh"
const noexec_tmpdir = "/run/bootc-test-noexec-tmp"

# The policy module: allow wrapper domains to transition to install_t when
# executing install_exec_t binaries (bootc, ostree), mirroring the existing
# init_t and unconfined_t transitions. Written in CIL so that installing it
# needs only semodule, not checkpolicy.
const policy_module = "(typetransition unconfined_service_t install_exec_t process install_t)
(allow unconfined_service_t install_t (process (transition)))
(allow install_t unconfined_service_t (process (sigchld)))
(typetransition initrc_t install_exec_t process install_t)
(allow initrc_t install_t (process (transition)))
(allow install_t initrc_t (process (sigchld)))
"

# Run `bootc status` from a wrapper script in a transient systemd service,
# with TMPDIR on a noexec tmpfs. Returns the `complete` record.
def run_wrapped_bootc_status [] {
    mkdir $noexec_tmpdir
    if (^findmnt -n $noexec_tmpdir | complete).exit_code != 0 {
        ^mount -t tmpfs -o noexec,nosuid,nodev tmpfs $noexec_tmpdir
    }

    # Print the wrapper's own SELinux context to stderr so we can verify the
    # test exercises the intended domain.
    "#!/bin/bash
set -euo pipefail
echo \"wrapper-context: $(cat /proc/$$/attr/current | tr -d '\\0')\" >&2
exec bootc status --format=json
" | save --force $wrapper
    chmod 0755 $wrapper
    # Label it like a regular executable (e.g. a script in /usr/libexec), so
    # systemd runs it as unconfined_service_t.
    ^chcon -t bin_t $wrapper

    let r = ^systemd-run --wait --pipe --quiet --collect $"--setenv=TMPDIR=($noexec_tmpdir)" $wrapper | complete
    print $"exit code: ($r.exit_code)"
    print $"stderr: ($r.stderr)"
    assert ($r.stderr | str contains "unconfined_service_t") $"Expected wrapper to run as unconfined_service_t, stderr: ($r.stderr)"
    $r
}

# Run on the first boot
def initial_build [] {
    tap begin "bootc from a wrapper service fails without the policy module"

    # Crosscheck that the base image reproduces the failure. Once the base
    # policy includes the transition (see the selinux-policy PR above), this
    # starts failing and the test should be updated.
    let r = run_wrapped_bootc_status
    assert ($r.exit_code != 0) "Expected wrapped bootc status to fail on the base image; does the base policy now include the unconfined_service_t -> install_t transition?"
    assert ($r.stderr | str contains "execve: Permission denied") $"Expected execve failure, got: ($r.stderr)"

    let td = mktemp -d
    cd $td

    bootc image copy-to-storage

    $policy_module | save bootc-wrapper-install-t.cil
    "FROM localhost/bootc
COPY bootc-wrapper-install-t.cil /usr/share/selinux/packages/
RUN semodule -N -i /usr/share/selinux/packages/bootc-wrapper-install-t.cil
" | save Dockerfile
    podman build -t localhost/bootc-derived-install-t .

    bootc switch --transport containers-storage localhost/bootc-derived-install-t

    # See ../bug-soft-reboot.md - TMT cannot handle systemd soft-reboots
    # https://tmt.readthedocs.io/en/stable/stories/features.html#reboot-during-test
    tmt-reboot
}

# The second boot; verify the same wrapper now works
def second_boot [] {
    tap begin "bootc from a wrapper service works with the policy module"

    assert (^semodule -l | lines | any {|m| $m == "bootc-wrapper-install-t" }) "Expected policy module to be installed"

    # With TMPDIR noexec, bootc can only succeed if it entered install_t
    # directly, since its fallback re-exec from TMPDIR would fail.
    let r = run_wrapped_bootc_status
    assert ($r.exit_code == 0) $"Expected bootc status to succeed, stderr: ($r.stderr)"

    let st = $r.stdout | from json
    assert ($st.status.booted.image.image.image | str contains "bootc-derived-install-t") $"Expected derived image to be booted, got: ($st.status.booted.image.image.image)"

    tap ok
}

def main [] {
    # See https://tmt.readthedocs.io/en/stable/stories/features.html#reboot-during-test
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => initial_build,
        "1" => second_boot,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
