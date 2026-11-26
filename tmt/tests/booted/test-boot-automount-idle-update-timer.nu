# number: 64
# tmt:
#   summary: Apply an update from the timer after the /boot automount idles out
#   duration: 30m
# extra:
#   # The bug is in ostree's finalization, and the updater service only runs
#   # on ostree-booted systems.
#   fixme_skip_if_composefs: true
#
# Reproduces https://github.com/bootc-dev/bootc/issues/2402: when /boot is
# on the root filesystem and systemd-gpt-auto-generator also sets up a
# boot.automount (for the otherwise unused ESP), the automount idling out
# tears down ostree's /boot bind mount. Our other upgrade tests always
# reboot well within the idle timeout, so they never see that state.
#
# This test does:
# Skip unless /boot is an automount, and shorten its idle timeout
# bootc switch <a local v1 image>, so the host tracks containers-storage
# Build v2 under the same tag; stage nothing
# Wait for /boot to idle out and check that it is unmounted
# Fire bootc-fetch-apply-updates.timer, which stages v2 and reboots,
# running ostree-finalize-staged
# Verify we booted v2
#
use std assert
use tap.nu

const imgsrc = "localhost/bootc-2402"
const marker = "/usr/share/bootc-test-2402"
const automount_dropin = "/etc/systemd/system/boot.automount.d/50-bootc-test-idle.conf"
const idle_secs = 10
const updater = "bootc-fetch-apply-updates"

# Trigger the automount so that bootc and ostree can find /boot.
def touch_boot [] {
    ls /boot | ignore
}

# The filesystem types mounted at /boot, bottom first.
def boot_fstypes [] {
    findmnt -rn -o TARGET,FSTYPE | lines | parse "{target} {fstype}" | where target == "/boot" | get fstype
}

def build_image [version: string] {
    $version | save --force bootc-test-2402
    "FROM localhost/bootc
COPY bootc-test-2402 /usr/share/bootc-test-2402
" | save --force Dockerfile
    podman build -t $imgsrc .
}

# Run on the first boot
def initial_build [] {
    tap begin "update timer after /boot automount idle (bootc#2402)"

    let automounted = (
        do { ^findmnt --mountpoint /boot --types autofs --noheadings } | complete
    ).exit_code == 0
    if not $automounted {
        print "/boot is not automounted; skipping"
        tap ok
        return
    }
    systemctl cat boot.automount boot.mount

    mkdir ($automount_dropin | path dirname)
    $"[Automount]\nTimeoutIdleSec=($idle_secs)s\n" | save --force $automount_dropin

    bootc image copy-to-storage
    build_image "v1"
    touch_boot
    bootc switch --transport containers-storage $imgsrc
    tmt-reboot
}

# Booted v1 with the short idle timeout; stage v2 from the timer
def second_boot [] {
    touch_boot
    bootc status
    let booted = bootc status --json | from json | get status.booted.image
    assert equal $booted.image.transport containers-storage
    assert equal $booted.image.image $imgsrc
    assert equal (open $marker | str trim) "v1"
    assert equal (systemctl show -P TimeoutIdleUSec boot.automount | str trim) $"($idle_secs)s"

    build_image "v2"

    print $"Waiting for /boot to idle out after ($idle_secs)s"
    mut fstypes = boot_fstypes
    for _ in 1..60 {
        if $fstypes == ["autofs"] {
            break
        }
        sleep 2sec
        $fstypes = boot_fstypes
    }
    assert equal $fstypes ["autofs"] "/boot should only be the idle autofs mount"

    # Fire the timer as shipped, apart from when it fires. On success the
    # service reboots into v2 itself; once its main process has exited
    # without that, reboot anyway so that the next boot reports it.
    # tmt-reboot passes the command on in JSON without escaping it, so it
    # must not contain double quotes; it is not a nu interpolated string
    # because of the shell's $(...).
    mkdir $"/run/systemd/system/($updater).timer.d"
    "[Timer]
OnBootSec=
OnUnitInactiveSec=
RandomizedDelaySec=0
OnActiveSec=1s
" | save $"/run/systemd/system/($updater).timer.d/50-bootc-test.conf"
    systemctl daemon-reload
    tmt-reboot -c "systemctl restart bootc-fetch-apply-updates.timer; until test $(systemctl show -P ExecMainExitTimestampMonotonic bootc-fetch-apply-updates.service) != 0; do sleep 1; done; systemctl reboot"
}

# Check that the update from the timer was finalized and booted
def third_boot [] {
    touch_boot
    bootc status
    journalctl -b -1 -o short-monotonic --no-pager -u $"($updater).service" -u $"($updater).timer" -u ostree-finalize-staged.service -u boot.automount -u boot.mount
    assert equal (open $marker | str trim) "v2" "the update applied by the timer should have booted"
    tap ok
}

def main [] {
    # See https://tmt.readthedocs.io/en/stable/stories/features.html#reboot-during-test
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => initial_build,
        "1" => second_boot,
        "2" => third_boot,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
