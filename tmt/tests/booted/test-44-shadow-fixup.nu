# number: 44
# tmt:
#   summary: Test bootc-sysusers-shadow-sync removes orphaned gshadow entries before sysusers
#   duration: 30m
#
# Reproduces the stale-shadow problem: a gshadow entry exists for a group that
# is absent from /etc/group and /usr/lib/group.  sysusers tries to create the
# group from its sysusers.d definition and hits the stale gshadow entry.
#
# Two boots, one image build.  The stale entry is injected on the live running
# system (not in the image), matching the real rechunk/rebase scenario where
# rechunk resets /etc/group but the writable /etc overlay retains stale gshadow
# entries from prior sysusers runs.
#
#   Boot 0 (initial_build):
#     - Inject testbootcgroup:!:: into the live /etc/gshadow (writable overlay).
#       This simulates what rechunk leaves behind after resetting /etc/group.
#     - Build Image B: adds sysusers.d entry for testbootcgroup so sysusers will
#       try to create the group on boot.  Image B's /etc/gshadow is clean.
#
#   3-way merge (base→Image B) for /etc/gshadow:
#     base (no entry) + local (stale entry) + new image (no entry)
#     → local modification wins, stale entry persists into the new deployment.
#   /etc/group: absent in base, local, and new image → still absent after merge.
#
#   Boot 1: bootc-sysusers-shadow-sync.service removes the stale gshadow entry,
#   then sysusers creates testbootcgroup cleanly from its sysusers.d definition.
#
use std assert
use tap.nu
use bootc_testlib.nu

# Image B: has a sysusers.d entry for testbootcgroup so that systemd-sysusers
# will try to create the group on boot.  Crucially, /etc/gshadow is NOT touched
# here — the stale entry lives only in the running system's writable /etc
# overlay (injected below), which is the actual rechunk/rebase scenario.
const DOCKERFILE_B = '
FROM localhost/bootc as base

RUN printf "g testbootcgroup 7373\n" > /usr/lib/sysusers.d/testbootcgroup.conf

# Verify the image itself has no gshadow or group entry for testbootcgroup.
# The stale gshadow entry is injected on the live system, not in the image.
RUN ! grep -q testbootcgroup /etc/gshadow
RUN ! grep -q testbootcgroup /etc/group
'

def initial_build [] {
    tap begin "shadow fixup test"

    bootc image copy-to-storage

    # Inject the stale gshadow entry as a local modification on the running system.
    # This simulates what rechunk/rebase leaves behind: a gshadow entry for a group
    # that no longer appears in /etc/group or /usr/lib/group.
    "testbootcgroup:!::\n" | save --append /etc/gshadow
    print "Injected stale gshadow entry: testbootcgroup:!::"

    # On UKI composefs the derived image needs a sealed UKI; make_uki_containerfile
    # appends the necessary build stages when running on a UKI system.
    (tap make_uki_containerfile $DOCKERFILE_B) | save --force Dockerfile
    podman build -t localhost/bootc-shadow-fixup-b .

    bootc switch --transport containers-storage localhost/bootc-shadow-fixup-b
    bootc_testlib reboot
}

def second_boot [] {
    # systemctl show -P ActiveState always exits 0 and prints a plain string.
    let active_state = (^systemctl show -P ActiveState bootc-sysusers-shadow-sync.service | str trim)

    # Always print the unit status (includes recent journal lines) for context.
    do { ^systemctl status bootc-sysusers-shadow-sync.service } | complete | get stdout | print

    assert ($active_state == "active") $"bootc-sysusers-shadow-sync.service not active: ($active_state)"

    # Print the service journal for diagnostic context; don't assert on it.
    # The log message is emitted via tracing_journald, which can be silently
    # dropped if the journal socket is not yet visible at process start (e.g.
    # volatile journals, early-boot races).  The file-state checks below are
    # the authoritative proof that the service did its job.
    ^journalctl -u bootc-sysusers-shadow-sync.service -b 0 --no-pager | print

    # sysusers must have (re)created the group cleanly in /etc/group.
    let group_lines = (open /etc/group | lines | where { |l| $l | str starts-with "testbootcgroup:" })
    assert (($group_lines | length) == 1) $"expected exactly one testbootcgroup in /etc/group, got: ($group_lines)"

    # Stale entry must be gone; sysusers wrote exactly one fresh gshadow entry.
    let gshadow_lines = (open /etc/gshadow | lines | where { |l| $l | str starts-with "testbootcgroup:" })
    assert (($gshadow_lines | length) == 1) $"expected exactly one testbootcgroup in /etc/gshadow, got: ($gshadow_lines)"

    tap ok
}

def main [] {
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => initial_build,
        "1" => second_boot,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
