# number: 27
# tmt:
#   summary: Execute custom selinux policy test
#   duration: 30m
#   adjust:
#     - when: running_env != image_mode
#       enabled: false
#       because: these tests require features only available in image mode
# extra:
#   fixme_skip_if_composefs: true
#
# Verify that correct labels are applied after a deployment
use std assert
use tap.nu

# This code runs on *each* boot.
# Here we just capture information.
bootc status

# Run on the first boot
def initial_build [] {
    tap begin "local image push + pull + upgrade"

    let td = mktemp -d
    cd $td

    bootc image copy-to-storage

    # A simple derived container that customizes selinux policy for random dir
    "FROM localhost/bootc
RUN mkdir /opt123; echo \"/opt123 /opt\" >> /etc/selinux/targeted/contexts/files/file_contexts.subs_dist
" | save Dockerfile
    # Build it
    podman build -t localhost/bootc-derived .

    bootc switch --transport containers-storage localhost/bootc-derived

    assert (not ("/opt123" | path exists))

    # See ../bug-soft-reboot.md - TMT cannot handle systemd soft-reboots
    # https://tmt.readthedocs.io/en/stable/stories/features.html#reboot-during-test
    tmt-reboot
}

# The second boot; verify we're in the derived image and directory has correct selinux label
def second_boot [] {
    tap begin "Verify directory exists and has correct SELinux label"

    assert ("/opt123" | path exists)

    # Verify the directories have the correct SELinux labels
    let opt123_label = (^stat --format=%C /opt123 | str trim)
    let opt_label = (^stat --format=%C /opt | str trim)

    print $"opt123 SELinux label: ($opt123_label)"
    print $"opt SELinux label: ($opt_label)"

    # Both should have the same label (system_u:object_r:usr_t:s0)
    assert ($opt123_label | str contains "system_u:object_r:usr_t:s0") $"Expected system_u:object_r:usr_t:s0 label for /opt123, got: ($opt123_label)"
    assert ($opt_label | str contains "system_u:object_r:usr_t:s0") $"Expected system_u:object_r:usr_t:s0 label for /opt, got: ($opt_label)"

    # Verify both labels are the same
    assert ($opt123_label == $opt_label) $"Labels should be the same: opt123=($opt123_label) vs opt=($opt_label)"

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
