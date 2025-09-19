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
RUN mkdir /usr/lib/opt123 && echo "/usr/lib/opt123 /opt" > /usr/etc/selinux/targeted/contexts/files/file_contexts.subs_dist
" | save Dockerfile
    # Build it
    podman build -t localhost/bootc-derived .

    bootc switch --soft-reboot=auto --transport containers-storage localhost/bootc-derived
    
    assert (not ("/usr/lib/opt123" | path exists))

    # https://tmt.readthedocs.io/en/stable/stories/features.html#reboot-during-test
    tmt-reboot
}

# The second boot; verify we're in the derived image and directory has correct selinux label
def second_boot [] {
    tap begin "Verify directory exists and has correct SELinux label"

    assert ("/usr/lib/opt123" | path exists)

    # Verify the directory has the correct SELinux label (opt_t)
    let label = (ls -Z /usr/lib/opt123 | get security_context | first)
    assert ($label | str contains "opt_t") $"Expected opt_t label, got: ($label)"

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
