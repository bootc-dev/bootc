# Verify that soft reboot works (on by default)
use std assert
use tap.nu

let soft_reboot_capable = "/usr/lib/systemd/system/soft-reboot.target" | path exists
if not $soft_reboot_capable {
    echo "Skipping, system is not soft reboot capable"
    return
}

# This code runs on *each* boot.
# Here we just capture information.
bootc status
let st = bootc status --json | from json
let booted = $st.status.booted.image

# Run on the first boot
def initial_build [] {
    tap begin "local image push + pull + upgrade"

    let td = mktemp -d
    cd $td

    bootc image copy-to-storage

    # A simple derived container that adds a file, but also injects some kargs
    "FROM localhost/bootc
RUN echo test content > /usr/share/testfile-for-soft-reboot.txt
" | save Dockerfile
    # Build it
    podman build -t localhost/bootc-derived .

    bootc switch --transport containers-storage localhost/bootc-derived
    let st = bootc status --json | from json
    assert ($st.status.staged.soft_reboot_capable) == true

    # And reboot into it
    tmt-reboot
}

# The second boot; verify we're in the derived image
def second_boot [] {
    assert ("/usr/share/testfile-for-soft-reboot.txt" | path exists)

    assert equal (systemctl show -P SoftRebootsCount) "1"
}

def main [] {
    # See https://tmt.readthedocs.io/en/stable/stories/features.html#reboot-during-test
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => initial_build,
        "1" => second_boot,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
