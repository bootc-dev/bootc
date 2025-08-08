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

    bootc switch --queue-soft-reboot --transport containers-storage localhost/bootc-derived
    let st = bootc status --json | from json
    assert $st.status.staged.softRebootCapable

    # And reboot into it
    tmt-reboot
}

# The second boot; verify we're in the derived image
def second_boot [] {
    assert ("/usr/share/testfile-for-soft-reboot.txt" | path exists)

    assert equal (systemctl show -P SoftRebootsCount) "1"
}

# Run on the second boot
def second_build [] {
    tap begin "local image push + pull + upgrade"

    let td = mktemp -d
    cd $td

    bootc image copy-to-storage

    # A new derived with new kargs which should stop the soft reboot.
    "FROM localhost/bootc
RUN echo test content > /usr/share/testfile-for-soft-reboot.txt
RUN echo 'kargs = ["foo1=bar2"]' | tee /usr/lib/bootc/kargs.d/00-foo1bar2.toml > /dev/null
" | save Dockerfile
    # Build it
    podman build -t localhost/bootc-derived .

    bootc update --queue-soft-reboot --transport containers-storage
    let st = bootc status --json | from json
    assert (not $st.status.staged.softRebootCapable)

    # And reboot into it
    tmt-reboot
}

# The third boot; verify we're in the derived image
def third_boot [] {
    assert ("/usr/lib/bootc/kargs.d/00-foo1bar2.toml" | path exists)

    assert equal (systemctl show -P SoftRebootsCount) "0"
}

def main [] {
    # See https://tmt.readthedocs.io/en/stable/stories/features.html#reboot-during-test
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => initial_build,
        "1" => second_boot,
        "2" => second_build,
        "3" => third_boot,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
