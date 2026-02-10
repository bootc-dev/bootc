# number: 24
# extra:
#   try_bind_storage: true
#   works_for_composefs: true
# tmt:
#   summary: Execute local upgrade tests
#   duration: 30m
#
# This test does:
# bootc image copy-to-storage
# podman build <from that image>
# bootc switch <into that image> --apply
# Verify we boot into the new image
#
use std assert
use tap.nu

# This code runs on *each* boot.
# Here we just capture information.
bootc status
journalctl --list-boots

let st = bootc status --json | from json
let booted = $st.status.booted.image

# Parse the kernel commandline into a list.
# This is not a proper parser, but good enough
# for what we need here.
def parse_cmdline []  {
    open /proc/cmdline | str trim | split row " "
}

def imgsrc [] {
    $env.BOOTC_upgrade_image? | default "localhost/bootc-derived-local"
}

# Run on the first boot
def initial_build [] {
    tap begin "local image push + pull + upgrade"

    let imgsrc = imgsrc
    # For the packit case, we build locally right now
    if ($imgsrc | str ends-with "-local") {
        bootc image copy-to-storage

        # A simple derived container that adds a file
        "FROM localhost/bootc
RUN touch /usr/share/testing-bootc-upgrade-apply
" | save Dockerfile
         # Build it
        podman build -t $imgsrc .
    }

    # Now, switch into the new image
    print $"Applying ($imgsrc)"
    bootc switch --transport containers-storage ($imgsrc)
    tmt-reboot
}

# Check we have the updated image
def second_boot [] {
    print "verifying second boot"
    assert equal $booted.image.transport containers-storage
    assert equal $booted.image.image $"(imgsrc)"

    # Verify the new file exists
    "/usr/share/testing-bootc-upgrade-apply" | path exists

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
