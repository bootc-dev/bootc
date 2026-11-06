# number: 68
# tmt:
#   summary: Stage a UKI over a staged UKI of another version
#   duration: 30m
# extra:
#   skip_if_ostree: true
#
# A UKI's boot entry has the version from its os-release in its file name, so
# staging an image of another version doesn't overwrite the staged entry. Make
# sure that entry goes away, along with the deployment it belongs to.
use std assert
use tap.nu

let st = bootc status --json | from json

let is_uki = (($st.status.booted.composefs.bootType | str downcase) == "uki")
let is_sdboot = (($st.status.booted.composefs.bootloader | str downcase) == "systemd")

if not ($is_uki and $is_sdboot) {
    exit 0
}

# Build an image with this VERSION_ID and stage it
def stage [version: string] {
    let containerfile = $"
        FROM localhost/bootc as base
        RUN sed -i 's/^VERSION_ID=.*/VERSION_ID=($version)/' /usr/lib/os-release
    "

    (tap make_uki_containerfile $containerfile) | podman build -t $"localhost/bootc-($version)" . -f -

    bootc switch --transport containers-storage $"localhost/bootc-($version)"
}

def first_boot [] {
    bootc image copy-to-storage

    stage "restage1"
    let replaced = (bootc status --json | from json).status.staged.composefs.verity
    $replaced | save /var/replaced-verity

    stage "restage2"

    mkdir /var/tmp/efi
    mount /dev/disk/by-partlabel/EFI-SYSTEM /var/tmp/efi

    let staged = (glob /var/tmp/efi/loader/entries.staged/*.conf)
    assert equal ($staged | length) 2 $"Expected the new and booted entries, found ($staged)"
    assert (not ($staged | any { |f| $f | str contains "restage1" }))

    let status = (bootc status --json | from json).status
    assert ($status.staged.image.image.image | str ends-with "bootc-restage2")
    assert (not ($"/sysroot/state/deploy/($replaced)" | path exists))

    tmt-reboot
}

def second_boot [] {
    assert equal $st.status.booted.image.image.image "localhost/bootc-restage2"
    assert (not ($"/sysroot/state/deploy/(open /var/replaced-verity)" | path exists))

    tap ok
}

def main [] {
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => first_boot,
        "1" => second_boot,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
