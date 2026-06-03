# number: 45
# tmt:
#   summary: Test composefs backend resilience to state corruption
#   duration: 30m

use std assert
use tap.nu

if not (tap is_composefs) {
    exit 0
}

let st = bootc status --json | from json
let booted = $st.status.booted.image
let is_uki = ($st.status.booted.composefs.bootType | str downcase) == "uki"
let is_grub = ($st.status.booted.composefs.bootloader | str downcase) == "grub"

# NOTE: Not testing for grub menuentries as that's niche case and we will
# remove it once we have https://github.com/bootc-dev/bootc/issues/2212
if ($is_uki and $is_grub) {
    exit 0
}

def first_boot [] {
    bootc image copy-to-storage

    let bootloader = $st.status.booted.composefs.bootloader | str downcase
    
    let entries_dir = if $bootloader == "systemd" or $bootloader == "grub-cc" {
        mkdir /var/tmp/efi
        mount /dev/disk/by-partlabel/EFI-SYSTEM /var/tmp/efi
        "/var/tmp/efi/loader/entries"
    } else {
        "/sysroot/boot/loader/entries"
    }

    let booted_verity = $st.status.booted.composefs.verity

    # Add some random entry in /boot/loader/entries to simulate
    # https://github.com/bootc-dev/bootc/issues/2208
    systemd-run -p MountFlags=slave -qdPG -- /bin/sh -c $"
        mount -orw,remount /sysroot
        cd ($entries_dir)
        cp * new-entry.conf
        
        sed -i 's;($booted_verity);bad-verity;' new-entry.conf
    "

    # This should work but log a warning in journal
    bootc status

    assert (
        journalctl F_MESSAGE_ID=d264f924dadb4c31bff0412107d391fb
        | str contains $"No origin file for deployment bad-verity"
    )

    # Create a simple derived image to switch to
    tap make_uki_containerfile $"
        FROM localhost/bootc as base
        RUN echo 'first-deployment' > /usr/share/deployment-marker
    " | podman build -t localhost/bootc-test-1 . -f -

    bootc switch --transport containers-storage localhost/bootc-test-1

    # Remove /run/composefs to simulate switch/update that failed midway
    # and make sure switch still works
    rm -rf /run/composefs

    assert ((bootc status --json | from json | get status.staged) == null)

    bootc switch --transport containers-storage localhost/bootc-test-1

    tmt-reboot
}

# Test the same thing but with an existing rollback deployment
def second_boot [] {
    assert equal $booted.image.image "localhost/bootc-test-1"
    
    # Create another derived image  
    tap make_uki_containerfile $"
        FROM localhost/bootc as base
        RUN echo 'second-deployment' > /usr/share/deployment-marker
    " | podman build -t localhost/bootc-test-2 . -f -

    bootc switch --transport containers-storage localhost/bootc-test-2

    # Remove the origin file for staged deployment
    # Make sure bootc status and switch still work
    let staged_verity = (bootc status --json | from json).status.staged.composefs.verity

    systemd-run -p MountFlags=slave -qdPG -- /bin/sh -c $"
        mount -orw,remount /sysroot
        rm -rvf /sysroot/state/deploy/($staged_verity)/($staged_verity).origin
    "

    # This should work but log a warning in journal
    bootc status

    assert (
        journalctl F_MESSAGE_ID=d264f924dadb4c31bff0412107d391fb
        | str contains $"No origin file for deployment ($staged_verity)"
    )

    # Switch again and it should work
    bootc switch --transport containers-storage localhost/bootc-test-2

    tap ok
}

def main [] {
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => first_boot,
        "1" => second_boot,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
