# number: 39
# extra:
#   try_bind_storage: true
# tmt:
#   summary: Test composefs upgrade with pre-built (optionally sealed) image
#   duration: 30m
#
# This test verifies that upgrading a composefs system works correctly,
# including sealed UKI images. The upgrade image is pre-built on the host
# with proper sealing and made available via bind-storage-ro.
#
use std assert
use tap.nu

bootc status
journalctl --list-boots

let st = bootc status --json | from json
let booted = $st.status.booted.image
let is_composefs = (tap is_composefs)

# This test only makes sense for composefs
if not $is_composefs {
    tap begin "composefs upgrade (skipped - not composefs)"
    print "# SKIP: not running on composefs"
    tap ok
    exit 0
}

def upgrade_image [] {
    $env.BOOTC_upgrade_image? | default "localhost/bootc-upgrade"
}

# First boot: save the original verity digest, then switch to the upgrade image
def first_boot [] {
    tap begin "composefs upgrade with pre-built image"

    # Save the original verity so we can check for two UKIs after upgrade
    $st.status.booted.composefs.verity | save /var/original-verity

    let img = (upgrade_image)
    print $"Switching to upgrade image: ($img)"

    # The upgrade image should be available via host container storage
    # (passed through --bind-storage-ro by bcvk)
    bootc switch --transport containers-storage $img
    tmt-reboot
}

# Second boot: verify the upgrade succeeded and both UKIs exist
def second_boot [] {
    print "Verifying composefs upgrade"

    # Verify we booted from the upgrade image
    let img = (upgrade_image)
    assert equal $booted.image.transport containers-storage
    assert equal $booted.image.image $img

    # Verify composefs is still active after the upgrade
    assert (tap is_composefs) "composefs should still be active after upgrade"

    # Verify the upgrade marker file exists
    assert ("/usr/share/testing-bootc-upgrade-apply" | path exists) "upgrade marker file should exist"

    # Verify composefs properties are preserved after the upgrade
    let composefs_info = $st.status.booted.composefs
    print $"composefs info: ($composefs_info)"

    # Verify there is a valid verity digest (composefs was properly deployed)
    assert (($composefs_info.verity | str length) > 0) "composefs verity digest should be present"

    # For UKI boot type, verify both the original and upgrade UKIs exist on the ESP
    if ($composefs_info.bootType | str downcase) == "uki" {
        let bootloader = ($composefs_info.bootloader | str downcase)

        # UKIs are stored in EFI/Linux/bootc/ on the ESP
        let boot_dir = if $bootloader == "systemd" {
            mkdir /var/tmp/efi
            mount /dev/vda2 /var/tmp/efi
            "/var/tmp/efi/EFI/Linux/bootc"
        } else {
            "/sysroot/boot/EFI/Linux/bootc"
        }

        let original_verity = (open /var/original-verity | str trim)
        let upgrade_verity = $composefs_info.verity

        print $"boot_dir: ($boot_dir)"
        print $"original verity: ($original_verity)"
        print $"upgrade verity: ($upgrade_verity)"

        # The two verities must differ since the upgrade image has different content
        assert ($original_verity != $upgrade_verity) "upgrade should produce a different verity digest"

        # There should be two .efi UKI files on the ESP: one for the booted
        # deployment (upgrade) and one for the rollback (original)
        let efi_files = (glob $"($boot_dir)/*.efi")
        print $"EFI files: ($efi_files)"
        assert ((($efi_files | length) >= 2)) $"expected at least 2 UKIs on ESP, found ($efi_files | length)"
    }

    tap ok
}

def main [] {
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => first_boot,
        "1" => second_boot,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
