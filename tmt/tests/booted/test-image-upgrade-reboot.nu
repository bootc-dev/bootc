# number: 24
# extra:
#   try_bind_storage: true
# tmt:
#   summary: Execute local upgrade tests
#   duration: 30m
#   adjust:
#     - when: distro == centos-9 and boot_type == uki and seal_state == sealed
#       enabled: false
#       because: CentOS 9 cannot consume the signed host upgrade because shared storage is unavailable and its guest-local UKI builder produces unsigned images
#
# This test does:
# bootc image copy-to-storage
# podman build <from that image>
# bootc switch <into that image> (stage only)
# bootc switch --apply <same image> (spec unchanged, must still reboot)
# Verify we boot into the new image
#
# For composefs builds, it additionally verifies that composefs is
# still active after upgrade.  For sealed UKI builds, it checks that
# both the original and upgrade UKIs exist on the ESP.
#
use std assert
use tap.nu

# This code runs on *each* boot.
# Here we just capture information.
bootc status
bootc internals fsck
journalctl --list-boots

let st = bootc status --json | from json
let booted = $st.status.booted.image
let is_composefs = (tap is_composefs)

# Parse the kernel commandline into a list.
# This is not a proper parser, but good enough
# for what we need here.
def parse_cmdline []  {
    open /proc/cmdline | str trim | split row " "
}

def assert_composefs_uki_format [] {
    let erofs_version = tap selected_erofs_version
    let params = parse_cmdline
    let has_v1 = ($params | any { |p| $p | str starts-with "composefs.digest=" })
    let has_v2 = ($params | any { |p| $p | str starts-with "composefs=" })

    if $erofs_version == "v1" {
        assert $has_v1 "V1 UKI must contain composefs.digest="
        assert $has_v2 "V1 UKI must retain a V2 fallback"
    } else if $erofs_version == "v2" {
        assert $has_v2 "V2 UKI must contain composefs="
        assert (not $has_v1) "Explicit V2 UKI must not contain composefs.digest="
    } else {
        error make { msg: $"Unsupported EROFS version: ($erofs_version)" }
    }
}

def imgsrc [] {
    $env.BOOTC_upgrade_image? | default "localhost/bootc-derived-local"
}

# Run on the first boot
def initial_build [] {
    tap begin "local image push + pull + upgrade"

    let imgsrc = imgsrc
    let erofs_version = tap selected_erofs_version
    # For the packit case, we build locally right now
    if ($imgsrc | str ends-with "-local") {
        bootc image copy-to-storage

        # A simple derived container that adds a file
        (
            tap make_uki_containerfile --erofs-version $erofs_version "
                FROM localhost/bootc as base
                RUN touch /usr/share/testing-bootc-upgrade-apply
        ") | save Dockerfile

         # Build it
        podman build -t $imgsrc .
    }

    # For composefs, save state so we can verify it's preserved after upgrade.
    if $is_composefs {
        "true" | save /var/was-composefs
        $st.status.booted.composefs.verity | save /var/original-verity
    }

    # Now, switch into the new image. First stage it, then run switch --apply for
    # the same target. This exercises the case where --apply must still reboot for
    # staged deployments.
    print $"Staging ($imgsrc)"
    bootc switch --transport containers-storage ($imgsrc)
    print "Re-running with --apply (spec unchanged, should still reboot)"
    tmt-reboot -c $"bootc switch --apply --transport containers-storage ($imgsrc)"
}

# Check we have the updated image
def second_boot [] {
    print "verifying second boot"
    assert equal $booted.image.transport containers-storage
    assert equal $booted.image.image $"(imgsrc)"

    # Verify the new file exists
    assert ("/usr/share/testing-bootc-upgrade-apply" | path exists) "upgrade marker file should exist"

    # If the previous boot was composefs, verify composefs survived the upgrade
    let was_composefs = ("/var/was-composefs" | path exists)
    if $was_composefs {
        assert $is_composefs "composefs should still be active after upgrade"

        let composefs_info = $st.status.booted.composefs
        print $"composefs info: ($composefs_info)"

        assert (($composefs_info.verity | str length) > 0) "composefs verity digest should be present"

        # For UKI boot type, verify both the original and upgrade UKIs exist on the ESP
        if ($composefs_info.bootType | str downcase) == "uki" {
            assert_composefs_uki_format
            mkdir /var/tmp/efi
            mount /dev/disk/by-partlabel/EFI-SYSTEM /var/tmp/efi
            let boot_dir = "/var/tmp/efi/EFI/Linux/bootc"

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
            assert (($efi_files | length) >= 2) $"expected at least 2 UKIs on ESP, found ($efi_files | length)"
        }
    }

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
