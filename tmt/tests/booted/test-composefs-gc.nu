# number: 35
# tmt:
#   summary: Test composefs garbage collection with same and different kernel+initrd
#   duration: 30m
# extra:
#   skip_if_ostree: true
#   fixme_skip_if_uki: true

use std assert
use tap.nu

if not (tap is_composefs) {
    exit 0
}

# bootc status
let st = bootc status --json | from json
let booted = $st.status.booted.image

let dir_prefix = "bootc_composefs-"

if ($st.status.booted.composefs.bootType | str downcase) == "uki" {
    exit 0
}

# Create a large file in a new container image, then bootc switch to the image
def first_boot [] {
    bootc image copy-to-storage

    echo $"
        FROM localhost/bootc
        RUN dd if=/dev/zero of=/usr/share/large-test-file bs=1k count=1337
        RUN echo 'large-file-marker' | dd of=/usr/share/large-test-file conv=notrunc
    " | podman build -t localhost/bootc-derived . -f -

    bootc switch --transport containers-storage localhost/bootc-derived

    # Find the large file's verity and save it
    let new_st = bootc status --json | from json
    let path = bootc internals cfs dump-files $new_st.status.staged.composefs.verity /usr/share/large-test-file --backing-path-only | awk '{print $2}'
    echo $"/sysroot/composefs/objects/($path)" | save /var/large-file-marker-objpath

    echo $st.status.booted.composefs.verity | save /var/first-verity

    tmt-reboot
}

# Create a container image derived from the first boot image, but update the initrd
def second_boot [] {
    assert equal $booted.image.image "localhost/bootc-derived"

    let path = cat /var/large-file-marker-objpath
    assert ($path | path exists)

    # Create another image with a different initrd so we can test kernel + initrd cleanup
    echo "
        FROM localhost/bootc

        RUN echo 'echo hello' > /usr/bin/hello
        RUN chmod +x /usr/bin/hello

        RUN mkdir /usr/lib/dracut/modules.d/99something

        RUN cat <<-EOF > /usr/lib/dracut/modules.d/99something/module-setup.sh
            #!/usr/bin/bash

            check() {
                return 0
            }

            depends() {
                return 0
            }

            install() {
                inst '/usr/bin/hello' /bin/hello
            }
        EOF

        RUN set -x; kver=$(cd /usr/lib/modules && echo *); dracut -vf --add bootc /usr/lib/modules/$kver/initramfs.img $kver;
    " | lines | each { str trim } | str join "\n" | podman build -t localhost/bootc-derived-initrd . -f -

    bootc switch --transport containers-storage localhost/bootc-derived-initrd

    tmt-reboot
}

def third_boot [] {
    assert equal $booted.image.image "localhost/bootc-derived-initrd"

    # Also assert we have two different kernel + initrd pairs
    let booted_verity = (bootc status --json | from json).status.booted.composefs.verity

    let bootloader = ((bootc status --json | from json).status.booted.composefs.bootloader | str downcase)

    let boot_dir = if $bootloader == "systemd" or $bootloader == "grub-cc" {
        # TODO: Some concrete API for this would be great
        mkdir /var/tmp/efi
        mount /dev/disk/by-partlabel/EFI-SYSTEM /var/tmp/efi
        "/var/tmp/efi/EFI/Linux"
    } else {
        "/sysroot/boot"
    }

    assert ($"($boot_dir)/($dir_prefix)($booted_verity)" | path exists)

    # This is for the rollback, but since the rollback and the very
    # first boot have the same kernel + initrd pair, and this rollback
    # was deployed after the first boot, we will still be using the very
    # first verity for the boot binary name
    assert ($"($boot_dir)/($dir_prefix)(cat /var/first-verity)" | path exists)

    echo $"($boot_dir)/($dir_prefix)(cat /var/first-verity)" | save /var/to-be-deleted-kernel

    # Switching and rebooting here won't delete the old kernel because we still
    # have it as the rollback deployment
    echo "
        FROM localhost/bootc-derived-initrd
        RUN echo 'another file' > /usr/share/another-one
    " | podman build -t localhost/bootc-final . -f -


    bootc switch --transport containers-storage localhost/bootc-final

    tmt-reboot
}

def fourth_boot [] {
    let bootloader = ((bootc status --json | from json).status.booted.composefs.bootloader | str downcase)

    if $bootloader == "systemd" or $bootloader == "grub-cc" {
        # TODO: Some concrete API for this would be great
        mkdir /var/tmp/efi
        mount /dev/disk/by-partlabel/EFI-SYSTEM /var/tmp/efi
    }

    assert equal $booted.image.image "localhost/bootc-final"
    assert (not ((cat /var/to-be-deleted-kernel | path exists)))

    # Now we want to test preservation of shared BLS binaries
    # This takes at least 3 reboots
    1..3 | each { |i|
        echo $"
            FROM localhost/bootc-derived-initrd
            RUN echo '($i)' > /usr/share/($i)
        " | podman build -t $"localhost/bootc-shared-($i)" . -f -
    }

    bootc switch --transport containers-storage localhost/bootc-shared-1

    # The large file should be GC'd in the previous switch
    let path = cat /var/large-file-marker-objpath
    assert (not ($path | path exists))

    tmt-reboot
}

def fifth_boot [i: int] {
    assert equal $booted.image.image $"localhost/bootc-shared-($i)"

    # Just this being booted counts as success
    if $i == 3 {
        # After multiple GC cycles, assert the repo is fully clean.
        # Regression check for issue #1808: GC must not identify any live
        # deployment objects as garbage.
        bootc internals composefs-gc --assert-no-op
        tap ok
        return
    }

    bootc switch --transport containers-storage $"localhost/bootc-shared-($i + 1)"

    tmt-reboot
}

def main [] {
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => first_boot,
        "1" => second_boot,
        "2" => third_boot,
        "3" => fourth_boot,
        "4" => { fifth_boot 1 },
        "5" => { fifth_boot 2 },
        "6" => { fifth_boot 3 },
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}

