# number: 41
# tmt:
#   summary: Test composefs garbage collection for UKI
#   duration: 30m

use std assert
use tap.nu

if not (tap is_composefs) {
    exit 0
}

# bootc status
let st = bootc status --json | from json
let booted = $st.status.booted.image

let uki_prefix = "bootc_composefs-"

let is_uki = (($st.status.booted.composefs.bootType | str downcase) == "uki")

if not $is_uki {
    exit 0
}

# Create a large file in a new container image, then bootc switch to the image
def first_boot [] {
    bootc image copy-to-storage

    mut containerfile = $"
        FROM localhost/bootc as base
        RUN dd if=/dev/zero of=/usr/share/large-test-file bs=1k count=1337
        RUN echo 'large-file-marker' | dd of=/usr/share/large-test-file conv=notrunc
    "

    $containerfile = (tap make_uki_containerfile $containerfile)

    echo $containerfile | podman build -t localhost/bootc-first . -f -

    bootc switch --transport containers-storage localhost/bootc-first

    # Find the large file's verity and save it
    let new_st = bootc status --json | from json
    let path = bootc internals cfs dump-files $new_st.status.staged.composefs.verity /usr/share/large-test-file --backing-path-only | awk '{print $2}'
    echo $"/sysroot/composefs/objects/($path)" | save /var/large-file-marker-objpath

    echo $st.status.booted.composefs.verity | save /var/boot0-verity

    tmt-reboot
}

# Create a container image derived from the first boot image
def second_boot [] {
    mkdir /var/tmp/efi
    mount /dev/disk/by-partlabel/EFI-SYSTEM /var/tmp/efi

    assert equal $booted.image.image "localhost/bootc-first"
    assert ($"/var/tmp/efi/EFI/Linux/bootc/($uki_prefix)(cat /var/boot0-verity).efi" | path exists)

    echo $st.status.booted.composefs.verity | save /var/boot1-verity

    let path = cat /var/large-file-marker-objpath
    assert ($path | path exists)

    mut containerfile = echo "
        FROM localhost/bootc as base
        RUN echo 'second' > /usr/share/second
    " 

    $containerfile = (tap make_uki_containerfile $containerfile)

    echo $containerfile | podman build -t localhost/bootc-second . -f -

    bootc switch --transport containers-storage localhost/bootc-second

    tmt-reboot
}

def third_boot [] {
    mkdir /var/tmp/efi
    mount /dev/disk/by-partlabel/EFI-SYSTEM /var/tmp/efi

    assert equal $booted.image.image "localhost/bootc-second"
    assert (not ($"/var/tmp/efi/EFI/Linux/bootc/($uki_prefix)(cat /var/boot0-verity).efi" | path exists))
    assert ($"/var/tmp/efi/EFI/Linux/bootc/($uki_prefix)(cat /var/boot1-verity).efi" | path exists)

    echo $st.status.booted.composefs.verity | save /var/boot2-verity

    # this is not deleted yet
    let path = cat /var/large-file-marker-objpath
    assert ($path | path exists)

    mut containerfile = echo "
        FROM localhost/bootc as base
        RUN echo 'third' > /usr/share/third
    " 

    $containerfile = (tap make_uki_containerfile $containerfile)

    echo $containerfile | podman build -t localhost/bootc-third . -f -

    bootc switch --transport containers-storage localhost/bootc-third

    tmt-reboot
}


def fourth_boot [] {
    mkdir /var/tmp/efi
    mount /dev/disk/by-partlabel/EFI-SYSTEM /var/tmp/efi

    assert equal $booted.image.image "localhost/bootc-third"
    assert (not ($"/var/tmp/efi/EFI/Linux/bootc/($uki_prefix)(cat /var/boot1-verity).efi" | path exists))
    assert ($"/var/tmp/efi/EFI/Linux/bootc/($uki_prefix)(cat /var/boot2-verity).efi" | path exists)

    mut containerfile = "
        FROM localhost/bootc as base
        RUN echo 'another file' > /usr/share/another-one
    " 

    $containerfile = (tap make_uki_containerfile $containerfile)

    echo $containerfile | podman build -t localhost/bootc-final . -f -

    bootc switch --transport containers-storage localhost/bootc-final

    let path = cat /var/large-file-marker-objpath
    assert (not ($path | path exists))

    tap ok
}

def main [] {
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => first_boot,
        "1" => second_boot,
        "2" => third_boot,
        "3" => fourth_boot,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}

