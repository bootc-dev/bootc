use std assert
use tap.nu

tap begin "Test EFI/UKI key"

let st = bootc status --json | from json

if not (tap is_composefs) {
    exit 0
}

let bootloader = $st.status.booted.composefs.bootloader

# Only for UKIs
if ($st.status.booted.composefs.bootType | str downcase) != "uki" {
    exit 0
}

let systemd_version = systemctl --version | lines | first | awk '{print $2}' | into int

echo $"($systemd_version)"

echo "BLS entry"
echo (cat /boot/loader/entries/*)

# Both bootloaders support BLI so EFI should be mounted at /boot
let efi_line = (
    open /boot/loader/entries/*
    | lines
    | where $it =~ '^efi'
)

let uki_line = (
    open /boot/loader/entries/*
    | lines
    | where $it =~ '^uki'
)

if $bootloader == "grub-cc" {
    assert equal ($efi_line | length) 1
    assert equal ($uki_line | length) 0
} else {

    if $systemd_version >= 258 {
        assert equal ($efi_line | length) 0
        assert equal ($uki_line | length) 1
    } else {
        assert equal ($efi_line | length) 1
        assert equal ($uki_line | length) 0
    }
}

tap ok
