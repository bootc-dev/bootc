use std assert
use tap.nu

# On a composefs install with systemd-boot and no bootupd in the image,
# bootctl installs systemd-boot directly as the removable-media fallback, with
# no shim anywhere in the boot path. Verify that layout.

tap begin "systemd-boot without bootupd boots directly, without shim"

let st = bootc status --json | from json
let bootloader = ($st.status.booted.composefs?.bootloader? | default "" | str downcase)
if $bootloader != "systemd" {
    print "Not a composefs systemd-boot install, skipping"
    exit 0
}
if (tap image_ships_bootupd) {
    print "Image ships bootupd, which the test images pair with a systemd-boot component, skipping"
    exit 0
}

let arch = (tap efi_arch)
let esp = (tap esp_mountpoint)
print $"ESP is mounted at ($esp)"

# Firmware loads systemd-boot itself from the removable-media fallback path.
let fallback = $"($esp)/EFI/BOOT/BOOT($arch | str upcase).EFI"
assert ($fallback | path exists) $"missing ($fallback)"
assert (tap is_systemd_boot $fallback) $"($fallback) is not systemd-boot"

# bootctl also keeps its own copy under EFI/systemd.
let bootctl_copy = $"($esp)/EFI/systemd/systemd-boot($arch).efi"
assert ($bootctl_copy | path exists) $"missing ($bootctl_copy)"
assert (tap is_systemd_boot $bootctl_copy) $"($bootctl_copy) is not systemd-boot"

# No shim, and no bootloader hiding under shim's second-stage name. vfat
# preserves case, so match either spelling of the suffix.
let shims = (glob $"($esp)/EFI/**/shim*.[eE][fF][iI]")
assert (($shims | length) == 0) $"found shim on the ESP: ($shims)"
let second_stages = (glob $"($esp)/EFI/*/grub($arch).[eE][fF][iI]")
assert (($second_stages | length) == 0) $"found a second stage binary on the ESP: ($second_stages)"
let binaries = (glob $"($esp)/EFI/**/*.[eE][fF][iI]" | where {|p| tap is_shim $p })
assert (($binaries | length) == 0) $"found shim binaries on the ESP: ($binaries)"

# We actually booted through systemd-boot.
let bootctl = (do { ^bootctl } | complete)
assert ($bootctl.exit_code == 0) $"bootctl failed: ($bootctl.stderr)"
assert ($bootctl.stdout | str contains "Product: systemd-boot") "the running boot loader is not systemd-boot"

tap ok
