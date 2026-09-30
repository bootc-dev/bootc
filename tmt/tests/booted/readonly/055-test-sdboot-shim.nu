use std assert
use tap.nu

# On a composefs install with an explicit request for systemd-boot, bootc
# installs it through bootupd when the image's bootupd can install it, which
# puts shim in front of systemd-boot under the second-stage name baked into
# shim. The test images that ship bootupd along with systemd-boot (the
# systemd-shim CI leg) guarantee such a bootupd. Verify that layout, and that
# bootupd recorded what it installed.

tap begin "systemd-boot via bootupd keeps shim in the boot path"

let st = bootc status --json | from json
let bootloader = ($st.status.booted.composefs?.bootloader? | default "" | str downcase)
if $bootloader != "systemd" {
    print "Not a composefs systemd-boot install, skipping"
    exit 0
}
if not (tap image_ships_bootupd) {
    print "Image ships no bootupd, so systemd-boot was installed by bootctl, skipping"
    exit 0
}

let arch = (tap efi_arch)
let esp = (tap esp_mountpoint)
print $"ESP is mounted at ($esp)"

# The removable-media fallback path is shim, the first stage.
let fallback = $"($esp)/EFI/BOOT/BOOT($arch | str upcase).EFI"
assert ($fallback | path exists) $"missing ($fallback)"
assert (tap is_shim $fallback) $"($fallback) is not shim"

# shim lives in the vendor directory, next to the second stage it loads.
let shims = (glob $"($esp)/EFI/*/shim($arch).efi")
assert (($shims | length) == 1) $"expected exactly one vendor shim on the ESP, found ($shims)"
let vendor_dir = ($shims | first | path dirname)
print $"Vendor directory is ($vendor_dir)"

# The second stage carries grub's name because that is what shim looks for,
# but it must be systemd-boot.
let second_stage = $"($vendor_dir)/grub($arch).efi"
assert ($second_stage | path exists) $"missing second stage ($second_stage)"
assert (tap is_systemd_boot $second_stage) $"($second_stage) is not systemd-boot"

# bootctl install was not involved: it would have left its own copy behind.
let bootctl_copy = $"($esp)/EFI/systemd/systemd-boot($arch).efi"
assert (not ($bootctl_copy | path exists)) $"($bootctl_copy) exists, systemd-boot was installed by bootctl"

# We actually booted through systemd-boot.
let bootctl = (do { ^bootctl } | complete)
assert ($bootctl.exit_code == 0) $"bootctl failed: ($bootctl.stderr)"
assert ($bootctl.stdout | str contains "Product: systemd-boot") "the running boot loader is not systemd-boot"

# bootupd recorded the components it installed.
let status = (do { ^bootupctl status } | complete)
print $status.stdout
print $status.stderr
assert ($status.exit_code == 0) "bootupctl status failed"
assert ($status.stdout | str contains "systemd-boot") "bootupctl status does not report systemd-boot"

tap ok
