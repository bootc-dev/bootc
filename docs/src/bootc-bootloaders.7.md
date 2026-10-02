# Bootloaders in `bootc`

`bootc` supports two ways to manage bootloaders.

## bootupd

[bootupd](https://github.com/coreos/bootupd/) is a project explicitly designed to abstract over and manage bootloader installation and configuration.
On EFI, it installs GRUB with shim in front of it, and since 0.3.0 can install grub-cc and systemd-boot the same way.

When you run `bootc install`, it invokes `bootupctl backend install` to install the bootloader to the target disk or filesystem. The specific bootloader configuration is determined by the container image and the target system's hardware.

Currently, `bootc` only runs `bootupd` during the installation process. It does **not** automatically run `bootupctl update` to update the bootloader after installation. This means that bootloader updates must be handled separately, typically by the user or an automated system update process.

## systemd-boot

NOTE: systemd-boot is only supported for Composefs Backend and not for Ostree

If bootupd is not present in the input container image, then systemd-boot will be used
by default (except on s390x). When bootupd is present, GRUB is the default; request
systemd-boot with `--bootloader systemd`, or with `bootloader = "systemd"` in the
`[install]` section of the install configuration.

systemd-boot is installed one of two ways:

- Through bootupd, with shim in front of it, when the image's bootupd can install it:
  its `--bootloader` accepts `systemd` (bootupd 0.3.0 and newer), its update metadata
  lists a systemd-boot component, and the target has a single ESP. The systemd-boot
  package must ship the binary as a bootupd component, as Fedora's `systemd-boot-x64`
  does since 262, and the metadata must be regenerated after installing it, because the
  metadata of the base image does not list packages added later (see the example below).
  The image must also ship shim; to install systemd-boot without shim, remove bootupd.
- Through `bootctl install` otherwise. This writes systemd-boot directly to
  `EFI/BOOT/BOOT<arch>.EFI`, with no shim. bootc does not run `bootctl update` later.
  Unless the image enables `systemd-boot-update.service` (Fedora and CentOS images
  disable it), nothing updates that copy of systemd-boot.

For example, a Fedora image for x86_64 adds the component with:

```dockerfile
RUN dnf -y install systemd-boot-x64 && bootupctl backend generate-update-metadata
```

With shim in front of it, systemd-boot boots with the firmware's stock Secure Boot keys
as long as shim trusts the key systemd-boot is signed with, and fwupd can chain its UEFI
capsule updates through shim. Fedora's shim does not trust the key Fedora's
systemd-boot is signed with yet ([rhbz#2268695](https://bugzilla.redhat.com/show_bug.cgi?id=2268695)).
Until it does, either boot without Secure Boot, or enroll the certificate systemd-boot is
signed with (`fedora-signer-20250530` for systemd-boot 262) as a Machine Owner Key.
bootc images ship `mokutil` but not sbsigntools: run the first two commands in a container
of the image with sbsigntools installed, and the last one on the system itself.

```
sbattach --detach systemd-boot.p7 /usr/lib/efi/systemd-boot/*/EFI/fedora/grubx64.efi
openssl pkcs7 -inform DER -in systemd-boot.p7 -print_certs | openssl x509 -outform DER -out systemd-boot.der
mokutil --import systemd-boot.der
```

`mokutil --import` asks for a one-time password, which MokManager asks for again on the
next boot to complete the enrollment. This trusts only that certificate: should Fedora
sign a later systemd-boot with a different one, the system stops booting at shim once
`bootloader-update.service` installs it, unless that one is enrolled too. Without shim,
the firmware's `db` must trust the signers of systemd-boot and of the kernels or UKIs it
boots.

Once bootupd has installed systemd-boot, it owns shim and systemd-boot on the ESP:
images that enable `bootloader-update.service` update them at boot, and every image
the system later updates or switches to must keep shipping the systemd-boot component.
The first bootloader update from an image without it that carries a newer shim removes
systemd-boot from the ESP, and the system stops booting at shim.

Adding a systemd-boot component to an image also affects GRUB installs from it:

- A bootupd that does not accept `--bootloader systemd` copies every component, so
  systemd-boot replaces GRUB's second stage. Only add the component together with a
  bootupd that accepts it.
- With both GRUB and systemd-boot components, the metadata has no default bootloader.
  Tools that run `bootupctl backend install` without `--bootloader`, such as older
  releases of bootc and the installer in bootc-image-builder's ISOs, then fail whenever
  only bootupd's EFI component is targeted: on EFI-booted x86_64 machines unless
  `--generic-image` is used, and on every aarch64 install. Run
  `bootupctl backend set-default-bootloader grub` after generating the metadata to keep
  GRUB their default; regenerating the metadata clears it again. bootc itself ignores
  that default and installs the bootloader it is asked for.

Secure Boot keys from `/usr/lib/bootc/install/secureboot-keys` are staged on the ESP on
both paths, as described under Secure Boot Keys in
[the install reference](man/bootc-install.8.md).

## s390x

bootc uses `zipl`.

## none

It is possible to skip bootloader installation entirely by using `--bootloader=none` (or `bootloader = "none"` in the [install] section of the config file).

With this option, users can have explicit control over how the boot loading is handled, without bootc or bootupd intervention.

NOTE: none is only supported for the Ostree backend and not for Composefs. It is also not supported for the s390x architecture. If used with `--generic-image`, it will lead to a generic image that does not have support for any bootloader.
