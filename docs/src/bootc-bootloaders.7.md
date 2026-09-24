# Bootloaders in `bootc`

`bootc` supports two ways to manage bootloaders.

## bootupd

[bootupd](https://github.com/coreos/bootupd/) is a project explicitly designed to abstract over and manage bootloader installation and configuration.
Today it primarily supports GRUB+shim. There are pending patches for it to support systemd-boot as well. 

When you run `bootc install`, it invokes `bootupctl backend install` to install the bootloader to the target disk or filesystem. The specific bootloader configuration is determined by the container image and the target system's hardware.

Currently, `bootc` only runs `bootupd` during the installation process. It does **not** automatically run `bootupctl update` to update the bootloader after installation. This means that bootloader updates must be handled separately, typically by the user or an automated system update process.

## systemd-boot

NOTE: systemd-boot is only supported for Composefs Backend and not for Ostree

If bootupd is not present in the input container image, then systemd-boot will be used
by default (except on s390x).

## s390x

bootc uses `zipl`.

## none

It is possible to skip bootloader installation entirely by using `--bootloader=none` (or `bootloader = "none"` in the [install] section of the config file).

With this option, users can have explicit control over how the boot loading is handled, without bootc or bootupd intervention.

NOTE: none is only supported for the Ostree backend and not for Composefs. It is also not supported for the s390x architecture. If used with `--generic-image`, it will lead to a generic image that does not have support for any bootloader.

## composefs backend

Whenever the container image has a UKI, bootc automatically selects the composefs backend during installation (see [Prerequisites](building/bootc-sealed-images.7.md#prerequisites) for the currently-supported UKI + systemd-boot configuration for building sealed images). Note that having a UKI does not by itself make an install sealed — that also depends on whether fs-verity enforcement is on, per [Overview](bootc-composefs.7.md#overview).

Composefs installs using a traditional `vmlinuz`/`initramfs.img` layout instead of a UKI can enforce fs-verity, but are never sealed, since nothing authenticates the root digest. They can use either `bootupd` (GRUB) or systemd-boot, the same as the ostree backend. Under the hood, bootc writes standard BLS boot entries for both UKI and traditional kernels; see the [composefs boot module documentation](https://github.com/bootc-dev/bootc/blob/main/crates/lib/src/bootc_composefs/boot.rs) for details on how entry filenames and sort-keys are chosen to sort correctly on both GRUB and systemd-boot.
