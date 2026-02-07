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
