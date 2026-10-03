# NAME

bootc-install - Install the running container to a target

# SYNOPSIS

**bootc install** \[*OPTIONS...*\] <*SUBCOMMAND*>

# DESCRIPTION

Install the running container to a target.

## Understanding installations

The `bootc install` flow turns a container image into a bootable system,
including filesystem, bootloader, and update metadata setup. It is not
simply a copy of the container filesystem.

See [Installing bootc compatible images](../bootc-installation.7.md) for the
installation model, prerequisites, and end-to-end examples. This reference
documents the command and its subcommands.

## Secure Boot Keys

When installing with `systemd-boot`, bootc can let `systemd-boot` can handle enrollment of Secure Boot keys by putting signed EFI signature lists in `/usr/lib/bootc/install/secureboot-keys` which will copy over into `ESP/loader/keys` after bootloader installation. The keys will be copied to `loader/keys` subdirectory of the ESP. after installing `systemd-boot` to the system. More information on how key enrollment works with `systemd-boot` is available in the [systemd-boot](https://github.com/systemd/systemd/blob/26b2085d54ebbfca8637362eafcb4a8e3faf832f/man/systemd-boot.xml#L392) man page.

The keys are staged whether bootc installs systemd-boot with `bootctl` or through
bootupd. Through bootupd, shim sits in front of systemd-boot, so the enrolled `db` must
also contain the Microsoft UEFI CA 2023, which signs shim, or the firmware may refuse to
start shim. The older Microsoft Corporation UEFI CA 2011 also starts current shim builds,
but bootupd 0.3.2 and newer refuse every bootloader update under Secure Boot without the
2023 CA, so neither shim nor systemd-boot is updated and `bootloader-update.service` fails.
Note that systemd-boot enrolls a key set named `auto` without asking when it runs in a
virtual machine in setup mode.

<!-- BEGIN GENERATED OPTIONS -->
<!-- END GENERATED OPTIONS -->

# SUBCOMMANDS

<!-- BEGIN GENERATED SUBCOMMANDS -->
| Command | Description |
|---------|-------------|
| **bootc install mount** | Mount an installed deployment into a caller-owned directory |
| **bootc install to-disk** | Install to the target block device |
| **bootc install to-filesystem** | Install to an externally created filesystem structure |
| **bootc install to-existing-root** | Install to the host root filesystem |
| **bootc install finalize** | Execute this as the penultimate step of an installation using `install to-filesystem` |
| **bootc install ensure-completion** | Intended for use in environments that are performing an ostree-based installation, not bootc |
| **bootc install print-configuration** | Output JSON to stdout that contains the merged installation configuration as it may be relevant to calling processes using `install to-filesystem` that in particular want to discover the desired root filesystem type from the container image |

<!-- END GENERATED SUBCOMMANDS -->

# VERSION

<!-- VERSION PLACEHOLDER -->
