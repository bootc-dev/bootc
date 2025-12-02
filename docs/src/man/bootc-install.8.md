# NAME

bootc-install - Install the running container to a target

# SYNOPSIS

**bootc install** \[*OPTIONS...*\] <*SUBCOMMAND*>

# DESCRIPTION

Install the running container to a target.

## Understanding installations

OCI containers are effectively layers of tarballs with JSON for
metadata; they cannot be booted directly. The `bootc install` flow is
a highly opinionated method to take the contents of the container image
and install it to a target block device (or an existing filesystem) in
such a way that it can be booted.

For example, a Linux partition table and filesystem is used, and the
bootloader and kernel embedded in the container image are also prepared.

A bootc installed container currently uses OSTree as a backend, and this
sets it up such that a subsequent `bootc upgrade` can perform in-place
updates.

An installation is not simply a copy of the container filesystem, but
includes other setup and metadata.

## Secure Boot Keys

When installing with `systemd-boot`, bootc can let `systemd-boot` can handle enrollment of Secure Boot keys by putting signed EFI signature lists in `/usr/lib/bootc/install/secureboot-keys` which will copy over into `ESP/loader/keys` after bootloader installation. The keys will be copied to `loader/keys` subdirectory of the ESP. after installing `systemd-boot` to the system. More information on how key enrollment works with `systemd-boot` is available in the [systemd-boot](https://github.com/systemd/systemd/blob/26b2085d54ebbfca8637362eafcb4a8e3faf832f/man/systemd-boot.xml#L392) man page.

<!-- BEGIN GENERATED OPTIONS -->
<!-- END GENERATED OPTIONS -->

# SUBCOMMANDS

<!-- BEGIN GENERATED SUBCOMMANDS -->
| Command | Description |
|---------|-------------|
| **bootc install to-disk** | Install to the target block device |
| **bootc install to-filesystem** | Install to an externally created filesystem structure |
| **bootc install to-existing-root** | Install to the host root filesystem |
| **bootc install finalize** | Execute this as the penultimate step of an installation using `install to-filesystem` |
| **bootc install ensure-completion** | Intended for use in environments that are performing an ostree-based installation, not bootc |
| **bootc install print-configuration** | Output JSON to stdout that contains the merged installation configuration as it may be relevant to calling processes using `install to-filesystem` that in particular want to discover the desired root filesystem type from the container image |

<!-- END GENERATED SUBCOMMANDS -->

# VERSION

<!-- VERSION PLACEHOLDER -->

