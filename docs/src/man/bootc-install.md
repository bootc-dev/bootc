# NAME

bootc-install - Install the running container to a target

# SYNOPSIS

**bootc install** \[**-h**\|**\--help**\] \<*subcommands*\>

# DESCRIPTION

Install the running container to a target.

\## Understanding installations

OCI containers are effectively layers of tarballs with JSON for
metadata; they cannot be booted directly. The \`bootc install\` flow is
a highly opinionated method to take the contents of the container image
and install it to a target block device (or an existing filesystem) in
such a way that it can be booted.

For example, a Linux partition table and filesystem is used, and the
bootloader and kernel embedded in the container image are also prepared.

A bootc installed container currently uses OSTree as a backend, and this
sets it up such that a subsequent \`bootc upgrade\` can perform in-place
updates.

An installation is not simply a copy of the container filesystem, but
includes other setup and metadata.

# OPTIONS

**-v**, **\--verbose**

:   Increase logging verbosity

    Use `-vv`, `-vvv` to increase verbosity more.

**-h**, **\--help**

:   Print help (see a summary with -h)

# SUBCOMMANDS

bootc-install-to-disk(8)

:   Install to the target block device

bootc-install-to-filesystem(8)

:   Install to an externally created filesystem structure

bootc-install-to-existing-root(8)

:   Install to the host root filesystem

bootc-install-finalize(8)

:   Execute this as the penultimate step of an installation using
    \`install to-filesystem\`

bootc-install-ensure-completion(8)

:   Intended for use in environments that are performing an ostree-based
    installation, not bootc

bootc-install-print-configuration(8)

:   Output JSON to stdout that contains the merged installation
    configuration as it may be relevant to calling processes using
    \`install to-filesystem\` that in particular want to discover the
    desired root filesystem type from the container image

bootc-install-help(8)

:   Print this message or the help of the given subcommand(s)

# VERSION

v1.1.6
