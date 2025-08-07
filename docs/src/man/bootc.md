# NAME

bootc - Deploy and transactionally in-place with bootable container
images

# SYNOPSIS

**bootc** \[**-h**\|**\--help**\] \[**-V**\|**\--version**\]
\<*subcommands*\>

# DESCRIPTION

Deploy and transactionally in-place with bootable container images.

The \`bootc\` project currently uses ostree-containers as a backend to
support a model of bootable container images. Once installed, whether
directly via \`bootc install\` (executed as part of a container) or via
another mechanism such as an OS installer tool, further updates can be
pulled and \`bootc upgrade\`.

# OPTIONS

**-h**, **\--help**

:   Print help (see a summary with \'-h\')

**-V**, **\--version**

:   Print version

# SUBCOMMANDS

bootc-upgrade(8)

:   Download and queue an updated container image to apply

bootc-switch(8)

:   Target a new container image reference to boot

bootc-rollback(8)

:   Change the bootloader entry ordering; the deployment under
    \`rollback\` will be queued for the next boot, and the current will
    become rollback. If there is a \`staged\` entry (an unapplied,
    queued upgrade) then it will be discarded

bootc-edit(8)

:   Apply full changes to the host specification

bootc-status(8)

:   Display status

bootc-usr-overlay(8)

:   Adds a transient writable overlayfs on \`/usr\` that will be
    discarded on reboot

bootc-install(8)

:   Install the running container to a target

bootc-container(8)

:   Operations which can be executed as part of a container build

bootc-help(8)

:   Print this message or the help of the given subcommand(s)

# VERSION

v1.6.0
