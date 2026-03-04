# NAME

bootc-usr-overlay - Adds a transient overlayfs on `/usr` that will be discarded
on reboot

# SYNOPSIS

**bootc usr-overlay** \[*OPTIONS...*\]

# DESCRIPTION

Adds a transient overlayfs on `/usr` that will be discarded on reboot. The
overlayfs is read/write by default.

## USE CASES

A common pattern is wanting to use tracing/debugging tools, such as
`strace` that may not be in the base image. A system package manager
such as `apt` or `dnf` can apply changes into this transient overlay
that will be discarded on reboot.

## /ETC AND /VAR

However, this command has no effect on `/etc` and `/var` - changes
written there will persist. It is common for package installations to
modify these directories.

## UNMOUNTING

Almost always, a system process will hold a reference to the open mount
point. You can however invoke `umount -l /usr` to perform a "lazy
unmount".

<!-- BEGIN GENERATED OPTIONS -->
<!-- END GENERATED OPTIONS -->

# VERSION

<!-- VERSION PLACEHOLDER -->

