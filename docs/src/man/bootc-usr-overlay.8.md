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

## STORAGE AND MEMORY REQUIREMENTS

The transient overlay is backed by a `tmpfs` filesystem, which means all
data written to the overlay (i.e. installed packages) is stored in
**system memory (RAM)**, not on persistent disk.  By default the kernel
sizes this `tmpfs` at 50% of physical RAM.

On systems with limited memory, installing large packages into the
overlay can exhaust available RAM and result in `ENOSPC` ("No space left
on device") errors.  There is currently no pre-flight space check and no
early warning before the `tmpfs` is full.

Keep this in mind when using transient overlays in memory-constrained
environments such as CI runners or small virtual machines.  If the
combined size of the packages being installed approaches half of the
system's RAM, consider increasing the VM's memory allocation instead.

## /ETC AND /VAR

However, this command has no effect on `/etc` and `/var` - changes
written there will persist. It is common for package installations to
modify these directories.

## UNMOUNTING

Almost always, a system process will hold a reference to the open mount
point. You can however invoke `umount -l /usr` to perform a "lazy
unmount".

# OPTIONS

<!-- BEGIN GENERATED OPTIONS -->
**--read-only**

    Mount the overlayfs as read-only. A read-only overlayfs is useful since it may be remounted as read/write in a private mount namespace and written to while the mount point remains read-only to the rest of the system

<!-- END GENERATED OPTIONS -->

# VERSION

<!-- VERSION PLACEHOLDER -->

