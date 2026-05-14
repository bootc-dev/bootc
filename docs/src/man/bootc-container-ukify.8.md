# NAME

bootc-container-ukify - Build a Unified Kernel Image (UKI) using ukify

# SYNOPSIS

bootc container ukify [OPTIONS] [-- UKIFY_ARGS...]

# DESCRIPTION

Build a Unified Kernel Image (UKI) using ukify

This command computes the necessary arguments from the container image
(kernel, initrd, cmdline, os-release) and invokes ukify with them.
Any additional arguments after `--` are passed through to ukify unchanged.

# OPTIONS

<!-- BEGIN GENERATED OPTIONS -->
**ARGS**

    Additional arguments to pass to ukify (after `--`)

**--rootfs**=*ROOTFS*

    Operate on the provided rootfs

    Default: /

**--allow-missing-verity**

    Make fs-verity validation optional in case the filesystem doesn't support it

**--write-dumpfile-to**=*WRITE_DUMPFILE_TO*

    Write a dumpfile to this path

**--kernel-dir**=*KERNEL_DIR*

    The directory containing the kernel and initramfs.img Must be of the format /parent/$kernel_version

<!-- END GENERATED OPTIONS -->

# EXAMPLES

    bootc container ukify --rootfs /target -- --output /output/uki.efi

# SEE ALSO

**bootc**(8), **ukify**(1)

# VERSION

<!-- VERSION PLACEHOLDER -->
