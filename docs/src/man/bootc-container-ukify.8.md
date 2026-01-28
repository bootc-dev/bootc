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

<!-- END GENERATED OPTIONS -->

# EXAMPLES

    bootc container ukify --rootfs /target -- --output /output/uki.efi

# SEE ALSO

**bootc**(8), **ukify**(1)

# VERSION

<!-- VERSION PLACEHOLDER -->
