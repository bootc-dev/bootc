# NAME

bootc-container-aboot - Build an Android boot or ukiboot image using aboot-update

# SYNOPSIS

bootc container aboot [OPTIONS]

# DESCRIPTION

Build an Android boot image or ukiboot UKI from a container root filesystem using
`aboot-update`. The image type and configuration details depends on the `aboot.cfg`. This
image includes kernel, initrd, cmdline, and (optionally) dtb.

The image is written to `aboot-<kernel-version>.img` in the output directory.  By default,
that directory is `/boot` within the supplied root filesystem.  `aboot-update` must be
available in the build environment.

# OPTIONS

<!-- BEGIN GENERATED OPTIONS -->
**--rootfs**=*ROOTFS*

    Operate on the provided rootfs

    Default: /

**--allow-missing-verity**

    Make fs-verity validation optional in case the filesystem doesn't support it

**--write-dumpfile-to**=*WRITE_DUMPFILE_TO*

    Write a dumpfile to this path

**--kernel-dir**=*KERNEL_DIR*

    The directory containing vmlinuz and initramfs.img. Must be of the format /parent/$kernel_version

**--out**=*OUT*

    Output directory. Defaults to $rootfs/boot

<!-- END GENERATED OPTIONS -->

# EXAMPLES

    bootc container aboot --rootfs /target --kernel-dir /kernel/KVER --out /out

# SEE ALSO

**bootc**(8), **bootc-container-ukify**(8)

# VERSION

<!-- VERSION PLACEHOLDER -->
