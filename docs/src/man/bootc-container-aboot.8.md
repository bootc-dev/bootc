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

By default, or with `--erofs-version=v1`, the command line contains the V1
composefs argument followed by a V2 compatibility fallback. Use
`--erofs-version=v1-only` to omit the V2 fallback and shorten the kernel command
line. This requires a V1 composefs repository on the target machine.
Explicit `--erofs-version=v2` emits only the legacy V2 argument.

# OPTIONS

<!-- BEGIN GENERATED OPTIONS -->
**--rootfs**=*ROOTFS*

    Operate on the provided rootfs

    Default: /

**--allow-missing-verity**

    Make fs-verity validation optional in case the filesystem doesn't support it

**--erofs-version**=*EROFS_VERSION*

    EROFS format version to use when computing the composefs digest

    Possible values:
    - v1
    - v1-only
    - v2

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
