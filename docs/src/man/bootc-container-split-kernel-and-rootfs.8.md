# NAME

bootc-container-split-kernel-and-rootfs - Split kernel and rootfs from a container image

# SYNOPSIS

bootc container split-kernel-and-rootfs

# DESCRIPTION

Split kernel and rootfs from a container image

# OPTIONS

<!-- BEGIN GENERATED OPTIONS -->
**--rootfs**=*ROOTFS*

    Operate on the provided rootfs

    Default: /

**--output**=*OUTPUT*

    Output directory for the extracted kernel files

<!-- END GENERATED OPTIONS -->

# EXAMPLES

**Extract kernel files from the current root filesystem to `/kernel`:**

```
bootc container split-kernel-and-rootfs --output /kernel
```

This extracts the kernel and initramfs from the current root filesystem (/) and places them in `/kernel/<kernel-version>/` with filenames `vmlinuz` and `initramfs.img`.

**Extract kernel files from a mounted container rootfs:**

```
bootc container split-kernel-and-rootfs --rootfs /mnt/container-rootfs --output /output/kernels
```

This extracts kernel files from a container filesystem mounted at `/mnt/container-rootfs` and places them in the output directory.

**Example output structure:**

After running the command, the output directory will contain:

```
/output/kernels/
└── 6.5.0-15-generic/
    ├── vmlinuz
    └── initramfs.img
```

where `6.5.0-15-generic` is the detected kernel version from the source rootfs.

# SEE ALSO

**bootc**(8)

# VERSION

<!-- VERSION PLACEHOLDER -->
