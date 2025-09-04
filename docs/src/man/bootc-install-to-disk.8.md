# NAME

bootc-install-to-disk - Install to the target block device

# SYNOPSIS

**bootc install to-disk** [*OPTIONS*] <*DEVICE*>

# DESCRIPTION

Install to the target block device.

This command must be invoked inside of the container, which will be
installed. The container must be run in `--privileged` mode, and
hence will be able to see all block devices on the system.

The default storage layout uses the root filesystem type configured in
the container image, alongside any required system partitions such as
the EFI system partition. Use `install to-filesystem` for anything
more complex such as RAID, LVM, LUKS etc.

# OPTIONS

<!-- BEGIN GENERATED OPTIONS -->
<!-- END GENERATED OPTIONS -->

# EXAMPLES

Install to a disk, wiping all existing data:

    bootc install to-disk --wipe /dev/sda

Install with a specific root filesystem type:

    bootc install to-disk --filesystem xfs /dev/nvme0n1

Install with TPM2 LUKS encryption:

    bootc install to-disk --block-setup tpm2-luks /dev/sda

Install with custom kernel arguments:

    bootc install to-disk --karg=nosmt --karg=console=ttyS0 /dev/sda

# SEE ALSO

**bootc**(8), **bootc-install**(8), **bootc-install-to-filesystem**(8)

# VERSION

<!-- VERSION PLACEHOLDER -->
