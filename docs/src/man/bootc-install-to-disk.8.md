# NAME

bootc-install-to-disk - Install to the target block device

# SYNOPSIS

**bootc install to-disk** \[*OPTIONS...*\] <*DEVICE*>

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
**DEVICE**

    Target block device for installation.  The entire device will be wiped

    This argument is required.

**--wipe**

    Automatically wipe all existing data on device

**--block-setup**=*BLOCK_SETUP*

    Target root block device setup

    Possible values:
    - direct
    - tpm2-luks

**--filesystem**=*FILESYSTEM*

    Target root filesystem type

    Possible values:
    - xfs
    - ext4
    - btrfs

**--root-size**=*ROOT_SIZE*

    Size of the root partition (default specifier: M).  Allowed specifiers: M (mebibytes), G (gibibytes), T (tebibytes)

**--source-imgref**=*SOURCE_IMGREF*

    Install the system from an explicitly given source

**--target-transport**=*TARGET_TRANSPORT*

    The transport; e.g. oci, oci-archive, containers-storage.  Defaults to `registry`

    Default: registry

**--target-imgref**=*TARGET_IMGREF*

    Specify the image to fetch for subsequent updates

**--enforce-container-sigpolicy**

    This is the inverse of the previous `--target-no-signature-verification` (which is now a no-op).  Enabling this option enforces that `/etc/containers/policy.json` includes a default policy which requires signatures

**--run-fetch-check**

    Verify the image can be fetched from the bootc image. Updates may fail when the installation host is authenticated with the registry but the pull secret is not in the bootc image

**--skip-fetch-check**

    Verify the image can be fetched from the bootc image. Updates may fail when the installation host is authenticated with the registry but the pull secret is not in the bootc image

**--disable-selinux**

    Disable SELinux in the target (installed) system

**--karg**=*KARG*

    Add a kernel argument.  This option can be provided multiple times

**--root-ssh-authorized-keys**=*ROOT_SSH_AUTHORIZED_KEYS*

    The path to an `authorized_keys` that will be injected into the `root` account

**--generic-image**

    Perform configuration changes suitable for a "generic" disk image. At the moment:

**--bound-images**=*BOUND_IMAGES*

    How should logically bound images be retrieved

    Possible values:
    - stored
    - skip
    - pull

    Default: stored

**--stateroot**=*STATEROOT*

    The stateroot name to use. Defaults to `default`

**--via-loopback**

    Instead of targeting a block device, write to a file via loopback

**--composefs-backend**

    If true, composefs backend is used, else ostree backend is used

    Default: false

**--insecure**

    Make fs-verity validation optional in case the filesystem doesn't support it

    Default: false

**--bootloader**=*BOOTLOADER*

    The bootloader to use

    Possible values:
    - grub
    - systemd

**--uki-addon**=*UKI_ADDON*

    Name of the UKI addons to install without the ".efi.addon" suffix. This option can be provided multiple times if multiple addons are to be installed

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
