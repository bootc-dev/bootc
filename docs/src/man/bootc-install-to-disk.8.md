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

## Partitioning details

The default as of bootc 1.11 uses the [Discoverable Partitions Specification](https://uapi-group.org/specifications/specs/discoverable_partitions_specification/)
(DPS) for the generated root filesystem, as well as any required system partitions
such as the EFI system partition.

### Partition layout

The installer creates a GPT partition table with architecture-appropriate
partitions. The exact layout varies by architecture but generally includes:

- **Boot partition** (architecture-specific): BIOS boot for x86_64, PReP for ppc64le, etc.
- **ESP**: EFI System Partition on UEFI architectures (x86_64, aarch64), at least 512 MiB
- **Boot**: Separate `/boot` partition, only created when using LUKS encryption
- **Root**: The root filesystem, using the remaining disk space

The root partition uses an architecture-specific DPS type GUID. Specific partition
sizes and type GUIDs are implementation details that may change between versions;
use `install to-filesystem` if you need precise control over the partition layout.

### Root filesystem discovery

Note that by default when used with "type 1" bootloader setups (i.e. non-UKI)
a kernel argument `root=UUID=<uuid of filesystem>` is injected by default.
This provides compatibility with existing initramfs implementations.

When used with the composefs backend and UKIs, it's recommended that
a bootloader implementing the DPS specification is used and that the root
partition is auto-discovered. In this configuration, `systemd-gpt-auto-generator`
in the initramfs will automatically find and mount the root partition based on
its DPS type GUID, without requiring an explicit `root=` kernel argument.

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

**--bootupd-skip-boot-uuid**

    Don't pass --write-uuid to bootupd during bootloader installation

**--bootloader**=*BOOTLOADER*

    The bootloader to use

    Possible values:
    - grub
    - systemd
    - none

**--via-loopback**

    Instead of targeting a block device, write to a file via loopback

**--composefs-backend**

    If true, composefs backend is used, else ostree backend is used

    Default: false

**--insecure**

    Make fs-verity validation optional in case the filesystem doesn't support it

    Default: false

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
