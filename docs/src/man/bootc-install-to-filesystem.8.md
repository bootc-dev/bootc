# NAME

bootc-install-to-filesystem - Install to an externally created
filesystem structure

# SYNOPSIS

**bootc install to-filesystem** \[*OPTIONS...*\] <*ROOT_PATH*>

# DESCRIPTION

Install to an externally created filesystem structure.

In this variant of installation, the root filesystem alongside any
necessary platform partitions (such as the EFI system partition) are
prepared and mounted by an external tool or script. The root filesystem
is currently expected to be empty by default.

# OPTIONS

<!-- BEGIN GENERATED OPTIONS -->
**ROOT_PATH**

    Path to the mounted root filesystem

    This argument is required.

**--root-mount-spec**=*ROOT_MOUNT_SPEC*

    Source device specification for the root filesystem.  For example, UUID=2e9f4241-229b-4202-8429-62d2302382e1

**--boot-mount-spec**=*BOOT_MOUNT_SPEC*

    Mount specification for the /boot filesystem

**--replace**=*REPLACE*

    Initialize the system in-place; at the moment, only one mode for this is implemented. In the future, it may also be supported to set up an explicit "dual boot" system

    Possible values:
    - wipe
    - alongside

**--acknowledge-destructive**

    If the target is the running system's root filesystem, this will skip any warnings

**--skip-finalize**

    The default mode is to "finalize" the target filesystem by invoking `fstrim` and similar operations, and finally mounting it readonly.  This option skips those operations.  It is then the responsibility of the invoking code to perform those operations

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

# VERSION

<!-- VERSION PLACEHOLDER -->

