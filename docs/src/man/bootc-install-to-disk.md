# NAME

bootc-install-to-disk - Install to the target block device

# SYNOPSIS

**bootc install to-disk** \[**\--wipe**\] \[**\--block-setup**\]
\[**\--filesystem**\] \[**\--root-size**\] \[**\--source-imgref**\]
\[**\--target-transport**\] \[**\--target-imgref**\]
\[**\--enforce-container-sigpolicy**\] \[**\--skip-fetch-check**\]
\[**\--disable-selinux**\] \[**\--karg**\]
\[**\--root-ssh-authorized-keys**\] \[**\--generic-image**\]
\[**\--bound-images**\] \[**\--stateroot**\] \[**\--via-loopback**\]
\[**-h**\|**\--help**\] \<*DEVICE*\>

# DESCRIPTION

Install to the target block device.

This command must be invoked inside of the container, which will be
installed. The container must be run in \`\--privileged\` mode, and
hence will be able to see all block devices on the system.

The default storage layout uses the root filesystem type configured in
the container image, alongside any required system partitions such as
the EFI system partition. Use \`install to-filesystem\` for anything
more complex such as RAID, LVM, LUKS etc.

# OPTIONS

**-v**, **\--verbose**

:   Increase logging verbosity

    Use `-vv`, `-vvv` to increase verbosity more.

**\--wipe**

:   Automatically wipe all existing data on device

**\--block-setup**=*BLOCK_SETUP*

:   Target root block device setup.

    direct: Filesystem written directly to block device tpm2-luks: Bind
    unlock of filesystem to presence of the default tpm2 device.\

    \
    \[*possible values: *direct, tpm2-luks\]

**\--filesystem**=*FILESYSTEM*

:   Target root filesystem type\

    \
    \[*possible values: *xfs, ext4, btrfs\]

**\--root-size**=*ROOT_SIZE*

:   Size of the root partition (default specifier: M). Allowed
    specifiers: M (mebibytes), G (gibibytes), T (tebibytes).

    By default, all remaining space on the disk will be used.

**\--source-imgref**=*SOURCE_IMGREF*

:   Install the system from an explicitly given source.

    By default, bootc install and install-to-filesystem assumes that it
    runs in a podman container, and it takes the container image to
    install from the podmans container registry. If \--source-imgref is
    given, bootc uses it as the installation source, instead of the
    behaviour explained in the previous paragraph. See skopeo(1) for
    accepted formats.

**\--target-transport**=*TARGET_TRANSPORT* \[default: registry\]

:   The transport; e.g. oci, oci-archive, containers-storage. Defaults
    to \`registry\`

**\--target-imgref**=*TARGET_IMGREF*

:   Specify the image to fetch for subsequent updates

**\--enforce-container-sigpolicy**

:   This is the inverse of the previous
    \`\--target-no-signature-verification\` (which is now a no-op).
    Enabling this option enforces that \`/etc/containers/policy.json\`
    includes a default policy which requires signatures

**\--skip-fetch-check**

:   By default, the accessiblity of the target image will be verified
    (just the manifest will be fetched). Specifying this option
    suppresses the check; use this when you know the issues it might
    find are addressed.

    A common reason this may fail is when one is using an image which
    requires registry authentication, but not embedding the pull secret
    in the image so that updates can be fetched by the installed OS
    \"day 2\".

**\--disable-selinux**

:   Disable SELinux in the target (installed) system.

    This is currently necessary to install \*from\* a system with
    SELinux disabled but where the target does have SELinux enabled.

**\--karg**=*KARG*

:   Add a kernel argument. This option can be provided multiple times.

    Example: \--karg=nosmt \--karg=console=ttyS0,114800n8

**\--root-ssh-authorized-keys**=*ROOT_SSH_AUTHORIZED_KEYS*

:   The path to an \`authorized_keys\` that will be injected into the
    \`root\` account.

    The implementation of this uses systemd \`tmpfiles.d\`, writing to a
    file named \`/etc/tmpfiles.d/bootc-root-ssh.conf\`. This will have
    the effect that by default, the SSH credentials will be set if not
    present. The intention behind this is to allow mounting the whole
    \`/root\` home directory as a \`tmpfs\`, while still getting the SSH
    key replaced on boot.

**\--generic-image**

:   Perform configuration changes suitable for a \"generic\" disk image.
    At the moment:

    \- All bootloader types will be installed - Changes to the system
    firmware will be skipped

**\--bound-images**=*BOUND_IMAGES* \[default: stored\]

:   How should logically bound images be retrieved\

    \
    *Possible values:*

    -   stored: Bound images must exist in the sources root container
        storage (default)

    -   pull: Bound images will be pulled and stored directly in the
        targets bootc container storage

**\--stateroot**=*STATEROOT*

:   The stateroot name to use. Defaults to \`default\`

**\--via-loopback**

:   Instead of targeting a block device, write to a file via loopback

**-h**, **\--help**

:   Print help (see a summary with -h)

\<*DEVICE*\>

:   Target block device for installation. The entire device will be
    wiped

# VERSION

v1.1.6
