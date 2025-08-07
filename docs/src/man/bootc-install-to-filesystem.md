# NAME

bootc-install-to-filesystem - Install to an externally created
filesystem structure

# SYNOPSIS

**bootc install to-filesystem** \[**\--root-mount-spec**\]
\[**\--boot-mount-spec**\] \[**\--replace**\]
\[**\--acknowledge-destructive**\] \[**\--skip-finalize**\]
\[**\--source-imgref**\] \[**\--target-transport**\]
\[**\--target-imgref**\] \[**\--enforce-container-sigpolicy**\]
\[**\--run-fetch-check**\] \[**\--skip-fetch-check**\]
\[**\--disable-selinux**\] \[**\--karg**\]
\[**\--root-ssh-authorized-keys**\] \[**\--generic-image**\]
\[**\--bound-images**\] \[**\--stateroot**\] \[**-h**\|**\--help**\]
\<*ROOT_PATH*\>

# DESCRIPTION

Install to an externally created filesystem structure.

In this variant of installation, the root filesystem alongside any
necessary platform partitions (such as the EFI system partition) are
prepared and mounted by an external tool or script. The root filesystem
is currently expected to be empty by default.

# OPTIONS

**\--root-mount-spec**=*ROOT_MOUNT_SPEC*

:   Source device specification for the root filesystem. For example,
    UUID=2e9f4241-229b-4202-8429-62d2302382e1

    If not provided, the UUID of the target filesystem will be used.

**\--boot-mount-spec**=*BOOT_MOUNT_SPEC*

:   Mount specification for the /boot filesystem.

    This is optional. If \`/boot\` is detected as a mounted partition,
    then its UUID will be used.

**\--replace**=*REPLACE*

:   Initialize the system in-place; at the moment, only one mode for
    this is implemented. In the future, it may also be supported to set
    up an explicit \"dual boot\" system\

    \
    *Possible values:*

    -   wipe: Completely wipe the contents of the target filesystem.
        This cannot be done if the target filesystem is the one the
        system is booted from

    -   alongside: This is a destructive operation in the sense that the
        bootloader state will have its contents wiped and replaced.
        However, the running system (and all files) will remain in place
        until reboot

**\--acknowledge-destructive**

:   If the target is the running system\'s root filesystem, this will
    skip any warnings

**\--skip-finalize**

:   The default mode is to \"finalize\" the target filesystem by
    invoking \`fstrim\` and similar operations, and finally mounting it
    readonly. This option skips those operations. It is then the
    responsibility of the invoking code to perform those operations

**\--source-imgref**=*SOURCE_IMGREF*

:   Install the system from an explicitly given source.

    By default, bootc install and install-to-filesystem assumes that it
    runs in a podman container, and it takes the container image to
    install from the podman\'s container registry. If \--source-imgref
    is given, bootc uses it as the installation source, instead of the
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

**\--run-fetch-check**

:   Verify the image can be fetched from the bootc image. Updates may
    fail when the installation host is authenticated with the registry
    but the pull secret is not in the bootc image

**\--skip-fetch-check**

:   Verify the image can be fetched from the bootc image. Updates may
    fail when the installation host is authenticated with the registry
    but the pull secret is not in the bootc image

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

    -   stored: Bound images must exist in the source\'s root container
        storage (default)

    -   pull: Bound images will be pulled and stored directly in the
        target\'s bootc container storage

**\--stateroot**=*STATEROOT*

:   The stateroot name to use. Defaults to \`default\`

**-h**, **\--help**

:   Print help (see a summary with \'-h\')

\<*ROOT_PATH*\>

:   Path to the mounted root filesystem.

    By default, the filesystem UUID will be discovered and used for
    mounting. To override this, use \`\--root-mount-spec\`.

# VERSION

v1.6.0
