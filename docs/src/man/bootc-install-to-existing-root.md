# NAME

bootc-install-to-existing-root - Install to the host root filesystem

# SYNOPSIS

**bootc install to-existing-root** \[**\--replace**\]
\[**\--source-imgref**\] \[**\--target-transport**\]
\[**\--target-imgref**\] \[**\--enforce-container-sigpolicy**\]
\[**\--run-fetch-check**\] \[**\--skip-fetch-check**\]
\[**\--disable-selinux**\] \[**\--karg**\]
\[**\--root-ssh-authorized-keys**\] \[**\--generic-image**\]
\[**\--bound-images**\] \[**\--stateroot**\]
\[**\--acknowledge-destructive**\] \[**\--cleanup**\]
\[**-h**\|**\--help**\] \[*ROOT_PATH*\]

# DESCRIPTION

Install to the host root filesystem.

This is a variant of \`install to-filesystem\` that is designed to
install \"alongside\" the running host root filesystem. Currently, the
host root filesystem\'s \`/boot\` partition will be wiped, but the
content of the existing root will otherwise be retained, and will need
to be cleaned up if desired when rebooted into the new root.

# OPTIONS

**\--replace**=*REPLACE* \[default: alongside\]

:   Configure how existing data is treated\

    \
    *Possible values:*

    -   wipe: Completely wipe the contents of the target filesystem.
        This cannot be done if the target filesystem is the one the
        system is booted from

    -   alongside: This is a destructive operation in the sense that the
        bootloader state will have its contents wiped and replaced.
        However, the running system (and all files) will remain in place
        until reboot

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

**\--acknowledge-destructive**

:   Accept that this is a destructive action and skip a warning timer

**\--cleanup**

:   Add the bootc-destructive-cleanup systemd service to delete files
    from the previous install on first boot

**-h**, **\--help**

:   Print help (see a summary with \'-h\')

\[*ROOT_PATH*\] \[default: /target\]

:   Path to the mounted root; this is now not necessary to provide.
    Historically it was necessary to ensure the host rootfs was mounted
    at here via e.g. \`-v /:/target\`

# VERSION

v1.6.0
