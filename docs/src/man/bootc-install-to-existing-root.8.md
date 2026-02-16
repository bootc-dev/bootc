# NAME

bootc-install-to-existing-root - Install to the host root filesystem

# SYNOPSIS

**bootc install to-existing-root** \[*OPTIONS...*\] \[*ROOT_PATH*\]

# DESCRIPTION

Install to the host root filesystem.

This is a variant of `install to-filesystem` that is designed to
install \"alongside\" the running host root filesystem. Currently, the
host root filesystem\'s `/boot` partition will be wiped, but the
content of the existing root will otherwise be retained, and will need
to be cleaned up if desired when rebooted into the new root.

## Managing configuration: before and after reboot

When using `to-existing-root`, there are two distinct scenarios for managing
configuration files:

1. **Before rebooting**: Injecting new configuration into the newly installed system
2. **After rebooting**: Migrating configuration from the old system to the new system

### Before reboot: Injecting new configuration

If you need to inject new configuration files (such as custom `/etc/fstab` entries,
systemd mount units, or other configuration) into the newly installed system before
rebooting, you can find the deployment directory in the ostree repository structure.
The new deployment is located at:

```
/ostree/deploy/<stateroot>/deploy/<checksum>.<serial>/
```

Where `<stateroot>` defaults to `default` unless you specified a different
value with `--stateroot`.

To find the path to the newly installed deployment:

```bash
# Get the full deployment path directly
DEPLOY_PATH=$(ostree admin --sysroot=/target --print-current-dir)
```

This will return the full path, for example:
`/target/ostree/deploy/default/deploy/807f233831a03d315289a4ba29c1670d8bd326d4569eabee7a84f25327997307.0`

You can then modify files in that deployment. For example, to add systemd mount units:

```bash
# Get deployment path
DEPLOY_PATH=$(ostree admin --sysroot=/target --print-current-dir)
# Add a systemd mount unit
vi ${DEPLOY_PATH}/etc/systemd/system/data.mount
```

#### Injecting kernel arguments for local state

A better approach for machine-local configuration like filesystem mounts is to
inject kernel arguments during installation. Kernel arguments are ideal for
local/machine-specific state in a bootc system.

For filesystem mounts, use `systemd.mount-extra` instead of `/etc/fstab`:

```bash
# Add a mount via kernel argument (preferred over /etc/fstab)
bootc install to-existing-root \
  --karg="systemd.mount-extra=UUID=<uuid>:/data:xfs:defaults"
```

The `systemd.mount-extra` syntax is: `source:path:type:options`

You can also inject other local kernel arguments for machine-specific configuration:

```bash
# Add console settings for serial access
bootc install to-existing-root --karg="console=ttyS0,115200"

# Add storage-specific options
bootc install to-existing-root --karg="rootflags=subvol=root"
```

This approach is cleaner than editing configuration files because kernel arguments
are explicitly designed for local/machine-specific state in a bootc system.

**Note:** In the future, this functionality will be provided via a dedicated
bootc API to make finding and modifying the deployment more straightforward.

### After reboot: Migrating data from the old system

After rebooting into the new bootc system, the previous root filesystem data
is accessible at `/sysroot` (the "physical root"). This allows you to migrate
data from the old system to the new one.

**Important:** Any configuration data from `/etc` that you want to use in the
new system must be **manually copied** from `/sysroot/etc` to `/etc` after
rebooting. There is currently no automated mechanism for migrating this data.

For example, to migrate configuration after rebooting:

```bash
# After rebooting into the new system
# Copy network configuration from the old system
cp /sysroot/etc/sysconfig/network-scripts/ifcfg-eth0 /etc/sysconfig/network-scripts/

# Copy application configuration
cp -r /sysroot/etc/myapp /etc/

# Selectively merge configuration files
vi /etc/resolv.conf  # Add nameservers from /sysroot/etc/resolv.conf

# For user accounts, use proper tools
vipw  # Carefully review and merge users from /sysroot/etc/passwd
```

This applies to network configurations, user accounts, application settings,
and other system configuration stored in `/etc`. Review files in `/sysroot/etc`
and manually copy or merge what you need into `/etc`.

**Note:** For filesystem mounts from `/etc/fstab` in the old system, consider
using kernel arguments (via `systemd.mount-extra`) injected before reboot instead
of migrating the fstab entries. See the "Injecting kernel arguments" section above.

# OPTIONS

<!-- BEGIN GENERATED OPTIONS -->
**ROOT_PATH**

    Path to the mounted root; this is now not necessary to provide. Historically it was necessary to ensure the host rootfs was mounted at here via e.g. `-v /:/target`

**--replace**=*REPLACE*

    Configure how existing data is treated

    Possible values:
    - wipe
    - alongside

    Default: alongside

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

**--acknowledge-destructive**

    Accept that this is a destructive action and skip a warning timer

**--cleanup**

    Add the bootc-destructive-cleanup systemd service to delete files from the previous install on first boot

**--composefs-backend**

    If true, composefs backend is used, else ostree backend is used

    Default: false

**--insecure**

    Make fs-verity validation optional in case the filesystem doesn't support it

    Default: false

**--uki-addon**=*UKI_ADDON*

    Name of the UKI addons to install without the ".efi.addon" suffix. This option can be provided multiple times if multiple addons are to be installed

<!-- END GENERATED OPTIONS -->

# VERSION

<!-- VERSION PLACEHOLDER -->

