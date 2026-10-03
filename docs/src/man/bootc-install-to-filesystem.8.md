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

## Install result

An installer that wraps this command often needs to know where the new
deployment ended up, for example to add configuration to its `/etc`
before the first boot. With one of the `--output-*` options, bootc
writes a machine-readable summary of the installation once it has
succeeded. The format is either JSON (`--output-json-*`) or "pairs"
(`--output-pairs-*`), and the destination is either a path, which is
replaced atomically (`--output-*-path`), or a file descriptor inherited
from the caller and open for writing (`--output-*-fd`), which bootc
closes after writing. A bad destination makes bootc fail before
installing anything. A path is resolved before bootc sets up its own
mounts, so one under e.g. `/tmp` works too. When running bootc in a
container, the path must be in a volume shared with the caller, and an
fd must be passed with `podman run --preserve-fds`.

The keys are a stable interface: new ones may be added, but the
existing ones keep their meaning. Paths are relative to the root of the
target filesystem.

| JSON key         | Pairs key         | Meaning                                                   |
|------------------|-------------------|-----------------------------------------------------------|
| `backend`        | `BACKEND`         | Storage backend: `ostree` or `composefs`                  |
| `stateroot`      | `STATEROOT`       | Stateroot of the deployment                               |
| `deploymentPath` | `DEPLOYMENT_PATH` | Root directory of the deployment                          |
| `etcPath`        | `ETC_PATH`        | Persistent `/etc` of the deployment                       |
| `varPath`        | `VAR_PATH`        | Persistent `/var`, shared by the stateroot's deployments  |
| `bootloader`     | `BOOTLOADER`      | Bootloader: `grub`, `grub-cc`, `systemd` or `none`        |
| `image`          | `IMAGE`           | Image the system updates from (see `--target-imgref`)     |
| `imageTransport` | `IMAGE_TRANSPORT` | Transport of that image, e.g. `registry`                  |
| `imageDigest`    | `IMAGE_DIGEST`    | Manifest digest of the installed image                    |

The pairs format is that of `lsblk --pairs --shell`, with one
`KEY="value"` per line: keys are valid shell variable names, and values
are double-quoted with `"`, `\`, `$` and `` ` `` escaped by a backslash,
so the output can be passed to `eval` or sourced with `.`. Control
characters, which bootc does not emit in practice, are written as
`\xNN` as in lsblk.

# OPTIONS

<!-- BEGIN GENERATED OPTIONS -->
**ROOT_PATH**

    Path to the mounted root filesystem

    This argument is required.

**--root-mount-spec**=*ROOT_MOUNT_SPEC*

    Source device specification for the root filesystem.  For example, `UUID=2e9f4241-229b-4202-8429-62d2302382e1`. If not provided, the UUID of the target filesystem will be used. This option is provided as some use cases might prefer to mount by a label instead via e.g. `LABEL=rootfs`

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

    This is the inverse of the previous `--target-no-signature-verification` (which is now a no-op).  Enabling this option enforces that `containers-policy.json` (see `man containers-policy.json` for the full search path) includes a default policy which requires signatures

**--run-fetch-check**

    Verify the image can be fetched from the bootc image. Updates may fail when the installation host is authenticated with the registry but the pull secret is not in the bootc image

**--skip-fetch-check**

    Verify the image can be fetched from the bootc image. Updates may fail when the installation host is authenticated with the registry but the pull secret is not in the bootc image

**--disable-selinux**

    Disable SELinux in the target (installed) system

**--karg**=*KARG*

    Add a kernel argument.  This option can be provided multiple times

**--karg-delete**=*KARG_DELETE*

    Remove a kernel argument.  This option can be provided multiple times

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
    - grub-cc
    - systemd
    - none

**--composefs-backend**

    Use the composefs backend instead of ostree. This is the default for images with a UKI, and for images with /usr/lib/composefs/setup-root-conf.toml and no ostree prepare-root.conf

    Default: false

**--allow-missing-verity**

    Make fs-verity validation optional in case the filesystem doesn't support it (composefs backend only)

    Default: false

**--uki-addon**=*UKI_ADDON*

    Name of the UKI addons to install without the ".efi.addon" suffix. This option can be provided multiple times if multiple addons are to be installed (composefs backend only)

**--output-json-path**=*PATH*

    Write the result of the installation as JSON to this path, replacing it atomically

**--output-json-fd**=*FD*

    Write the result of the installation as JSON to this inherited file descriptor, which must be open for writing, then close it

**--output-pairs-path**=*PATH*

    Write the result of the installation as shell-quoted KEY="value" lines, like `lsblk --pairs --shell`, to this path, replacing it atomically

**--output-pairs-fd**=*FD*

    Write the result of the installation as shell-quoted KEY="value" lines to this inherited file descriptor, which must be open for writing, then close it

<!-- END GENERATED OPTIONS -->

# EXAMPLES

Install to a filesystem mounted at `/mnt`, read the result into shell
variables through file descriptor 3 (sending bootc's own output to
stderr), then add a systemd unit to the new deployment's `/etc`:

    set -e
    pairs=$(bootc install to-filesystem --output-pairs-fd 3 /mnt 3>&1 >&2)
    eval "$pairs"
    cp my-firstboot.service "/mnt/$ETC_PATH/systemd/system/"

Assigning the output first, rather than running `eval "$(bootc ...)"`,
makes `set -e` stop the script if the installation fails.

The same result as JSON in a file:

    bootc install to-filesystem --output-json-path /run/install-result.json /mnt
    jq -r .etcPath /run/install-result.json

# SEE ALSO

**bootc**(8), **bootc-install**(8), **bootc-install-to-disk**(8)

# VERSION

<!-- VERSION PLACEHOLDER -->

