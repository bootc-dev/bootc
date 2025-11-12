# Installing "bootc compatible" images

A key goal of the bootc project is to think of bootable operating systems
as container images.  Docker/OCI container images are just tarballs
wrapped with some JSON.  But in order to boot a system (whether on bare metal
or virtualized), one needs a few key components:

- bootloader
- kernel (and optionally initramfs)
- root filesystem (xfs/ext4/btrfs etc.)

The bootloader state is managed by the external [bootupd](https://github.com/coreos/bootupd/)
project which abstracts over bootloader installs and upgrades.  The invocation of
`bootc install` will always run `bootupd` to handle bootloader installation
to the target disk.   The default expectation is that bootloader contents and install logic
come from the container image in a `bootc` based system.

The Linux kernel (and optionally initramfs) is embedded in the container image; the canonical location
is `/usr/lib/modules/$kver/vmlinuz`, and the initramfs should be in `initramfs.img`
in that directory.

The `bootc install` command bridges the two worlds of a standard, runnable OCI image
and a bootable system by running tooling logic embedded
in the container image to create the filesystem and bootloader setup dynamically.
This requires running the container via `--privileged`; it uses the running Linux kernel
on the host to write the file content from the running container image; not the kernel
inside the container.

There are two sub-commands: `bootc install to-disk` and `bootc install to-filesystem`.

However, nothing *else* (external) is required to perform a basic installation
to disk - the container image itself comes with a baseline self-sufficient installer
that sets things up ready to boot.

## Internal vs external installers

The `bootc install to-disk` process only sets up a very simple
filesystem layout, using the default filesystem type defined in the container image,
plus hardcoded requisite platform-specific partitions such as the ESP.

In general, the `to-disk` flow should be considered mainly a "demo" for
the `bootc install to-filesystem` flow, which can be used by "external" installers
today.  For example, in the  [Fedora/CentOS bootc project](https://docs.fedoraproject.org/en-US/bootc/)
project, there are two "external" installers in Anaconda and `bootc-image-builder`.

More on this below.

## Executing `bootc install`

The two installation commands allow you to install the container image
either directly to a block device (`bootc install to-disk`) or to an existing
filesystem (`bootc install to-filesystem`).

The installation commands **MUST** be run **from** the container image
that will be installed, using `--privileged` and a few
other options. This means you are (currently) not able to install `bootc`
to an existing system and install your container image. Failure to run
`bootc` from a container image will result in an error.

Here's an example of using `bootc install` (root/elevated permission required):

```bash
podman run --rm --privileged --pid=host -v /var/lib/containers:/var/lib/containers -v /dev:/dev --security-opt label=type:unconfined_t <image> bootc install to-disk /path/to/disk
```

Note that while `--privileged` is used, this command will not perform any
destructive action on the host system.  Among other things, `--privileged`
makes sure that all host devices are mounted into container. `/path/to/disk` is
the host's block device where `<image>` will be installed on.

The `--pid=host --security-opt label=type:unconfined_t` today
make it more convenient for bootc to perform some privileged
operations; in the future these requirements may be dropped.

The `-v /var/lib/containers:/var/lib/containers` option is required in order
for the container to access its own underlying image, which is used by
the installation process.

Jump to the section for [`install to-filesystem`](#more-advanced-installation) later
in this document for additional information about that method.

### "day 2" updates, security and fetch configuration

By default the `bootc install` path will find the pull specification used
for the `podman run` invocation and use it to set up "day 2" OS updates that `bootc update`
will use.

For example, if you invoke `podman run --privileged ... quay.io/examplecorp/exampleos:latest bootc install ...`
then the installed operating system will fetch updates from `quay.io/examplecorp/exampleos:latest`.
This can be overridden via `--target_imgref`; this is handy in cases like performing
installation in a manufacturing environment from a mirrored registry.

By default, the installation process will verify that the container (representing the target OS)
can fetch its own updates.

Additionally note that to perform an upgrade with a target image reference set to an
authenticated registry, you must provide a pull secret.  One path is to embed the pull secret into
the image in `/etc/ostree/auth.json`.

### Configuring the default root filesystem type

To use the `to-disk` installation flow, the container should include a root filesystem
type.  If it does not, then each user will need to specify `install to-disk --filesystem`.

To set a default filesystem type for `bootc install to-disk` as part of your OS/distribution base image,
create a file named `/usr/lib/bootc/install/00-<osname>.toml` with the contents of the form:

```toml
[install.filesystem.root]
type = "xfs"
```

Configuration files found in this directory will be merged, with higher alphanumeric values
taking precedence.  If for example you are building a derived container image from the above OS,
you could create a `50-myos.toml`  that sets `type = "btrfs"` which will override the
prior setting.

For other available options, see [bootc-install-config](man/bootc-install-config.5.md).

## Installing an "unconfigured" image

The bootc project aims to support generic/general-purpose operating
systems and distributions that will ship unconfigured images.  An
unconfigured image does not have a default password or SSH key, etc.

For more information, see [Image building and configuration guidance](building/guidance.md).

## More advanced installation with `to-filesystem`

The basic `bootc install to-disk` logic is really a pretty small (but opinionated) wrapper
for a set of lower level tools that can also be invoked independently.

The `bootc install to-disk` command is effectively:

- `mkfs.$fs /dev/disk`
- `mount /dev/disk /mnt`
- `bootc install to-filesystem --karg=root=UUID=<uuid of /mnt> --imgref $self /mnt`

There may be a bit more involved here; for example configuring
`--block-setup tpm2-luks` will configure the root filesystem
with LUKS bound to the TPM2 chip, currently via [systemd-cryptenroll](https://www.freedesktop.org/software/systemd/man/systemd-cryptenroll.html#).

Some OS/distributions may not want to enable it at all; it
can be configured off at build time via Cargo features.

### Using `bootc install to-filesystem`

The usual expected way for an external storage system to work
is to provide `root=<UUID>` and `rootflags` kernel arguments
to describe to the initial RAM disk how to find and mount the
root partition. For more on this, see the below section
discussing mounting the root filesystem.

Note that if a separate `/boot` is needed (e.g. for LUKS) you will also need to provide `--boot-mount-spec UUID=...`.

The `bootc install to-filesystem` command allows an operating
system or distribution to ship a separate installer that creates more complex block
storage or filesystem setups, but reuses the "top half" of the logic.
For example, a goal is to change [Anaconda](https://github.com/rhinstaller/anaconda/)
to use this.

#### Postprocessing after to-filesystem

Some installation tools may want to inject additional data, such as adding
an `/etc/hostname` into the target root. At the current time, bootc does
not offer a direct API to do this. However, the backend for bootc is
ostree, and it is possible to enumerate the deployments via ostree APIs.

We hope to provide a bootc-supported method to find the deployment in
the future.

However, for tools that do perform any changes, there is a new
`bootc install finalize` command which is optional, but recommended
to run as the penultimate step before unmounting the target filesystem.

This command will perform some basic sanity checks and may also
perform fixups on the target root. For example, a direction
currently for bootc is to stop using `/etc/fstab`. While `install finalize`
does not do this today, in the future it may automatically migrate
`etc/fstab` to `rootflags` kernel arguments.

### Using `bootc install to-disk --via-loopback`

Because every `bootc` system comes with an opinionated default installation
process, you can create a raw disk image that you can boot via virtualization. Run these commands as root:

```bash
truncate -s 10G myimage.raw
podman run --rm --privileged --pid=host --security-opt label=type:unconfined_t -v /dev:/dev -v /var/lib/containers:/var/lib/containers -v .:/output <yourimage> bootc install to-disk --generic-image --via-loopback /output/myimage.raw
```

Notice that we use `--generic-image` for this use case.

Set the environment variable `BOOTC_DIRECT_IO=on` to create the loopback device with direct-io enabled.

### Using `bootc install to-existing-root`

This is a variant of `install to-filesystem`, which maximizes convenience for using
an existing Linux system, converting it into the target container image.  Note that
the `/boot` (and `/boot/efi`) partitions *will be reinitialized* - so this is a
somewhat destructive operation for the existing Linux installation.

Also, because the filesystem is reused, it's required that the target system kernel
support the root storage setup already initialized.

The core command should look like this (root/elevated permission required):

```bash
podman run --rm --privileged -v /dev:/dev -v /var/lib/containers:/var/lib/containers -v /:/target \
             --pid=host --security-opt label=type:unconfined_t \
             <image> \
             bootc install to-existing-root
```

It is assumed in this command that the target rootfs is pased via `-v /:/target` at this time.

As noted above, the data in `/boot` will be wiped, but everything else in the existing
operating `/` is **NOT** automatically cleaned up.  This can
be useful, because it allows the new image to automatically import data from the previous
host system!  For example, container images, database, user home directory data, config
files in `/etc` are all available after the subsequent reboot in `/sysroot` (which
is the "physical root").

However, previous mount points or subvolumes will not be automatically
mounted in the new system, e.g. a btrfs subvolume for /home will not be automatically mounted to
/sysroot/home. These filesystems will persist and can be handled any way you want like manually
mounting them or defining the mount points as part of the bootc image.

A special case of this trick is using the `--root-ssh-authorized-keys` flag to inherit
root's SSH keys (which may have been injected from e.g. cloud instance userdata
via a tool like `cloud-init`).  To do this, just add
`--root-ssh-authorized-keys /target/root/.ssh/authorized_keys`
to the above.


### Using `system-reinstall-bootc`

This is a separate binary included with bootc. It is an opinionated, interactive CLI that wraps `bootc install to-existing-root`. See [bootc install to-existing-root](#Using-bootc-install-to-existing-root) for details on the installation operation.

`system-reinstall-bootc` can be run from an existing Linux system. It will pull the supplied image, prompt to setup SSH keys for accessing the system, and run `bootc install to-existing-root` with all the bind mounts and SSH keys configured.

It will also add the `bootc-destructive-cleanup.service` systemd unit that will run on first boot to cleanup parts of the previous system. The cleanup actions can be configured per distribution by creating a script and packaging it similar to [this one for Fedora](https://github.com/bootc-dev/bootc/blob/main/contrib/scripts/fedora-bootc-destructive-cleanup).

### Using `bootc install to-filesystem --source-imgref <imgref>`

By default, `bootc install` has to be run inside a podman container. With this assumption,
it can escape the container, find the source container image (including its layers) in
the podman's container storage and use it to create the image.

When `--source-imgref <imgref>` is given, `bootc` no longer assumes that it runs inside podman.
Instead, the given container image reference (see [containers-transports(5)](https://github.com/containers/image/blob/main/docs/containers-transports.5.md)
for accepted formats) is used to fetch the image. Note that `bootc install` still has to be
run inside a chroot created from the container image. However, this allows users to use
a different sandboxing tool (e.g. [bubblewrap](https://github.com/containers/bubblewrap)).

This argument is mainly useful for 3rd-party tooling for building disk images from bootable
containers (e.g. based on [osbuild](https://github.com/osbuild/osbuild)).   


## Finding and configuring the physical root filesystem

On a bootc system, the "physical root" is different from
the "logical root" of the booted container. For more on
that, see [filesystem](filesystem.md). This section
is about how the physical root filesystem is discovered.

Systems using systemd will often default to using
[systemd-fstab-generator](https://www.freedesktop.org/software/systemd/man/latest/systemd-fstab-generator.html)
and/or [systemd-gpt-auto-generator](https://www.freedesktop.org/software/systemd/man/latest/systemd-gpt-auto-generator.html#).
Support for the latter though for the root filesystem is conditional on EFI and a bootloader implementing the bootloader interface.

Outside of the discoverable partition model, a common baseline default for installers is to set `root=UUID=`
(and optionally `rootflags=`) kernel arguments as machine specific state.
When using `install to-filesystem`, you should provide these as explicit
kernel arguments.

Some installation tools may want to generate an `/etc/fstab`. An important
consideration is that when composefs is on by default (as it is expected
to be) it will no longer work to have an entry for `/` in `/etc/fstab`
(or a systemd `.mount` unit) that handles remounting the rootfs with
updated options after exiting the initrd.

In general, prefer using the `rootflags` kernel argument for that
use case; it ensures that the filesystem is mounted with the
correct options to start, and avoid having an entry for `/`
in `/etc/fstab`.

The physical root is mounted at `/sysroot`. It is an option
for legacy `/etc/fstab` references for `/` to use
`/sysroot` by default, but `rootflags` is preferred.

## Configuring machine-local state

Per the [filesystem](filesystem.md) section, `/etc` and `/var` are machine-local
state by default.  If you want to inject additional content after the installation
process, at the current time this can be done by manually finding the
target "deployment root" which will be underneath `/ostree/deploy/<stateroot/deploy/`.

Installation software such as [Anaconda](https://github.com/rhinstaller/anaconda)
do this today to implement generic `%post` scripts and the like.

However, it is very likely that a generic bootc API to do this will be added.
