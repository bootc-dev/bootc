# container export

Experimental features are subject to change or removal. Please
do provide feedback on them.

## Overview

The `bootc container export` command exports a container filesystem as a
tar archive suitable for unpacking onto a target system. The output includes
proper SELinux labeling (computed from the image's policy) and can optionally
relocate the kernel to `/boot` for compatibility with legacy installers like
Anaconda's `liveimg` command.

This is hidden from `--help` output; run `bootc container export --help`
directly to see usage.

## Usage

```
bootc container export [OPTIONS] TARGET
```

### Options

- `--format <FORMAT>` - Export format (default: `tar`)
- `-o, --output <PATH>` - Output file (defaults to stdout)
- `--kernel-in-boot` - Copy kernel and initramfs from `/usr/lib/modules` to `/boot` for legacy compatibility
- `--disable-selinux` - Disable SELinux labeling in the exported archive

### Examples

Export a mounted container image to a tar file:

```
bootc container export /run/target -o /output/rootfs.tar
```

Export to stdout and pipe to another command:

```
bootc container export /run/target | tar -C /mnt -xf -
```

Export with kernel relocation for legacy installers:

```
bootc container export --kernel-in-boot /run/target -o rootfs.tar
```

Using podman to mount and export an image:

```
podman run --rm \
    --mount=type=image,source=quay.io/fedora/fedora-bootc:42,target=/run/target \
    quay.io/fedora/fedora-bootc:42 \
    bootc container export --kernel-in-boot -o /output/rootfs.tar /run/target
```

## Anaconda liveimg integration

The tar export can be used with Anaconda's `liveimg` kickstart command to install
bootc-built images on systems without native bootc support in the installer.

### Important considerations

**This creates a traditional filesystem install, NOT a full bootc system.**
The installed system will:

- Have the filesystem contents from the container image
- Boot with a standard GRUB setup
- NOT have ostree/bootc infrastructure for atomic updates

For full bootc functionality, use `bootc install` or Anaconda's native `bootc`
kickstart command (available in Fedora 43+).

### Container image requirements

At the current time this is only tested with a workflow starting
`FROM quay.io/fedora/fedora-bootc` or equivalent. In theory, this workflow
would be compatible with an image starting with just `FROM fedora` then
`RUN dnf -y install kernel` etc., but that is not tested.

For the first case right now, you must include as part of your container
build this logic or equivalent:

```dockerfile
RUN sed -i '/layout=ostree/d' /usr/lib/kernel/install.conf && \
    rm -vf /usr/lib/kernel/install.conf.d/*-bootc-*.conf \
           /usr/lib/kernel/install.d/*-rpmostree.install
```

The sed command removes the `layout=ostree` line from `install.conf` while
preserving any other settings. The rm commands remove the bootc drop-in
and rpm-ostree plugin that would otherwise intercept `kernel-install` and
delegate to rpm-ostree (which doesn't work outside an ostree deployment).

### Required kickstart configuration

When using the exported tar with Anaconda's `liveimg`, several kickstart
options are required for a successful installation.

#### Bootloader setup via kernel-install

The `%post` script should use `kernel-install add` to set up the bootloader.
This creates BLS entries, copies the kernel, and generates an initramfs
via the standard plugin chain (50-dracut, 90-loaderentry, etc.):

```
%post --erroronfail
set -eux

KVER=$(ls /usr/lib/modules | head -1)

# Ensure machine-id exists (needed by kernel-install for BLS filenames)
if [ ! -s /etc/machine-id ]; then
    systemd-machine-id-setup
fi

# kernel-install creates the BLS entry, copies vmlinuz, and generates
# initramfs via the standard plugin chain (50-dracut, 90-loaderentry, etc.)
kernel-install add "$KVER" "/usr/lib/modules/$KVER/vmlinuz"

# Regenerate grub config to pick up BLS entries
grub2-mkconfig -o /boot/grub2/grub.cfg
%end
```
