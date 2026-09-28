# container export

Experimental features are subject to change or removal. Please
do provide feedback on them.

## Overview

The `bootc container export` command exports a container filesystem as a
tar archive suitable for unpacking onto a target system.

However, this is a bit more than a simple format transformation:

- The output includes SELinux labeling (computed from the image's policy)
- The kernel can optionally be copied to `/boot` for compatibility with Anaconda's `liveimg` command

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

Complete example using podman

```
podman run --rm \
    --mount=type=image,source=quay.io/example/example,target=/run/target \
    quay.io/example/example \
    bootc container export --kernel-in-boot /run/target > example.tar
```

There is also an `-o` option to write to a file directly, but when
using `podman run` shell redirection is simpler since `-o` would
require a bind mount to write to the host filesystem.

## Anaconda liveimg integration

A key targeted use case for this is Anaconda's `liveimg` kickstart command
which accepts any generic filesystem payload (tar, squashfs).

### Important considerations

The installed system will *not* have any bootc/ostree/composefs filesystem
structure, will not be read-only etc. The semantics of the installed
system are exactly the same as any other usage of Anaconda `liveimg`
or equivalent.

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

While the `liveimg` verb handles most of the basics, some `%post`
scripting is also required.

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
