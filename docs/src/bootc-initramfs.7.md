# Managing the initramfs after installation

The initramfs is part of the container image and is updated together with the
image. On systems using the OSTree backend with a split kernel and initramfs,
the canonical path is `/usr/lib/modules/$kver/initramfs.img`. Editing the copy
in `/boot` is not supported because `bootc` replaces it from the container
image during an update.

For how to modify and regenerate the initramfs *inside* an image build,
including dracut drop-in configuration, see your operating system's
documentation, for example Fedora's
[bootc initramfs guide](https://docs.fedoraproject.org/en-US/bootc/initramfs/).

## Prefer generic configuration

Content that at first looks machine-specific often does not need to be. A
single generic image can carry configuration that dispatches on a
machine-specific identifier at runtime — a hardware MAC address, a DMI
property, a disk serial, and so on. A udev rule that matches particular
hardware, for instance, can ship in the base or a shared derived image and
still only act on the machine that has that hardware.

Reach for a machine-local image only when the content genuinely cannot be
expressed generically. Keeping configuration in shared images means fewer
distinct images to build, test, and update.

## Machine-local initramfs content

When machine-specific initramfs content really is required — such as a udev
rule needed to unlock local storage that cannot be selected generically — and
until `bootc` has a dedicated interface for this use case, build a
machine-local derived image containing the configuration and its regenerated
initramfs. This keeps the image, rather than mutable files in `/boot`, as the
source of truth.

> This procedure applies to the OSTree backend with a split kernel and
> initramfs. It does not apply to sealed composefs/UKI images.

Create a build context containing the machine-specific files. For example:

```text
.
├── Containerfile
└── 98-storage.rules
```

The `Containerfile` derives from the image shown by `bootc status`, adds the
files, and regenerates the initramfs. Configure dracut with a drop-in under
`/usr/lib/dracut/dracut.conf.d` and regenerate for the image's kernel, per your
OS's initramfs documentation:

```Dockerfile
FROM quay.io/example/example-bootc:latest

COPY 98-storage.rules /etc/udev/rules.d/98-storage.rules
RUN echo 'install_items+=" /etc/udev/rules.d/98-storage.rules "' \
      > /usr/lib/dracut/dracut.conf.d/50-storage.conf

RUN set -xe; kver=$(ls /usr/lib/modules); \
    env DRACUT_NO_XATTR=1 dracut -vf "/usr/lib/modules/${kver}/initramfs.img" "$kver"; \
    bootc container lint
```

A bootc image must contain exactly one kernel, so `ls /usr/lib/modules` must
resolve to a single directory; `bootc container lint` checks this image
invariant. Dracut must be told the kernel version explicitly, because its
default targets the *running* kernel, which is not what a build should use. The
exact dracut modules and arguments depend on the base image and the content
being added.

Build the image locally and deploy it exactly as any other local build; see
[Booting local builds](bootc-local-builds.7.md) for building against the booted
image, the `containers-storage` transport, and automating the rebuild. Rebuild
and switch to this derived image whenever either the base image or the
machine-specific configuration changes.

## The rpm-ostree client-side initramfs mechanism

On rpm-ostree-managed systems, `rpm-ostree initramfs --enable` enables
client-side initramfs regeneration and accepts additional dracut arguments.
However, this mechanism predates bootc and records the regenerated initramfs as
a local rpm-ostree modification in the deployment origin (a
`regenerate-initramfs` key under `[rpmostree]`).

Bootc does not currently know how to reproduce or carry that configuration
onto a new container-image deployment. It marks a deployment with rpm-ostree
local modifications as incompatible, and `bootc upgrade` refuses to update it
with an error such as "Deployment contains local rpm-ostree modifications".
Running `rpm-ostree reset` removes the local modifications and allows bootc to
manage the deployment again, but also removes the client-side initramfs
configuration. It may remove other rpm-ostree package layering and overrides as
well, so inspect the pending changes before running it. Therefore, do not use
`rpm-ostree initramfs --enable` for this workflow if the system is intended to
continue receiving updates through bootc; use a derived container image
instead. See also
[Relationship with rpm-ostree](bootc-relationships.7.md#relationship-with-rpm-ostree).

## Future direction

[UKI add-ons](https://uapi-group.org/specifications/specs/unified_kernel_image/#addon-uki-format)
are the intended mechanism for adding machine-specific kernel arguments or
initrd content without rebuilding a Unified Kernel Image. The bootc project is
working toward this model for composefs/UKI systems.

For OSTree environments that do not use composefs with sealed UKIs, support for
supplementary initrds has been requested in
[ostree#3634](https://github.com/ostreedev/ostree/issues/3634), and a general
bootc interface is being designed in
[bootc#2414](https://github.com/bootc-dev/bootc/issues/2414). Until that design
is implemented, use the machine-local derived-image workflow above.
