# Managing the initramfs after installation

The initramfs is part of the container image and is updated together with the
image. On systems using the OSTree backend with a split kernel and initramfs,
the canonical path is `/usr/lib/modules/$kver/initramfs.img`. Editing the copy
in `/boot` is not supported because `bootc` replaces it from the container
image during an update.

Some systems need machine-specific initramfs content after installation, such
as a udev rule required to unlock local storage. Until `bootc` has a dedicated
interface for this use case, build a machine-local derived image containing the
configuration and its regenerated initramfs. This keeps the image, rather than
mutable files in `/boot`, as the source of truth.

> This procedure applies to the OSTree backend with a split kernel and
> initramfs. It does not apply to sealed composefs/UKI images.

## Build a machine-local image

Create a build context containing the machine-specific files. For example:

```text
.
├── Containerfile
└── 98-thunderbolt.rules
```

The `Containerfile` can derive from the image shown by `bootc status` and
regenerate its initramfs:

```Dockerfile
FROM quay.io/example/example-bootc:latest

COPY 98-thunderbolt.rules /etc/udev/rules.d/98-thunderbolt.rules

RUN set -eu; \
    kver="$(ls -1 /usr/lib/modules)"; \
    mkdir -p /var/tmp; \
    dracut --verbose --force --reproducible \
        --install "/etc/udev/rules.d/98-thunderbolt.rules" \
        "/usr/lib/modules/${kver}/initramfs.img" "${kver}"; \
    rm -rf /var/tmp; \
    bootc container lint
```

A bootc image must contain exactly one kernel. Consequently, the `kver`
assignment above must resolve to one directory; `bootc container lint` checks
this image invariant. The exact `dracut` arguments and modules depend on the
base image and the content being added.

Build the image locally, then stage it through the Podman container storage:

```console
$ sudo podman build --security-opt=label=disable --pull=newer \
    --tag localhost/machine-bootc:latest .
$ sudo bootc switch --transport containers-storage localhost/machine-bootc:latest
$ sudo systemctl reboot
```

See [Booting local builds](booting-local-builds.md) for more about the
`containers-storage` transport. Rebuild and switch to this derived image
whenever either the base image or the machine-specific initramfs configuration
changes. A systemd service and timer can automate those steps if required.

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
