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
changes. A systemd service and timer can automate the rebuild if required.

### Automate the local build

For example, store the build context in `/var/lib/machine-bootc` and create a
system service:

```systemd
# /etc/systemd/system/machine-bootc-build.service
[Unit]
Description=Build the machine-local bootc image
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/var/lib/machine-bootc
ExecStart=/usr/bin/podman build --security-opt=label=disable --pull=newer --tag localhost/machine-bootc:latest .
```

Schedule the build with a timer:

```systemd
# /etc/systemd/system/machine-bootc-build.timer
[Unit]
Description=Build the machine-local bootc image daily

[Timer]
OnCalendar=*-*-* 06:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

Enable the timer:

```console
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now machine-bootc-build.timer
```

This example automates only the build. It intentionally leaves staging the new
image and rebooting as explicit operations. A deployment can be automated too,
but should include appropriate validation and reboot policy for the machine.

## The rpm-ostree client-side initramfs mechanism

On rpm-ostree-managed systems, `rpm-ostree initramfs --enable` enables
client-side initramfs regeneration and accepts additional dracut arguments.
However, this mechanism predates bootc and records the regenerated initramfs as
a local rpm-ostree modification in the deployment origin.

Bootc does not currently know how to reproduce or carry that configuration
onto a new container-image deployment. It marks a deployment with rpm-ostree
local modifications as incompatible and `bootc upgrade` refuses to update it.
Running `rpm-ostree reset` removes the local modifications and allows bootc to
manage the deployment again, but also removes the client-side initramfs
configuration. It may remove other rpm-ostree package layering and overrides as
well, so inspect the pending changes before running it. Therefore, do not use
`rpm-ostree initramfs --enable` for this workflow if the system is intended to
continue receiving updates through bootc; use a derived container image
instead. See also [Relationship with rpm-ostree](relationships.md#relationship-with-rpm-ostree).

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
