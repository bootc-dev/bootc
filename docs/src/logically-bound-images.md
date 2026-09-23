# Logically Bound Images

## About logically bound images

This feature enables an association of container "app" images to a base bootc system image. Use cases for this include:

- Logging (e.g. journald->remote log forwarder container)
- Monitoring (e.g. [Prometheus node_exporter](https://github.com/prometheus/node_exporter))
- Configuration management agents
- Security agents

These types of things are commonly not updated outside of the host, and there's a secondary important property: We *always* want them present and available on the host, possibly from very early on in the boot. In contrast with default usage of tools like `podman` or `docker`, images may be pulled dynamically *after* the boot starts; requiring functioning networking, etc. For example if the remote registry is unavailable temporarily, the host system may run for a longer period of time without log forwarding or monitoring, which can be very undesirable.

Another simple way to say this is that logically bound images allow you to reference container images with the same confidence you can with `ExecStart=` in a systemd unit.

The term "logically bound" was created to contrast with [physically bound](https://github.com/bootc-dev/bootc/issues/644) images. There are some trade-offs between the two approaches. Some benefits of logically bound images are:

- The bootc system image can be updated without re-downloading the app image bits.
- The app images can be updated without modifying the bootc system image, this would be especially useful for development work

## Using logically bound images

Each image is defined in a [Podman Quadlet](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html) `.image` or `.container` file. An image is selected to be bound by creating a symlink in the `/usr/lib/bootc/bound-images.d` directory pointing to a `.image` or `.container` file. 

With these defined, during a `bootc upgrade` or `bootc switch` the bound images defined in the new bootc image will be automatically pulled into the bootc image storage, and are available to container runtimes such as podman by explicitly configuring them to point to the bootc storage as an "additional image store", via e.g.:

`podman --storage-opt=additionalimagestore=/usr/lib/bootc/storage run <image> ...`

An example Containerfile

```Dockerfile
FROM quay.io/myorg/myimage:latest

COPY ./my-app.image /usr/share/containers/systemd/my-app.image
COPY ./another-app.container /usr/share/containers/systemd/another-app.container

RUN ln -s /usr/share/containers/systemd/my-app.image /usr/lib/bootc/bound-images.d/my-app.image && \
    ln -s /usr/share/containers/systemd/another-app.container /usr/lib/bootc/bound-images.d/another-app.container
```

In the `.container` definition, you should use:

```
GlobalArgs=--storage-opt=additionalimagestore=/usr/lib/bootc/storage
```

NOTE: Do *not* attempt to globally enable `/usr/lib/bootc/storage` in `/etc/containers/storage.conf`; only
use the bootc storage for logically bound images, not also floating images. For more, see below.

## Pull secret

Images are fetched using the global bootc pull secret by default (`/etc/ostree/auth.json`). It is not yet supported to configure `PullSecret` in these image definitions.

## Garbage collection

The bootc image store is owned by bootc; images will be garbage collected when they are no longer referenced
by a file in `/usr/lib/bootc/bound-images.d`.

## Applying changes without a reboot (experimental)

The container images for logically bound images live in a single bootc-owned
storage shared by all deployments, so after a `bootc upgrade` or `bootc switch`
the new images are already on disk. What is tied to a deployment is only the
*definition*: the symlink in `/usr/lib/bootc/bound-images.d` and the quadlet
file it references, which the running system reads from its own `/usr`.

If the staged deployment differs from the booted one *only* in bound image
definitions, they can be applied to the running system without a reboot:

```
bootc apply-live bound-images
```

This writes the changed quadlet files to `/run/containers/systemd/`, which
podman gives precedence over `/etc` and `/usr`, reloads systemd and restarts
the affected `.container` units (removed units are stopped). Pass `--dry-run`
to see what would change, or `--no-restart` to write the definitions without
touching any units; a later plain invocation restarts the units still
pending, as does re-running after a failed restart.

If the staged deployment contains any other change, the command fails and
lists the out-of-scope paths; a reboot is required to apply it. Note that a
locally modified quadlet in `/etc/containers/systemd` that also changed in
the image is reported this way, since the local copy wins in `/etc`.

Because `/run` is transient, the override disappears on the next boot, at
which point the staged deployment's own content applies. (A soft reboot
preserves `/run`; the override is cleared when one is prepared.) The applied
state is shown in `bootc status` and recorded in `/run/bootc/apply-live/`;
images recorded there are protected from garbage collection until reboot,
even if the staged deployment is discarded (for example by `bootc rollback`).

Limitations: only the `.container` or `.image` file referenced from
`bound-images.d` is applied. Quadlet drop-ins (`*.container.d/`) and other
referenced quadlet files (`.volume`, `.network`, `.pod`) are not copied, and
changes to them are treated as out of scope. A `.container` unit that
references a changed `.image` is not restarted unless its own file changed.
Removed units are stopped but not masked, so a dependency could start them
again until reboot. Only supported on ostree-backed systems.

## Installation

Logically bound images must be present in the default container store (`/var/lib/containers`) when invoking
[bootc install](bootc-install.md); the images will be copied into the target system and present
directly at boot, alongside the bootc base image.

## Limitations

The *only* field parsed and honored by bootc currently is the `Image` field of a `.image` or `.container` file.

Other pull-relevant flags such as `PullSecret=` for example are not supported (see above).
Another example unsupported flag is `Arch` (the default host architecture is always used).

There is no mechanism to inject arbitrary arguments to the `podman pull` (or equivalent)
invocation used by bootc. However, many properties used for container registry interaction
can be configured via [containers-registries.conf](https://github.com/containers/image/blob/main/docs/containers-registries.conf.5.md)
and apply to all commands operating on that image.

It is not currently supported in general to launch "rootless" containers from system-owned
image stores in general, whether from `/var/lib/containers` or the `/usr/lib/bootc/storage`.
There is no integration between bootc and "rootless" storage today, and none is planned.
Instead, it's recommended to ensure that your "system" or "rootful" containers drop
privileges. More in e.g. <https://github.com/containers/podman/discussions/13728>.

### Distro/OS installer support

At the current time, logically bound images are [not supported by Anaconda](https://github.com/rhinstaller/anaconda/discussions/5197).

## Comparison with default podman systemd units

In the comparison below, the term "floating" will be used for non-logically bound images. These images are often fetched by e.g. [podman-systemd](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html) and may be upgraded, added or removed independently of the host upgrade lifecycle.

### Lifecycle

- **Floating image:** The images are downloaded by the machine the first time it starts (requiring networking typically). Tools such as `podman auto-update` can be used to upgrade them independently of the host.
- **Logically bound image:** The images are referenced by the bootable container and are ensured to be available when the (bootc based) server starts. The image is always upgraded via `bootc upgrade` and appears read-only to other processes (e.g. `podman`).

### Upgrades, rollbacks and garbage collection

- **Floating image:** Managed by the user (`podman auto-update`, `podman image prune`). This can be triggered at anytime independent of the host upgrades or rollbacks, and host upgrades/rollbacks do not affect the set of images.
- **Logically bound image:** Managed exclusively by `bootc` during upgrades. The logically bound images corresponding to rollback deployments will also be retained. `bootc` performs garbage collection of unused images.

### "rootless" container image

- **Floating image:** Supported.
- **Logically bound image:** Not supported (`bootc` cannot be invoked as non-root). Instead, it's recommended to just drop most privileges for launched logically bound containers.

## Avoid using /usr/lib/bootc/storage for floating images

Because images and in particular *layers* of images can be removed over time as
the OS upgrades, if you attempt to globally enable `/usr/lib/bootc/storage`
in the global `/etc/containers/storage.conf` that would also apply to "floating"
container images (i.e. the default `podman run` and other runtimes), it can
cause a bug where floating images can later fail if layers that were reused
in the LBI storage are removed. In the future, this restriction may be lifted,
but at the current time you can only configure this additional storage
for logically bound images.
