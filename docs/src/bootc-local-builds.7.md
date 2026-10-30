# Booting local builds

In some scenarios, you may want to boot a *locally* built
container image, in order to apply a persistent hotfix
to a specific server, or as part of a development/testing
scenario.

## Building a new local image

At the current time, the bootc host container storage is distinct
from that of the `podman` container runtime storage (default
configuration in `/var/lib/containers`).

It not currently streamlined to export the booted host container
storage into the podman storage.

Hence today, to replicate the exact container image the
host has booted, take the container image referenced
in `bootc status` and turn it into a `podman pull`
invocation.

Next, craft a container build file with your desired changes:
```
FROM <image>
RUN apt|dnf upgrade https://example.com/systemd-hotfix.package
```

## Copying an updated image into the bootc storage

This command is straightforward; we just need to tell bootc
to fetch updates from `containers-storage`, which is the
local "application" container runtime (podman) storage:

```
$ bootc switch --transport containers-storage quay.io/fedora/fedora-bootc:40
```

From there, the new image will be queued for the next boot
and a `reboot` will apply it.

For more on valid transports, see [containers-transports](https://github.com/containers/image/blob/main/docs/containers-transports.5.md).

## Automating local rebuilds

The build and switch above can be automated with a systemd service and timer.
For example, keep the build context in `/var/lib/machine-bootc` and build the
image on a schedule:

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

```console
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now machine-bootc-build.timer
```

This automates only the build. Staging the new image with `bootc switch` and
rebooting are intentionally left as explicit operations; automate them only
with a reboot policy appropriate for the machine.

Automating the rebuild is only worthwhile if the build reliably produces a new
image *when, and only when, an input changed*. With `--pull=newer` an identical
rebuild is a full cache hit and yields the same image, so nothing new is
deployed. But that relies on the build cache, not on reproducible output: a
step whose result is not deterministic (regenerating an initramfs is a common
example) can produce a different image on a cache-busted rebuild even when
nothing meaningful changed, causing needless reboots. Prefer reproducible build
steps for anything driven on a timer.
