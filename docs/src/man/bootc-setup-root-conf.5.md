# NAME

bootc-setup-root-conf.toml

# SYNOPSIS

`/usr/lib/composefs/setup-root-conf.toml`

# DESCRIPTION

When the composefs backend is active, `bootc-root-setup.service` runs in the
initramfs to mount the root filesystem before switch-root.  It reads this
optional TOML configuration file to control how `/`, `/etc`, and `/var` are
mounted.

If the file does not exist all options take their documented defaults.

The `51bootc` dracut module installs this file into the initramfs automatically
when it is present on the host image.  Image authors can therefore ship the
file at this path in their container image and rebuild the initramfs with a
plain `dracut --force`; no `--include` flags are needed.

**NOTE**: The composefs backend and this configuration file are experimental
and subject to change without notice.

# SECTIONS

## `[root]`

Controls the mount of the root (`/`) filesystem.

`transient` (boolean, default: `false`)
  If `true`, the composefs root is wrapped in a tmpfs overlay before
  switch-root.  All writes to `/` are discarded at the next reboot.
  This is useful for kiosk or lab systems where runtime modifications
  must never persist.

## `[etc]`

Controls how `/etc` is mounted from the deployment state directory.

`mount` (string)
  One of `"none"`, `"bind"` (default), `"overlay"`, or `"transient"`.

  - `none` (alias `"root"`) — `/etc` is not remounted; the composefs image's
    `/etc` is used directly and is read-only.  The system sees exactly the
    `/etc` baked into the container image, with no per-deployment state
    overlaid on top.  **This requires the OS and all services to work without
    a writable `/etc`**: SSH host keys, `machine-id`, NetworkManager leases,
    and similar files that are normally generated on first boot into the
    deployment's writable `/etc` must either be baked into the image or
    generated elsewhere (e.g. `/var`, systemd credentials).  This mode is
    most useful in combination with `[root] transient = true`, where the
    transient overlay already provides a writable surface over `/etc`.
  - `bind` — `/etc` is bind-mounted from the deployment state directory,
    preserving persistent per-machine changes across reboots (the default
    ostree behaviour).
  - `overlay` — `/etc` is an overlayfs with the deployment state as the upper
    layer; writes go to state and persist across reboots.
  - `transient` — `/etc` is a tmpfs overlay; all runtime edits are discarded
    on reboot.  Suitable for immutable or sealed images where `/etc` drift
    is undesirable.

`transient` (boolean, default: `false`)
  Shorthand for `mount = "transient"`.  Ignored when `mount` is also set.

## `[var]`

Controls how `/var` is mounted from the deployment state directory.

`mount` (string)
  One of `"bind"` (default) or `"none"`.

  - `bind` — `/var` is bind-mounted from the deployment state directory,
    preserving persistent per-machine data across reboots (the default).
  - `none` (alias `"root"`) — `/var` is not remounted; the composefs image's
    empty `/var` directory is used.  Combine with `systemd.volatile=state`
    (see below) to get a fresh tmpfs on every boot.

For a fresh, ephemeral `/var` on every boot (e.g. for stateless or kiosk
systems), use the `systemd.volatile=state` kernel argument.  `bootc-root-setup`
detects this karg automatically and skips the `/var` bind-mount, so no
explicit `[var]` section is needed.  The karg can be baked into the image via
`/usr/lib/bootc/kargs.d/`:

```toml
# /usr/lib/bootc/kargs.d/50-var-volatile.toml
kargs = ["systemd.volatile=state"]
```

This causes systemd to mount `/var` as a plain tmpfs at early boot, which is
fully compatible with tools like podman that use overlayfs under `/var`.
Note: unlike `/etc` and `/root`, using overlayfs (the `"transient"` mount type
from earlier releases) for `/var` is not supported because it breaks podman and
other tools that use overlayfs under `/var/lib/containers`.

# EXAMPLES

Default (all persistent, equivalent to an absent file):

```toml
[etc]
mount = "bind"
```

Transient `/etc` — suitable for sealed or integrity-verified images where
runtime `/etc` changes should be discarded on reboot:

```toml
[etc]
transient = true
```

Transient root with read-only `/etc` — `/` and `/etc` follow the composefs
image exactly within the session (all writes discarded on reboot).  To also
make `/var` ephemeral, combine with `systemd.volatile=state` in kargs.d:

```toml
[root]
transient = true

[etc]
mount = "root"
```

# FILES

`/usr/lib/composefs/setup-root-conf.toml`
  The configuration file read by `bootc-root-setup.service`.

# SEE ALSO

**bootc-root-setup.service(5)**, **bootc(8)**

# VERSION

<!-- VERSION PLACEHOLDER -->
