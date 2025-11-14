# NAME

bootc-root-setup.service

# DESCRIPTION

This service runs in the initramfs to set up the root filesystem when composefs is enabled.
It is only activated when the `composefs` kernel command line parameter is present.

The service performs the following operations:

- Mounts the composefs image specified in the kernel command line
- Sets up `/etc` and `/var` directories from the deployment state
- Optionally configures transient overlays based on the configuration file
- Prepares the root filesystem for switch-root

This service runs after `sysroot.mount` and `ostree-prepare-root.service`, and before
`initrd-root-fs.target`.

# CONFIGURATION FILE

The service reads an optional configuration file at `/usr/lib/composefs/setup-root-conf.toml`.
If this file does not exist, default settings are used.

**WARNING**: The configuration file format and composefs integration are experimental
and subject to change.

## Configuration Options

The configuration file uses TOML format with the following sections:

### `[root]`

- `transient` (boolean): If true, mounts the root filesystem as a transient overlay.
  This makes all changes to `/` ephemeral and lost on reboot. Default: false.

### `[etc]`

- `mount` (string): Mount type for `/etc`. Options: "none", "bind", "overlay", "transient".
  Default: "bind".
- `transient` (boolean): Shorthand for `mount = "transient"`. Default: false.

### `[var]`

- `mount` (string): Mount type for `/var`. Options: "none", "bind", "overlay", "transient".
  Default: "bind".
- `transient` (boolean): Shorthand for `mount = "transient"`. Default: false.

## Example Configuration

```toml
[root]
transient = false

[etc]
mount = "bind"

[var]
mount = "overlay"
```

# EXPERIMENTAL STATUS

The composefs integration, including this service and its configuration file format,
is experimental and subject to change.

# SEE ALSO

**bootc(8)**

# VERSION

<!-- VERSION PLACEHOLDER -->
