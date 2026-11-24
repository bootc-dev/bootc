# Preserving `/var` with `bootc install to-existing-root`

This feature is experimental and requires the `--experimental` flag. Experimental
features are subject to change or removal.

## Overview

When installing to an existing root with the OSTree backend, `--preserve-var`
copies the old system's `/var` into the new deployment before rebooting. This
can retain machine-local state when converting an existing Linux system to
bootc.

## Usage

Enable preservation explicitly:

```bash
bootc install to-existing-root --experimental --preserve-var
```

The option is only available with the OSTree backend. It does not change the
behavior of installs that do not pass `--preserve-var`.

## Copy behavior and exclusions

The migration uses reflinks when supported by the filesystem and otherwise
performs a full copy. It creates each new entry in a staging location and
renames it into place atomically for namespace visibility.

Existing entries in the destination are not overwritten. When both source and
destination entries are directories, their contents are merged recursively and
children already present in the destination are retained. For other collisions,
the destination entry is kept, the source entry is skipped, and the collision
is reported in the install output. An incompatible destination type for a
nested mountpoint placeholder is an error. The preservation copy itself does
not modify the old system's source `/var`. If `--cleanup` is also specified,
cleanup of the previous install is scheduled for the next boot, and only after
the preservation copy succeeds. Before separately cleaning the old system,
verify that all important state has been copied or otherwise retained.

The following paths below `/var` are always excluded:

- `tmp`
- `cache`
- `log/journal`
- `lib/containers`

To exclude additional paths, pass `--preserve-var-skip` one or more times. Paths
are relative to `/var`, and each may contain at most one slash:

```bash
bootc install to-existing-root --experimental --preserve-var \
  --preserve-var-skip lib/rpm \
  --preserve-var-skip lib/my-application
```

The same exclusions can be configured with the `preserve-var-skip` install
configuration key; see
[`bootc-install-config(5)`](man/bootc-install-config.5.md). These configurable
exclusions apply only when `--preserve-var` is enabled. The always-excluded
paths cannot be re-included.

## Limitations and cautions

Do not combine `--preserve-var` with `--replace=wipe`: wiping the target would
erase the source `/var` before it can be copied.

The copy proceeds over time; it is not a tree-wide point-in-time snapshot or a
global all-or-nothing transaction. A later failure can leave a partial
migration. Neither reflinks nor a full copy provide a consistent snapshot of
live data. Stop stateful services before copying their data, or use a
consistent snapshot.

There is no crash-durability guarantee: copied content and renames are not
guaranteed to survive sudden power loss or a kernel failure.

An interrupted migration may leave hidden `.bootc-preserve-var.*` staging
directories in the new `/var`; they are not automatically cleaned up. Verify
that no migration is still running and that an individual directory is an
abandoned migration artifact before removing it.

## See also

- [`bootc install to-existing-root`](bootc-installation.7.md#using-bootc-install-to-existing-root)
- [`bootc-install-to-existing-root(8)`](man/bootc-install-to-existing-root.8.md)
- [`bootc-install-config(5)`](man/bootc-install-config.5.md)
