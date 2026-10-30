# Factory reset with `bootc install reset`

This is an experimental feature; use `--experimental` flag to acknowledge.

## Overview

The `bootc install reset` command allows you to perform a non-destructive factory reset of an existing bootc system. This creates a fresh installation state in a new stateroot while preserving the existing system's files on disk. After rebooting into the new deployment, you can still access the old system's data by examining files in `/sysroot/ostree/deploy/<old-stateroot>/`.

## How it works

When you run `bootc install reset`:

1. A new stateroot is created with an automatically generated name (format: `state-<year>-<serial>`, e.g., `s2025-0`)
2. A fresh deployment is created in the new stateroot using the currently booted image (or optionally a different image via `--target-imgref`)
3. Kernel arguments related to root filesystem configuration are automatically inherited from the current deployment
4. The `/boot` fstab entry is preserved from the current system if it exists
5. The new deployment becomes the default boot target

After rebooting, you'll be running in a completely fresh system state:
- `/etc` contains only the configuration from the container image
- `/var` is empty (no user data or state from the previous system)
- The old stateroot's files remain on disk at `/sysroot/ostree/deploy/<old-stateroot>/` and can be accessed for data recovery or inspection

## Usage

Basic usage (reset to the same image currently running):

```bash
bootc install reset --experimental
```

Reset and switch to a different image:

```bash
bootc install reset --experimental --target-imgref quay.io/example/myimage:latest
```

Reset with custom stateroot name:

```bash
bootc install reset --experimental --stateroot production-2025
```

Reset and immediately reboot:

```bash
bootc install reset --experimental --apply
```

Add custom kernel arguments:

```bash
bootc install reset --experimental --karg=console=ttyS0,115200n8
```

Skip inheriting root filesystem kernel arguments:

```bash
bootc install reset --experimental --no-root-kargs
```

## Kernel arguments

By default, `bootc install reset` automatically inherits kernel arguments from the currently booted deployment that are related to root filesystem configuration. This includes:

- `root=` - Root device specification
- `rootflags=` - Root filesystem mount options
- `rd.*` arguments - Initramfs arguments (e.g., for LVM, LUKS, network root)
- Kernel arguments defined in `/usr/lib/bootc/kargs.d/` and `/etc/bootc/kargs.d/`

You can:
- Add additional kernel arguments with `--karg` (can be specified multiple times)
- Skip automatic root filesystem argument inheritance with `--no-root-kargs`

## Use cases

- **Development/testing**: Quickly return to a clean state while preserving the ability to boot back to your development environment
- **Troubleshooting**: Reset to a known-good state without losing access to the problematic deployment for debugging
- **System refresh**: Start fresh after accumulating configuration changes, while keeping the old state accessible
- **Image testing**: Test a new image version in a separate stateroot before committing to it

## Cleaning up the old stateroot

After performing a factory reset and rebooting into the new stateroot, the old stateroot remains on disk at `/sysroot/ostree/deploy/<old-stateroot>/`. This allows you to access files from the previous system if needed.

Once you no longer need the old stateroot, you can remove it to free up disk space:

1. First, remove any remaining deployments from the old stateroot:

```bash
# List all deployments to find the old stateroot's deployment index
ostree admin status

# Remove the old deployment(s) by index
# The index is shown in the output (e.g., "1" for the second deployment)
ostree admin undeploy <index>
```

2. After all deployments from the old stateroot are removed, you can delete the stateroot directory:

```bash
# Replace "default" with your old stateroot name if different
mount -o remount,rw /sysroot
rm -rf /sysroot/ostree/deploy/default
```

**Note:** You cannot remove the stateroot directory while deployments still exist in it. OSTree protects deployment directories with filesystem-level mechanisms, so you must undeploy them first using `ostree admin undeploy`.

## Limitations

- This command requires `--experimental` flag as the feature is still under development
- Only works on systems already running bootc (not for initial installations)
- The old stateroot is not automatically removed and will consume disk space until manually deleted (see "Cleaning up the old stateroot" section above)

## See also

- `bootc switch` - Switch to a different container image
- `bootc status` - View current deployment status
