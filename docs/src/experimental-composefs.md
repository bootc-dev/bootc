# composefs backend

Experimental features are subject to change or removal. Please
do provide feedback on them.

Tracking issue: <https://github.com/bootc-dev/bootc/issues/1190>

## Overview

The composefs backend is an experimental alternative storage backend that uses [composefs-rs](https://github.com/containers/composefs-rs) instead of ostree for storing and managing bootc system deployments.

**Status**: Experimental. The composefs backend is under active development and not yet suitable for production use. The feature is always compiled in as of bootc v1.10.1.

## Key Benefits

- **Native container integration**: Direct use of container image formats without the ostree layer
- **UKI support**: First-class support for Unified Kernel Images (UKIs) and systemd-boot
- **Sealed images**: Enables building cryptographically sealed, securely-bootable images
- **Simpler architecture**: Reduces dependency on ostree as an implementation detail

## Building Sealed Images

### Using `just build-sealed`

This is an entrypoint focused on *bootc development* itself - it builds bootc
from source.

```bash
just build-sealed
```

We are working on documenting individual steps to build a sealed image outside of
this tooling.

## How Sealed Images Work

A sealed image includes:
- A Unified Kernel Image (UKI) that combines kernel, initramfs, and boot parameters
- The composefs fsverity digest embedded in the kernel command line
- Secure Boot signatures on both the UKI and systemd-boot loader

The UKI is placed in `/boot/EFI/Linux/` and includes the composefs digest in its command line:
```
composefs=${COMPOSEFS_FSVERITY} root=UUID=...
```

This enables the boot chain to verify the integrity of the root filesystem.

## Installation

When installing a composefs-backend system, use:

```bash
bootc install to-disk /dev/sdX
```

**Note**: Sealed images will require fsverity support on the target filesystem by default.

## Testing Composefs

To run the composefs integration tests:

```bash
just test-composefs
```

This builds a sealed image and runs the composefs test suite using `bcvk` (bootc VM tooling).

## Current Limitations

- **Experimental**: In particular, the on-disk formats are subject to change
- **UX refinement**: The user experience for building and managing sealed images is still being improved

## Related Issues

- [#1190](https://github.com/bootc-dev/bootc/issues/1190) - composefs-native backend (main tracker)
- [#1498](https://github.com/bootc-dev/bootc/issues/1498) - Sealed image build UX + implementation
- [#1703](https://github.com/bootc-dev/bootc/issues/1703) - OCI config mismatch issues
- [#20](https://github.com/bootc-dev/bootc/issues/20) - Unified storage (long-term goal)
- [#806](https://github.com/bootc-dev/bootc/issues/806) - UKI/systemd-boot tracker

## Additional Resources

- See [filesystem.md](filesystem.md) for information about composefs in the standard ostree backend
- See [bootloaders.md](bootloaders.md) for bootloader configuration details
