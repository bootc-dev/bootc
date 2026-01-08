# composefs backend

Experimental features are subject to change or removal. Please
do provide feedback on them.

Tracking issue: <https://github.com/bootc-dev/bootc/issues/1190>

## Overview

The composefs backend is an experimental alternative storage backend that uses [composefs-rs](https://github.com/containers/composefs-rs) instead of ostree for storing and managing bootc system deployments.

**Status**: Experimental. The composefs backend is under active development and not yet suitable for production use. The feature is always compiled in as of bootc v1.10.1.

A key goal is custom "sealed" images, signed with your own Secure Boot keys.
This is based on [Unified Kernel Images](https://uapi-group.org/specifications/specs/unified_kernel_image/)
that embed a digest of the target container root filesystem, typically alongside a bootloader (such
as systemd-boot) also signed with your key.

### UKIs in bootc containers

There must be exactly one UKI placed in `/boot/EFI/Linux/<name>.efi`.

### Bootloader support

To use sealed images, ensure that the target container image has systemd-boot,
and does not have `bootupd`.

### Installation

There is a `--composefs-backend` option for `bootc install`; however, if
a UKI and systemd-boot are detected, it will automatically be used.

### Developing and testing bootc with sealed composefs

Use `just variant=composefs-sealeduki-sdboot build` to build a local sealed
UKI, using Secure Boot keys generated in `target/test-secureboot`. This is
not a production path.

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
