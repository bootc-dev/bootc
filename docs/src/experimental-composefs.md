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

## How Sealed Images Work

A sealed image is a cryptographically signed and verified bootc image that provides end-to-end integrity protection. This is achieved through:

- **Unified Kernel Images (UKIs)**: Combining kernel, initramfs, and boot parameters into a single signed binary
- **Composefs integration**: Using composefs with fsverity for content-addressed filesystem verification
- **Secure Boot**: Cryptographic signatures on both the UKI and systemd-boot loader

A sealed image includes:

1. **composefs digest**: A SHA-512 hash of the entire root filesystem, computed at build time
2. **Unified Kernel Image (UKI)**: A single EFI binary containing the kernel, initramfs, and kernel command line with the composefs digest embedded
3. **Secure Boot signature**: The UKI is signed with your private key

At boot time, the composefs digest in the kernel command line (e.g., `composefs=<sha512-hash>`) is verified against the mounted root filesystem. This creates a chain of trust from firmware to userspace, ensuring the system will only boot if the root filesystem matches exactly what was signed.

## Building Sealed Images

### Prerequisites

For sealed images, the container must:

- Include a kernel and initramfs in `/usr/lib/modules/<kver>/`
- Have systemd-boot available (and NOT have `bootupd`)
- Not include a pre-built UKI (the build process generates one)

Sealed images also require:

- Secure Boot support in the target system firmware
- A filesystem with fsverity support (e.g., ext4, btrfs) for the root partition

### Build Pattern: Compute Digest and Generate UKI in One Stage

The key to building sealed images is using a multi-stage Dockerfile where a separate stage mounts the target rootfs, computes its composefs digest, and generates the signed UKI in one step:

```dockerfile
# Build your rootfs with all packages and configuration
FROM <base-image> as rootfs
RUN apt|dnf|zypper install ... && bootc container lint --fatal-warnings

# Generate the sealed UKI in a tools stage
FROM <tools-image> as sealed-uki
RUN --mount=type=bind,from=rootfs,target=/target \
    --mount=type=secret,id=secureboot_key \
    --mount=type=secret,id=secureboot_cert <<EORUN
set -euo pipefail

# Compute the composefs digest from the mounted rootfs
digest=$(bootc container compute-composefs-digest /target)

# Find the kernel version
kver=$(ls /target/usr/lib/modules)

# Generate and sign the UKI with the digest embedded
ukify build \
  --linux "/target/usr/lib/modules/${kver}/vmlinuz" \
  --initrd "/target/usr/lib/modules/${kver}/initramfs.img" \
  --cmdline "composefs=${digest} rw" \
  --os-release "@/target/usr/lib/os-release" \
  --signtool sbsign \
  --secureboot-private-key /run/secrets/secureboot_key \
  --secureboot-certificate /run/secrets/secureboot_cert \
  --output "/out/${kver}.efi"
EORUN

# Final image: copy the sealed UKI into place
FROM rootfs
COPY --from=sealed-uki /out/*.efi /boot/EFI/Linux/
# Remove raw kernel/initramfs (now embedded in UKI)
RUN rm -f /usr/lib/modules/*/vmlinuz /usr/lib/modules/*/initramfs.img
```

This pattern works because:

1. The `--mount=type=bind,from=rootfs` provides read-only access to the target filesystem
2. `bootc container compute-composefs-digest` computes the SHA-512 hash of the rootfs
3. `ukify` creates the UKI with that digest in the kernel command line (`composefs=<digest>`)
4. The final stage copies the signed UKI into the rootfs without modifying any files used in the digest calculation

### The `bootc container compute-composefs-digest` Command

```bash
bootc container compute-composefs-digest [PATH]
```

Computes the composefs digest for a filesystem. The digest is a 128-character SHA-512 hex string that uniquely identifies the filesystem contents.

**Options:**

- `PATH`: Path to the filesystem root (default: `/target`)
- `--write-dumpfile-to <PATH>`: Generate a dumpfile for debugging

> **Note**: This command is currently hidden from `--help` output as it's part of the experimental composefs feature set.

### Final Image Structure

The sealed image should have:

- The signed UKI at `/boot/EFI/Linux/<kver>.efi`
- A signed systemd-boot at `/boot/EFI/BOOT/BOOTX64.EFI` and `/boot/EFI/systemd/systemd-bootx64.efi`
- The raw `vmlinuz` and `initramfs.img` removed from `/usr/lib/modules/<kver>/` (they're now embedded in the UKI)

### External Signing Workflow

For production environments with dedicated signing infrastructure:

1. **Build unsigned UKI**: Compute digest and create an unsigned UKI (omit `--signtool` from ukify)
2. **Sign externally**: Take the unsigned UKI to your signing infrastructure
3. **Complete the seal**: Inject the signed UKI into the final image

This workflow is planned for streamlining in future releases (see [#1498](https://github.com/bootc-dev/bootc/issues/1498)).

## Developing and Testing bootc with composefs

See [CONTRIBUTING.md](https://github.com/bootc-dev/bootc/blob/main/CONTRIBUTING.md) for information on building and testing bootc itself with composefs support.

## Bootloader Support

To use sealed images, the container image must have a UKI and systemd-boot installed (and not have `bootupd`). If these conditions are met, bootc will automatically detect and use the composefs backend during installation.

## Installation

There is a `--composefs-backend` option for `bootc install` to explicitly select a composefs backend apart from sealed images; this is not as heavily tested yet.

## Current Limitations

- **Experimental**: The on-disk formats are subject to change
- **UX refinement**: The user experience for building and managing sealed images is still being improved
- **SELinux**: Currently uses `enforcing=0` in the kernel command line (see [#1826](https://github.com/bootc-dev/bootc/issues/1826))
- **kargs.d**: Custom kernel arguments from `/usr/lib/bootc/kargs.d` are not yet automatically included in sealed UKIs

## Related Issues

- [#1190](https://github.com/bootc-dev/bootc/issues/1190) - composefs-native backend (main tracker)
- [#1498](https://github.com/bootc-dev/bootc/issues/1498) - Sealed image build UX + implementation
- [#1703](https://github.com/bootc-dev/bootc/issues/1703) - OCI config mismatch issues
- [#1826](https://github.com/bootc-dev/bootc/issues/1826) - SELinux enforcement with composefs
- [#20](https://github.com/bootc-dev/bootc/issues/20) - Unified storage (long-term goal)
- [#806](https://github.com/bootc-dev/bootc/issues/806) - UKI/systemd-boot tracker

## Additional Resources

- See [filesystem.md](filesystem.md) for information about composefs in the standard ostree backend
- See [bootloaders.md](bootloaders.md) for bootloader configuration details
- [composefs-rs](https://github.com/containers/composefs-rs) - The underlying composefs implementation
- [Unified Kernel Images specification](https://uapi-group.org/specifications/specs/unified_kernel_image/)
- [ukify documentation](https://www.freedesktop.org/software/systemd/man/latest/ukify.html) - Tool for building UKIs
