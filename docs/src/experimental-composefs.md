# composefs backend

Experimental features are subject to change or removal. Please
do provide feedback on them.

## Overview

The composefs backend is an experimental alternative storage backend that uses [composefs-rs](https://github.com/composefs/composefs-rs) instead of ostree for storing and managing bootc system deployments.

The composefs backend has two independent integrity controls:

- **fs-verity enforcement.** By default every object in the composefs
  repository must have fs-verity enabled, and the root filesystem is only
  mounted if its digest matches the one on the kernel command line. Building a
  UKI with `--allow-missing-verity` adds a `?` marker to that argument, which
  makes fs-verity optional (for filesystems such as XFS that lack it). Both UKI
  and traditional kernel/initramfs installs can enforce fs-verity.
- **Boot authentication.** In a *sealed* deployment fs-verity is enforced and
  the expected root digest is embedded in a UKI signed for Secure Boot, so
  firmware authenticates the digest and the digest authenticates the root
  filesystem. A BLS entry or an
  unsigned UKI still has fs-verity checked at mount time, but nothing
  authenticates the digest itself.

## EROFS formats

composefs-rs can encode the EROFS image for a root filesystem in two formats,
which produce different digests for the same content:

- **V1** is compatible with the C composefs tools and is the default for new
  repositories. Its kernel argument is
  `composefs.digest=v1-sha512-12:<digest>`.
- **V2** is the older composefs-rs format, kept as a fallback. bootc writes
  its kernel argument as the bare `composefs=<digest>`.

By default `bootc container ukify` computes both digests and writes the V1
argument followed by the V2 one. `--erofs-version=v2` writes only the V2
argument.

Each argument names one exact image. Staging fails unless every digest in the
UKI matches an image bootc generated for that container image. At boot,
bootc's initramfs tries the arguments in order and moves on to the next one if
an image is missing, but an image that fails fs-verity checks stops the boot.
bootc never substitutes a different digest.

Existing repositories keep the format configuration recorded in their
metadata; opening one with a newer bootc doesn't convert it.

### The bare `composefs=` argument

Released UKIs have used the bare `composefs=<digest>` argument for different
formats:

- bootc 1.16.0 through 1.16.2 predate format versioning and use the original
  composefs-rs encoding that V2 descends from.
- bootc 1.16.3 writes a V2 digest.
- bootc 1.16.4 through 1.16.13 write a **V1** digest, because composefs-rs
  switched its default while `ukify` kept emitting only the bare argument.
- Releases after 1.16.13 write V2 there again, after an explicit V1 argument.

So bootc accepts a bare `composefs=` digest that matches either a V1 or a V2
image, and only enforces the format for the explicit
`composefs.digest=v1-…`/`composefs.digest=v2-…` form.

### Upgrading from bootc 1.16

When you update bootc in an image, **regenerate the initramfs before
generating the UKI**. The initramfs contains bootc's own mount logic, and
keeping an old initramfs with a newer bootc is not supported.

For a sealed deployment, sign the new UKI with a key the existing machine
trusts. If the deployment was built with `--allow-missing-verity`, keep that
flag. Then publish the image and run `bootc upgrade` as usual.

What happens next depends on the bootc version doing the staging. A client
that only understands `composefs=`, such as 1.16.0, stages the V2 fallback;
the new initramfs boots it, and the next upgrade (now staged by the new bootc)
moves the system to V1. bootc 1.16.4 and later already understand
`composefs.digest=` and stage V1 directly.

The 1.16.0 path is covered by the `test-49-composefs-1-16-bridge` TMT test for
both sealed and `--allow-missing-verity` UKIs, including rollback and garbage
collection. Upgrades from other releases, and from BLS (non-UKI) composefs
installs, are not yet tested.

## Storage and repository structure

Unlike the ostree backend, which keeps its repository at `/ostree/repo`, the composefs backend splits its on-disk state across two top-level directories in the physical sysroot:

- `/composefs`: The [composefs-rs repository](https://github.com/composefs/composefs-rs/blob/main/crates/composefs/src/repository_format.rs) (mode `0700`), containing:
  - `objects/`: content-addressed file storage, keyed by SHA-512 fs-verity digest and shared via reflink (`FICLONE`) where the filesystem supports it
  - `images/`: EROFS images describing each deployment's root filesystem metadata, possibly in both [formats](#erofs-formats)
  - `streams/`: OCI manifest, config, and layer splitstreams captured during image pulls
  - `bootc/storage/`: the `containers-storage:` instance backing logically bound images, reflink-shared with the composefs object store
- `/state/deploy/<deployment-id>/`: Persistent per-deployment state, one directory per deployment (see below for how it is named):
  - `etc/`: a writable copy of the deployment's `/etc`, bind-mounted onto the booted root's `/etc`
  - `var`: a symlink to the shared `/state/os/default/var`, bind-mounted onto the booted root's `/var`
  - `<deployment-id>.origin`: an INI file recording the image reference, boot type (BLS or UKI) and digest, and the OCI manifest digest (the latter is what keeps a deployment's objects alive across garbage collection)

Although composefs-rs supports other fs-verity hash algorithms, bootc currently hardcodes `SHA-512` for the repository. This is why EROFS image IDs and object identifiers are 128-character hex strings.

Three kinds of digest show up here and are easy to confuse. The OCI manifest
digest names the pulled container image (see the origin file above). An EROFS
digest names one bootable image under `images/` and is what the kernel command
line refers to; a deployment may have one of each format. The deployment ID names the
state directory; it is the digest of the boot image selected when the
deployment was staged.

There is no `/ostree/repo`; the composefs backend doesn't use the ostree repository at all. A minimal `/ostree` directory is still created, but only to hold a compatibility symlink (`ostree/bootc -> ../composefs/bootc`) so that existing tooling expecting `/usr/lib/bootc/storage` to resolve through `ostree/bootc` keeps working.

Transient, not-yet-finalized deployment state (used while staging an update before reboot) lives under `/run/composefs/staged-deployment` and is never persisted to disk.

## How Sealed Images Work

A sealed image is a cryptographically signed and verified bootc image that provides end-to-end integrity protection. This is achieved through:

- **Unified Kernel Images (UKIs)**: Combining kernel, initramfs, and boot parameters into a single signed binary
- **Composefs integration**: Using composefs with fs-verity for content-addressed filesystem verification
- **Secure Boot**: Cryptographic signatures on both the UKI and systemd-boot loader

A sealed image includes:

1. **composefs digest**: A SHA-512 hash of the entire root filesystem, computed at build time
2. **Unified Kernel Image (UKI)**: A single EFI binary containing the kernel, initramfs, and kernel command line with the composefs digest embedded
3. **Secure Boot signature**: The UKI is signed with your private key

At boot time, the composefs digest in the kernel command line (e.g. `composefs.digest=v1-sha512-12:<digest>`) is verified against the mounted root filesystem. This creates a chain of trust from firmware to userspace, ensuring the system will only boot if the root filesystem matches exactly what was signed.

## Building Sealed Images

### Prerequisites

For sealed images, the container must:

- Include a kernel and initramfs in `/usr/lib/modules/<kver>/`
- Have systemd-boot available (and NOT have `bootupd`)
- Not include a pre-built UKI (the build process generates one)

Sealed images also require:

- Secure Boot support in the target system firmware
- A filesystem with fs-verity support (e.g., ext4, btrfs) for the root partition

#### Using without Secure Boot

You can use a sealed UKI without Secure Boot enabled. The composefs and mounting
code is fully orthogonal to Secure Boot - the fs-verity digest of the root filesystem
and all of its contents will still be validated at runtime, which does provide
an increased level of integrity.

However: nothing validates that root digest itself, meaning any locally running
code can replace the UKI (e.g. after a container breakout) and fully control
the next boot.

It is intentional to support booting with Secure Boot disabled, because a
valid use case is to temporarily disable it in order to test a change locally
on e.g. one machine, then re-enable it later. However at the current time it
is not yet streamlined to regenerate the UKI locally.

This is independent of `--allow-missing-verity` (see [Overview](#overview)),
which instead makes fs-verity on the root filesystem optional.

### Build Pattern: Split the Kernel, Then Generate the UKI in a Separate Stage

Building a sealed image involves three stages: build the rootfs, split the kernel and initramfs out of it, and generate the signed UKI from the split rootfs in a tools stage:

```dockerfile
# Build your rootfs with all packages and configuration
FROM <base-image> as rootfs
RUN apt|dnf|zypper install ... && bootc container lint --fatal-warnings

# Split the kernel and initramfs out of the rootfs. This moves
# /usr/lib/modules/<kver>/{vmlinuz,initramfs.img} into /kernel/<kver>/,
# since for a sealed image they end up embedded in the UKI instead.
FROM rootfs as split
RUN mkdir /kernel && bootc container split-kernel-and-rootfs --rootfs / --output /kernel

# Generate the sealed UKI in a tools stage
FROM <tools-image> as sealed-uki
RUN --mount=type=bind,from=split,target=/target \
    --mount=type=bind,from=split,source=/kernel,target=/kernel \
    --mount=type=secret,id=secureboot_key \
    --mount=type=secret,id=secureboot_cert <<EORUN
set -euo pipefail

mkdir -p /out
kver=$(ls /kernel)

# `bootc container ukify` computes the composefs digest of /target, reads
# extra kernel arguments from /target/usr/lib/bootc/kargs.d, and invokes the
# real `ukify` binary with the digest embedded in the cmdline. Everything
# after `--` is passed straight through to ukify.
bootc container ukify \
  --rootfs /target \
  --kernel-dir "/kernel/${kver}" \
  -- \
  --output "/out/${kver}.efi" \
  --signtool sbsign \
  --secureboot-private-key /run/secrets/secureboot_key \
  --secureboot-certificate /run/secrets/secureboot_cert
EORUN

# Final image: the split rootfs (kernel/initramfs already removed) plus the signed UKI
FROM split
COPY --from=sealed-uki /out/*.efi /boot/EFI/Linux/
```

This pattern works because:

1. `bootc container split-kernel-and-rootfs` removes the raw kernel and initramfs from the rootfs ahead of time, so the final image never carries a duplicate copy of them (they end up embedded in the UKI instead)
2. `bootc container ukify` handles computing the composefs digest and assembling the kernel command line, so you only need to pass `ukify`-specific options (like signing) after `--`
3. The final stage copies the signed UKI into the already-split rootfs

### The `bootc container ukify` Command

```bash
bootc container ukify --rootfs <PATH> [OPTIONS] -- [UKIFY_ARGS...]
```

This is the recommended way to build a UKI for a bootc image. It computes the composefs digest of `--rootfs` (using the lower-level `compute-composefs-digest` primitive described below), reads extra kernel arguments from `/usr/lib/bootc/kargs.d`, and invokes the system `ukify` binary with the resulting cmdline. Anything after `--` is forwarded to `ukify` unchanged (e.g. `--output`, `--signtool`, signing key/cert options).

**Options:**

- `--rootfs <PATH>`: Root filesystem to operate on (default: `/`)
- `--kernel-dir <PATH>`: Directory containing `vmlinuz`/`initramfs.img`, named `/parent/<kernel-version>`. Needed when the kernel has already been split out of `--rootfs`, e.g. via `split-kernel-and-rootfs`
- `--allow-missing-verity`: Make fs-verity validation optional, for filesystems that don't support it (e.g. XFS)
- `--erofs-version <v1|v2>`: `v1` (the default) writes a V1 argument followed
  by a V2 fallback; `v2` writes only V2. See [EROFS formats](#erofs-formats).
- `--write-dumpfile-to <PATH>`: Write a composefs dumpfile for debugging

### The `bootc container compute-composefs-digest` Command

```bash
bootc container compute-composefs-digest [PATH]
```

A lower-level primitive, used internally by `ukify` above, that computes just the composefs digest for a filesystem without building a UKI. The digest is a 128-character SHA-512 hex string that uniquely identifies the filesystem contents. Useful for scripting or debugging outside of the UKI build flow.

**Options:**

- `PATH`: Path to the filesystem root (default: `/target`)
- `--erofs-version <v1|v2>`: EROFS format for the computed digest (default: `v1`)
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

Whenever the container image has a UKI, bootc automatically selects the composefs backend during installation (see [Prerequisites](#prerequisites) above for the currently-supported UKI + systemd-boot configuration for building sealed images). Note that having a UKI does not by itself make an install sealed — that also depends on whether fs-verity enforcement is on, per [Overview](#overview) above.

Composefs installs using a traditional `vmlinuz`/`initramfs.img` layout instead of a UKI can enforce fs-verity, but are never sealed, since nothing authenticates the root digest. They can use either `bootupd` (GRUB) or systemd-boot, the same as the ostree backend. See [bootloaders.md](bootloaders.md) for the general bootloader selection rules. Under the hood, bootc writes standard BLS boot entries for both UKI and traditional kernels; see the [composefs boot module documentation](https://github.com/bootc-dev/bootc/blob/main/crates/lib/src/bootc_composefs/boot.rs) for details on how entry filenames and sort-keys are chosen to sort correctly on both GRUB and systemd-boot.

## Installation

There is a `--composefs-backend` option for `bootc install` to explicitly select a composefs backend apart from sealed images; this is not as heavily tested yet.

## Known issues

The composefs backend is experimental; on-disk formats are subject to change.

- Upgrades are tested only from bootc 1.16.0 UKI installs (see
  [Upgrading from bootc 1.16](#upgrading-from-bootc-116)), and that test
  doesn't yet run in CI.
- Recovery from missing or corrupt images and deployment state is not yet
  tested, nor is garbage collection when deployments are referenced by both V1
  and V2 boot entries (for example, that GC keeps a V2 fallback image a
  rollback deployment still boots from).
- How container signature enforcement carries over from installation into the
  installed system is not settled yet.
- Extended install APIs: Ability to cleanly implement anaconda %post and osbuild post mutations and general post-install pre-reboot; right now some tools just mount the deployment directory (note this one also relates to [APIs in general](https://github.com/bootc-dev/bootc/issues/522))
- [zstd:chunked pull failures](https://github.com/bootc-dev/bootc/issues/2408):
  images pushed with `--compression-format zstd:chunked` currently fail to
  pull on the composefs backend ("unexpected EOF reading tar entry"). Until a
  composefs-rs decode fix is incorporated, publish with plain zstd or gzip.

## Related issues

- [Unified storage](https://github.com/bootc-dev/bootc/issues/20): Not strictly a blocker but a really nice to have
- [Sealed image build UX](https://github.com/bootc-dev/bootc/issues/1498): Streamlined tooling for building sealed images
- In place transitions: 
  - First: support [factory reset](https://github.com/bootc-dev/bootc/issues/404) from ostree to composefs
  - Next: Support copying /etc and /var

## Additional Resources

- See [filesystem.md](filesystem.md) for information about composefs in the standard ostree backend
- See [bootloaders.md](bootloaders.md) for bootloader configuration details
- [composefs-rs](https://github.com/composefs/composefs-rs) - The underlying composefs implementation
- [composefs-rs repository format](https://github.com/composefs/composefs-rs/blob/main/crates/composefs/src/repository_format.rs) - Detailed on-disk layout of the `/composefs` repository
- [Unified Kernel Images specification](https://uapi-group.org/specifications/specs/unified_kernel_image/)
- [ukify documentation](https://www.freedesktop.org/software/systemd/man/latest/ukify.html) - Tool for building UKIs
