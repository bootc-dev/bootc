# composefs backend

Experimental features are subject to change or removal. Please
do provide feedback on them.

## Overview

The composefs backend is an experimental alternative storage backend that uses [composefs-rs](https://github.com/composefs/composefs-rs) instead of ostree for storing and managing bootc system deployments.

**Status**: Experimental, but close to stabilization! We are committed to in-place upgrades from all systems deployed since bootc 1.16.0.

The composefs backend supports two distinct levels of integrity guarantee, controlled by whether fsverity is strictly enforced on the root filesystem (i.e. whether the image was built with `--allow-missing-verity`):

- **Sealed**: The composefs digest is baked into the kernel command line of a UKI and *required* to match at boot.
- **Unsealed**: fsverity enforcement is optional, so composefs still provides content-addressed, deduplicated storage and garbage collection, but without a guarantee that the root filesystem matches what was signed. Unsealed composefs most commonly boots via a traditional `vmlinuz`/`initramfs.img` and a BLS boot entry, but a UKI built with `--allow-missing-verity` is *also* unsealed in this sense — packaging as a UKI is a boot convenience here, not by itself a security boundary. See [Bootloader Support](#bootloader-support) below.

## Storage and repository structure

Unlike the ostree backend, which keeps its repository at `/ostree/repo`, the composefs backend splits its on-disk state across two top-level directories in the physical sysroot:

- `/composefs`: The [composefs-rs repository](https://github.com/composefs/composefs-rs/blob/main/crates/composefs/src/repository_format.rs) (mode `0700`), containing:
  - `objects/`: content-addressed file storage, keyed by SHA-512 fsverity digest and shared via reflink (`FICLONE`) where the filesystem supports it
  - `images/`: EROFS images describing each deployment's root filesystem metadata
  - `streams/`: OCI manifest, config, and layer splitstreams captured during image pulls
  - `bootc/storage/`: the `containers-storage:` instance backing logically bound images, reflink-shared with the composefs object store
- `/state/deploy/<deployment-id>/`: Persistent per-deployment state, one directory per deployment (named after its composefs digest):
  - `etc/`: a writable copy of the deployment's `/etc`, bind-mounted onto the booted root's `/etc`
  - `var`: a symlink to the shared `/state/os/default/var`, bind-mounted onto the booted root's `/var`
  - `<deployment-id>.origin`: an INI file recording the image reference, boot type (BLS or UKI) and digest, and the OCI manifest digest (the latter is what keeps a deployment's objects alive across garbage collection)

Although composefs-rs supports other fsverity hash algorithms, bootc currently hardcodes `SHA-512` for the repository (see `Algorithm::SHA512` at every repository init/open call site, and the `ComposefsRepository` type alias in `crates/lib/src/store/mod.rs`). This is why deployment and object identifiers throughout this document (and in `bootc status`) are 128-character hex strings.

There is no `/ostree/repo`; the composefs backend doesn't use the ostree repository at all. A minimal `/ostree` directory is still created, but only to hold a compatibility symlink (`ostree/bootc -> ../composefs/bootc`) so that existing tooling expecting `/usr/lib/bootc/storage` to resolve through `ostree/bootc` keeps working.

Transient, not-yet-finalized deployment state (used while staging an update before reboot) lives under `/run/composefs/staged-deployment` and is never persisted to disk.

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

#### Using without Secure Boot

You can use a sealed UKI without Secure Boot enabled. The composefs and mounting
code is fully orthogonal to Secure Boot - the fsverity digest of the root filesystem
and all of its contents will still be validated at runtime, which does provide
an increased level of integrity.

However: nothing validates that root digest itself, meaning any locally running
code can replace the UKI (e.g. after a container breakout) and fully control
the next boot.

It is intentional to support booting with Secure Boot disabled, because a
valid use case is to temporarily disable it in order to test a change locally
on e.g. one machine, then re-enable it later. However at the current time it
is not yet streamlined to regenerate the UKI locally.

Note this is a different, independent weakening from `--allow-missing-verity`
(see [Overview](#overview) above): disabling Secure Boot only removes firmware
verification of the UKI's own signature, while the fsverity digest of the root
filesystem is still enforced. Building with `--allow-missing-verity` instead
disables that digest enforcement itself, which is what actually makes an image
unsealed regardless of whether Secure Boot is enabled.

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
- `--allow-missing-verity`: Make fsverity validation optional, for filesystems that don't support it (e.g. XFS)
- `--write-dumpfile-to <PATH>`: Write a composefs dumpfile for debugging

### The `bootc container compute-composefs-digest` Command

```bash
bootc container compute-composefs-digest [PATH]
```

A lower-level primitive, used internally by `ukify` above, that computes just the composefs digest for a filesystem without building a UKI. The digest is a 128-character SHA-512 hex string that uniquely identifies the filesystem contents. Useful for scripting or debugging outside of the UKI build flow.

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

## UKI Addons

UKI addons are signed PE binaries that [systemd-stub](https://www.freedesktop.org/software/systemd/man/latest/systemd-stub.html) loads alongside the main UKI at boot. Each addon carries extra kernel command-line parameters (or other PE sections) that get merged into the boot. This lets you ship optional configuration — debug flags, hardware quirks, site-specific parameters — separately from the base UKI, without rebuilding or re-signing it.

bootc supports two types of UKI addons:

- **Scoped addons** are tied to a specific UKI (and therefore a specific deployment). They live in a `<uki>.efi.extra.d/` directory next to the UKI on the ESP, and are cleaned up by garbage collection when the deployment is removed.
- **Global addons** apply to *every* UKI on the ESP. They live in `loader/addons/` and persist across deployments — they are not removed by GC.

### Building Images with Addons

Addons are built with `ukify` in the same Containerfile stage that produces the sealed UKI. Each addon is a separate `ukify build` invocation:

```dockerfile
# Inside the sealed-uki build stage, after building the main UKI:

# Scoped addon: lives in <kver>.efi.extra.d/, loaded only by this UKI
ukify build --cmdline 'debug loglevel=7' \
    --output /out/${kver}.efi.extra.d/debug.addon.efi

# Global addon: lives in loader/addons/, loaded by every UKI ergo every deployment
mkdir -p /out/loader/addons
ukify build --cmdline 'custom_param=value' \
    --output /out/loader/addons/site-config.addon.efi
```

The `finalize-uki` script (run in the final Containerfile stage) copies these directories into `/boot` alongside the UKI if they exist.

Addons can also be signed for Secure Boot by passing `--signtool` and key/cert options to `ukify build`, the same as for the main UKI.

### Selecting Addons at Install Time

An image can ship multiple addons, but none are installed unless explicitly requested. Use `--uki-addon` for scoped addons and `--global-uki-addon` for global ones. The name is the addon filename without the `.addon.efi` suffix:

```bash
# Install with one scoped and one global addon
bootc install to-disk \
    --uki-addon debug \
    --global-uki-addon site-config \
    /dev/sda

# Multiple addons of the same type
bootc install to-disk \
    --uki-addon debug \
    --uki-addon extra-kargs \
    --global-uki-addon site-config \
    /dev/sda
```

Without `--uki-addon` or `--global-uki-addon`, no addons are installed even if the image contains them.

### Addons on Upgrade and Switch

The same `--uki-addon` and `--global-uki-addon` options are available on `bootc upgrade` and `bootc switch`:

```bash
# Add a new addon during switch
bootc switch --uki-addon debug --global-uki-addon site-config \
    quay.io/myorg/myimage:v2

# Add an addon during upgrade
bootc upgrade --uki-addon debug
```

Once an addon is installed, it **persists across subsequent upgrades**. If the new image contains an addon with the same filename as one already installed, bootc automatically updates it with the version from the new image. You do not need to pass `--uki-addon` again on every upgrade — only when adding a new addon that wasn't previously installed.

If an addon name is passed but no matching file exists in the image, it is silently skipped.

### ESP Layout

On the EFI System Partition, bootc places addon files as follows:

```
ESP/
├── EFI/Linux/bootc/
│   ├── bootc-<deployment-id>.efi              # The UKI
│   └── bootc-<deployment-id>.efi.extra.d/     # Scoped addons for this UKI
│       ├── debug.addon.efi
│       └── extra-kargs.addon.efi
└── loader/addons/                              # Global addons
    └── site-config.addon.efi
```

Scoped addon directories are namespaced by the deployment's composefs digest, so different deployments can have different sets of scoped addons without colliding.

### Current Limitations

- **Global addons are not rollback-aware**: Rolling back to a previous deployment does not revert changes to global addons, since they are shared across all UKIs.

## Developing and Testing bootc with composefs

See [CONTRIBUTING.md](https://github.com/bootc-dev/bootc/blob/main/CONTRIBUTING.md) for information on building and testing bootc itself with composefs support.

## Bootloader Support

Whenever the container image has a UKI, bootc automatically selects the composefs backend during installation (see [Prerequisites](#prerequisites) above for the currently-supported UKI + systemd-boot configuration for building sealed images). Note that having a UKI does not by itself make an install sealed — that also depends on whether fsverity enforcement is on, per [Overview](#overview) above.

Composefs installs using a traditional `vmlinuz`/`initramfs.img` layout instead of a UKI are always unsealed, and can use either `bootupd` (GRUB) or systemd-boot, the same as the ostree backend. See [bootloaders.md](bootloaders.md) for the general bootloader selection rules. Under the hood, bootc writes standard BLS boot entries for both UKI and traditional kernels; see the [composefs boot module documentation](https://github.com/bootc-dev/bootc/blob/main/crates/lib/src/bootc_composefs/boot.rs) for details on how entry filenames and sort-keys are chosen to sort correctly on both GRUB and systemd-boot.

## Installation

There is a `--composefs-backend` option for `bootc install` to explicitly select a composefs backend apart from sealed images; this is not as heavily tested yet.

## Known Issues

The composefs backend is experimental; on-disk formats are subject to change.

### Stability blockers

- [Dual EROFS v1/v2 generation](https://github.com/bootc-dev/bootc/pull/2248) and https://github.com/bootc-dev/bootc/pull/2353

### Important

- Extended install APIs: Ability to cleanly implement anaconda %post and osbuild post mutations and general post-install pre-reboot; right now some tools just mount the deployment directory (note this one also relates to [APIs in general](https://github.com/bootc-dev/bootc/issues/522))
- [zstd:chunked pull failures](https://github.com/bootc-dev/bootc/issues/2408): Images pushed with `--compression-format zstd:chunked` currently fail to pull on the composefs backend ("unexpected EOF reading tar entry"). A [decode fix](https://github.com/composefs/composefs-rs/pull/381) is in flight in composefs-rs and reaches bootc with the next composefs-rs update; until then publishers should use plain zstd (or gzip).

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
