# composefs backend

Experimental features are subject to change or removal. Please
do provide feedback on them.

## Overview

The composefs backend is an experimental alternative storage backend that uses [composefs-rs](https://github.com/composefs/composefs-rs) instead of ostree for storing and managing bootc system deployments.

**Status: experimental.** New composefs repositories and UKIs use EROFS V1 by
default, while retaining a V2 compatibility path. This is not a general
compatibility promise for every older bootc release or existing composefs
installation. The tested compatibility claim is limited to the bootc 1.16.0
fixtures described in [Stabilization status](#stabilization-status).

Root filesystem verification and boot-artifact authentication are separate:

- A **strict fs-verity policy** requires verified composefs objects. A `?`
  marker in the composefs kernel arguments permits missing fs-verity instead.
  Both UKI and traditional kernel/initramfs+BLS installations can require
  fs-verity on supported filesystems.
- A **sealed UKI deployment** combines strict root verification with a signed
  UKI authenticated by Secure Boot. The UKI contains the trusted root digest.
  A BLS entry or an unsigned UKI does not provide that same authentication,
  even when root filesystem verification is strict.

Building a UKI with `--allow-missing-verity` adds the `?` marker. Merely
disabling Secure Boot does not add it or disable root filesystem verification.

## EROFS V1 transition and compatibility

EROFS V1 is the default for newly initialized composefs repositories.
`bootc container ukify` now emits V1 followed by a V2 fallback by default; it
does not probe the initramfs with `lsinitrd`. V1 uses the C-tool-compatible kernel argument
`composefs.digest=v1-sha512-12:<digest>`. V2 is the legacy composefs-rs format
and uses `composefs=<digest>`. Both digests are SHA-512 values, but they name
different EROFS encodings and must not be substituted for one another.

When building a UKI with the default V1, bootc computes both values and puts
the V1 argument first and the V2 argument second. A current initramfs tries
candidates in command-line order, so it selects V1 when its image is present.

When updating bootc in an image, **regenerate its initramfs before generating
the UKI**. Retaining an old initramfs while updating bootc is outside the
supported upgrade procedure.

For an existing bootc 1.16.0 UKI deployment:

1. Build the replacement image with updated bootc and a regenerated initramfs.
   Generate a new UKI with the default dual-digest output. For a sealed
   deployment, sign it with a key trusted by the existing machine. For a
   deployment permitting missing fs-verity, retain that policy when generating
   the UKI with `--allow-missing-verity`.
2. Publish the replacement image at the deployment's configured image
   reference, then run `bootc upgrade` on the old deployment and reboot.
3. The old client stages V2. The replacement image's new initramfs boots that
   V2 fallback with matching deployment state. A subsequent upgrade staged by
   the current client can select V1.

This procedure has been tested with the exact bootc 1.16.0 UKI fixtures in
both strict/sealed and missing-verity-permitted modes, including persistence,
rollback, and GC. It is not evidence for arbitrary earlier versions or for
historical BLS migration; those combinations need separate testing.

The only historical release in the tested compatibility scope is bootc 1.16.0.
Other historical releases, including v1.9's SHA-256 V2 identity, are not part
of this compatibility contract.

New repositories are configured to retain V1 as the default and V2 as an
additional format. Existing repositories retain the format configuration
recorded in their metadata when opened; they are not silently reinitialized
as V1 repositories. A successful fallback still requires the matching V2
image and an initramfs able to mount it. Missing images, malformed or
unrecognized kernel arguments, fs-verity policy rejection, or a UKI digest
that does not match the repository are boot/staging failures, not a safe
conversion to another digest.

For controlled V2 UKI generation, the supported CLI spelling is:

```bash
bootc container ukify --erofs-version=v2 ...
```

That produces only the V2 `composefs=` argument; it does not add a V1
fallback. The same `--erofs-version=v1` or `--erofs-version=v2` option is
available on the hidden `bootc container compute-composefs-digest` helpers.
The selected format must match images committed to the repository.

For the existing TMT build tests, `BOOTC_erofs_version=v1` or
`BOOTC_erofs_version=v2` selects the image format and is forwarded by
`just test-tmt-nobuild`; use the same setting for the base and synthetic
upgrade images. It is not an install-time flag: installation consumes the
UKI already in the image. Current tests cover current-client-to-current-client
same-format upgrades, not the old-client bridge. There is no supported BLS
install-time V2 control; the format is selected when the image and its boot
artifacts are built.

## Storage and repository structure

Unlike the ostree backend, which keeps its repository at `/ostree/repo`, the composefs backend splits its on-disk state across two top-level directories in the physical sysroot:

- `/composefs`: The [composefs-rs repository](https://github.com/composefs/composefs-rs/blob/main/crates/composefs/src/repository_format.rs) (mode `0700`), containing:
  - `objects/`: content-addressed file storage, keyed by SHA-512 fsverity digest and shared via reflink (`FICLONE`) where the filesystem supports it
  - `images/`: EROFS images describing each deployment's root filesystem metadata; a transition repository can contain both the V1 and V2 images for one root filesystem
  - `streams/`: OCI manifest, config, and layer splitstreams captured during image pulls
  - `bootc/storage/`: the `containers-storage:` instance backing logically bound images, reflink-shared with the composefs object store
- `/state/deploy/<deployment-id>/`: Persistent per-deployment state, one directory per deployment (named after the deployment identity selected while staging):
  - `etc/`: a writable copy of the deployment's `/etc`, bind-mounted onto the booted root's `/etc`
  - `var`: a symlink to the shared `/state/os/default/var`, bind-mounted onto the booted root's `/var`
  - `<deployment-id>.origin`: an INI file recording the image reference, boot type (BLS or UKI) and digest, and the OCI manifest digest (the latter is what keeps a deployment's objects alive across garbage collection)

Although composefs-rs supports other fsverity hash algorithms, bootc currently hardcodes `SHA-512` for the repository. This is why EROFS image IDs and object identifiers are 128-character hex strings.

Several identifiers appear together but have different purposes:

- The OCI manifest digest identifies the pulled container content and is recorded in the origin data; it is used to retain pull objects for garbage collection.
- A V1 or V2 EROFS/fs-verity digest identifies one bootable EROFS image. It is the value checked by the corresponding UKI kernel argument and is the root mount identity.
- The state-directory deployment ID identifies the writable `/etc` and `/var`
  state attached to a staged deployment. In the V1 transition it may be the
  preferred V1 boot image identity. Do not infer it from an arbitrary V2
  fallback digest or treat it as the OCI manifest digest.

This separation is important during fallback: an older client may boot the V2
root image and its existing state, while a later current-client upgrade can
select the V1 root image and the state directory selected for that deployment.
The repository's multiple boot-image IDs do not alias state directories.

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

Note this is a different, independent weakening from
`--allow-missing-verity` (see [Overview](#overview) above): disabling Secure
Boot only removes firmware verification of the UKI's own signature, while the
fsverity digest of the root filesystem is still enforced. The
`--allow-missing-verity` option makes verification optional for that UKI build;
it is not the only context in which an installation can be described as
unsealed.

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
- `--erofs-version <v1|v2>`: Select the EROFS digest format. The default and
  explicit `v1` produce V1 followed by a V2 fallback; explicit `v2` produces
  only the legacy V2 digest. This command does not probe the initramfs. See
  [EROFS V1 transition and compatibility](#erofs-v1-transition-and-compatibility).
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

Whenever the container image has a UKI, bootc automatically selects the composefs backend during installation (see [Prerequisites](#prerequisites) above for the currently-supported UKI + systemd-boot configuration for building sealed images). Note that having a UKI does not by itself make an install sealed — that also depends on whether fsverity enforcement is on, per [Overview](#overview) above.

Traditional composefs installs use a `vmlinuz`/`initramfs.img` layout. They can
require fs-verity, but do not provide the signed-UKI authentication described
above. They can use either `bootupd` (GRUB) or systemd-boot, the
same as the ostree backend. A UKI install is a separate boot path: the UKI
contains the kernel, initramfs, and command line, and its integrity policy is
determined independently of the BLS entry used to select it. See
[bootloaders.md](bootloaders.md) for the general bootloader selection rules.
Under the hood, bootc writes standard BLS boot entries for both paths; see the
[composefs boot module documentation](https://github.com/bootc-dev/bootc/blob/main/crates/lib/src/bootc_composefs/boot.rs)
for entry naming and sorting details.

## Installation

There is a `--composefs-backend` option for `bootc install` to explicitly select a composefs backend apart from sealed images; this is not as heavily tested yet.

## Stabilization status

The composefs backend is experimental; on-disk formats are subject to change.

This core-focused candidate contains the V1/V2 repository, UKI, initramfs, and
install changes.

### Evidence recorded so far

- Unit tests cover default V1 UKI argument ordering, explicit V2 UKI output,
  candidate selection, and V1/V2 digest generation.
- Initial repository-policy verification in test plan 23 passed for strict
  UKIs and UKIs containing `?`. The test checks fs-verity on the installed
  target's repository metadata and the installed UKI arguments, rather than
  inspecting the running installer's repository. This verifies initial
  installation policy, not historical migration compatibility.
- The bootc 1.16.0 old-stager UKI bridge passed in both strict/sealed and
  missing-verity-permitted modes. Each run booted current userspace via V2,
  then upgraded to V1, preserved `/etc` and `/var`, rolled back, and checked
  composefs GC. The images contained regenerated current initramfs. Historical
  BLS migration has not been established by these runs.
- These are opt-in, fixture-driven TMT tests, not fully automated CI coverage:
  the fixture build recipe currently depends on ignored one-off files. Making
  fixture production reproducible remains tracked work before treating this as
  generally provisioned regression coverage.
- Sealed CentOS 10 V1/V2 tests and a strict-policy downgrade-rejection control
  were reported as passing on the combined tree. The CentOS 9 sealed-upgrade
  case was deliberately skipped, so it is not evidence of compatibility.

The verified paths do not expand the compatibility contract beyond the exact
bootc 1.16.0 fixtures and configurations tested above.

### Remaining blockers before calling this stable

1. **Make fixture production reproducible.** Replace the ignored one-off
   fixture build inputs with a maintained recipe. Do not expand the
   compatibility claim beyond combinations actually tested.
2. **Exercise recovery and retention failures.** Add the missing xattr
   recovery fixture and assess corruption and garbage-collection paths,
   including references from both V1 and V2 boot entries. Acceptance requires
   a defined, tested outcome for missing/corrupt images and state, with no
   deletion of a live fallback image or its required state.
3. **Resolve signature-enforcement persistence.** The required semantics are
   still an OSTree/user decision: trust the local source, preserve target
   enforcement, and optionally run a fetch check without forcing installation
   online. Acceptance requires tests of those semantics and rejection of an
   insecure UKI under a strict target policy.

### Pending work that is not, by itself, a stability blocker

- **V2 test controls:** `BOOTC_erofs_version` is a TMT image-build control,
  not an install API. The verified historical bridge coverage remains opt-in
  until fixture production is reproducible.
- **Signature source work:** the source/persistence investigation is pending;
  the policy semantics above are the required behavior, not a claim that all
  persistence machinery is complete.
- [zstd:chunked pull failures](https://github.com/bootc-dev/bootc/issues/2408):
  images pushed with `--compression-format zstd:chunked` currently fail to
  pull on the composefs backend ("unexpected EOF reading tar entry"). Until a
  composefs-rs decode fix is incorporated and validated, publishers should use
  plain zstd or gzip.

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
