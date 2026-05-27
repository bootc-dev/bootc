# Unified storage

Experimental features are subject to change or removal. Please
do provide feedback on them.

Tracking issue: <https://github.com/bootc-dev/bootc/issues/20>

## Overview

Unified storage is the goal of having all storage for bootc be "unified" with the storage
used by a container runtime, such as podman.

Currently, bootc uses either ostree or composefs. [Logically bound images](logically-bound-images.md)
use the podman container storage.

## Goals

- Direct support for zstd:chunked: Container images using zstd:chunked compression
  can be efficiently pulled with deduplication
- Efficient `podman run <booted image>`: The booted OS image is directly accessible
  to podman without exporting/copying
- Shared layer storage: Layers common between the host image and app containers
  are stored only once
- When used with `bootc image cmd build`, can support direct build into the bootc-owned
  storage without a copy from the podman (or other app container) storage.

## Current status

**Status**: Experimental. The unified storage feature is under active development.

Currently supported:

- Installation with `--experimental-unified-storage` flag
- `bootc switch --experimental-unified-storage` to force the unified path
- Onboarding running systems via `bootc image set-unified`
- Auto-detection during upgrade/switch when image exists in bootc storage

### Why this isn't the default yet

A key blocker for enabling unified storage by default is
[container-libs#144](https://github.com/containers/container-libs/issues/144):
the containers/image stack currently copies data between `containers-storage:`
instances by serializing through tarballs. This means that when bootc imports
from its container storage into ostree, or when copying between different
container storage instances, each layer is fully re-serialized even when both
storages are on the same filesystem.

The architectural fix requires separating metadata from data in the copy path,
allowing file descriptors to be passed and reflinked rather than streamed
through tar. This will be solved by putting [composefs-rs](https://github.com/containers/composefs-rs)
in the middle to orchestrate zero-copy pulls. See [Future plans: composefs-to-ostree](#future-plans-composefs-to-ostree).

## Enabling unified storage

### During installation

Use the `--experimental-unified-storage` flag with `bootc install`:

```bash
bootc install to-disk --experimental-unified-storage /dev/sdX
```

This causes the installation to pull the source image into bootc's container
storage first, then import from there into ostree.

### On a running system

To onboard an existing system to unified storage, use:

```bash
bootc image set-unified
```

This re-pulls the currently booted image from its original source into the
bootc-owned container storage. After this, future `bootc upgrade` and
`bootc switch` operations will automatically use the unified storage path
when the image is detected in bootc storage.

## How it works

### Pull flow

With unified storage enabled:

1. The image is pulled using podman/skopeo into `/usr/lib/bootc/storage`
2. bootc then imports from `containers-storage:` transport into ostree
3. The image remains in bootc storage for podman access and layer sharing

### Auto-detection

During `bootc upgrade` or `bootc switch`, bootc automatically checks if the
target image already exists in the bootc container storage. If so, it uses
the unified storage path without requiring any flags. This means once you've
onboarded via `bootc image set-unified`, subsequent upgrades will automatically
use the unified path.

### Storage location

The bootc-owned container storage is at `/usr/lib/bootc/storage`, which is
a symlink to persistent storage under `/sysroot`. This is the same location
used for logically bound images.

## Example workflows

### Local build and boot

With unified storage, you can build a derived image locally and boot it directly:

```bash
# Copy the booted image to podman storage
bootc image copy-to-storage

# Switch to use containers-storage transport (enables unified path)
bootc switch --transport containers-storage localhost/bootc

# Onboard to unified storage
bootc image set-unified

# Build a derived image directly into bootc storage
bootc image cmd build -t localhost/my-custom .

# Switch to the derived image
bootc switch --transport containers-storage localhost/my-custom
```

### Using podman with the booted image

Once unified storage is enabled, podman can access the booted image:

```bash
podman --storage-opt=additionalimagestore=/usr/lib/bootc/storage run localhost/bootc
```

## Relationship to composefs backend

Unified storage is complementary to the [composefs backend](experimental-composefs.md).
While unified storage changes *how images are pulled* (using containers/storage),
the composefs backend changes *how the filesystem is stored and verified*.

## Future plans: composefs-to-ostree

These features will be combined in upcoming work to build a "composefs-first"
import pipeline. In this planned model, containers/storage will pull the image,
composefs will import it via reflinks (`FICLONE`), and then ostree will 
synthesize its commit by `FICLONE`ing from the composefs objects.

This will eliminate tar serialization entirely, meaning only one physical copy
of the image data will exist on disk, shared across all three stores.

## Future plans: composefs-as-storage

Looking further ahead, the ultimate evolution of unified storage is to make the host's `/sysroot/composefs` object store the single, global source of truth for all content-addressed files on the system.

Instead of `containers/storage` maintaining its own copy of application image layers and merely sharing the *host* OS layers, podman's composefs backend could be configured to write objects directly into `/sysroot/composefs` on bootc-managed systems.

This means there would be exactly one storage pool for:

1. The bootc host OS image
2. Logically bound app containers
3. Standard Podman app containers
4. Flatpak apps (by having flatpak's system helper write to the same object store)

Every file across the entire system—whether part of the base OS, a containerized database, or a desktop application—would be deduplicated automatically and perfectly at the object level via fsverity digests.

### Implementation notes

For developers, the internal design and target architecture for this three-store
unified storage model is documented in the rustdoc comments of the relevant source files:

- `crates/lib/src/store/mod.rs` — the target three-store architecture and reflink behavior
- `crates/lib/src/bootc_composefs/repo.rs` — composefs unified pull path stages
- `crates/lib/src/deploy.rs` — pull dispatch and ostree backend synthesis
- `crates/lib/src/image.rs` — `bootc image set-unified` entrypoints

## Limitations

- **Experimental**: The feature is not yet suitable for production use
- **Flag is hidden**: The `--experimental-unified-storage` install flag is
  hidden from `--help` output
- **Progress reporting**: Pull progress from podman is not yet integrated
  with bootc's progress reporting
- **Garbage collection**: Images in bootc storage are garbage collected based
  on deployment references; see [logically-bound-images.md](logically-bound-images.md)
  for details

## Related issues

- [#20](https://github.com/bootc-dev/bootc/issues/20) - Unified storage (main tracker)
- [#721](https://github.com/bootc-dev/bootc/issues/721) - bootc-owned containers/storage
- [#1190](https://github.com/bootc-dev/bootc/issues/1190) - composefs-native backend
- [containers/container-libs#144](https://github.com/containers/container-libs/issues/144) - Reflink support between container storages
