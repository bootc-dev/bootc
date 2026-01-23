# Unified storage

Experimental features are subject to change or removal. Please
do provide feedback on them.

Tracking issue: <https://github.com/bootc-dev/bootc/issues/20>

## Overview

Unified storage is an experimental feature that allows bootc to fetch and store
the default OS image in the same [containers/storage](https://github.com/containers/storage)
backend used for [logically bound images](logically-bound-images.md) (and by podman).
This enables several benefits:

- Direct support for zstd:chunked: Container images using zstd:chunked compression
  can be efficiently pulled with deduplication
- Efficient `podman run <booted image>`: The booted OS image is directly accessible
  to podman without exporting/copying
- Shared layer storage: Layers common between the host image and app containers
  are stored only once
- When used with `bootc image cmd build`, can support direct build into the bootc-owned
  storage without a copy from the podman (or other app container) storage.

## Background

Historically, bootc has used two separate storage backends:

1. **ostree**: For the booted host OS image, via [ostree-rs-ext](https://github.com/ostreedev/ostree-rs-ext/)
2. **containers/storage**: For logically bound images (LBIs)

This split created challenges: the booted image couldn't be easily accessed
by podman, and container layer sharing between the host and LBIs wasn't possible.

Unified storage addresses this by pulling the host image into the bootc-owned
container storage (`/usr/lib/bootc/storage`) first, then importing from there
into ostree and setting it up for booting (e.g. performing SELinux labeling).

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

With reflink support (as proposed in that issue), copies between storages on
the same filesystem would be nearly instantaneous and use no additional disk
space. Without it, unified storage works but involves redundant I/O and
temporary disk space usage proportional to layer sizes. This is particularly
noticeable with large non-chunked layers.

The architectural fix requires separating metadata from data in the copy path,
allowing file descriptors to be passed and reflinked rather than streamed
through tar. This is related to the composefs approach of content-addressed
storage with distinct metadata and data channels.

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
These features can potentially be combined in the future.

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
