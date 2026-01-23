# Internals

This section documents bootc's internal architecture for developers working
on the project. For user-facing documentation, see the rest of this book.

## Code Architecture

### CLI Structure

The `bootc` binary (`crates/cli`) is a thin wrapper that:

1. Performs global initialization (signal handlers, mounting filesystems)
2. Creates a tokio async runtime (single-threaded)
3. Delegates to `bootc_lib::cli::run_from_iter()`

The CLI uses [clap](https://docs.rs/clap) with derive macros. Each subcommand
typically opens the system storage via `store::BootedStorage::new_from_env()`,
performs the operation, and writes status to stdout or a progress fd.

CPU-intensive work is offloaded via `tokio::task::spawn_blocking`.

### Crate Organization

- **`bootc`** (`crates/cli`): Thin binary entrypoint
- **`bootc-lib`** (`crates/lib`): Core implementation library
- **`ostree-ext`** (`crates/ostree-ext`): OCI/ostree bridging, container import/export
- **Supporting crates**: Focused utilities (mount, blockdev, kernel cmdline, etc.)

Most functionality lives in `bootc-lib`, making it testable. The API is
internal and not stable for external consumers.

## Storage Backends

### OSTree Backend (stable, default)

Uses [ostree](https://ostreedev.github.io/ostree/) for content-addressed storage.
Container images are imported via `ostree-ext`. Deployments use ostree's native
mechanism with Boot Loader Specification (BLS) entries.

Key paths:

- `/sysroot/ostree/repo/` - OSTree repository
- `/sysroot/ostree/deploy/<stateroot>/` - Deployment directories

### Composefs Backend (experimental)

Uses [composefs-rs](https://github.com/containers/composefs-rs) directly,
enabling native UKI support and sealed images with fsverity integrity.

Key paths:

- `/sysroot/composefs/` - Composefs repository (EROFS images)
- `/sysroot/state/deploy/<deployment-id>/` - Per-deployment state
  (deployment-id is the SHA-512 fsverity digest)

Implementation: `bootc_composefs` module in `bootc-lib`.

## Key Modules

### The Store Module

The `store` module provides the `Storage` type abstracting both backends.
It lazily initializes:

- OSTree sysroot (`ostree::Sysroot`)
- Composefs repository (`composefs::Repository<Sha512HashValue>`)
- Container image storage for bound images (`podstorage::CStorage`)

### Deploy Module

Handles deployment lifecycle:

- Staging new deployments from container images
- Kernel argument management (`bootc_kargs`)
- Three-way merge of `/etc` configuration
- Rollback between deployments

### Spec Module

Defines core types (see [spec module rustdoc](internals/bootc_lib/spec/index.html)). These
are ultimately the types that are serialized to `bootc status --json` and form a key
part of the admin experience.

### bootc-owned Container Storage

The `podstorage` module implements bootc's own `containers-storage:` instance
at `/sysroot/ostree/bootc/storage/` (symlinked to `/usr/lib/bootc/storage/`).
This supports [Logically Bound Images](logically-bound-images.md) with proper
lifecycle management and garbage collection tied to deployments.

## Rustdoc API Documentation

The following rustdoc documentation is generated from the source code with
`--document-private-items` to expose internal APIs.

### Core crates

- [bootc-lib](internals/bootc_lib/index.html) - Core bootc implementation
- [bootc](internals/bootc/index.html) - CLI frontend

### Supporting crates

- [ostree-ext](internals/ostree_ext/index.html) - Extension APIs for OSTree
- [bootc-mount](internals/bootc_mount/index.html) - Internal mount utilities
- [bootc-kernel-cmdline](internals/bootc_kernel_cmdline/index.html) - Kernel command line parsing
- [bootc-initramfs-setup](internals/bootc_initramfs_setup/index.html) - Initramfs setup code
- [etc-merge](internals/etc_merge/index.html) - /etc merge handling

### Utility crates

- [bootc-internal-utils](internals/bootc_internal_utils/index.html) - Internal utilities
- [bootc-internal-blockdev](internals/bootc_internal_blockdev/index.html) - Block device handling
- [bootc-sysusers](internals/bootc_sysusers/index.html) - systemd-sysusers implementation
- [bootc-tmpfiles](internals/bootc_tmpfiles/index.html) - systemd-tmpfiles implementation

### External git crates

These crates are pulled from git and are not published to crates.io (so not on docs.rs).

- [composefs](internals/composefs/index.html) - Core composefs library
- [composefs-boot](internals/composefs_boot/index.html) - Boot support for composefs
- [composefs-oci](internals/composefs_oci/index.html) - OCI integration for composefs
