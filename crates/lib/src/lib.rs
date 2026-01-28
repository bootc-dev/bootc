// The internals docs are built with --document-private-items, so allow
// linking to private items from module documentation.
#![allow(rustdoc::private_intra_doc_links)]

//! # Bootable container tool
//!
//! This crate builds on top of ostree's container functionality
//! to provide a fully "container native" tool for using
//! bootable container images.
//!
//! For user-facing documentation, see <https://bootc-dev.github.io/bootc/>.
//! For architecture and internals documentation, see the
//! [Internals](https://bootc-dev.github.io/bootc/internals.html) section.
//!
//! # Crate Overview
//!
//! This is the core implementation library for bootc. The `bootc` binary
//! (`crates/cli`) is a thin wrapper that delegates to [`cli::run_from_iter`].
//!
//! The API is internal and not stable for external consumption.
//!
//! # Module Index
//!
//! ## Core Functionality
//!
//! - [`cli`] - Command-line interface implementation (clap-based)
//! - [`deploy`] - Deployment staging, rollback, and lifecycle management
//! - [`store`] - Storage backend abstraction (OSTree and Composefs)
//! - [`spec`] - Core types: [`spec::Host`], [`spec::HostSpec`], [`spec::BootEntry`]
//! - [`install`] - System installation (`bootc install to-disk`)
//! - [`status`] - Status reporting (`bootc status`)
//!
//! ## Container and Image Handling
//!
//! - [`image`] - Image operations and queries
//! - [`boundimage`] - Logically Bound Images (LBIs)
//! - [`podstorage`] - bootc-owned container storage (`/usr/lib/bootc/storage`)
//! - [`podman`] - Podman command helpers
//!
//! ## Storage Backends
//!
//! - [`bootc_composefs`] - Composefs backend implementation (experimental)
//! - The OSTree backend is implemented via `ostree-ext` and the [`store`] module
//!
//! ## Filesystem and Boot
//!
//! - [`bootloader`] - Bootloader configuration (GRUB, systemd-boot, UKI)
//! - [`kernel`] - Kernel and initramfs handling
//! - [`bootc_kargs`] - Kernel argument management
//! - [`lsm`] - Linux Security Module (SELinux) integration
//! - [`generator`] - Systemd generator for boot configuration
//!
//! ## Utilities
//!
//! - [`fsck`] - Filesystem consistency checks
//! - [`lints`] - Container image linting
//! - [`metadata`] - Image metadata extraction
//!
//! # Related Crates
//!
//! - [`ostree-ext`](../ostree_ext/index.html) - OCI/ostree bridging
//! - [`bootc-mount`](../bootc_mount/index.html) - Mount utilities
//! - [`bootc-kernel-cmdline`](../bootc_kernel_cmdline/index.html) - Cmdline parsing
//! - [`etc-merge`](../etc_merge/index.html) - `/etc` three-way merge

mod bootc_composefs;
pub(crate) mod bootc_kargs;
mod bootloader;
mod boundimage;
mod cfsctl;
pub mod cli;
mod composefs_consts;
mod containerenv;
pub(crate) mod deploy;
mod discoverable_partition_specification;
pub(crate) mod fsck;
pub(crate) mod generator;
mod glyph;
mod image;
mod install;
pub(crate) mod journal;
mod k8sapitypes;
mod kernel;
mod lints;
mod lsm;
pub(crate) mod metadata;
mod parsers;
mod podman;
mod podstorage;
mod progress_jsonl;
mod reboot;
pub mod spec;
mod status;
mod store;
mod task;
mod ukify;
mod utils;

#[cfg(feature = "docgen")]
mod cli_json;

#[cfg(feature = "rhsm")]
mod rhsm;

// Re-export blockdev crate for internal use
pub(crate) use bootc_blockdev as blockdev;
