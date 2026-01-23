//! # Extension APIs for ostree
//!
//! This crate builds on top of the core ostree C library
//! and the Rust bindings to it, adding new functionality
//! written in Rust.
//!
//! ## Key Modules
//!
//! - [`container`]: Bidirectional mapping between OCI container images and ostree commits.
//!   This is the core of bootc's ability to deploy container images as bootable systems.
//! - [`tar`]: Lossless export and import of ostree commits as tar archives.
//! - [`sysroot`]: Extensions for managing ostree deployments.
//! - [`chunking`]: Splitting ostree commits into layers for efficient container updates.

// See https://doc.rust-lang.org/rustc/lints/listing/allowed-by-default.html
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![forbid(unused_must_use)]
#![deny(unsafe_code)]
#![cfg_attr(feature = "dox", feature(doc_cfg))]
#![deny(clippy::dbg_macro)]
#![deny(clippy::todo)]

// Re-export our dependencies.  See https://gtk-rs.org/blog/2021/06/22/new-release.html
// "Dependencies are re-exported".  Users will need e.g. `gio::File`, so this avoids
// them needing to update matching versions.
pub use composefs;
pub use composefs_boot;
pub use composefs_oci;
pub use containers_image_proxy;
pub use containers_image_proxy::oci_spec;
pub use ostree;
pub use ostree::gio;
pub use ostree::gio::glib;

/// Our generic catchall fatal error, expected to be converted
/// to a string to output to a terminal or logs.
type Result<T> = anyhow::Result<T>;

// Import global functions.
pub mod globals;

mod isolation;

pub mod bootabletree;
pub mod cli;
pub mod container;
pub mod container_utils;
pub mod diff;
pub(crate) mod generic_decompress;
pub mod ima;
pub mod keyfileext;
pub(crate) mod logging;
pub mod ostree_prepareroot;
pub mod refescape;
#[doc(hidden)]
pub mod repair;
pub mod repo_options;
pub mod sysroot;
pub mod tar;
pub mod tokio_util;

pub mod selinux;

pub mod chunking;
pub mod commit;
pub mod objectsource;
pub(crate) mod objgv;
#[cfg(feature = "internal-testing-api")]
pub mod ostree_manual;
#[cfg(not(feature = "internal-testing-api"))]
pub(crate) mod ostree_manual;

pub(crate) mod statistics;

mod utils;

#[cfg(feature = "docgen")]
mod docgen;
pub mod fsverity;

/// Prelude, intended for glob import.
pub mod prelude {
    #[doc(hidden)]
    pub use ostree::prelude::*;
}

#[cfg(feature = "internal-testing-api")]
pub mod fixture;
#[cfg(feature = "internal-testing-api")]
pub mod integrationtest;

/// Check if the system has the soft reboot target, which signals
/// systemd support for soft reboots.
pub fn systemd_has_soft_reboot() -> bool {
    const UNIT: &str = "/usr/lib/systemd/system/soft-reboot.target";
    use std::sync::OnceLock;
    static EXISTS: OnceLock<bool> = OnceLock::new();
    *EXISTS.get_or_init(|| std::path::Path::new(UNIT).exists())
}
