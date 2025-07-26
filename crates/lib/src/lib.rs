//! # Bootable container tool
//!
//! This crate builds on top of ostree's container functionality
//! to provide a fully "container native" tool for using
//! bootable container images.

mod boundimage;
mod cfsctl;
pub mod cli;
pub(crate) mod deploy;
pub(crate) mod fsck;
pub(crate) mod generator;
mod glyph;
mod image;
mod imgstorage;
pub(crate) mod journal;
mod k8sapitypes;
pub(crate) mod kargs;
mod lints;
mod lsm;
pub(crate) mod metadata;
mod podman;
mod progress_jsonl;
mod reboot;
pub mod spec;
mod status;
mod store;
mod task;
mod utils;

#[cfg(feature = "docgen")]
mod docgen;

mod bootloader;
mod containerenv;
mod install;
mod kernel;

#[cfg(feature = "rhsm")]
mod rhsm;
#[cfg(feature = "grub")]
pub(crate) mod parsers;

// Re-export blockdev crate for internal use
pub(crate) use bootc_blockdev as blockdev;
