//! # Bootable container tool
//!
//! This crate builds on top of ostree's container functionality
//! to provide a fully "container native" tool for using
//! bootable container images.

pub(crate) mod bootc_kargs;
mod bootloader;
mod boundimage;
mod cfsctl;
pub mod cli;
mod composefs_consts;
mod containerenv;
pub(crate) mod deploy;
pub(crate) mod fsck;
pub(crate) mod generator;
mod glyph;
mod image;
mod install;
pub(crate) mod journal;
mod k8sapitypes;
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
mod utils;

#[cfg(feature = "docgen")]
mod docgen;

#[cfg(feature = "rhsm")]
mod rhsm;

// Re-export blockdev crate for internal use
pub(crate) use bootc_blockdev as blockdev;
