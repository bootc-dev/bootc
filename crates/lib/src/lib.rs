//! # Bootable container tool
//!
//! This crate builds on top of ostree's container functionality
//! to provide a fully "container native" tool for using
//! bootable container images.

mod bls_config;
pub(crate) mod bootc_kargs;
mod boundimage;
mod cfsctl;
pub mod cli;
mod composefs_consts;
pub(crate) mod deploy;
pub(crate) mod fsck;
pub(crate) mod generator;
mod glyph;
mod image;
pub(crate) mod journal;
mod k8sapitypes;
mod lints;
mod lsm;
pub(crate) mod metadata;
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

mod bootloader;
mod containerenv;
mod install;

#[cfg(feature = "composefs-backend")]
#[allow(dead_code)]
pub(crate) mod parsers;
#[cfg(feature = "rhsm")]
mod rhsm;

// Re-export blockdev crate for internal use
pub(crate) use bootc_blockdev as blockdev;
