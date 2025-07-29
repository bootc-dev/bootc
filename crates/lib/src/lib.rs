//! # Bootable container tool
//!
//! This crate builds on top of ostree's container functionality
//! to provide a fully "container native" tool for using
//! bootable container images.

mod boundimage;
pub mod cli;
mod composefs_consts;
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
pub(crate) mod parsers;
mod podman;
mod progress_jsonl;
mod reboot;
mod reexec;
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
