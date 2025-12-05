//! # bootc imagectl
//!
//! Tools for building and manipulating bootc container images.
//!
//! This crate provides functionality for:
//! - Building container root filesystems using rpm-ostree
//! - Rechunking images into split, reproducible layers
//! - Managing and listing build manifests
//!
//! Originally ported from the Python `bootc-base-imagectl` script.

mod build_rootfs;
mod cli;
mod constants;
mod list;
mod lockfile;
mod manifest;
mod rechunk;

use anyhow::Result;

// Re-export the CLI interface
pub use cli::ImageCtlCmd;

/// Execute an imagectl command
pub fn run(cmd: &ImageCtlCmd) -> Result<()> {
    match cmd {
        ImageCtlCmd::List => list::list_manifests(),
        ImageCtlCmd::BuildRootfs(opts) => build_rootfs::build_rootfs(opts),
        ImageCtlCmd::Rechunk(opts) => rechunk::rechunk(opts),
    }
}
