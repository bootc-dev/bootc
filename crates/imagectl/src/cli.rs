//! CLI argument definitions for imagectl commands

use camino::Utf8PathBuf;
use clap::Parser;

/// Image build and manipulation commands
#[derive(Debug, clap::Subcommand, PartialEq, Eq)]
pub enum ImageCtlCmd {
    /// Generate a container root filesystem from a manifest
    ///
    /// Uses rpm-ostree to compose a root filesystem from package manifests,
    /// with support for additional packages, overlays, and customizations.
    #[clap(name = "build-rootfs")]
    BuildRootfs(BuildRootfsOpts),

    /// Generate a new container image with split, reproducible, chunked layers
    ///
    /// Uses rpm-ostree to rechunk an existing container image into
    /// content-addressed layers for better deduplication and caching.
    Rechunk(RechunkOpts),

    /// List available build manifests
    ///
    /// Shows all available manifests that can be used with build-rootfs.
    List,
}

/// Options for building a container root filesystem
#[derive(Debug, Parser, PartialEq, Eq)]
pub struct BuildRootfsOpts {
    /// Also reinject the build configurations into the target
    #[clap(long)]
    pub reinject: bool,

    /// Use the specified manifest
    #[clap(long, default_value = "default")]
    pub manifest: String,

    /// Add a package to install
    #[clap(long, action = clap::ArgAction::Append)]
    pub install: Vec<String>,

    /// Cache repo metadata and RPMs in specified directory
    #[clap(long, default_value = "")]
    pub cachedir: String,

    /// Copy directory contents into the target as an ostree overlay
    #[clap(long, action = clap::ArgAction::Append)]
    pub add_dir: Vec<Utf8PathBuf>,

    /// Don't install documentation
    #[clap(long)]
    pub no_docs: bool,

    /// Run systemd-sysusers instead of injecting hardcoded passwd/group entries
    #[clap(long)]
    pub sysusers: bool,

    /// Hidden flag for nobody-99 compatibility
    #[clap(long, hide = true)]
    pub nobody_99: bool,

    /// Enable specific repositories only
    #[clap(long, action = clap::ArgAction::Append)]
    pub repo: Vec<String>,

    /// Lock package to specific version (NEVRA or NEVR format)
    #[clap(long, action = clap::ArgAction::Append)]
    pub lock: Vec<String>,

    /// Path to the target root directory that will be generated
    pub target: Utf8PathBuf,

    /// Path to the source root directory used for dnf configuration (default: /)
    pub source_root: Option<Utf8PathBuf>,
}

/// Options for rechunking a container image
#[derive(Debug, Parser, PartialEq, Eq)]
pub struct RechunkOpts {
    /// Configure the number of output layers
    #[clap(long)]
    pub max_layers: Option<u32>,

    /// Source image in container storage
    pub from_image: String,

    /// Destination image in container storage
    pub to_image: String,
}
