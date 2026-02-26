//! # Writing a container to a block device in a bootable way
//!
//! This module implements the core installation logic for bootc, enabling a container
//! image to be written to storage in a bootable form. It bridges the gap between
//! OCI container images and traditional bootable Linux systems.
//!
//! ## Overview
//!
//! The installation process transforms a container image into a bootable system by:
//!
//! 1. **Preparing the environment**: Validating we're running in a privileged container,
//!    handling SELinux re-execution if needed, and loading configuration.
//!
//! 2. **Setting up storage**: Either creating partitions (`to-disk`) or using
//!    externally-prepared filesystems (`to-filesystem`).
//!
//! 3. **Deploying the image**: Pulling the container image into an ostree repository
//!    and creating a deployment, or setting up a composefs-based root.
//!
//! 4. **Installing the bootloader**: Using bootupd, systemd-boot, or zipl depending
//!    on architecture and configuration.
//!
//! 5. **Finalizing**: Trimming the filesystem, flushing writes, and freezing/thawing
//!    the journal.
//!
//! ## Installation Modes
//!
//! ### `bootc install to-disk`
//!
//! Creates a complete bootable system on a block device. This is the simplest path
//! and handles partitioning automatically using the Discoverable Partitions
//! Specification (DPS). The partition layout includes:
//!
//! - **ESP** (EFI System Partition): Required for UEFI boot
//! - **BIOS boot partition**: For legacy boot on x86_64
//! - **Boot partition**: Optional, used when LUKS encryption is enabled
//! - **Root partition**: Uses architecture-specific DPS type GUIDs for auto-discovery
//!
//! ### `bootc install to-filesystem`
//!
//! Installs to a pre-mounted filesystem, allowing external tools to handle complex
//! storage layouts (RAID, LVM, custom LUKS configurations). The caller is responsible
//! for creating and mounting the filesystem, then providing appropriate `--karg`
//! options or mount specifications.
//!
//! ### `bootc install to-existing-root`
//!
//! "Alongside" installation mode that converts an existing Linux system. The boot
//! partition is wiped and replaced, but the root filesystem content is preserved
//! until reboot. Post-reboot, the old system is accessible at `/sysroot` for
//! data migration.
//!
//! ### `bootc install reset`
//!
//! Creates a new stateroot within an existing bootc system, effectively providing
//! a factory-reset capability without touching other stateroots.
//!
//! ## Storage Backends
//!
//! ### OSTree Backend (Default)
//!
//! Uses ostree-ext to convert container layers into an ostree repository. The
//! deployment is created via `ostree admin deploy`, and bootloader entries are
//! managed via BLS (Boot Loader Specification) files.
//!
//! ### Composefs Backend (Experimental)
//!
//! Alternative backend using composefs overlayfs for the root filesystem. Provides
//! stronger integrity guarantees via fs-verity and supports UKI (Unified Kernel
//! Images) for measured boot scenarios.
//!
//! ## Discoverable Partitions Specification (DPS)
//!
//! As of bootc 1.11, partitions are created with DPS type GUIDs from the
//! [UAPI Group specification](https://uapi-group.org/specifications/specs/discoverable_partitions_specification/).
//! This enables:
//!
//! - **Auto-discovery**: systemd-gpt-auto-generator can mount partitions without
//!   explicit configuration
//! - **Architecture awareness**: Root partition types are architecture-specific,
//!   preventing cross-architecture boot issues
//! - **Future extensibility**: Enables systemd-repart for declarative partition
//!   management
//!
//! See [`crate::discoverable_partition_specification`] for the partition type GUIDs.
//!
//! ## Installation Flow
//!
//! The high-level flow is:
//!
//! 1. **CLI entry** → [`install_to_disk`], [`install_to_filesystem`], or [`install_to_existing_root`]
//! 2. **Preparation** → [`prepare_install`] validates environment, handles SELinux, loads config
//! 3. **Storage setup** → (to-disk only) [`baseline::install_create_rootfs`] partitions and formats
//! 4. **Deployment** → [`install_to_filesystem_impl`] branches to OSTree or Composefs backend
//! 5. **Bootloader** → [`crate::bootloader::install_via_bootupd`] or architecture-specific installer
//! 6. **Finalization** → [`finalize_filesystem`] trims, flushes, and freezes the filesystem
//!
//! For a visual diagram of this flow, see the bootc documentation.
//!
//! ## Key Types
//!
//! - [`State`]: Immutable global state for the installation, including source image
//!   info, SELinux state, configuration, and composefs options.
//!
//! - [`RootSetup`]: Represents the prepared root filesystem, including mount paths,
//!   device information, boot partition specs, and kernel arguments.
//!
//! - [`SourceInfo`]: Information about the source container image, including the
//!   ostree-container reference and whether SELinux labels are present.
//!
//! - [`SELinuxFinalState`]: Tracks SELinux handling during installation (enabled,
//!   disabled, host-disabled, or force-disabled).
//!
//! ## Configuration
//!
//! Installation is configured via TOML files loaded from multiple paths in
//! systemd-style priority order:
//!
//! - `/usr/lib/bootc/install/*.toml` - Distribution/image defaults
//! - `/etc/bootc/install/*.toml` - Local overrides
//!
//! Files are merged alphanumerically, with higher-numbered files taking precedence.
//! See [`config::InstallConfiguration`] for the schema.
//!
//! Key configurable options include:
//! - Root filesystem type (xfs, ext4, btrfs)
//! - Allowed block setups (direct, tpm2-luks)
//! - Default kernel arguments
//! - Architecture-specific overrides
//!
//! ## Submodules
//!
//! - [`baseline`]: The "baseline" installer for simple partitioning (to-disk)
//! - [`config`]: TOML configuration parsing and merging
//! - [`completion`]: Post-installation hooks for external installers (Anaconda)
//! - [`osconfig`]: SSH key injection and OS configuration
//! - [`aleph`]: Installation provenance tracking (.bootc-aleph.json)
//! - `osbuild`: Helper APIs for bootc-image-builder integration

// This sub-module is the "basic" installer that handles creating basic block device
// and filesystem setup.
mod aleph;
#[cfg(feature = "install-to-disk")]
pub(crate) mod baseline;
pub(crate) mod completion;
pub(crate) mod config;
mod osbuild;
pub(crate) mod osconfig;

use std::collections::HashMap;
use std::io::Write;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process;
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use aleph::InstallAleph;
use anyhow::{Context, Result, anyhow, ensure};
use bootc_kernel_cmdline::utf8::{Cmdline, CmdlineOwned};
use bootc_utils::CommandRunExt;
use camino::Utf8Path;
use camino::Utf8PathBuf;
use canon_json::CanonJsonSerialize;
use cap_std::fs::{Dir, MetadataExt};
use cap_std_ext::cap_std;
use cap_std_ext::cap_std::fs::FileType;
use cap_std_ext::cap_std::fs_utf8::DirEntry as DirEntryUtf8;
use cap_std_ext::cap_tempfile::TempDir;
use cap_std_ext::cmdext::CapStdExtCommandExt;
use cap_std_ext::prelude::CapStdExtDirExt;
use clap::ValueEnum;
use fn_error_context::context;
use ostree::gio;
use ostree_ext::ostree;
use ostree_ext::ostree_prepareroot::{ComposefsState, Tristate};
use ostree_ext::prelude::Cast;
use ostree_ext::sysroot::{SysrootLock, allocate_new_stateroot, list_stateroots};
use ostree_ext::{container as ostree_container, ostree_prepareroot};
#[cfg(feature = "install-to-disk")]
use rustix::fs::FileTypeExt;
use rustix::fs::MetadataExt as _;
use serde::{Deserialize, Serialize};

#[cfg(feature = "install-to-disk")]
use self::baseline::InstallBlockDeviceOpts;
use crate::bootc_composefs::{boot::setup_composefs_boot, repo::initialize_composefs_repository};
use crate::boundimage::{BoundImage, ResolvedBoundImage};
use crate::containerenv::ContainerExecutionInfo;
use crate::deploy::{
    MergeState, PreparedImportMeta, PreparedPullResult, prepare_for_pull, pull_from_prepared,
};
use crate::install::config::Filesystem as FilesystemEnum;
use crate::lsm;
use crate::progress_jsonl::ProgressWriter;
use crate::spec::{Bootloader, ImageReference};
use crate::store::Storage;
use crate::task::Task;
use crate::utils::sigpolicy_from_opt;
use bootc_kernel_cmdline::{INITRD_ARG_PREFIX, ROOTFLAGS, bytes, utf8};
use bootc_mount::Filesystem;
use composefs::fsverity::FsVerityHashValue;

/// The toplevel boot directory
pub(crate) const BOOT: &str = "boot";
/// Directory for transient runtime state
#[cfg(feature = "install-to-disk")]
const RUN_BOOTC: &str = "/run/bootc";
/// The default path for the host rootfs
const ALONGSIDE_ROOT_MOUNT: &str = "/target";
/// Global flag to signal the booted system was provisioned via an alongside bootc install
pub(crate) const DESTRUCTIVE_CLEANUP: &str = "etc/bootc-destructive-cleanup";
/// This is an ext4 special directory we need to ignore.
const LOST_AND_FOUND: &str = "lost+found";
/// The filename of the composefs EROFS superblock; TODO move this into ostree
const OSTREE_COMPOSEFS_SUPER: &str = ".ostree.cfs";
/// The mount path for selinux
const SELINUXFS: &str = "/sys/fs/selinux";
/// The mount path for uefi
pub(crate) const EFIVARFS: &str = "/sys/firmware/efi/efivars";
pub(crate) const ARCH_USES_EFI: bool = cfg!(any(target_arch = "x86_64", target_arch = "aarch64"));

pub(crate) const EFI_LOADER_INFO: &str = "LoaderInfo-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";

const DEFAULT_REPO_CONFIG: &[(&str, &str)] = &[
    // Default to avoiding grub2-mkconfig etc.
    ("sysroot.bootloader", "none"),
    // Always flip this one on because we need to support alongside installs
    // to systems without a separate boot partition.
    ("sysroot.bootprefix", "true"),
    ("sysroot.readonly", "true"),
];

/// Kernel argument used to specify we want the rootfs mounted read-write by default
pub(crate) const RW_KARG: &str = "rw";

#[derive(clap::Args, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct InstallTargetOpts {
    // TODO: A size specifier which allocates free space for the root in *addition* to the base container image size
    // pub(crate) root_additional_size: Option<String>
    /// The transport; e.g. oci, oci-archive, containers-storage.  Defaults to `registry`.
    #[clap(long, default_value = "registry")]
    #[serde(default)]
    pub(crate) target_transport: String,

    /// Specify the image to fetch for subsequent updates
    #[clap(long)]
    pub(crate) target_imgref: Option<String>,

    /// This command line argument does nothing; it exists for compatibility.
    ///
    /// As of newer versions of bootc, this value is enabled by default,
    /// i.e. it is not enforced that a signature
    /// verification policy is enabled.  Hence to enable it, one can specify
    /// `--target-no-signature-verification=false`.
    ///
    /// It is likely that the functionality here will be replaced with a different signature
    /// enforcement scheme in the future that integrates with `podman`.
    #[clap(long, hide = true)]
    #[serde(default)]
    pub(crate) target_no_signature_verification: bool,

    /// This is the inverse of the previous `--target-no-signature-verification` (which is now
    /// a no-op).  Enabling this option enforces that `/etc/containers/policy.json` includes a
    /// default policy which requires signatures.
    #[clap(long)]
    #[serde(default)]
    pub(crate) enforce_container_sigpolicy: bool,

    /// Verify the image can be fetched from the bootc image. Updates may fail when the installation
    /// host is authenticated with the registry but the pull secret is not in the bootc image.
    #[clap(long)]
    #[serde(default)]
    pub(crate) run_fetch_check: bool,

    /// Verify the image can be fetched from the bootc image. Updates may fail when the installation
    /// host is authenticated with the registry but the pull secret is not in the bootc image.
    #[clap(long)]
    #[serde(default)]
    pub(crate) skip_fetch_check: bool,

    /// Use unified storage path to pull images (experimental)
    ///
    /// When enabled, this uses bootc's container storage (/usr/lib/bootc/storage) to pull
    /// the image first, then imports it from there. This is the same approach used for
    /// logically bound images.
    #[clap(long = "experimental-unified-storage", hide = true)]
    #[serde(default)]
    pub(crate) unified_storage_exp: bool,
}

#[derive(clap::Args, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct InstallSourceOpts {
    /// Install the system from an explicitly given source.
    ///
    /// By default, bootc install and install-to-filesystem assumes that it runs in a podman container, and
    /// it takes the container image to install from the podman's container registry.
    /// If --source-imgref is given, bootc uses it as the installation source, instead of the behaviour explained
    /// in the previous paragraph. See skopeo(1) for accepted formats.
    #[clap(long)]
    pub(crate) source_imgref: Option<String>,
}

#[derive(ValueEnum, Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum BoundImagesOpt {
    /// Bound images must exist in the source's root container storage (default)
    #[default]
    Stored,
    #[clap(hide = true)]
    /// Do not resolve any "logically bound" images at install time.
    Skip,
    // TODO: Once we implement https://github.com/bootc-dev/bootc/issues/863 update this comment
    // to mention source's root container storage being used as lookaside cache
    /// Bound images will be pulled and stored directly in the target's bootc container storage
    Pull,
}

impl std::fmt::Display for BoundImagesOpt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_possible_value().unwrap().get_name().fmt(f)
    }
}

#[derive(clap::Args, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct InstallConfigOpts {
    /// Disable SELinux in the target (installed) system.
    ///
    /// This is currently necessary to install *from* a system with SELinux disabled
    /// but where the target does have SELinux enabled.
    #[clap(long)]
    #[serde(default)]
    pub(crate) disable_selinux: bool,

    /// Add a kernel argument.  This option can be provided multiple times.
    ///
    /// Example: --karg=nosmt --karg=console=ttyS0,115200n8
    #[clap(long)]
    pub(crate) karg: Option<Vec<CmdlineOwned>>,

    /// The path to an `authorized_keys` that will be injected into the `root` account.
    ///
    /// The implementation of this uses systemd `tmpfiles.d`, writing to a file named
    /// `/etc/tmpfiles.d/bootc-root-ssh.conf`.  This will have the effect that by default,
    /// the SSH credentials will be set if not present.  The intention behind this
    /// is to allow mounting the whole `/root` home directory as a `tmpfs`, while still
    /// getting the SSH key replaced on boot.
    #[clap(long)]
    root_ssh_authorized_keys: Option<Utf8PathBuf>,

    /// Perform configuration changes suitable for a "generic" disk image.
    /// At the moment:
    ///
    /// - All bootloader types will be installed
    /// - Changes to the system firmware will be skipped
    #[clap(long)]
    #[serde(default)]
    pub(crate) generic_image: bool,

    /// How should logically bound images be retrieved.
    #[clap(long)]
    #[serde(default)]
    #[arg(default_value_t)]
    pub(crate) bound_images: BoundImagesOpt,

    /// The stateroot name to use. Defaults to `default`.
    #[clap(long)]
    pub(crate) stateroot: Option<String>,

    /// Don't pass --write-uuid to bootupd during bootloader installation.
    #[clap(long)]
    #[serde(default)]
    pub(crate) bootupd_skip_boot_uuid: bool,

    /// The bootloader to use.
    #[clap(long)]
    #[serde(default)]
    pub(crate) bootloader: Option<Bootloader>,
}

#[derive(Debug, Default, Clone, clap::Parser, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct InstallComposefsOpts {
    /// If true, composefs backend is used, else ostree backend is used
    #[clap(long, default_value_t)]
    #[serde(default)]
    pub(crate) composefs_backend: bool,

    /// Make fs-verity validation optional in case the filesystem doesn't support it
    #[clap(long, default_value_t, requires = "composefs_backend")]
    #[serde(default)]
    pub(crate) allow_missing_verity: bool,

    /// Name of the UKI addons to install without the ".efi.addon" suffix.
    /// This option can be provided multiple times if multiple addons are to be installed.
    #[clap(long, requires = "composefs_backend")]
    #[serde(default)]
    pub(crate) uki_addon: Option<Vec<String>>,
}

#[cfg(feature = "install-to-disk")]
#[derive(Debug, Clone, clap::Parser, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct InstallToDiskOpts {
    #[clap(flatten)]
    #[serde(flatten)]
    pub(crate) block_opts: InstallBlockDeviceOpts,

    #[clap(flatten)]
    #[serde(flatten)]
    pub(crate) source_opts: InstallSourceOpts,

    #[clap(flatten)]
    #[serde(flatten)]
    pub(crate) target_opts: InstallTargetOpts,

    #[clap(flatten)]
    #[serde(flatten)]
    pub(crate) config_opts: InstallConfigOpts,

    /// Instead of targeting a block device, write to a file via loopback.
    #[clap(long)]
    #[serde(default)]
    pub(crate) via_loopback: bool,

    #[clap(flatten)]
    #[serde(flatten)]
    pub(crate) composefs_opts: InstallComposefsOpts,
}

#[derive(ValueEnum, Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ReplaceMode {
    /// Completely wipe the contents of the target filesystem.  This cannot
    /// be done if the target filesystem is the one the system is booted from.
    Wipe,
    /// This is a destructive operation in the sense that the bootloader state
    /// will have its contents wiped and replaced.  However,
    /// the running system (and all files) will remain in place until reboot.
    ///
    /// As a corollary to this, you will also need to remove all the old operating
    /// system binaries after the reboot into the target system; this can be done
    /// with code in the new target system, or manually.
    Alongside,
}

impl std::fmt::Display for ReplaceMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_possible_value().unwrap().get_name().fmt(f)
    }
}

/// Options for installing to a filesystem
#[derive(Debug, Clone, clap::Args, PartialEq, Eq)]
pub(crate) struct InstallTargetFilesystemOpts {
    /// Path to the mounted root filesystem.
    ///
    /// By default, the filesystem UUID will be discovered and used for mounting.
    /// To override this, use `--root-mount-spec`.
    pub(crate) root_path: Utf8PathBuf,

    /// Source device specification for the root filesystem.  For example, `UUID=2e9f4241-229b-4202-8429-62d2302382e1`.
    /// If not provided, the UUID of the target filesystem will be used. This option is provided
    /// as some use cases might prefer to mount by a label instead via e.g. `LABEL=rootfs`.
    #[clap(long)]
    pub(crate) root_mount_spec: Option<String>,

    /// Mount specification for the /boot filesystem.
    ///
    /// This is optional. If `/boot` is detected as a mounted partition, then
    /// its UUID will be used.
    #[clap(long)]
    pub(crate) boot_mount_spec: Option<String>,

    /// Initialize the system in-place; at the moment, only one mode for this is implemented.
    /// In the future, it may also be supported to set up an explicit "dual boot" system.
    #[clap(long)]
    pub(crate) replace: Option<ReplaceMode>,

    /// If the target is the running system's root filesystem, this will skip any warnings.
    #[clap(long)]
    pub(crate) acknowledge_destructive: bool,

    /// The default mode is to "finalize" the target filesystem by invoking `fstrim` and similar
    /// operations, and finally mounting it readonly.  This option skips those operations.  It
    /// is then the responsibility of the invoking code to perform those operations.
    #[clap(long)]
    pub(crate) skip_finalize: bool,
}

#[derive(Debug, Clone, clap::Parser, PartialEq, Eq)]
pub(crate) struct InstallToFilesystemOpts {
    #[clap(flatten)]
    pub(crate) filesystem_opts: InstallTargetFilesystemOpts,

    #[clap(flatten)]
    pub(crate) source_opts: InstallSourceOpts,

    #[clap(flatten)]
    pub(crate) target_opts: InstallTargetOpts,

    #[clap(flatten)]
    pub(crate) config_opts: InstallConfigOpts,

    #[clap(flatten)]
    pub(crate) composefs_opts: InstallComposefsOpts,
}

#[derive(Debug, Clone, clap::Parser, PartialEq, Eq)]
pub(crate) struct InstallToExistingRootOpts {
    /// Configure how existing data is treated.
    #[clap(long, default_value = "alongside")]
    pub(crate) replace: Option<ReplaceMode>,

    #[clap(flatten)]
    pub(crate) source_opts: InstallSourceOpts,

    #[clap(flatten)]
    pub(crate) target_opts: InstallTargetOpts,

    #[clap(flatten)]
    pub(crate) config_opts: InstallConfigOpts,

    /// Accept that this is a destructive action and skip a warning timer.
    #[clap(long)]
    pub(crate) acknowledge_destructive: bool,

    /// Add the bootc-destructive-cleanup systemd service to delete files from
    /// the previous install on first boot
    #[clap(long)]
    pub(crate) cleanup: bool,

    /// Path to the mounted root; this is now not necessary to provide.
    /// Historically it was necessary to ensure the host rootfs was mounted at here
    /// via e.g. `-v /:/target`.
    #[clap(default_value = ALONGSIDE_ROOT_MOUNT)]
    pub(crate) root_path: Utf8PathBuf,

    #[clap(flatten)]
    pub(crate) composefs_opts: InstallComposefsOpts,
}

#[derive(Debug, clap::Parser, PartialEq, Eq)]
pub(crate) struct InstallResetOpts {
    /// Acknowledge that this command is experimental.
    #[clap(long)]
    pub(crate) experimental: bool,

    #[clap(flatten)]
    pub(crate) source_opts: InstallSourceOpts,

    #[clap(flatten)]
    pub(crate) target_opts: InstallTargetOpts,

    /// Name of the target stateroot. If not provided, one will be automatically
    /// generated of the form `s<year>-<serial>` where `<serial>` starts at zero and
    /// increments automatically.
    #[clap(long)]
    pub(crate) stateroot: Option<String>,

    /// Don't display progress
    #[clap(long)]
    pub(crate) quiet: bool,

    #[clap(flatten)]
    pub(crate) progress: crate::cli::ProgressOptions,

    /// Restart or reboot into the new target image.
    ///
    /// Currently, this option always reboots.  In the future this command
    /// will detect the case where no kernel changes are queued, and perform
    /// a userspace-only restart.
    #[clap(long)]
    pub(crate) apply: bool,

    /// Skip inheriting any automatically discovered root file system kernel arguments.
    #[clap(long)]
    no_root_kargs: bool,

    /// Add a kernel argument.  This option can be provided multiple times.
    ///
    /// Example: --karg=nosmt --karg=console=ttyS0,115200n8
    #[clap(long)]
    karg: Option<Vec<CmdlineOwned>>,
}

#[derive(Debug, clap::Parser, PartialEq, Eq)]
pub(crate) struct InstallPrintConfigurationOpts {
    /// Print all configuration.
    ///
    /// Print configuration that is usually handled internally, like kargs.
    #[clap(long)]
    pub(crate) all: bool,
}

/// Global state captured from the container.
#[derive(Debug, Clone)]
pub(crate) struct SourceInfo {
    /// Image reference we'll pull from (today always containers-storage: type)
    pub(crate) imageref: ostree_container::ImageReference,
    /// The digest to use for pulls
    pub(crate) digest: Option<String>,
    /// Whether or not SELinux appears to be enabled in the source commit
    pub(crate) selinux: bool,
    /// Whether the source is available in the host mount namespace
    pub(crate) in_host_mountns: bool,
}

// Shared read-only global state
#[derive(Debug)]
pub(crate) struct State {
    pub(crate) source: SourceInfo,
    /// Force SELinux off in target system
    pub(crate) selinux_state: SELinuxFinalState,
    #[allow(dead_code)]
    pub(crate) config_opts: InstallConfigOpts,
    pub(crate) target_opts: InstallTargetOpts,
    pub(crate) target_imgref: ostree_container::OstreeImageReference,
    #[allow(dead_code)]
    pub(crate) prepareroot_config: HashMap<String, String>,
    pub(crate) install_config: Option<config::InstallConfiguration>,
    /// The parsed contents of the authorized_keys (not the file path)
    pub(crate) root_ssh_authorized_keys: Option<String>,
    #[allow(dead_code)]
    pub(crate) host_is_container: bool,
    /// The root filesystem of the running container
    pub(crate) container_root: Dir,
    pub(crate) tempdir: TempDir,

    /// Set if we have determined that composefs is required
    #[allow(dead_code)]
    pub(crate) composefs_required: bool,

    // If Some, then --composefs_native is passed
    pub(crate) composefs_options: InstallComposefsOpts,
}

// Shared read-only global state
#[derive(Debug)]
pub(crate) struct PostFetchState {
    /// Detected bootloader type for the target system
    pub(crate) detected_bootloader: crate::spec::Bootloader,
}

impl InstallTargetOpts {
    pub(crate) fn imageref(&self) -> Result<Option<ostree_container::OstreeImageReference>> {
        let Some(target_imgname) = self.target_imgref.as_deref() else {
            return Ok(None);
        };
        let target_transport =
            ostree_container::Transport::try_from(self.target_transport.as_str())?;
        let target_imgref = ostree_container::OstreeImageReference {
            sigverify: ostree_container::SignatureSource::ContainerPolicyAllowInsecure,
            imgref: ostree_container::ImageReference {
                transport: target_transport,
                name: target_imgname.to_string(),
            },
        };
        Ok(Some(target_imgref))
    }
}

impl State {
    #[context("Loading SELinux policy")]
    pub(crate) fn load_policy(&self) -> Result<Option<ostree::SePolicy>> {
        if !self.selinux_state.enabled() {
            return Ok(None);
        }
        // We always use the physical container root to bootstrap policy
        let r = lsm::new_sepolicy_at(&self.container_root)?
            .ok_or_else(|| anyhow::anyhow!("SELinux enabled, but no policy found in root"))?;
        // SAFETY: Policy must have a checksum here
        tracing::debug!("Loaded SELinux policy: {}", r.csum().unwrap());
        Ok(Some(r))
    }

    #[context("Finalizing state")]
    #[allow(dead_code)]
    pub(crate) fn consume(self) -> Result<()> {
        self.tempdir.close()?;
        // If we had invoked `setenforce 0`, then let's re-enable it.
        if let SELinuxFinalState::Enabled(Some(guard)) = self.selinux_state {
            guard.consume()?;
        }
        Ok(())
    }

    /// Return an error if kernel arguments are provided, intended to be used for UKI paths
    pub(crate) fn require_no_kargs_for_uki(&self) -> Result<()> {
        if self
            .config_opts
            .karg
            .as_ref()
            .map(|v| !v.is_empty())
            .unwrap_or_default()
        {
            anyhow::bail!("Cannot use externally specified kernel arguments with UKI");
        }
        Ok(())
    }

    fn stateroot(&self) -> &str {
        // CLI takes precedence over config file
        self.config_opts
            .stateroot
            .as_deref()
            .or_else(|| {
                self.install_config
                    .as_ref()
                    .and_then(|c| c.stateroot.as_deref())
            })
            .unwrap_or(ostree_ext::container::deploy::STATEROOT_DEFAULT)
    }
}

/// A mount specification is a subset of a line in `/etc/fstab`.
///
/// There are 3 (ASCII) whitespace separated values:
///
/// `SOURCE TARGET [OPTIONS]`
///
/// Examples:
///   - /dev/vda3 /boot ext4 ro
///   - /dev/nvme0n1p4 /
///   - /dev/sda2 /var/mnt xfs
#[derive(Debug, Clone)]
pub(crate) struct MountSpec {
    pub(crate) source: String,
    pub(crate) target: String,
    pub(crate) fstype: String,
    pub(crate) options: Option<String>,
}

impl MountSpec {
    const AUTO: &'static str = "auto";

    pub(crate) fn new(src: &str, target: &str) -> Self {
        MountSpec {
            source: src.to_string(),
            target: target.to_string(),
            fstype: Self::AUTO.to_string(),
            options: None,
        }
    }

    /// Construct a new mount that uses the provided uuid as a source.
    pub(crate) fn new_uuid_src(uuid: &str, target: &str) -> Self {
        Self::new(&format!("UUID={uuid}"), target)
    }

    pub(crate) fn get_source_uuid(&self) -> Option<&str> {
        if let Some((t, rest)) = self.source.split_once('=') {
            if t.eq_ignore_ascii_case("uuid") {
                return Some(rest);
            }
        }
        None
    }

    pub(crate) fn to_fstab(&self) -> String {
        let options = self.options.as_deref().unwrap_or("defaults");
        format!(
            "{} {} {} {} 0 0",
            self.source, self.target, self.fstype, options
        )
    }

    /// Append a mount option
    pub(crate) fn push_option(&mut self, opt: &str) {
        let options = self.options.get_or_insert_with(Default::default);
        if !options.is_empty() {
            options.push(',');
        }
        options.push_str(opt);
    }
}

impl FromStr for MountSpec {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut parts = s.split_ascii_whitespace().fuse();
        let source = parts.next().unwrap_or_default();
        if source.is_empty() {
            tracing::debug!("Empty mount specification");
            return Ok(Self {
                source: String::new(),
                target: String::new(),
                fstype: Self::AUTO.into(),
                options: None,
            });
        }
        let target = parts
            .next()
            .ok_or_else(|| anyhow!("Missing target in mount specification {s}"))?;
        let fstype = parts.next().unwrap_or(Self::AUTO);
        let options = parts.next().map(ToOwned::to_owned);
        Ok(Self {
            source: source.to_string(),
            fstype: fstype.to_string(),
            target: target.to_string(),
            options,
        })
    }
}

impl SourceInfo {
    // Inspect container information and convert it to an ostree image reference
    // that pulls from containers-storage.
    #[context("Gathering source info from container env")]
    pub(crate) fn from_container(
        root: &Dir,
        container_info: &ContainerExecutionInfo,
    ) -> Result<Self> {
        if !container_info.engine.starts_with("podman") {
            anyhow::bail!("Currently this command only supports being executed via podman");
        }
        if container_info.imageid.is_empty() {
            anyhow::bail!("Invalid empty imageid");
        }
        let imageref = ostree_container::ImageReference {
            transport: ostree_container::Transport::ContainerStorage,
            name: container_info.image.clone(),
        };
        tracing::debug!("Finding digest for image ID {}", container_info.imageid);
        let digest = crate::podman::imageid_to_digest(&container_info.imageid)?;

        Self::new(imageref, Some(digest), root, true)
    }

    #[context("Creating source info from a given imageref")]
    pub(crate) fn from_imageref(imageref: &str, root: &Dir) -> Result<Self> {
        let imageref = ostree_container::ImageReference::try_from(imageref)?;
        Self::new(imageref, None, root, false)
    }

    fn have_selinux_from_repo(root: &Dir) -> Result<bool> {
        let cancellable = ostree::gio::Cancellable::NONE;

        let commit = Command::new("ostree")
            .args(["--repo=/ostree/repo", "rev-parse", "--single"])
            .run_get_string()?;
        let repo = ostree::Repo::open_at_dir(root.as_fd(), "ostree/repo")?;
        let root = repo
            .read_commit(commit.trim(), cancellable)
            .context("Reading commit")?
            .0;
        let root = root.downcast_ref::<ostree::RepoFile>().unwrap();
        let xattrs = root.xattrs(cancellable)?;
        Ok(crate::lsm::xattrs_have_selinux(&xattrs))
    }

    /// Construct a new source information structure
    fn new(
        imageref: ostree_container::ImageReference,
        digest: Option<String>,
        root: &Dir,
        in_host_mountns: bool,
    ) -> Result<Self> {
        let selinux = if Path::new("/ostree/repo").try_exists()? {
            Self::have_selinux_from_repo(root)?
        } else {
            lsm::have_selinux_policy(root)?
        };
        Ok(Self {
            imageref,
            digest,
            selinux,
            in_host_mountns,
        })
    }
}

pub(crate) fn print_configuration(opts: InstallPrintConfigurationOpts) -> Result<()> {
    let mut install_config = config::load_config()?.unwrap_or_default();
    if !opts.all {
        install_config.filter_to_external();
    }
    let stdout = std::io::stdout().lock();
    anyhow::Ok(install_config.to_canon_json_writer(stdout)?)
}

#[context("Creating ostree deployment")]
async fn initialize_ostree_root(state: &State, root_setup: &RootSetup) -> Result<(Storage, bool)> {
    let sepolicy = state.load_policy()?;
    let sepolicy = sepolicy.as_ref();
    // Load a fd for the mounted target physical root
    let rootfs_dir = &root_setup.physical_root;
    let cancellable = gio::Cancellable::NONE;

    let stateroot = state.stateroot();

    let has_ostree = rootfs_dir.try_exists("ostree/repo")?;
    if !has_ostree {
        Task::new("Initializing ostree layout", "ostree")
            .args(["admin", "init-fs", "--modern", "."])
            .cwd(rootfs_dir)?
            .run()?;
    } else {
        println!("Reusing extant ostree layout");

        let path = ".".into();
        let _ = crate::utils::open_dir_remount_rw(rootfs_dir, path)
            .context("remounting target as read-write")?;
        crate::utils::remove_immutability(rootfs_dir, path)?;
    }

    // Ensure that the physical root is labeled.
    // Another implementation: https://github.com/coreos/coreos-assembler/blob/3cd3307904593b3a131b81567b13a4d0b6fe7c90/src/create_disk.sh#L295
    crate::lsm::ensure_dir_labeled(rootfs_dir, "", Some("/".into()), 0o755.into(), sepolicy)?;

    // If we're installing alongside existing ostree and there's a separate boot partition,
    // we need to mount it to the sysroot's /boot so ostree can write bootloader entries there
    if has_ostree && root_setup.boot.is_some() {
        if let Some(boot) = &root_setup.boot {
            let source_boot = &boot.source;
            let target_boot = root_setup.physical_root_path.join(BOOT);
            tracing::debug!("Mount {source_boot} to {target_boot} on ostree");
            bootc_mount::mount(source_boot, &target_boot)?;
        }
    }

    // And also label /boot AKA xbootldr, if it exists
    if rootfs_dir.try_exists("boot")? {
        crate::lsm::ensure_dir_labeled(rootfs_dir, "boot", None, 0o755.into(), sepolicy)?;
    }

    // Build the list of ostree repo config options: defaults + install config
    let ostree_opts = state
        .install_config
        .as_ref()
        .and_then(|c| c.ostree.as_ref())
        .into_iter()
        .flat_map(|o| o.to_config_tuples());

    let repo_config: Vec<_> = DEFAULT_REPO_CONFIG
        .iter()
        .copied()
        .chain(ostree_opts)
        .collect();

    for (k, v) in repo_config.iter() {
        Command::new("ostree")
            .args(["config", "--repo", "ostree/repo", "set", k, v])
            .cwd_dir(rootfs_dir.try_clone()?)
            .run_capture_stderr()?;
    }

    let sysroot = {
        let path = format!(
            "/proc/{}/fd/{}",
            process::id(),
            rootfs_dir.as_fd().as_raw_fd()
        );
        ostree::Sysroot::new(Some(&gio::File::for_path(path)))
    };
    sysroot.load(cancellable)?;
    let repo = &sysroot.repo();

    let repo_verity_state = ostree_ext::fsverity::is_verity_enabled(&repo)?;
    let prepare_root_composefs = state
        .prepareroot_config
        .get("composefs.enabled")
        .map(|v| ComposefsState::from_str(&v))
        .transpose()?
        .unwrap_or(ComposefsState::default());
    if prepare_root_composefs.requires_fsverity() || repo_verity_state.desired == Tristate::Enabled
    {
        ostree_ext::fsverity::ensure_verity(repo).await?;
    }

    if let Some(booted) = sysroot.booted_deployment() {
        if stateroot == booted.stateroot() {
            anyhow::bail!("Cannot redeploy over booted stateroot {stateroot}");
        }
    }

    let sysroot_dir = crate::utils::sysroot_dir(&sysroot)?;

    // init_osname fails when ostree/deploy/{stateroot} already exists
    // the stateroot directory can be left over after a failed install attempt,
    // so only create it via init_osname if it doesn't exist
    // (ideally this would be handled by init_osname)
    let stateroot_path = format!("ostree/deploy/{stateroot}");
    if !sysroot_dir.try_exists(stateroot_path)? {
        sysroot
            .init_osname(stateroot, cancellable)
            .context("initializing stateroot")?;
    }

    state.tempdir.create_dir("temp-run")?;
    let temp_run = state.tempdir.open_dir("temp-run")?;

    // Bootstrap the initial labeling of the /ostree directory as usr_t
    // and create the imgstorage with the same labels as /var/lib/containers
    if let Some(policy) = sepolicy {
        let ostree_dir = rootfs_dir.open_dir("ostree")?;
        crate::lsm::ensure_dir_labeled(
            &ostree_dir,
            ".",
            Some("/usr".into()),
            0o755.into(),
            Some(policy),
        )?;
    }

    sysroot.load(cancellable)?;
    let sysroot = SysrootLock::new_from_sysroot(&sysroot).await?;
    let storage = Storage::new_ostree(sysroot, &temp_run)?;

    Ok((storage, has_ostree))
}

fn check_disk_space(
    repo_fd: impl AsFd,
    image_meta: &PreparedImportMeta,
    imgref: &ImageReference,
) -> Result<()> {
    let stat = rustix::fs::fstatvfs(repo_fd)?;
    let bytes_avail: u64 = stat.f_bsize * stat.f_bavail;
    tracing::trace!("bytes_avail: {bytes_avail}");

    if image_meta.bytes_to_fetch > bytes_avail {
        anyhow::bail!(
            "Insufficient free space for {image} (available: {bytes_avail} required: {bytes_to_fetch})",
            bytes_avail = ostree_ext::glib::format_size(bytes_avail),
            bytes_to_fetch = ostree_ext::glib::format_size(image_meta.bytes_to_fetch),
            image = imgref.image,
        );
    }

    Ok(())
}

#[context("Creating ostree deployment")]
async fn install_container(
    state: &State,
    root_setup: &RootSetup,
    sysroot: &ostree::Sysroot,
    storage: &Storage,
    has_ostree: bool,
) -> Result<(ostree::Deployment, InstallAleph)> {
    let sepolicy = state.load_policy()?;
    let sepolicy = sepolicy.as_ref();
    let stateroot = state.stateroot();

    // TODO factor out this
    let (src_imageref, proxy_cfg) = if !state.source.in_host_mountns {
        (state.source.imageref.clone(), None)
    } else {
        let src_imageref = {
            // We always use exactly the digest of the running image to ensure predictability.
            let digest = state
                .source
                .digest
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Missing container image digest"))?;
            let spec = crate::utils::digested_pullspec(&state.source.imageref.name, digest);
            ostree_container::ImageReference {
                transport: ostree_container::Transport::ContainerStorage,
                name: spec,
            }
        };

        let proxy_cfg = crate::deploy::new_proxy_config();
        (src_imageref, Some(proxy_cfg))
    };
    let src_imageref = ostree_container::OstreeImageReference {
        // There are no signatures to verify since we're fetching the already
        // pulled container.
        sigverify: ostree_container::SignatureSource::ContainerPolicyAllowInsecure,
        imgref: src_imageref,
    };

    // Pull the container image into the target root filesystem. Since this is
    // an install path, we don't need to fsync() individual layers.
    let spec_imgref = ImageReference::from(src_imageref.clone());
    let repo = &sysroot.repo();
    repo.set_disable_fsync(true);

    // Determine whether to use unified storage path.
    // During install, we only use unified storage if explicitly requested.
    // Auto-detection (None) is only appropriate for upgrade/switch on a running system.
    let use_unified = state.target_opts.unified_storage_exp;

    let prepared = if use_unified {
        tracing::info!("Using unified storage path for installation");
        crate::deploy::prepare_for_pull_unified(
            repo,
            &spec_imgref,
            Some(&state.target_imgref),
            storage,
        )
        .await?
    } else {
        prepare_for_pull(repo, &spec_imgref, Some(&state.target_imgref)).await?
    };

    let pulled_image = match prepared {
        PreparedPullResult::AlreadyPresent(existing) => existing,
        PreparedPullResult::Ready(image_meta) => {
            check_disk_space(root_setup.physical_root.as_fd(), &image_meta, &spec_imgref)?;
            pull_from_prepared(&spec_imgref, false, ProgressWriter::default(), *image_meta).await?
        }
    };

    repo.set_disable_fsync(false);

    // We need to read the kargs from the target merged ostree commit before
    // we do the deployment.
    let merged_ostree_root = sysroot
        .repo()
        .read_commit(pulled_image.ostree_commit.as_str(), gio::Cancellable::NONE)?
        .0;
    let kargsd = crate::bootc_kargs::get_kargs_from_ostree_root(
        &sysroot.repo(),
        merged_ostree_root.downcast_ref().unwrap(),
        std::env::consts::ARCH,
    )?;

    // If the target uses aboot, then we need to set that bootloader in the ostree
    // config before deploying the commit
    if ostree_ext::bootabletree::commit_has_aboot_img(&merged_ostree_root, None)? {
        tracing::debug!("Setting bootloader to aboot");
        Command::new("ostree")
            .args([
                "config",
                "--repo",
                "ostree/repo",
                "set",
                "sysroot.bootloader",
                "aboot",
            ])
            .cwd_dir(root_setup.physical_root.try_clone()?)
            .run_capture_stderr()
            .context("Setting bootloader config to aboot")?;
        sysroot.repo().reload_config(None::<&gio::Cancellable>)?;
    }

    // Keep this in sync with install/completion.rs for the Anaconda fixups
    let install_config_kargs = state.install_config.as_ref().and_then(|c| c.kargs.as_ref());

    // Final kargs, in order:
    // - root filesystem kargs
    // - install config kargs
    // - kargs.d from container image
    // - args specified on the CLI
    let mut kargs = Cmdline::new();

    kargs.extend(&root_setup.kargs);

    if let Some(install_config_kargs) = install_config_kargs {
        for karg in install_config_kargs {
            kargs.extend(&Cmdline::from(karg.as_str()));
        }
    }

    kargs.extend(&kargsd);

    if let Some(cli_kargs) = state.config_opts.karg.as_ref() {
        for karg in cli_kargs {
            kargs.extend(karg);
        }
    }

    // Finally map into &[&str] for ostree_container
    let kargs_strs: Vec<&str> = kargs.iter_str().collect();

    let mut options = ostree_container::deploy::DeployOpts::default();
    options.kargs = Some(kargs_strs.as_slice());
    options.target_imgref = Some(&state.target_imgref);
    options.proxy_cfg = proxy_cfg;
    options.skip_completion = true; // Must be set to avoid recursion!
    options.no_clean = has_ostree;
    let imgstate = crate::utils::async_task_with_spinner(
        "Deploying container image",
        ostree_container::deploy::deploy(&sysroot, stateroot, &src_imageref, Some(options)),
    )
    .await?;

    let deployment = sysroot
        .deployments()
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("Failed to find deployment"))?;
    // SAFETY: There must be a path
    let path = sysroot.deployment_dirpath(&deployment);
    let root = root_setup
        .physical_root
        .open_dir(path.as_str())
        .context("Opening deployment dir")?;

    // And do another recursive relabeling pass over the ostree-owned directories
    // but avoid recursing into the deployment root (because that's a *distinct*
    // logical root).
    if let Some(policy) = sepolicy {
        let deployment_root_meta = root.dir_metadata()?;
        let deployment_root_devino = (deployment_root_meta.dev(), deployment_root_meta.ino());
        for d in ["ostree", "boot"] {
            let mut pathbuf = Utf8PathBuf::from(d);
            crate::lsm::ensure_dir_labeled_recurse(
                &root_setup.physical_root,
                &mut pathbuf,
                policy,
                Some(deployment_root_devino),
            )
            .with_context(|| format!("Recursive SELinux relabeling of {d}"))?;
        }

        if let Some(cfs_super) = root.open_optional(OSTREE_COMPOSEFS_SUPER)? {
            let label = crate::lsm::require_label(policy, "/usr".into(), 0o644)?;
            crate::lsm::set_security_selinux(cfs_super.as_fd(), label.as_bytes())?;
        } else {
            tracing::warn!("Missing {OSTREE_COMPOSEFS_SUPER}; composefs is not enabled?");
        }
    }

    // Write the entry for /boot to /etc/fstab.  TODO: Encourage OSes to use the karg?
    // Or better bind this with the grub data.
    // We omit it if the boot mountspec argument was empty
    if let Some(boot) = root_setup.boot.as_ref() {
        if !boot.source.is_empty() {
            crate::lsm::atomic_replace_labeled(&root, "etc/fstab", 0o644.into(), sepolicy, |w| {
                writeln!(w, "{}", boot.to_fstab()).map_err(Into::into)
            })?;
        }
    }

    if let Some(contents) = state.root_ssh_authorized_keys.as_deref() {
        osconfig::inject_root_ssh_authorized_keys(&root, sepolicy, contents)?;
    }

    let aleph = InstallAleph::new(&src_imageref, &imgstate, &state.selinux_state)?;
    Ok((deployment, aleph))
}

/// Run a command in the host mount namespace
pub(crate) fn run_in_host_mountns(cmd: &str) -> Result<Command> {
    let mut c = Command::new(bootc_utils::reexec::executable_path()?);
    c.lifecycle_bind()
        .args(["exec-in-host-mount-namespace", cmd]);
    Ok(c)
}

#[context("Re-exec in host mountns")]
pub(crate) fn exec_in_host_mountns(args: &[std::ffi::OsString]) -> Result<()> {
    let (cmd, args) = args
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("Missing command"))?;
    tracing::trace!("{cmd:?} {args:?}");
    let pid1mountns = std::fs::File::open("/proc/1/ns/mnt").context("open pid1 mountns")?;
    rustix::thread::move_into_link_name_space(
        pid1mountns.as_fd(),
        Some(rustix::thread::LinkNameSpaceType::Mount),
    )
    .context("setns")?;
    rustix::process::chdir("/").context("chdir")?;
    // Work around supermin doing chroot() and not pivot_root
    // https://github.com/libguestfs/supermin/blob/5230e2c3cd07e82bd6431e871e239f7056bf25ad/init/init.c#L288
    if !Utf8Path::new("/usr").try_exists().context("/usr")?
        && Utf8Path::new("/root/usr")
            .try_exists()
            .context("/root/usr")?
    {
        tracing::debug!("Using supermin workaround");
        rustix::process::chroot("/root").context("chroot")?;
    }
    Err(Command::new(cmd).args(args).arg0(bootc_utils::NAME).exec()).context("exec")?
}

pub(crate) struct RootSetup {
    #[cfg(feature = "install-to-disk")]
    luks_device: Option<String>,
    pub(crate) device_info: bootc_blockdev::PartitionTable,
    /// Absolute path to the location where we've mounted the physical
    /// root filesystem for the system we're installing.
    pub(crate) physical_root_path: Utf8PathBuf,
    /// Directory file descriptor for the above physical root.
    pub(crate) physical_root: Dir,
    /// Target root path /target.
    pub(crate) target_root_path: Option<Utf8PathBuf>,
    pub(crate) rootfs_uuid: Option<String>,
    /// True if we should skip finalizing
    skip_finalize: bool,
    boot: Option<MountSpec>,
    pub(crate) kargs: CmdlineOwned,
}

fn require_boot_uuid(spec: &MountSpec) -> Result<&str> {
    spec.get_source_uuid()
        .ok_or_else(|| anyhow!("/boot is not specified via UUID= (this is currently required)"))
}

impl RootSetup {
    /// Get the UUID= mount specifier for the /boot filesystem; if there isn't one, the root UUID will
    /// be returned.
    pub(crate) fn get_boot_uuid(&self) -> Result<Option<&str>> {
        self.boot.as_ref().map(require_boot_uuid).transpose()
    }

    // Drop any open file descriptors and return just the mount path and backing luks device, if any
    #[cfg(feature = "install-to-disk")]
    fn into_storage(self) -> (Utf8PathBuf, Option<String>) {
        (self.physical_root_path, self.luks_device)
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum SELinuxFinalState {
    /// Host and target both have SELinux, but user forced it off for target
    ForceTargetDisabled,
    /// Host and target both have SELinux
    Enabled(Option<crate::lsm::SetEnforceGuard>),
    /// Host has SELinux disabled, target is enabled.
    HostDisabled,
    /// Neither host or target have SELinux
    Disabled,
}

impl SELinuxFinalState {
    /// Returns true if the target system will have SELinux enabled.
    pub(crate) fn enabled(&self) -> bool {
        match self {
            SELinuxFinalState::ForceTargetDisabled | SELinuxFinalState::Disabled => false,
            SELinuxFinalState::Enabled(_) | SELinuxFinalState::HostDisabled => true,
        }
    }

    /// Returns the canonical stringified version of self.  This is only used
    /// for debugging purposes.
    pub(crate) fn to_aleph(&self) -> &'static str {
        match self {
            SELinuxFinalState::ForceTargetDisabled => "force-target-disabled",
            SELinuxFinalState::Enabled(_) => "enabled",
            SELinuxFinalState::HostDisabled => "host-disabled",
            SELinuxFinalState::Disabled => "disabled",
        }
    }
}

/// If we detect that the target ostree commit has SELinux labels,
/// and we aren't passed an override to disable it, then ensure
/// the running process is labeled with install_t so it can
/// write arbitrary labels.
pub(crate) fn reexecute_self_for_selinux_if_needed(
    srcdata: &SourceInfo,
    override_disable_selinux: bool,
) -> Result<SELinuxFinalState> {
    // If the target state has SELinux enabled, we need to check the host state.
    if srcdata.selinux {
        let host_selinux = crate::lsm::selinux_enabled()?;
        tracing::debug!("Target has SELinux, host={host_selinux}");
        let r = if override_disable_selinux {
            println!("notice: Target has SELinux enabled, overriding to disable");
            SELinuxFinalState::ForceTargetDisabled
        } else if host_selinux {
            // /sys/fs/selinuxfs is not normally mounted, so we do that now.
            // Because SELinux enablement status is cached process-wide and was very likely
            // already queried by something else (e.g. glib's constructor), we would also need
            // to re-exec.  But, selinux_ensure_install does that unconditionally right now too,
            // so let's just fall through to that.
            setup_sys_mount("selinuxfs", SELINUXFS)?;
            // This will re-execute the current process (once).
            let g = crate::lsm::selinux_ensure_install_or_setenforce()?;
            SELinuxFinalState::Enabled(g)
        } else {
            SELinuxFinalState::HostDisabled
        };
        Ok(r)
    } else {
        Ok(SELinuxFinalState::Disabled)
    }
}

/// Trim, flush outstanding writes, and freeze/thaw the target mounted filesystem;
/// these steps prepare the filesystem for its first booted use.
pub(crate) fn finalize_filesystem(
    fsname: &str,
    root: &Dir,
    path: impl AsRef<Utf8Path>,
) -> Result<()> {
    let path = path.as_ref();
    // fstrim ensures the underlying block device knows about unused space
    Task::new(format!("Trimming {fsname}"), "fstrim")
        .args(["--quiet-unsupported", "-v", path.as_str()])
        .cwd(root)?
        .run()?;
    // Remounting readonly will flush outstanding writes and ensure we error out if there were background
    // writeback problems.
    Task::new(format!("Finalizing filesystem {fsname}"), "mount")
        .cwd(root)?
        .args(["-o", "remount,ro", path.as_str()])
        .run()?;
    // Finally, freezing (and thawing) the filesystem will flush the journal, which means the next boot is clean.
    for a in ["-f", "-u"] {
        Command::new("fsfreeze")
            .cwd_dir(root.try_clone()?)
            .args([a, path.as_str()])
            .run_capture_stderr()?;
    }
    Ok(())
}

/// A heuristic check that we were invoked with --pid=host
fn require_host_pidns() -> Result<()> {
    if rustix::process::getpid().is_init() {
        anyhow::bail!("This command must be run with the podman --pid=host flag")
    }
    tracing::trace!("OK: we're not pid 1");
    Ok(())
}

/// Verify that we can access /proc/1, which will catch rootless podman (with --pid=host)
/// for example.
fn require_host_userns() -> Result<()> {
    let proc1 = "/proc/1";
    let pid1_uid = Path::new(proc1)
        .metadata()
        .with_context(|| format!("Querying {proc1}"))?
        .uid();
    // We must really be in a rootless container, or in some way
    // we're not part of the host user namespace.
    ensure!(
        pid1_uid == 0,
        "{proc1} is owned by {pid1_uid}, not zero; this command must be run in the root user namespace (e.g. not rootless podman)"
    );
    tracing::trace!("OK: we're in a matching user namespace with pid1");
    Ok(())
}

/// Ensure that /tmp is a tmpfs because in some cases we might perform
/// operations which expect it (as it is on a proper host system).
/// Ideally we have people run this container via podman run --read-only-tmpfs
/// actually.
pub(crate) fn setup_tmp_mount() -> Result<()> {
    let st = rustix::fs::statfs("/tmp")?;
    if st.f_type == libc::TMPFS_MAGIC {
        tracing::trace!("Already have tmpfs /tmp")
    } else {
        // Note we explicitly also don't want a "nosuid" tmp, because that
        // suppresses our install_t transition
        Command::new("mount")
            .args(["tmpfs", "-t", "tmpfs", "/tmp"])
            .run_capture_stderr()?;
    }
    Ok(())
}

/// By default, podman/docker etc. when passed `--privileged` mount `/sys` as read-only,
/// but non-recursively.  We selectively grab sub-filesystems that we need.
#[context("Ensuring sys mount {fspath} {fstype}")]
pub(crate) fn setup_sys_mount(fstype: &str, fspath: &str) -> Result<()> {
    tracing::debug!("Setting up sys mounts");
    let rootfs = format!("/proc/1/root/{fspath}");
    // Does mount point even exist in the host?
    if !Path::new(rootfs.as_str()).try_exists()? {
        return Ok(());
    }

    // Now, let's find out if it's populated
    if std::fs::read_dir(rootfs)?.next().is_none() {
        return Ok(());
    }

    // Check that the path that should be mounted is even populated.
    // Since we are dealing with /sys mounts here, if it's populated,
    // we can be at least a little certain that it's mounted.
    if Path::new(fspath).try_exists()? && std::fs::read_dir(fspath)?.next().is_some() {
        return Ok(());
    }

    // This means the host has this mounted, so we should mount it too
    Command::new("mount")
        .args(["-t", fstype, fstype, fspath])
        .run_capture_stderr()?;

    Ok(())
}

/// Verify that we can load the manifest of the target image
#[context("Verifying fetch")]
async fn verify_target_fetch(
    tmpdir: &Dir,
    imgref: &ostree_container::OstreeImageReference,
) -> Result<()> {
    let tmpdir = &TempDir::new_in(&tmpdir)?;
    let tmprepo = &ostree::Repo::create_at_dir(tmpdir.as_fd(), ".", ostree::RepoMode::Bare, None)
        .context("Init tmp repo")?;

    tracing::trace!("Verifying fetch for {imgref}");
    let mut imp =
        ostree_container::store::ImageImporter::new(tmprepo, imgref, Default::default()).await?;
    use ostree_container::store::PrepareResult;
    let prep = match imp.prepare().await? {
        // SAFETY: It's impossible that the image was already fetched into this newly created temporary repository
        PrepareResult::AlreadyPresent(_) => unreachable!(),
        PrepareResult::Ready(r) => r,
    };
    tracing::debug!("Fetched manifest with digest {}", prep.manifest_digest);
    Ok(())
}

/// Preparation for an install; validates and prepares some (thereafter immutable) global state.
async fn prepare_install(
    mut config_opts: InstallConfigOpts,
    source_opts: InstallSourceOpts,
    target_opts: InstallTargetOpts,
    mut composefs_options: InstallComposefsOpts,
    target_fs: Option<FilesystemEnum>,
) -> Result<Arc<State>> {
    tracing::trace!("Preparing install");
    let rootfs = cap_std::fs::Dir::open_ambient_dir("/", cap_std::ambient_authority())
        .context("Opening /")?;

    let host_is_container = crate::containerenv::is_container(&rootfs);
    let external_source = source_opts.source_imgref.is_some();
    let (source, target_rootfs) = match source_opts.source_imgref {
        None => {
            ensure!(
                host_is_container,
                "Either --source-imgref must be defined or this command must be executed inside a podman container."
            );

            crate::cli::require_root(true)?;

            require_host_pidns()?;
            // Out of conservatism we only verify the host userns path when we're expecting
            // to do a self-install (e.g. not bootc-image-builder or equivalent).
            require_host_userns()?;
            let container_info = crate::containerenv::get_container_execution_info(&rootfs)?;
            // This command currently *must* be run inside a privileged container.
            match container_info.rootless.as_deref() {
                Some("1") => anyhow::bail!(
                    "Cannot install from rootless podman; this command must be run as root"
                ),
                Some(o) => tracing::debug!("rootless={o}"),
                // This one shouldn't happen except on old podman
                None => tracing::debug!(
                    "notice: Did not find rootless= entry in {}",
                    crate::containerenv::PATH,
                ),
            };
            tracing::trace!("Read container engine info {:?}", container_info);

            let source = SourceInfo::from_container(&rootfs, &container_info)?;
            (source, Some(rootfs.try_clone()?))
        }
        Some(source) => {
            crate::cli::require_root(false)?;
            let source = SourceInfo::from_imageref(&source, &rootfs)?;
            (source, None)
        }
    };

    // Parse the target CLI image reference options and create the *target* image
    // reference, which defaults to pulling from a registry.
    if target_opts.target_no_signature_verification {
        // Perhaps log this in the future more prominently, but no reason to annoy people.
        tracing::debug!(
            "Use of --target-no-signature-verification flag which is enabled by default"
        );
    }
    let target_sigverify = sigpolicy_from_opt(target_opts.enforce_container_sigpolicy);
    let target_imgname = target_opts
        .target_imgref
        .as_deref()
        .unwrap_or(source.imageref.name.as_str());
    let target_transport =
        ostree_container::Transport::try_from(target_opts.target_transport.as_str())?;
    let target_imgref = ostree_container::OstreeImageReference {
        sigverify: target_sigverify,
        imgref: ostree_container::ImageReference {
            transport: target_transport,
            name: target_imgname.to_string(),
        },
    };
    tracing::debug!("Target image reference: {target_imgref}");

    let (composefs_required, kernel) = if let Some(root) = target_rootfs.as_ref() {
        let kernel = crate::kernel::find_kernel(root)?;

        (
            kernel.as_ref().map(|k| k.kernel.unified).unwrap_or(false),
            kernel,
        )
    } else {
        (false, None)
    };

    tracing::debug!("Composefs required: {composefs_required}");

    if composefs_required {
        composefs_options.composefs_backend = true;
    }

    if composefs_options.composefs_backend
        && matches!(config_opts.bootloader, Some(Bootloader::None))
    {
        anyhow::bail!("Bootloader set to none is not supported with the composefs backend");
    }

    // We need to access devices that are set up by the host udev
    bootc_mount::ensure_mirrored_host_mount("/dev")?;
    // We need to read our own container image (and any logically bound images)
    // from the host container store.
    bootc_mount::ensure_mirrored_host_mount("/var/lib/containers")?;
    // In some cases we may create large files, and it's better not to have those
    // in our overlayfs.
    bootc_mount::ensure_mirrored_host_mount("/var/tmp")?;
    // udev state is required for running lsblk during install to-disk
    // see https://github.com/bootc-dev/bootc/pull/688
    bootc_mount::ensure_mirrored_host_mount("/run/udev")?;
    // We also always want /tmp to be a proper tmpfs on general principle.
    setup_tmp_mount()?;
    // Allocate a temporary directory we can use in various places to avoid
    // creating multiple.
    let tempdir = cap_std_ext::cap_tempfile::TempDir::new(cap_std::ambient_authority())?;
    // And continue to init global state
    osbuild::adjust_for_bootc_image_builder(&rootfs, &tempdir)?;

    if target_opts.run_fetch_check {
        verify_target_fetch(&tempdir, &target_imgref).await?;
    }

    // Even though we require running in a container, the mounts we create should be specific
    // to this process, so let's enter a private mountns to avoid leaking them.
    if !external_source && std::env::var_os("BOOTC_SKIP_UNSHARE").is_none() {
        super::cli::ensure_self_unshared_mount_namespace()?;
    }

    setup_sys_mount("efivarfs", EFIVARFS)?;

    // Now, deal with SELinux state.
    let selinux_state = reexecute_self_for_selinux_if_needed(&source, config_opts.disable_selinux)?;
    tracing::debug!("SELinux state: {selinux_state:?}");

    println!("Installing image: {:#}", &target_imgref);
    if let Some(digest) = source.digest.as_deref() {
        println!("Digest: {digest}");
    }

    let install_config = config::load_config()?;
    if let Some(ref config) = install_config {
        tracing::debug!("Loaded install configuration");
        // Merge config file values into config_opts (CLI takes precedence)
        // Only apply config file value if CLI didn't explicitly set it
        if !config_opts.bootupd_skip_boot_uuid {
            config_opts.bootupd_skip_boot_uuid = config
                .bootupd
                .as_ref()
                .and_then(|b| b.skip_boot_uuid)
                .unwrap_or(false);
        }

        if config_opts.bootloader.is_none() {
            config_opts.bootloader = config.bootloader.clone();
        }
    } else {
        tracing::debug!("No install configuration found");
    }

    let root_filesystem = target_fs
        .or(install_config
            .as_ref()
            .and_then(|c| c.filesystem_root())
            .and_then(|r| r.fstype))
        .ok_or_else(|| anyhow::anyhow!("No root filesystem specified"))?;

    let mut is_uki = false;

    // For composefs backend, automatically disable fs-verity hard requirement if the
    // filesystem doesn't support it
    //
    // If we have a sealed UKI on our hands, then we can assume that user wanted fs-verity so
    // we hard require it in that particular case
    //
    // NOTE: This isn't really 100% accurate 100% of the time as the cmdline can be in an addon
    match kernel {
        Some(k) => match k.k_type {
            crate::kernel::KernelType::Uki {
                allow_missing_fsverity,
                ..
            } => {
                if !allow_missing_fsverity {
                    anyhow::ensure!(
                        root_filesystem.supports_fsverity(),
                        "Specified filesystem {root_filesystem} does not support fs-verity"
                    );
                }

                composefs_options.allow_missing_verity = allow_missing_fsverity;
                is_uki = true;
            }

            crate::kernel::KernelType::Vmlinuz { .. } => {}
        },

        None => {}
    }

    // If `--allow-missing-verity` is already passed via CLI, don't modify
    if composefs_options.composefs_backend && !composefs_options.allow_missing_verity && !is_uki {
        composefs_options.allow_missing_verity = !root_filesystem.supports_fsverity();

        tracing::debug!(
            "Missing fsverity {}",
            if composefs_options.allow_missing_verity {
                "allowed"
            } else {
                "not allowed"
            }
        );
    }

    if let Some(crate::spec::Bootloader::None) = config_opts.bootloader {
        if cfg!(target_arch = "s390x") {
            anyhow::bail!("Bootloader set to none is not supported for the s390x architecture");
        }
    }

    // Convert the keyfile to a hashmap because GKeyFile isnt Send for probably bad reasons.
    let prepareroot_config = {
        let kf = ostree_prepareroot::require_config_from_root(&rootfs)?;
        let mut r = HashMap::new();
        for grp in kf.groups() {
            for key in kf.keys(&grp)? {
                let key = key.as_str();
                let value = kf.value(&grp, key)?;
                r.insert(format!("{grp}.{key}"), value.to_string());
            }
        }
        r
    };

    // Eagerly read the file now to ensure we error out early if e.g. it doesn't exist,
    // instead of much later after we're 80% of the way through an install.
    let root_ssh_authorized_keys = config_opts
        .root_ssh_authorized_keys
        .as_ref()
        .map(|p| std::fs::read_to_string(p).with_context(|| format!("Reading {p}")))
        .transpose()?;

    // Create our global (read-only) state which gets wrapped in an Arc
    // so we can pass it to worker threads too. Right now this just
    // combines our command line options along with some bind mounts from the host.
    let state = Arc::new(State {
        selinux_state,
        source,
        config_opts,
        target_opts,
        target_imgref,
        install_config,
        prepareroot_config,
        root_ssh_authorized_keys,
        container_root: rootfs,
        tempdir,
        host_is_container,
        composefs_required,
        composefs_options,
    });

    Ok(state)
}

impl PostFetchState {
    pub(crate) fn new(state: &State, d: &Dir) -> Result<Self> {
        // Determine bootloader type for the target system
        // Priority: user-specified > bootupd availability > systemd-boot fallback
        let detected_bootloader = {
            if let Some(bootloader) = state.config_opts.bootloader.clone() {
                bootloader
            } else {
                if crate::bootloader::supports_bootupd(d)? {
                    crate::spec::Bootloader::Grub
                } else {
                    crate::spec::Bootloader::Systemd
                }
            }
        };
        println!("Bootloader: {detected_bootloader}");
        let r = Self {
            detected_bootloader,
        };
        Ok(r)
    }
}

/// Given a baseline root filesystem with an ostree sysroot initialized:
/// - install the container to that root
/// - install the bootloader
/// - Other post operations, such as pulling bound images
async fn install_with_sysroot(
    state: &State,
    rootfs: &RootSetup,
    storage: &Storage,
    boot_uuid: &str,
    bound_images: BoundImages,
    has_ostree: bool,
) -> Result<()> {
    let ostree = storage.get_ostree()?;
    let c_storage = storage.get_ensure_imgstore()?;

    // And actually set up the container in that root, returning a deployment and
    // the aleph state (see below).
    let (deployment, aleph) = install_container(state, rootfs, ostree, storage, has_ostree).await?;
    // Write the aleph data that captures the system state at the time of provisioning for aid in future debugging.
    aleph.write_to(&rootfs.physical_root)?;

    let deployment_path = ostree.deployment_dirpath(&deployment);

    let deployment_dir = rootfs
        .physical_root
        .open_dir(&deployment_path)
        .context("Opening deployment dir")?;
    let postfetch = PostFetchState::new(state, &deployment_dir)?;

    if cfg!(target_arch = "s390x") {
        // TODO: Integrate s390x support into install_via_bootupd
        crate::bootloader::install_via_zipl(&rootfs.device_info, boot_uuid)?;
    } else {
        match postfetch.detected_bootloader {
            Bootloader::Grub => {
                crate::bootloader::install_via_bootupd(
                    &rootfs.device_info,
                    &rootfs
                        .target_root_path
                        .clone()
                        .unwrap_or(rootfs.physical_root_path.clone()),
                    &state.config_opts,
                    Some(&deployment_path.as_str()),
                )?;
            }
            Bootloader::Systemd => {
                anyhow::bail!("bootupd is required for ostree-based installs");
            }
            Bootloader::None => {
                tracing::debug!("Skip bootloader installation due set to None");
            }
        }
    }
    tracing::debug!("Installed bootloader");

    tracing::debug!("Performing post-deployment operations");

    match bound_images {
        BoundImages::Skip => {}
        BoundImages::Resolved(resolved_bound_images) => {
            // Now copy each bound image from the host's container storage into the target.
            for image in resolved_bound_images {
                let image = image.image.as_str();
                c_storage.pull_from_host_storage(image).await?;
            }
        }
        BoundImages::Unresolved(bound_images) => {
            crate::boundimage::pull_images_impl(c_storage, bound_images)
                .await
                .context("pulling bound images")?;
        }
    }

    Ok(())
}

enum BoundImages {
    Skip,
    Resolved(Vec<ResolvedBoundImage>),
    Unresolved(Vec<BoundImage>),
}

impl BoundImages {
    async fn from_state(state: &State) -> Result<Self> {
        let bound_images = match state.config_opts.bound_images {
            BoundImagesOpt::Skip => BoundImages::Skip,
            others => {
                let queried_images = crate::boundimage::query_bound_images(&state.container_root)?;
                match others {
                    BoundImagesOpt::Stored => {
                        // Verify each bound image is present in the container storage
                        let mut r = Vec::with_capacity(queried_images.len());
                        for image in queried_images {
                            let resolved = ResolvedBoundImage::from_image(&image).await?;
                            tracing::debug!("Resolved {}: {}", resolved.image, resolved.digest);
                            r.push(resolved)
                        }
                        BoundImages::Resolved(r)
                    }
                    BoundImagesOpt::Pull => {
                        // No need to resolve the images, we will pull them into the target later
                        BoundImages::Unresolved(queried_images)
                    }
                    BoundImagesOpt::Skip => anyhow::bail!("unreachable error"),
                }
            }
        };

        Ok(bound_images)
    }
}

async fn ostree_install(state: &State, rootfs: &RootSetup, cleanup: Cleanup) -> Result<()> {
    // We verify this upfront because it's currently required by bootupd
    let boot_uuid = rootfs
        .get_boot_uuid()?
        .or(rootfs.rootfs_uuid.as_deref())
        .ok_or_else(|| anyhow!("No uuid for boot/root"))?;
    tracing::debug!("boot uuid={boot_uuid}");

    let bound_images = BoundImages::from_state(state).await?;

    // Initialize the ostree sysroot (repo, stateroot, etc.)

    {
        let (sysroot, has_ostree) = initialize_ostree_root(state, rootfs).await?;

        install_with_sysroot(
            state,
            rootfs,
            &sysroot,
            &boot_uuid,
            bound_images,
            has_ostree,
        )
        .await?;
        let ostree = sysroot.get_ostree()?;

        if matches!(cleanup, Cleanup::TriggerOnNextBoot) {
            let sysroot_dir = crate::utils::sysroot_dir(ostree)?;
            tracing::debug!("Writing {DESTRUCTIVE_CLEANUP}");
            sysroot_dir.atomic_write(DESTRUCTIVE_CLEANUP, b"")?;
        }

        // Ensure the image storage is SELinux-labeled. This must happen
        // after all image pulls are complete.
        sysroot.ensure_imgstore_labeled()?;

        // We must drop the sysroot here in order to close any open file
        // descriptors.
    };

    // Run this on every install as the penultimate step
    install_finalize(&rootfs.physical_root_path).await?;

    Ok(())
}

async fn install_to_filesystem_impl(
    state: &State,
    rootfs: &mut RootSetup,
    cleanup: Cleanup,
) -> Result<()> {
    if matches!(state.selinux_state, SELinuxFinalState::ForceTargetDisabled) {
        rootfs.kargs.extend(&Cmdline::from("selinux=0"));
    }
    // Drop exclusive ownership since we're done with mutation
    let rootfs = &*rootfs;

    match &rootfs.device_info.label {
        bootc_blockdev::PartitionType::Dos => crate::utils::medium_visibility_warning(
            "Installing to `dos` format partitions is not recommended",
        ),
        bootc_blockdev::PartitionType::Gpt => {
            // The only thing we should be using in general
        }
        bootc_blockdev::PartitionType::Unknown(o) => {
            crate::utils::medium_visibility_warning(&format!("Unknown partition label {o}"))
        }
    }

    if state.composefs_options.composefs_backend {
        // Load a fd for the mounted target physical root

        let (id, verity) = initialize_composefs_repository(
            state,
            rootfs,
            state.composefs_options.allow_missing_verity,
        )
        .await?;
        tracing::info!("id: {id}, verity: {}", verity.to_hex());

        setup_composefs_boot(
            rootfs,
            state,
            &id,
            state.composefs_options.allow_missing_verity,
        )
        .await?;
    } else {
        ostree_install(state, rootfs, cleanup).await?;
    }

    // Finalize mounted filesystems
    if !rootfs.skip_finalize {
        let bootfs = rootfs.boot.as_ref().map(|_| ("boot", "boot"));
        for (fsname, fs) in std::iter::once(("root", ".")).chain(bootfs) {
            finalize_filesystem(fsname, &rootfs.physical_root, fs)?;
        }
    }

    Ok(())
}

fn installation_complete() {
    println!("Installation complete!");
}

/// Implementation of the `bootc install to-disk` CLI command.
#[context("Installing to disk")]
#[cfg(feature = "install-to-disk")]
pub(crate) async fn install_to_disk(mut opts: InstallToDiskOpts) -> Result<()> {
    // Log the disk installation operation to systemd journal
    const INSTALL_DISK_JOURNAL_ID: &str = "8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2";
    let source_image = opts
        .source_opts
        .source_imgref
        .as_ref()
        .map(|s| s.as_str())
        .unwrap_or("none");
    let target_device = opts.block_opts.device.as_str();

    tracing::info!(
        message_id = INSTALL_DISK_JOURNAL_ID,
        bootc.source_image = source_image,
        bootc.target_device = target_device,
        bootc.via_loopback = if opts.via_loopback { "true" } else { "false" },
        "Starting disk installation from {} to {}",
        source_image,
        target_device
    );

    let mut block_opts = opts.block_opts;
    let target_blockdev_meta = block_opts
        .device
        .metadata()
        .with_context(|| format!("Querying {}", &block_opts.device))?;
    if opts.via_loopback {
        if !opts.config_opts.generic_image {
            crate::utils::medium_visibility_warning(
                "Automatically enabling --generic-image when installing via loopback",
            );
            opts.config_opts.generic_image = true;
        }
        if !target_blockdev_meta.file_type().is_file() {
            anyhow::bail!(
                "Not a regular file (to be used via loopback): {}",
                block_opts.device
            );
        }
    } else if !target_blockdev_meta.file_type().is_block_device() {
        anyhow::bail!("Not a block device: {}", block_opts.device);
    }

    let state = prepare_install(
        opts.config_opts,
        opts.source_opts,
        opts.target_opts,
        opts.composefs_opts,
        block_opts.filesystem,
    )
    .await?;

    // This is all blocking stuff
    let (mut rootfs, loopback) = {
        let loopback_dev = if opts.via_loopback {
            let loopback_dev =
                bootc_blockdev::LoopbackDevice::new(block_opts.device.as_std_path())?;
            block_opts.device = loopback_dev.path().into();
            Some(loopback_dev)
        } else {
            None
        };

        let state = state.clone();
        let rootfs = tokio::task::spawn_blocking(move || {
            baseline::install_create_rootfs(&state, block_opts)
        })
        .await??;
        (rootfs, loopback_dev)
    };

    install_to_filesystem_impl(&state, &mut rootfs, Cleanup::Skip).await?;

    // Drop all data about the root except the bits we need to ensure any file descriptors etc. are closed.
    let (root_path, luksdev) = rootfs.into_storage();
    Task::new_and_run(
        "Unmounting filesystems",
        "umount",
        ["-R", root_path.as_str()],
    )?;
    if let Some(luksdev) = luksdev.as_deref() {
        Task::new_and_run("Closing root LUKS device", "cryptsetup", ["close", luksdev])?;
    }

    if let Some(loopback_dev) = loopback {
        loopback_dev.close()?;
    }

    // At this point, all other threads should be gone.
    if let Some(state) = Arc::into_inner(state) {
        state.consume()?;
    } else {
        // This shouldn't happen...but we will make it not fatal right now
        tracing::warn!("Failed to consume state Arc");
    }

    installation_complete();

    Ok(())
}

/// Require that a directory contains only mount points recursively.
/// Returns Ok(()) if all entries in the directory tree are either:
/// - Mount points (on different filesystems)
/// - Directories that themselves contain only mount points (recursively)
/// - The lost+found directory
///
/// Returns an error if any non-mount entry is found.
///
/// This handles cases like /var containing /var/lib (not a mount) which contains
/// /var/lib/containers (a mount point).
#[context("Requiring directory contains only mount points")]
fn require_dir_contains_only_mounts(parent_fd: &Dir, dir_name: &str) -> Result<()> {
    tracing::trace!("Checking directory {dir_name} for non-mount entries");
    let Some(dir_fd) = parent_fd.open_dir_noxdev(dir_name)? else {
        // The directory itself is a mount point
        tracing::trace!("{dir_name} is a mount point");
        return Ok(());
    };

    if dir_fd.entries()?.next().is_none() {
        anyhow::bail!("Found empty directory: {dir_name}");
    }

    for entry in dir_fd.entries()? {
        tracing::trace!("Checking entry in {dir_name}");
        let entry = DirEntryUtf8::from_cap_std(entry?);
        let entry_name = entry.file_name()?;

        if entry_name == LOST_AND_FOUND {
            continue;
        }

        let etype = entry.file_type()?;
        if etype == FileType::dir() {
            require_dir_contains_only_mounts(&dir_fd, &entry_name)?;
        } else {
            anyhow::bail!("Found entry in {dir_name}: {entry_name}");
        }
    }

    Ok(())
}

#[context("Verifying empty rootfs")]
fn require_empty_rootdir(rootfs_fd: &Dir) -> Result<()> {
    for e in rootfs_fd.entries()? {
        let e = DirEntryUtf8::from_cap_std(e?);
        let name = e.file_name()?;
        if name == LOST_AND_FOUND {
            continue;
        }

        // Check if this entry is a directory
        let etype = e.file_type()?;
        if etype == FileType::dir() {
            require_dir_contains_only_mounts(rootfs_fd, &name)?;
        } else {
            anyhow::bail!("Non-empty root filesystem; found {name:?}");
        }
    }
    Ok(())
}

/// Remove all entries in a directory, but do not traverse across distinct devices.
/// If mount_err is true, then an error is returned if a mount point is found;
/// otherwise it is silently ignored.
fn remove_all_in_dir_no_xdev(d: &Dir, mount_err: bool) -> Result<()> {
    for entry in d.entries()? {
        let entry = entry?;
        let name = entry.file_name();
        let etype = entry.file_type()?;
        if etype == FileType::dir() {
            if let Some(subdir) = d.open_dir_noxdev(&name)? {
                remove_all_in_dir_no_xdev(&subdir, mount_err)?;
                d.remove_dir(&name)?;
            } else if mount_err {
                anyhow::bail!("Found unexpected mount point {name:?}");
            }
        } else {
            d.remove_file_optional(&name)?;
        }
    }
    anyhow::Ok(())
}

#[context("Removing boot directory content except loader dir on ostree")]
fn remove_all_except_loader_dirs(bootdir: &Dir, is_ostree: bool) -> Result<()> {
    let entries = bootdir
        .entries()
        .context("Reading boot directory entries")?;

    for entry in entries {
        let entry = entry.context("Reading directory entry")?;
        let file_name = entry.file_name();
        let file_name = if let Some(n) = file_name.to_str() {
            n
        } else {
            anyhow::bail!("Invalid non-UTF8 filename: {file_name:?} in /boot");
        };

        // TODO: Preserve basically everything (including the bootloader entries
        // on non-ostree) by default until the very end of the install. And ideally
        // make the "commit" phase an optional step after.
        if is_ostree && file_name.starts_with("loader") {
            continue;
        }

        let etype = entry.file_type()?;
        if etype == FileType::dir() {
            // Open the directory and remove its contents
            if let Some(subdir) = bootdir.open_dir_noxdev(&file_name)? {
                remove_all_in_dir_no_xdev(&subdir, false)
                    .with_context(|| format!("Removing directory contents: {}", file_name))?;
                bootdir.remove_dir(&file_name)?;
            }
        } else {
            bootdir
                .remove_file_optional(&file_name)
                .with_context(|| format!("Removing file: {}", file_name))?;
        }
    }
    Ok(())
}

#[context("Removing boot directory content")]
fn clean_boot_directories(rootfs: &Dir, rootfs_path: &Utf8Path, is_ostree: bool) -> Result<()> {
    let bootdir =
        crate::utils::open_dir_remount_rw(rootfs, BOOT.into()).context("Opening /boot")?;

    if ARCH_USES_EFI {
        // On booted FCOS, esp is not mounted by default
        // Mount ESP part at /boot/efi before clean
        crate::bootloader::mount_esp_part(&rootfs, &rootfs_path, is_ostree)?;
    }

    // This should not remove /boot/efi note.
    remove_all_except_loader_dirs(&bootdir, is_ostree).context("Emptying /boot")?;

    // TODO: we should also support not wiping the ESP.
    if ARCH_USES_EFI {
        if let Some(efidir) = bootdir
            .open_dir_optional(crate::bootloader::EFI_DIR)
            .context("Opening /boot/efi")?
        {
            remove_all_in_dir_no_xdev(&efidir, false).context("Emptying EFI system partition")?;
        }
    }

    Ok(())
}

struct RootMountInfo {
    mount_spec: String,
    kargs: Vec<String>,
}

/// Discover how to mount the root filesystem, using existing kernel arguments and information
/// about the root mount.
fn find_root_args_to_inherit(
    cmdline: &bytes::Cmdline,
    root_info: &Filesystem,
) -> Result<RootMountInfo> {
    // If we have a root= karg, then use that
    let root = cmdline
        .find_utf8("root")?
        .and_then(|p| p.value().map(|p| p.to_string()));
    let (mount_spec, kargs) = if let Some(root) = root {
        let rootflags = cmdline.find(ROOTFLAGS);
        let inherit_kargs = cmdline.find_all_starting_with(INITRD_ARG_PREFIX);
        (
            root,
            rootflags
                .into_iter()
                .chain(inherit_kargs)
                .map(|p| utf8::Parameter::try_from(p).map(|p| p.to_string()))
                .collect::<Result<Vec<_>, _>>()?,
        )
    } else {
        let uuid = root_info
            .uuid
            .as_deref()
            .ok_or_else(|| anyhow!("No filesystem uuid found in target root"))?;
        (format!("UUID={uuid}"), Vec::new())
    };

    Ok(RootMountInfo { mount_spec, kargs })
}

fn warn_on_host_root(rootfs_fd: &Dir) -> Result<()> {
    // Seconds for which we wait while warning
    const DELAY_SECONDS: u64 = 20;

    let host_root_dfd = &Dir::open_ambient_dir("/proc/1/root", cap_std::ambient_authority())?;
    let host_root_devstat = rustix::fs::fstatvfs(host_root_dfd)?;
    let target_devstat = rustix::fs::fstatvfs(rootfs_fd)?;
    if host_root_devstat.f_fsid != target_devstat.f_fsid {
        tracing::debug!("Not the host root");
        return Ok(());
    }
    let dashes = "----------------------------";
    let timeout = Duration::from_secs(DELAY_SECONDS);
    eprintln!("{dashes}");
    crate::utils::medium_visibility_warning(
        "WARNING: This operation will OVERWRITE THE BOOTED HOST ROOT FILESYSTEM and is NOT REVERSIBLE.",
    );
    eprintln!("Waiting {timeout:?} to continue; interrupt (Control-C) to cancel.");
    eprintln!("{dashes}");

    let bar = indicatif::ProgressBar::new_spinner();
    bar.enable_steady_tick(Duration::from_millis(100));
    std::thread::sleep(timeout);
    bar.finish();

    Ok(())
}

pub enum Cleanup {
    Skip,
    TriggerOnNextBoot,
}

/// Implementation of the `bootc install to-filesystem` CLI command.
#[context("Installing to filesystem")]
pub(crate) async fn install_to_filesystem(
    opts: InstallToFilesystemOpts,
    targeting_host_root: bool,
    cleanup: Cleanup,
) -> Result<()> {
    // Log the installation operation to systemd journal
    const INSTALL_FILESYSTEM_JOURNAL_ID: &str = "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3";
    let source_image = opts
        .source_opts
        .source_imgref
        .as_ref()
        .map(|s| s.as_str())
        .unwrap_or("none");
    let target_path = opts.filesystem_opts.root_path.as_str();

    tracing::info!(
        message_id = INSTALL_FILESYSTEM_JOURNAL_ID,
        bootc.source_image = source_image,
        bootc.target_path = target_path,
        bootc.targeting_host_root = if targeting_host_root { "true" } else { "false" },
        "Starting filesystem installation from {} to {}",
        source_image,
        target_path
    );

    // And the last bit of state here is the fsopts, which we also destructure now.
    let mut fsopts = opts.filesystem_opts;

    // If we're doing an alongside install, automatically set up the host rootfs
    // mount if it wasn't done already.
    if targeting_host_root
        && fsopts.root_path.as_str() == ALONGSIDE_ROOT_MOUNT
        && !fsopts.root_path.try_exists()?
    {
        tracing::debug!("Mounting host / to {ALONGSIDE_ROOT_MOUNT}");
        std::fs::create_dir(ALONGSIDE_ROOT_MOUNT)?;
        bootc_mount::bind_mount_from_pidns(
            bootc_mount::PID1,
            "/".into(),
            ALONGSIDE_ROOT_MOUNT.into(),
            true,
        )
        .context("Mounting host / to {ALONGSIDE_ROOT_MOUNT}")?;
    }

    let target_root_path = fsopts.root_path.clone();

    // Get a file descriptor for the root path /target
    let target_rootfs_fd =
        Dir::open_ambient_dir(&target_root_path, cap_std::ambient_authority())
            .with_context(|| format!("Opening target root directory {target_root_path}"))?;

    tracing::debug!("Target root filesystem: {target_root_path}");

    if let Some(false) = target_rootfs_fd.is_mountpoint(".")? {
        anyhow::bail!("Not a mountpoint: {target_root_path}");
    }

    // Check that the target is a directory
    {
        let root_path = &fsopts.root_path;
        let st = root_path
            .symlink_metadata()
            .with_context(|| format!("Querying target filesystem {root_path}"))?;
        if !st.is_dir() {
            anyhow::bail!("Not a directory: {root_path}");
        }
    }

    // If we're installing to an ostree root, then find the physical root from
    // the deployment root.
    let possible_physical_root = fsopts.root_path.join("sysroot");
    let possible_ostree_dir = possible_physical_root.join("ostree");
    let is_already_ostree = possible_ostree_dir.exists();
    if is_already_ostree {
        tracing::debug!(
            "ostree detected in {possible_ostree_dir}, assuming target is a deployment root and using {possible_physical_root}"
        );
        fsopts.root_path = possible_physical_root;
    };

    // Get a file descriptor for the root path
    // It will be /target/sysroot on ostree OS, or will be /target
    let rootfs_fd = if is_already_ostree {
        let root_path = &fsopts.root_path;
        let rootfs_fd = Dir::open_ambient_dir(&fsopts.root_path, cap_std::ambient_authority())
            .with_context(|| format!("Opening target root directory {root_path}"))?;

        tracing::debug!("Root filesystem: {root_path}");

        if let Some(false) = rootfs_fd.is_mountpoint(".")? {
            anyhow::bail!("Not a mountpoint: {root_path}");
        }
        rootfs_fd
    } else {
        target_rootfs_fd.try_clone()?
    };

    // Gather data about the root filesystem
    let inspect = bootc_mount::inspect_filesystem(&fsopts.root_path)?;

    // Gather global state, destructuring the provided options.
    // IMPORTANT: We might re-execute the current process in this function (for SELinux among other things)
    // IMPORTANT: and hence anything that is done before MUST BE IDEMPOTENT.
    // IMPORTANT: In practice, we should only be gathering information before this point,
    // IMPORTANT: and not performing any mutations at all.
    let state = prepare_install(
        opts.config_opts,
        opts.source_opts,
        opts.target_opts,
        opts.composefs_opts,
        Some(inspect.fstype.as_str().try_into()?),
    )
    .await?;

    // Check to see if this happens to be the real host root
    if !fsopts.acknowledge_destructive {
        warn_on_host_root(&target_rootfs_fd)?;
    }

    match fsopts.replace {
        Some(ReplaceMode::Wipe) => {
            let rootfs_fd = rootfs_fd.try_clone()?;
            println!("Wiping contents of root");
            tokio::task::spawn_blocking(move || remove_all_in_dir_no_xdev(&rootfs_fd, true))
                .await??;
        }
        Some(ReplaceMode::Alongside) => {
            clean_boot_directories(&target_rootfs_fd, &target_root_path, is_already_ostree)?
        }
        None => require_empty_rootdir(&rootfs_fd)?,
    }

    // We support overriding the mount specification for root (i.e. LABEL vs UUID versus
    // raw paths).
    // We also support an empty specification as a signal to omit any mountspec kargs.
    // CLI takes precedence over config file.
    let config_root_mount_spec = state
        .install_config
        .as_ref()
        .and_then(|c| c.root_mount_spec.as_ref());
    let root_info = if let Some(s) = fsopts.root_mount_spec.as_ref().or(config_root_mount_spec) {
        RootMountInfo {
            mount_spec: s.to_string(),
            kargs: Vec::new(),
        }
    } else if targeting_host_root {
        // In the to-existing-root case, look at /proc/cmdline
        let cmdline = bytes::Cmdline::from_proc()?;
        find_root_args_to_inherit(&cmdline, &inspect)?
    } else {
        // Otherwise, gather metadata from the provided root and use its provided UUID as a
        // default root= karg.
        let uuid = inspect
            .uuid
            .as_deref()
            .ok_or_else(|| anyhow!("No filesystem uuid found in target root"))?;
        let kargs = match inspect.fstype.as_str() {
            "btrfs" => {
                let subvol = crate::utils::find_mount_option(&inspect.options, "subvol");
                subvol
                    .map(|vol| format!("rootflags=subvol={vol}"))
                    .into_iter()
                    .collect::<Vec<_>>()
            }
            _ => Vec::new(),
        };
        RootMountInfo {
            mount_spec: format!("UUID={uuid}"),
            kargs,
        }
    };
    tracing::debug!("Root mount: {} {:?}", root_info.mount_spec, root_info.kargs);

    let boot_is_mount = {
        if let Some(boot_metadata) = target_rootfs_fd.symlink_metadata_optional(BOOT)? {
            let root_dev = rootfs_fd.dir_metadata()?.dev();
            let boot_dev = boot_metadata.dev();
            tracing::debug!("root_dev={root_dev} boot_dev={boot_dev}");
            root_dev != boot_dev
        } else {
            tracing::debug!("No /{BOOT} directory found");
            false
        }
    };
    // Find the UUID of /boot because we need it for GRUB.
    let boot_uuid = if boot_is_mount {
        let boot_path = target_root_path.join(BOOT);
        tracing::debug!("boot_path={boot_path}");
        let u = bootc_mount::inspect_filesystem(&boot_path)
            .with_context(|| format!("Inspecting /{BOOT}"))?
            .uuid
            .ok_or_else(|| anyhow!("No UUID found for /{BOOT}"))?;
        Some(u)
    } else {
        None
    };
    tracing::debug!("boot UUID: {boot_uuid:?}");

    // Find the real underlying backing device for the root.  This is currently just required
    // for GRUB (BIOS) and in the future zipl (I think).
    let backing_device = {
        let mut dev = inspect.source;
        loop {
            tracing::debug!("Finding parents for {dev}");
            let mut parents = bootc_blockdev::find_parent_devices(&dev)?.into_iter();
            let Some(parent) = parents.next() else {
                break;
            };
            if let Some(next) = parents.next() {
                anyhow::bail!(
                    "Found multiple parent devices {parent} and {next}; not currently supported"
                );
            }
            dev = parent;
        }
        dev
    };
    tracing::debug!("Backing device: {backing_device}");
    let device_info = bootc_blockdev::partitions_of(Utf8Path::new(&backing_device))?;

    let rootarg = format!("root={}", root_info.mount_spec);
    // CLI takes precedence over config file.
    let config_boot_mount_spec = state
        .install_config
        .as_ref()
        .and_then(|c| c.boot_mount_spec.as_ref());
    let mut boot = if let Some(spec) = fsopts.boot_mount_spec.as_ref().or(config_boot_mount_spec) {
        // An empty boot mount spec signals to omit the mountspec kargs
        // See https://github.com/bootc-dev/bootc/issues/1441
        if spec.is_empty() {
            None
        } else {
            Some(MountSpec::new(&spec, "/boot"))
        }
    } else {
        // Read /etc/fstab to get boot entry, but only use it if it's UUID-based
        // Otherwise fall back to boot_uuid
        read_boot_fstab_entry(&rootfs_fd)?
            .filter(|spec| spec.get_source_uuid().is_some())
            .or_else(|| {
                boot_uuid
                    .as_deref()
                    .map(|boot_uuid| MountSpec::new_uuid_src(boot_uuid, "/boot"))
            })
    };
    // Ensure that we mount /boot readonly because it's really owned by bootc/ostree
    // and we don't want e.g. apt/dnf trying to mutate it.
    if let Some(boot) = boot.as_mut() {
        boot.push_option("ro");
    }
    // By default, we inject a boot= karg because things like FIPS compliance currently
    // require checking in the initramfs.
    let bootarg = boot.as_ref().map(|boot| format!("boot={}", &boot.source));

    // If the root mount spec is empty, we omit the mounts kargs entirely.
    // https://github.com/bootc-dev/bootc/issues/1441
    let mut kargs = if root_info.mount_spec.is_empty() {
        Vec::new()
    } else {
        [rootarg]
            .into_iter()
            .chain(root_info.kargs)
            .collect::<Vec<_>>()
    };

    kargs.push(RW_KARG.to_string());

    if let Some(bootarg) = bootarg {
        kargs.push(bootarg);
    }

    let kargs = Cmdline::from(kargs.join(" "));

    let skip_finalize =
        matches!(fsopts.replace, Some(ReplaceMode::Alongside)) || fsopts.skip_finalize;
    let mut rootfs = RootSetup {
        #[cfg(feature = "install-to-disk")]
        luks_device: None,
        device_info,
        physical_root_path: fsopts.root_path,
        physical_root: rootfs_fd,
        target_root_path: Some(target_root_path.clone()),
        rootfs_uuid: inspect.uuid.clone(),
        boot,
        kargs,
        skip_finalize,
    };

    install_to_filesystem_impl(&state, &mut rootfs, cleanup).await?;

    // Drop all data about the root except the path to ensure any file descriptors etc. are closed.
    drop(rootfs);

    installation_complete();

    Ok(())
}

pub(crate) async fn install_to_existing_root(opts: InstallToExistingRootOpts) -> Result<()> {
    // Log the existing root installation operation to systemd journal
    const INSTALL_EXISTING_ROOT_JOURNAL_ID: &str = "7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1";
    let source_image = opts
        .source_opts
        .source_imgref
        .as_ref()
        .map(|s| s.as_str())
        .unwrap_or("none");
    let target_path = opts.root_path.as_str();

    tracing::info!(
        message_id = INSTALL_EXISTING_ROOT_JOURNAL_ID,
        bootc.source_image = source_image,
        bootc.target_path = target_path,
        bootc.cleanup = if opts.cleanup {
            "trigger_on_next_boot"
        } else {
            "skip"
        },
        "Starting installation to existing root from {} to {}",
        source_image,
        target_path
    );

    let cleanup = match opts.cleanup {
        true => Cleanup::TriggerOnNextBoot,
        false => Cleanup::Skip,
    };

    let opts = InstallToFilesystemOpts {
        filesystem_opts: InstallTargetFilesystemOpts {
            root_path: opts.root_path,
            root_mount_spec: None,
            boot_mount_spec: None,
            replace: opts.replace,
            skip_finalize: true,
            acknowledge_destructive: opts.acknowledge_destructive,
        },
        source_opts: opts.source_opts,
        target_opts: opts.target_opts,
        config_opts: opts.config_opts,
        composefs_opts: opts.composefs_opts,
    };

    install_to_filesystem(opts, true, cleanup).await
}

/// Read the /boot entry from /etc/fstab, if it exists
fn read_boot_fstab_entry(root: &Dir) -> Result<Option<MountSpec>> {
    let fstab_path = "etc/fstab";
    let fstab = match root.open_optional(fstab_path)? {
        Some(f) => f,
        None => return Ok(None),
    };

    let reader = std::io::BufReader::new(fstab);
    for line in std::io::BufRead::lines(reader) {
        let line = line?;
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Parse the mount spec
        let spec = MountSpec::from_str(line)?;

        // Check if this is a /boot entry
        if spec.target == "/boot" {
            return Ok(Some(spec));
        }
    }

    Ok(None)
}

pub(crate) async fn install_reset(opts: InstallResetOpts) -> Result<()> {
    let rootfs = &Dir::open_ambient_dir("/", cap_std::ambient_authority())?;
    if !opts.experimental {
        anyhow::bail!("This command requires --experimental");
    }

    let prog: ProgressWriter = opts.progress.try_into()?;

    let sysroot = &crate::cli::get_storage().await?;
    let ostree = sysroot.get_ostree()?;
    let repo = &ostree.repo();
    let (booted_ostree, _deployments, host) = crate::status::get_status_require_booted(ostree)?;

    let stateroots = list_stateroots(ostree)?;
    let target_stateroot = if let Some(s) = opts.stateroot {
        s
    } else {
        let now = chrono::Utc::now();
        let r = allocate_new_stateroot(&ostree, &stateroots, now)?;
        r.name
    };

    let booted_stateroot = booted_ostree.stateroot();
    assert!(booted_stateroot.as_str() != target_stateroot);
    let (fetched, spec) = if let Some(target) = opts.target_opts.imageref()? {
        let mut new_spec = host.spec;
        new_spec.image = Some(target.into());
        let fetched = crate::deploy::pull(
            repo,
            &new_spec.image.as_ref().unwrap(),
            None,
            opts.quiet,
            prog.clone(),
        )
        .await?;
        (fetched, new_spec)
    } else {
        let imgstate = host
            .status
            .booted
            .map(|b| b.query_image(repo))
            .transpose()?
            .flatten()
            .ok_or_else(|| anyhow::anyhow!("No image source specified"))?;
        (Box::new((*imgstate).into()), host.spec)
    };
    let spec = crate::deploy::RequiredHostSpec::from_spec(&spec)?;

    // Compute the kernel arguments to inherit. By default, that's only those involved
    // in the root filesystem.
    let mut kargs = crate::bootc_kargs::get_kargs_in_root(rootfs, std::env::consts::ARCH)?;

    // Extend with root kargs
    if !opts.no_root_kargs {
        let bootcfg = booted_ostree
            .deployment
            .bootconfig()
            .ok_or_else(|| anyhow!("Missing bootcfg for booted deployment"))?;
        if let Some(options) = bootcfg.get("options") {
            let options_cmdline = Cmdline::from(options.as_str());
            let root_kargs = crate::bootc_kargs::root_args_from_cmdline(&options_cmdline);
            kargs.extend(&root_kargs);
        }
    }

    // Extend with user-provided kargs
    if let Some(user_kargs) = opts.karg.as_ref() {
        for karg in user_kargs {
            kargs.extend(karg);
        }
    }

    let from = MergeState::Reset {
        stateroot: target_stateroot.clone(),
        kargs,
    };
    crate::deploy::stage(sysroot, from, &fetched, &spec, prog.clone(), false).await?;

    // Copy /boot entry from /etc/fstab to the new stateroot if it exists
    if let Some(boot_spec) = read_boot_fstab_entry(rootfs)? {
        let staged_deployment = ostree
            .staged_deployment()
            .ok_or_else(|| anyhow!("No staged deployment found"))?;
        let deployment_path = ostree.deployment_dirpath(&staged_deployment);
        let sysroot_dir = crate::utils::sysroot_dir(ostree)?;
        let deployment_root = sysroot_dir.open_dir(&deployment_path)?;

        // Write the /boot entry to /etc/fstab in the new deployment
        crate::lsm::atomic_replace_labeled(
            &deployment_root,
            "etc/fstab",
            0o644.into(),
            None,
            |w| writeln!(w, "{}", boot_spec.to_fstab()).map_err(Into::into),
        )?;

        tracing::debug!(
            "Copied /boot entry to new stateroot: {}",
            boot_spec.to_fstab()
        );
    }

    sysroot.update_mtime()?;

    if opts.apply {
        crate::reboot::reboot()?;
    }
    Ok(())
}

/// Implementation of `bootc install finalize`.
pub(crate) async fn install_finalize(target: &Utf8Path) -> Result<()> {
    // Log the installation finalization operation to systemd journal
    const INSTALL_FINALIZE_JOURNAL_ID: &str = "6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0";

    tracing::info!(
        message_id = INSTALL_FINALIZE_JOURNAL_ID,
        bootc.target_path = target.as_str(),
        "Starting installation finalization for target: {}",
        target
    );

    crate::cli::require_root(false)?;
    let sysroot = ostree::Sysroot::new(Some(&gio::File::for_path(target)));
    sysroot.load(gio::Cancellable::NONE)?;
    let deployments = sysroot.deployments();
    // Verify we find a deployment
    if deployments.is_empty() {
        anyhow::bail!("Failed to find deployment in {target}");
    }

    // Log successful finalization
    tracing::info!(
        message_id = INSTALL_FINALIZE_JOURNAL_ID,
        bootc.target_path = target.as_str(),
        "Successfully finalized installation for target: {}",
        target
    );

    // For now that's it! We expect to add more validation/postprocessing
    // later, such as munging `etc/fstab` if needed. See

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_opts_serializable() {
        let c: InstallToDiskOpts = serde_json::from_value(serde_json::json!({
            "device": "/dev/vda"
        }))
        .unwrap();
        assert_eq!(c.block_opts.device, "/dev/vda");
    }

    #[test]
    fn test_mountspec() {
        let mut ms = MountSpec::new("/dev/vda4", "/boot");
        assert_eq!(ms.to_fstab(), "/dev/vda4 /boot auto defaults 0 0");
        ms.push_option("ro");
        assert_eq!(ms.to_fstab(), "/dev/vda4 /boot auto ro 0 0");
        ms.push_option("relatime");
        assert_eq!(ms.to_fstab(), "/dev/vda4 /boot auto ro,relatime 0 0");
    }

    #[test]
    fn test_gather_root_args() {
        // A basic filesystem using a UUID
        let inspect = Filesystem {
            source: "/dev/vda4".into(),
            target: "/".into(),
            fstype: "xfs".into(),
            maj_min: "252:4".into(),
            options: "rw".into(),
            uuid: Some("965eb3c7-5a3f-470d-aaa2-1bcf04334bc6".into()),
            children: None,
        };
        let kargs = bytes::Cmdline::from("");
        let r = find_root_args_to_inherit(&kargs, &inspect).unwrap();
        assert_eq!(r.mount_spec, "UUID=965eb3c7-5a3f-470d-aaa2-1bcf04334bc6");

        let kargs = bytes::Cmdline::from(
            "root=/dev/mapper/root rw someother=karg rd.lvm.lv=root systemd.debug=1",
        );

        // In this case we take the root= from the kernel cmdline
        let r = find_root_args_to_inherit(&kargs, &inspect).unwrap();
        assert_eq!(r.mount_spec, "/dev/mapper/root");
        assert_eq!(r.kargs.len(), 1);
        assert_eq!(r.kargs[0], "rd.lvm.lv=root");

        // non-UTF8 data in non-essential parts of the cmdline should be ignored
        let kargs = bytes::Cmdline::from(
            b"root=/dev/mapper/root rw non-utf8=\xff rd.lvm.lv=root systemd.debug=1",
        );
        let r = find_root_args_to_inherit(&kargs, &inspect).unwrap();
        assert_eq!(r.mount_spec, "/dev/mapper/root");
        assert_eq!(r.kargs.len(), 1);
        assert_eq!(r.kargs[0], "rd.lvm.lv=root");

        // non-UTF8 data in `root` should fail
        let kargs = bytes::Cmdline::from(
            b"root=/dev/mapper/ro\xffot rw non-utf8=\xff rd.lvm.lv=root systemd.debug=1",
        );
        let r = find_root_args_to_inherit(&kargs, &inspect);
        assert!(r.is_err());

        // non-UTF8 data in `rd.` should fail
        let kargs = bytes::Cmdline::from(
            b"root=/dev/mapper/root rw non-utf8=\xff rd.lvm.lv=ro\xffot systemd.debug=1",
        );
        let r = find_root_args_to_inherit(&kargs, &inspect);
        assert!(r.is_err());
    }

    // As this is a unit test we don't try to test mountpoints, just verify
    // that we have the equivalent of rm -rf *
    #[test]
    fn test_remove_all_noxdev() -> Result<()> {
        let td = cap_std_ext::cap_tempfile::TempDir::new(cap_std::ambient_authority())?;

        td.create_dir_all("foo/bar/baz")?;
        td.write("foo/bar/baz/test", b"sometest")?;
        td.symlink_contents("/absolute-nonexistent-link", "somelink")?;
        td.write("toptestfile", b"othertestcontents")?;

        remove_all_in_dir_no_xdev(&td, true).unwrap();

        assert_eq!(td.entries()?.count(), 0);

        Ok(())
    }

    #[test]
    fn test_read_boot_fstab_entry() -> Result<()> {
        let td = cap_std_ext::cap_tempfile::TempDir::new(cap_std::ambient_authority())?;

        // Test with no /etc/fstab
        assert!(read_boot_fstab_entry(&td)?.is_none());

        // Test with /etc/fstab but no /boot entry
        td.create_dir("etc")?;
        td.write("etc/fstab", "UUID=test-uuid / ext4 defaults 0 0\n")?;
        assert!(read_boot_fstab_entry(&td)?.is_none());

        // Test with /boot entry
        let fstab_content = "\
# /etc/fstab
UUID=root-uuid / ext4 defaults 0 0
UUID=boot-uuid /boot ext4 ro 0 0
UUID=home-uuid /home ext4 defaults 0 0
";
        td.write("etc/fstab", fstab_content)?;
        let boot_spec = read_boot_fstab_entry(&td)?.unwrap();
        assert_eq!(boot_spec.source, "UUID=boot-uuid");
        assert_eq!(boot_spec.target, "/boot");
        assert_eq!(boot_spec.fstype, "ext4");
        assert_eq!(boot_spec.options, Some("ro".to_string()));

        // Test with /boot entry with comments
        let fstab_content = "\
# /etc/fstab
# Created by anaconda
UUID=root-uuid / ext4 defaults 0 0
# Boot partition
UUID=boot-uuid /boot ext4 defaults 0 0
";
        td.write("etc/fstab", fstab_content)?;
        let boot_spec = read_boot_fstab_entry(&td)?.unwrap();
        assert_eq!(boot_spec.source, "UUID=boot-uuid");
        assert_eq!(boot_spec.target, "/boot");

        Ok(())
    }

    #[test]
    fn test_require_dir_contains_only_mounts() -> Result<()> {
        // Test 1: Empty directory should fail (not a mount point)
        {
            let td = cap_std_ext::cap_tempfile::TempDir::new(cap_std::ambient_authority())?;
            td.create_dir("empty")?;
            assert!(require_dir_contains_only_mounts(&td, "empty").is_err());
        }

        // Test 2: Directory with only lost+found should succeed (lost+found is ignored)
        {
            let td = cap_std_ext::cap_tempfile::TempDir::new(cap_std::ambient_authority())?;
            td.create_dir_all("var/lost+found")?;
            assert!(require_dir_contains_only_mounts(&td, "var").is_ok());
        }

        // Test 3: Directory with a regular file should fail
        {
            let td = cap_std_ext::cap_tempfile::TempDir::new(cap_std::ambient_authority())?;
            td.create_dir("var")?;
            td.write("var/test.txt", b"content")?;
            assert!(require_dir_contains_only_mounts(&td, "var").is_err());
        }

        // Test 4: Nested directory structure with a file should fail
        {
            let td = cap_std_ext::cap_tempfile::TempDir::new(cap_std::ambient_authority())?;
            td.create_dir_all("var/lib/containers")?;
            td.write("var/lib/containers/storage.db", b"data")?;
            assert!(require_dir_contains_only_mounts(&td, "var").is_err());
        }

        // Test 5: boot directory with grub should fail (grub2 is not a mount and contains files)
        {
            let td = cap_std_ext::cap_tempfile::TempDir::new(cap_std::ambient_authority())?;
            td.create_dir_all("boot/grub2")?;
            td.write("boot/grub2/grub.cfg", b"config")?;
            assert!(require_dir_contains_only_mounts(&td, "boot").is_err());
        }

        // Test 6: Nested empty directories should fail (empty directories are not mount points)
        {
            let td = cap_std_ext::cap_tempfile::TempDir::new(cap_std::ambient_authority())?;
            td.create_dir_all("var/lib/containers")?;
            td.create_dir_all("var/log/journal")?;
            assert!(require_dir_contains_only_mounts(&td, "var").is_err());
        }

        // Test 7: Directory with lost+found and a file should fail (lost+found is ignored, but file is not allowed)
        {
            let td = cap_std_ext::cap_tempfile::TempDir::new(cap_std::ambient_authority())?;
            td.create_dir_all("var/lost+found")?;
            td.write("var/data.txt", b"content")?;
            assert!(require_dir_contains_only_mounts(&td, "var").is_err());
        }

        // Test 8: Directory with a symlink should fail
        {
            let td = cap_std_ext::cap_tempfile::TempDir::new(cap_std::ambient_authority())?;
            td.create_dir("var")?;
            td.symlink_contents("../usr/lib", "var/lib")?;
            assert!(require_dir_contains_only_mounts(&td, "var").is_err());
        }

        // Test 9: Deeply nested directory with a file should fail
        {
            let td = cap_std_ext::cap_tempfile::TempDir::new(cap_std::ambient_authority())?;
            td.create_dir_all("var/lib/containers/storage/overlay")?;
            td.write("var/lib/containers/storage/overlay/file.txt", b"data")?;
            assert!(require_dir_contains_only_mounts(&td, "var").is_err());
        }

        Ok(())
    }
}
