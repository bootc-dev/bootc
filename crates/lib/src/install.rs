//! # Writing a container to a block device in a bootable way
//!
//! This module supports installing a bootc-compatible image to
//! a block device directly via the `install` verb, or to an externally
//! set up filesystem via `install to-filesystem`.

// This sub-module is the "basic" installer that handles creating basic block device
// and filesystem setup.
#[cfg(feature = "install-to-disk")]
pub(crate) mod baseline;
pub(crate) mod completion;
pub(crate) mod config;
mod osbuild;
pub(crate) mod osconfig;

use std::collections::HashMap;
use std::fs::create_dir_all;
use std::io::Write;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, ensure, Context, Result};
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
use chrono::prelude::*;
use clap::ValueEnum;
use fn_error_context::context;
use ostree::gio;
use ostree_ext::composefs::{
    fsverity::{FsVerityHashValue, Sha256HashValue},
    repository::Repository as ComposefsRepository,
    util::Sha256Digest,
};
use ostree_ext::composefs_boot::{
    bootloader::BootEntry, write_boot::write_boot_simple as composefs_write_boot_simple, BootOps,
};
use ostree_ext::composefs_oci::{
    image::create_filesystem as create_composefs_filesystem, pull as composefs_oci_pull,
};
use ostree_ext::oci_spec;
use ostree_ext::ostree;
use ostree_ext::ostree_prepareroot::{ComposefsState, Tristate};
use ostree_ext::prelude::Cast;
use ostree_ext::sysroot::SysrootLock;
use ostree_ext::{
    container as ostree_container, container::ImageReference as OstreeExtImgRef, ostree_prepareroot,
};
#[cfg(feature = "install-to-disk")]
use rustix::fs::FileTypeExt;
use rustix::fs::MetadataExt as _;
use serde::{Deserialize, Serialize};

#[cfg(feature = "install-to-disk")]
use self::baseline::InstallBlockDeviceOpts;
use crate::boundimage::{BoundImage, ResolvedBoundImage};
use crate::containerenv::ContainerExecutionInfo;
use crate::deploy::{prepare_for_pull, pull_from_prepared, PreparedImportMeta, PreparedPullResult};
use crate::lsm;
use crate::progress_jsonl::ProgressWriter;
use crate::spec::ImageReference;
use crate::store::Storage;
use crate::task::Task;
use crate::utils::sigpolicy_from_opt;
use bootc_mount::Filesystem;

/// The toplevel boot directory
const BOOT: &str = "boot";
/// Directory for transient runtime state
#[cfg(feature = "install-to-disk")]
const RUN_BOOTC: &str = "/run/bootc";
/// The default path for the host rootfs
const ALONGSIDE_ROOT_MOUNT: &str = "/target";
/// Global flag to signal the booted system was provisioned via an alongside bootc install
const DESTRUCTIVE_CLEANUP: &str = "bootc-destructive-cleanup";
/// This is an ext4 special directory we need to ignore.
const LOST_AND_FOUND: &str = "lost+found";
/// The filename of the composefs EROFS superblock; TODO move this into ostree
const OSTREE_COMPOSEFS_SUPER: &str = ".ostree.cfs";
/// The mount path for selinux
const SELINUXFS: &str = "/sys/fs/selinux";
/// The mount path for uefi
const EFIVARFS: &str = "/sys/firmware/efi/efivars";
pub(crate) const ARCH_USES_EFI: bool = cfg!(any(target_arch = "x86_64", target_arch = "aarch64"));

const DEFAULT_REPO_CONFIG: &[(&str, &str)] = &[
    // Default to avoiding grub2-mkconfig etc.
    ("sysroot.bootloader", "none"),
    // Always flip this one on because we need to support alongside installs
    // to systems without a separate boot partition.
    ("sysroot.bootprefix", "true"),
    ("sysroot.readonly", "true"),
];

/// Kernel argument used to specify we want the rootfs mounted read-write by default
const RW_KARG: &str = "rw";

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
    /// Example: --karg=nosmt --karg=console=ttyS0,114800n8
    #[clap(long)]
    karg: Option<Vec<String>>,

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
}

#[derive(ValueEnum, Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub(crate) enum BootType {
    #[default]
    Bls,
    Uki,
}

#[derive(Debug, Clone, clap::Parser, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct InstallComposefsOpts {
    #[clap(long, value_enum, default_value_t)]
    pub(crate) boot: BootType,
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

    #[clap(long)]
    pub(crate) composefs_native: bool,

    #[clap(flatten)]
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

    /// Source device specification for the root filesystem.  For example, UUID=2e9f4241-229b-4202-8429-62d2302382e1
    ///
    /// If not provided, the UUID of the target filesystem will be used.
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

    // If Some, then --composefs_native is passed
    pub(crate) composefs_options: Option<InstallComposefsOpts>,
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

    fn stateroot(&self) -> &str {
        self.config_opts
            .stateroot
            .as_deref()
            .unwrap_or(ostree_ext::container::deploy::STATEROOT_DEFAULT)
    }
}

/// Path to initially deployed version information
const BOOTC_ALEPH_PATH: &str = ".bootc-aleph.json";

/// The "aleph" version information is injected into /root/.bootc-aleph.json
/// and contains the image ID that was initially used to install.  This can
/// be used to trace things like the specific version of `mkfs.ext4` or
/// kernel version that was used.
#[derive(Debug, Serialize)]
struct InstallAleph {
    /// Digested pull spec for installed image
    image: String,
    /// The version number
    version: Option<String>,
    /// The timestamp
    timestamp: Option<chrono::DateTime<Utc>>,
    /// The `uname -r` of the kernel doing the installation
    kernel: String,
    /// The state of SELinux at install time
    selinux: String,
}

/// A mount specification is a subset of a line in `/etc/fstab`.
///
/// There are 3 (ASCII) whitespace separated values:
///
/// SOURCE TARGET [OPTIONS]
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
            anyhow::bail!("Invalid empty mount specification");
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

impl InstallToDiskOpts {
    pub(crate) fn validate(&self) -> Result<()> {
        if !self.composefs_native {
            // Reject using --boot without --composefs
            if self.composefs_opts.boot != BootType::default() {
                anyhow::bail!("--boot must not be provided without --composefs");
            }
        }

        Ok(())
    }
}

impl InstallAleph {
    #[context("Creating aleph data")]
    pub(crate) fn new(
        src_imageref: &ostree_container::OstreeImageReference,
        imgstate: &ostree_container::store::LayeredImageState,
        selinux_state: &SELinuxFinalState,
    ) -> Result<Self> {
        let uname = rustix::system::uname();
        let labels = crate::status::labels_of_config(&imgstate.configuration);
        let timestamp = labels
            .and_then(|l| {
                l.get(oci_spec::image::ANNOTATION_CREATED)
                    .map(|s| s.as_str())
            })
            .and_then(bootc_utils::try_deserialize_timestamp);
        let r = InstallAleph {
            image: src_imageref.imgref.name.clone(),
            version: imgstate.version().as_ref().map(|s| s.to_string()),
            timestamp,
            kernel: uname.release().to_str()?.to_string(),
            selinux: selinux_state.to_aleph().to_string(),
        };
        Ok(r)
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

        let commit = Task::new("Reading ostree commit", "ostree")
            .args(["--repo=/ostree/repo", "rev-parse", "--single"])
            .quiet()
            .read()?;
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

pub(crate) fn print_configuration() -> Result<()> {
    let mut install_config = config::load_config()?.unwrap_or_default();
    install_config.filter_to_external();
    let stdout = std::io::stdout().lock();
    anyhow::Ok(install_config.to_canon_json_writer(stdout)?)
}

#[context("Creating ostree deployment")]
async fn initialize_ostree_root(
    state: &State,
    root_setup: &RootSetup,
) -> Result<(Storage, bool, crate::imgstorage::Storage)> {
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

    // And also label /boot AKA xbootldr, if it exists
    if rootfs_dir.try_exists("boot")? {
        crate::lsm::ensure_dir_labeled(rootfs_dir, "boot", None, 0o755.into(), sepolicy)?;
    }

    for (k, v) in DEFAULT_REPO_CONFIG.iter() {
        Command::new("ostree")
            .args(["config", "--repo", "ostree/repo", "set", k, v])
            .cwd_dir(rootfs_dir.try_clone()?)
            .run()?;
    }

    let sysroot = {
        let path = format!("/proc/self/fd/{}", rootfs_dir.as_fd().as_raw_fd());
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

    let imgstore = crate::imgstorage::Storage::create(&sysroot_dir, &temp_run, sepolicy)?;

    sysroot.load(cancellable)?;
    let sysroot = SysrootLock::new_from_sysroot(&sysroot).await?;
    Ok((Storage::new(sysroot, &temp_run)?, has_ostree, imgstore))
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
    has_ostree: bool,
) -> Result<(ostree::Deployment, InstallAleph)> {
    let sepolicy = state.load_policy()?;
    let sepolicy = sepolicy.as_ref();
    let stateroot = state.stateroot();

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

        let proxy_cfg = ostree_container::store::ImageProxyConfig::default();
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

    let pulled_image = match prepare_for_pull(repo, &spec_imgref, Some(&state.target_imgref))
        .await?
    {
        PreparedPullResult::AlreadyPresent(existing) => existing,
        PreparedPullResult::Ready(image_meta) => {
            check_disk_space(root_setup.physical_root.as_fd(), &image_meta, &spec_imgref)?;
            pull_from_prepared(&spec_imgref, false, ProgressWriter::default(), image_meta).await?
        }
    };

    repo.set_disable_fsync(false);

    // We need to read the kargs from the target merged ostree commit before
    // we do the deployment.
    let merged_ostree_root = sysroot
        .repo()
        .read_commit(pulled_image.ostree_commit.as_str(), gio::Cancellable::NONE)?
        .0;
    let kargsd = crate::kargs::get_kargs_from_ostree_root(
        &sysroot.repo(),
        merged_ostree_root.downcast_ref().unwrap(),
        std::env::consts::ARCH,
    )?;
    let kargsd = kargsd.iter().map(|s| s.as_str());

    // Keep this in sync with install/completion.rs for the Anaconda fixups
    let install_config_kargs = state
        .install_config
        .as_ref()
        .and_then(|c| c.kargs.as_ref())
        .into_iter()
        .flatten()
        .map(|s| s.as_str());
    // Final kargs, in order:
    // - root filesystem kargs
    // - install config kargs
    // - kargs.d from container image
    // - args specified on the CLI
    let kargs = root_setup
        .kargs
        .iter()
        .map(|v| v.as_str())
        .chain(install_config_kargs)
        .chain(kargsd)
        .chain(state.config_opts.karg.iter().flatten().map(|v| v.as_str()))
        .collect::<Vec<_>>();
    let mut options = ostree_container::deploy::DeployOpts::default();
    options.kargs = Some(kargs.as_slice());
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
    if let Some(boot) = root_setup.boot.as_ref() {
        crate::lsm::atomic_replace_labeled(&root, "etc/fstab", 0o644.into(), sepolicy, |w| {
            writeln!(w, "{}", boot.to_fstab()).map_err(Into::into)
        })?;
    }

    if let Some(contents) = state.root_ssh_authorized_keys.as_deref() {
        osconfig::inject_root_ssh_authorized_keys(&root, sepolicy, contents)?;
    }

    let aleph = InstallAleph::new(&src_imageref, &imgstate, &state.selinux_state)?;
    Ok((deployment, aleph))
}

/// Run a command in the host mount namespace
pub(crate) fn run_in_host_mountns(cmd: &str) -> Command {
    let mut c = Command::new("/proc/self/exe");
    c.lifecycle_bind()
        .args(["exec-in-host-mount-namespace", cmd]);
    c
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
    Err(Command::new(cmd).args(args).exec()).context("exec")?
}

pub(crate) struct RootSetup {
    #[cfg(feature = "install-to-disk")]
    luks_device: Option<String>,
    device_info: bootc_blockdev::PartitionTable,
    /// Absolute path to the location where we've mounted the physical
    /// root filesystem for the system we're installing.
    physical_root_path: Utf8PathBuf,
    /// Directory file descriptor for the above physical root.
    physical_root: Dir,
    rootfs_uuid: Option<String>,
    /// True if we should skip finalizing
    skip_finalize: bool,
    boot: Option<MountSpec>,
    kargs: Vec<String>,
}

fn require_boot_uuid(spec: &MountSpec) -> Result<&str> {
    spec.get_source_uuid()
        .ok_or_else(|| anyhow!("/boot is not specified via UUID= (this is currently required)"))
}

impl RootSetup {
    /// Get the UUID= mount specifier for the /boot filesystem; if there isn't one, the root UUID will
    /// be returned.
    fn get_boot_uuid(&self) -> Result<Option<&str>> {
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
        Task::new("Flushing filesystem journal", "fsfreeze")
            .quiet()
            .cwd(root)?
            .args([a, path.as_str()])
            .run()?;
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
    ensure!(pid1_uid == 0, "{proc1} is owned by {pid1_uid}, not zero; this command must be run in the root user namespace (e.g. not rootless podman)");
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
        Task::new("Mounting tmpfs /tmp", "mount")
            .args(["tmpfs", "-t", "tmpfs", "/tmp"])
            .quiet()
            .run()?;
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
    Task::new(format!("Mounting {fstype} {fspath}"), "mount")
        .args(["-t", fstype, fstype, fspath])
        .quiet()
        .run()?;

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
    config_opts: InstallConfigOpts,
    source_opts: InstallSourceOpts,
    target_opts: InstallTargetOpts,
    composefs_opts: Option<InstallComposefsOpts>,
) -> Result<Arc<State>> {
    tracing::trace!("Preparing install");
    let rootfs = cap_std::fs::Dir::open_ambient_dir("/", cap_std::ambient_authority())
        .context("Opening /")?;

    let host_is_container = crate::containerenv::is_container(&rootfs);
    let external_source = source_opts.source_imgref.is_some();
    let source = match source_opts.source_imgref {
        None => {
            ensure!(host_is_container, "Either --source-imgref must be defined or this command must be executed inside a podman container.");

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

            SourceInfo::from_container(&rootfs, &container_info)?
        }
        Some(source) => {
            crate::cli::require_root(false)?;
            SourceInfo::from_imageref(&source, &rootfs)?
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

    // We need to access devices that are set up by the host udev
    bootc_mount::ensure_mirrored_host_mount("/dev")?;
    // We need to read our own container image (and any logically bound images)
    // from the host container store.
    bootc_mount::ensure_mirrored_host_mount("/var/lib/containers")?;
    // In some cases we may create large files, and it's better not to have those
    // in our overlayfs.
    bootc_mount::ensure_mirrored_host_mount("/var/tmp")?;
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
    if install_config.is_some() {
        tracing::debug!("Loaded install configuration");
    } else {
        tracing::debug!("No install configuration found");
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
        target_imgref,
        install_config,
        prepareroot_config,
        root_ssh_authorized_keys,
        container_root: rootfs,
        tempdir,
        host_is_container,
        composefs_options: composefs_opts,
    });

    Ok(state)
}

/// Given a baseline root filesystem with an ostree sysroot initialized:
/// - install the container to that root
/// - install the bootloader
/// - Other post operations, such as pulling bound images
async fn install_with_sysroot(
    state: &State,
    rootfs: &RootSetup,
    sysroot: &Storage,
    boot_uuid: &str,
    bound_images: BoundImages,
    has_ostree: bool,
    imgstore: &crate::imgstorage::Storage,
) -> Result<()> {
    // And actually set up the container in that root, returning a deployment and
    // the aleph state (see below).
    let (_deployment, aleph) = install_container(state, rootfs, &sysroot, has_ostree).await?;
    // Write the aleph data that captures the system state at the time of provisioning for aid in future debugging.
    rootfs
        .physical_root
        .atomic_replace_with(BOOTC_ALEPH_PATH, |f| {
            anyhow::Ok(aleph.to_canon_json_writer(f)?)
        })
        .context("Writing aleph version")?;

    if cfg!(target_arch = "s390x") {
        // TODO: Integrate s390x support into install_via_bootupd
        crate::bootloader::install_via_zipl(&rootfs.device_info, boot_uuid)?;
    } else {
        crate::bootloader::install_via_bootupd(
            &rootfs.device_info,
            &rootfs.physical_root_path,
            &state.config_opts,
        )?;
    }
    tracing::debug!("Installed bootloader");

    tracing::debug!("Perfoming post-deployment operations");

    match bound_images {
        BoundImages::Skip => {}
        BoundImages::Resolved(resolved_bound_images) => {
            // Now copy each bound image from the host's container storage into the target.
            for image in resolved_bound_images {
                let image = image.image.as_str();
                imgstore.pull_from_host_storage(image).await?;
            }
        }
        BoundImages::Unresolved(bound_images) => {
            crate::boundimage::pull_images_impl(imgstore, bound_images)
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

fn open_composefs_repo(rootfs_dir: &Dir) -> Result<ComposefsRepository<Sha256HashValue>> {
    ComposefsRepository::open_path(rootfs_dir, "composefs")
        .context("Failed to open composefs repository")
}

async fn initialize_composefs_repository(
    state: &State,
    root_setup: &RootSetup,
) -> Result<(Sha256Digest, impl FsVerityHashValue)> {
    let rootfs_dir = &root_setup.physical_root;

    rootfs_dir
        .create_dir_all("composefs")
        .context("Creating dir 'composefs'")?;

    tracing::warn!("STATE: {state:#?}");

    let repo = open_composefs_repo(rootfs_dir)?;

    let OstreeExtImgRef {
        name: image_name,
        transport,
    } = &state.source.imageref;

    // transport's display is already of type "<transport_type>:"
    composefs_oci_pull(&Arc::new(repo), &format!("{transport}{image_name}",), None).await
}

#[context("Setting up BLS boot")]
fn setup_composefs_bls_boot(
    root_setup: &RootSetup,
    // TODO: Make this generic
    repo: ComposefsRepository<Sha256HashValue>,
    id: &Sha256HashValue,
    entry: BootEntry<Sha256HashValue>,
) -> Result<()> {
    let rootfs_uuid = match &root_setup.rootfs_uuid {
        Some(u) => u,
        None => anyhow::bail!("Expected rootfs to have a UUID by now"),
    };

    let cmdline_refs = [
        "console=ttyS0,115200",
        &format!("root=UUID={rootfs_uuid}"),
        "rw",
    ];

    composefs_write_boot_simple(
        &repo,
        entry,
        &id,
        root_setup.physical_root_path.as_std_path(), // /run/mounts/bootc/boot
        Some("boot"),
        Some(&format!("{}", id.to_hex())),
        &cmdline_refs,
    )?;

    Ok(())
}

#[context("Setting up UKI boot")]
fn setup_composefs_uki_boot(
    root_setup: &RootSetup,
    // TODO: Make this generic
    repo: ComposefsRepository<Sha256HashValue>,
    id: &Sha256HashValue,
    entry: BootEntry<Sha256HashValue>,
) -> Result<()> {
    let rootfs_uuid = match &root_setup.rootfs_uuid {
        Some(u) => u,
        None => anyhow::bail!("Expected rootfs to have a UUID by now"),
    };

    let boot_dir = root_setup.physical_root_path.join("boot");
    create_dir_all(&boot_dir).context("Failed to create boot dir")?;

    composefs_write_boot_simple(
        &repo,
        entry,
        &id,
        boot_dir.as_std_path(),
        None,
        Some(&format!("{}", id.to_hex())),
        &[],
    )?;

    // Add the user grug cfg
    // TODO: We don't need this for BLS. Have a flag for BLS vs UKI, or maybe we can figure it out
    // via the boot entries above
    let grub_user_config = format!(
        r#"
menuentry "Fedora Bootc UKI" {{
    insmod fat
    insmod chain
    search --no-floppy --set=root --fs-uuid {rootfs_uuid}
    chainloader /boot/EFI/Linux/{uki_id}.efi
}}
"#,
        uki_id = id.to_hex()
    );

    std::fs::write(boot_dir.join("grub2/user.cfg"), grub_user_config)
        .context("Failed to write grub2/user.cfg")?;

    Ok(())
}

#[context("Setting up composefs boot")]
fn setup_composefs_boot(root_setup: &RootSetup, state: &State, image_id: &str) -> Result<()> {
    let boot_uuid = root_setup
        .get_boot_uuid()?
        .or(root_setup.rootfs_uuid.as_deref())
        .ok_or_else(|| anyhow!("No uuid for boot/root"))?;

    if cfg!(target_arch = "s390x") {
        // TODO: Integrate s390x support into install_via_bootupd
        crate::bootloader::install_via_zipl(&root_setup.device_info, boot_uuid)?;
    } else {
        crate::bootloader::install_via_bootupd(
            &root_setup.device_info,
            &root_setup.physical_root_path,
            &state.config_opts,
        )?;
    }

    let repo = open_composefs_repo(&root_setup.physical_root)?;

    let mut fs = create_composefs_filesystem(&repo, image_id, None)?;

    let entries = fs.transform_for_boot(&repo)?;
    let id = fs.commit_image(&repo, None)?;

    println!("{entries:#?}");

    let Some(entry) = entries.into_iter().next() else {
        anyhow::bail!("No boot entries!");
    };

    let Some(composefs_opts) = &state.composefs_options else {
        anyhow::bail!("Could not find options for composefs")
    };

    match composefs_opts.boot {
        BootType::Bls => setup_composefs_bls_boot(root_setup, repo, &id, entry)?,
        BootType::Uki => setup_composefs_uki_boot(root_setup, repo, &id, entry)?,
    };

    let state_path = root_setup
        .physical_root_path
        .join(format!("state/{}", id.to_hex()));

    create_dir_all(state_path.join("var"))?;
    create_dir_all(state_path.join("etc/upper"))?;
    create_dir_all(state_path.join("etc/work"))?;

    Ok(())
}

async fn install_to_filesystem_impl(
    state: &State,
    rootfs: &mut RootSetup,
    cleanup: Cleanup,
) -> Result<()> {
    if matches!(state.selinux_state, SELinuxFinalState::ForceTargetDisabled) {
        rootfs.kargs.push("selinux=0".to_string());
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

    // We verify this upfront because it's currently required by bootupd
    let boot_uuid = rootfs
        .get_boot_uuid()?
        .or(rootfs.rootfs_uuid.as_deref())
        .ok_or_else(|| anyhow!("No uuid for boot/root"))?;
    tracing::debug!("boot uuid={boot_uuid}");

    let bound_images = BoundImages::from_state(state).await?;

    if state.composefs_options.is_some() {
        // Load a fd for the mounted target physical root
        let (id, verity) = initialize_composefs_repository(state, rootfs).await?;

        tracing::warn!(
            "id = {id}, verity = {verity}",
            id = hex::encode(id),
            verity = verity.to_hex()
        );

        setup_composefs_boot(rootfs, state, &hex::encode(id))?;
    } else {
        // Initialize the ostree sysroot (repo, stateroot, etc.)

        {
            let (sysroot, has_ostree, imgstore) = initialize_ostree_root(state, rootfs).await?;

            install_with_sysroot(
                state,
                rootfs,
                &sysroot,
                &boot_uuid,
                bound_images,
                has_ostree,
                &imgstore,
            )
            .await?;

            if matches!(cleanup, Cleanup::TriggerOnNextBoot) {
                let sysroot_dir = crate::utils::sysroot_dir(&sysroot)?;
                tracing::debug!("Writing {DESTRUCTIVE_CLEANUP}");
                sysroot_dir.atomic_write(format!("etc/{}", DESTRUCTIVE_CLEANUP), b"")?;
            }

            // We must drop the sysroot here in order to close any open file
            // descriptors.
        };

        // Run this on every install as the penultimate step
        install_finalize(&rootfs.physical_root_path).await?;
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
    opts.validate()?;

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
        if opts.composefs_native {
            Some(opts.composefs_opts)
        } else {
            None
        },
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

#[context("Verifying empty rootfs")]
fn require_empty_rootdir(rootfs_fd: &Dir) -> Result<()> {
    for e in rootfs_fd.entries()? {
        let e = DirEntryUtf8::from_cap_std(e?);
        let name = e.file_name()?;
        if name == LOST_AND_FOUND {
            continue;
        }
        // There must be a boot directory (that is empty)
        if name == BOOT {
            let mut entries = rootfs_fd.read_dir(BOOT)?;
            if let Some(e) = entries.next() {
                let e = DirEntryUtf8::from_cap_std(e?);
                let name = e.file_name()?;
                if matches!(name.as_str(), LOST_AND_FOUND | crate::bootloader::EFI_DIR) {
                    continue;
                }
                anyhow::bail!("Non-empty boot directory, found {name}");
            }
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

#[context("Removing boot directory content")]
fn clean_boot_directories(rootfs: &Dir, is_ostree: bool) -> Result<()> {
    let bootdir =
        crate::utils::open_dir_remount_rw(rootfs, BOOT.into()).context("Opening /boot")?;

    if is_ostree {
        // On ostree systems, the boot directory already has our desired format, we should only
        // remove the bootupd-state.json file to avoid bootupctl complaining it already exists.
        bootdir
            .remove_file_optional("bootupd-state.json")
            .context("removing bootupd-state.json")?;
    } else {
        // This should not remove /boot/efi note.
        remove_all_in_dir_no_xdev(&bootdir, false).context("Emptying /boot")?;
        // TODO: Discover the ESP the same way bootupd does it; we should also
        // support not wiping the ESP.
        if ARCH_USES_EFI {
            if let Some(efidir) = bootdir
                .open_dir_optional(crate::bootloader::EFI_DIR)
                .context("Opening /boot/efi")?
            {
                remove_all_in_dir_no_xdev(&efidir, false)
                    .context("Emptying EFI system partition")?;
            }
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
fn find_root_args_to_inherit(cmdline: &[&str], root_info: &Filesystem) -> Result<RootMountInfo> {
    let cmdline = || cmdline.iter().copied();
    let root = crate::kernel::find_first_cmdline_arg(cmdline(), "root");
    // If we have a root= karg, then use that
    let (mount_spec, kargs) = if let Some(root) = root {
        let rootflags = cmdline().find(|arg| arg.starts_with(crate::kernel::ROOTFLAGS));
        let inherit_kargs =
            cmdline().filter(|arg| arg.starts_with(crate::kernel::INITRD_ARG_PREFIX));
        (
            root.to_owned(),
            rootflags
                .into_iter()
                .chain(inherit_kargs)
                .map(ToOwned::to_owned)
                .collect(),
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

/// Implementation of the `bootc install to-filsystem` CLI command.
#[context("Installing to filesystem")]
pub(crate) async fn install_to_filesystem(
    opts: InstallToFilesystemOpts,
    targeting_host_root: bool,
    cleanup: Cleanup,
) -> Result<()> {
    // Gather global state, destructuring the provided options.
    // IMPORTANT: We might re-execute the current process in this function (for SELinux among other things)
    // IMPORTANT: and hence anything that is done before MUST BE IDEMPOTENT.
    // IMPORTANT: In practice, we should only be gathering information before this point,
    // IMPORTANT: and not performing any mutations at all.
    let state = prepare_install(opts.config_opts, opts.source_opts, opts.target_opts, None).await?;
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

    // Check to see if this happens to be the real host root
    if !fsopts.acknowledge_destructive {
        let root_path = &fsopts.root_path;
        let rootfs_fd = Dir::open_ambient_dir(root_path, cap_std::ambient_authority())
            .with_context(|| format!("Opening target root directory {root_path}"))?;
        warn_on_host_root(&rootfs_fd)?;
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
    let rootfs_fd = {
        let root_path = &fsopts.root_path;
        let rootfs_fd = Dir::open_ambient_dir(&fsopts.root_path, cap_std::ambient_authority())
            .with_context(|| format!("Opening target root directory {root_path}"))?;

        tracing::debug!("Root filesystem: {root_path}");

        if let Some(false) = rootfs_fd.is_mountpoint(".")? {
            anyhow::bail!("Not a mountpoint: {root_path}");
        }
        rootfs_fd
    };

    match fsopts.replace {
        Some(ReplaceMode::Wipe) => {
            let rootfs_fd = rootfs_fd.try_clone()?;
            println!("Wiping contents of root");
            tokio::task::spawn_blocking(move || remove_all_in_dir_no_xdev(&rootfs_fd, true))
                .await??;
        }
        Some(ReplaceMode::Alongside) => clean_boot_directories(&rootfs_fd, is_already_ostree)?,
        None => require_empty_rootdir(&rootfs_fd)?,
    }

    // Gather data about the root filesystem
    let inspect = bootc_mount::inspect_filesystem(&fsopts.root_path)?;

    // We support overriding the mount specification for root (i.e. LABEL vs UUID versus
    // raw paths).
    let root_info = if let Some(s) = fsopts.root_mount_spec {
        RootMountInfo {
            mount_spec: s.to_string(),
            kargs: Vec::new(),
        }
    } else if targeting_host_root {
        // In the to-existing-root case, look at /proc/cmdline
        let cmdline = crate::kernel::parse_cmdline()?;
        let cmdline = cmdline.iter().map(|s| s.as_str()).collect::<Vec<_>>();
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
        let root_dev = rootfs_fd.dir_metadata()?.dev();
        let boot_dev = rootfs_fd
            .symlink_metadata_optional(BOOT)?
            .ok_or_else(|| {
                anyhow!("No /{BOOT} directory found in root; this is is currently required")
            })?
            .dev();
        tracing::debug!("root_dev={root_dev} boot_dev={boot_dev}");
        root_dev != boot_dev
    };
    // Find the UUID of /boot because we need it for GRUB.
    let boot_uuid = if boot_is_mount {
        let boot_path = fsopts.root_path.join(BOOT);
        let u = bootc_mount::inspect_filesystem(&boot_path)
            .context("Inspecting /{BOOT}")?
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
    let mut boot = if let Some(spec) = fsopts.boot_mount_spec {
        Some(MountSpec::new(&spec, "/boot"))
    } else {
        boot_uuid
            .as_deref()
            .map(|boot_uuid| MountSpec::new_uuid_src(boot_uuid, "/boot"))
    };
    // Ensure that we mount /boot readonly because it's really owned by bootc/ostree
    // and we don't want e.g. apt/dnf trying to mutate it.
    if let Some(boot) = boot.as_mut() {
        boot.push_option("ro");
    }
    // By default, we inject a boot= karg because things like FIPS compliance currently
    // require checking in the initramfs.
    let bootarg = boot.as_ref().map(|boot| format!("boot={}", &boot.source));
    let kargs = [rootarg]
        .into_iter()
        .chain(root_info.kargs)
        .chain([RW_KARG.to_string()])
        .chain(bootarg)
        .collect::<Vec<_>>();

    let skip_finalize =
        matches!(fsopts.replace, Some(ReplaceMode::Alongside)) || fsopts.skip_finalize;
    let mut rootfs = RootSetup {
        #[cfg(feature = "install-to-disk")]
        luks_device: None,
        device_info,
        physical_root_path: fsopts.root_path,
        physical_root: rootfs_fd,
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
    };

    install_to_filesystem(opts, true, cleanup).await
}

/// Implementation of `bootc install finalize`.
pub(crate) async fn install_finalize(target: &Utf8Path) -> Result<()> {
    crate::cli::require_root(false)?;
    let sysroot = ostree::Sysroot::new(Some(&gio::File::for_path(target)));
    sysroot.load(gio::Cancellable::NONE)?;
    let deployments = sysroot.deployments();
    // Verify we find a deployment
    if deployments.is_empty() {
        anyhow::bail!("Failed to find deployment in {target}");
    }

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
        let r = find_root_args_to_inherit(&[], &inspect).unwrap();
        assert_eq!(r.mount_spec, "UUID=965eb3c7-5a3f-470d-aaa2-1bcf04334bc6");

        // In this case we take the root= from the kernel cmdline
        let r = find_root_args_to_inherit(
            &[
                "root=/dev/mapper/root",
                "rw",
                "someother=karg",
                "rd.lvm.lv=root",
                "systemd.debug=1",
            ],
            &inspect,
        )
        .unwrap();
        assert_eq!(r.mount_spec, "/dev/mapper/root");
        assert_eq!(r.kargs.len(), 1);
        assert_eq!(r.kargs[0], "rd.lvm.lv=root");
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
}
