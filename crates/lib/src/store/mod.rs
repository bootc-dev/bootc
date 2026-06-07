//! The [`Storage`] type holds references to three different types of
//! storage that together implement the unified storage model.
//!
//! # Three-store architecture
//!
//! Unified storage makes OS image data simultaneously visible in three
//! content-addressed stores that share physical disk blocks on a reflink-capable
//! filesystem (XFS, btrfs):
//!
//! 1. **bootc-owned containers-storage** at `/sysroot/ostree/bootc/storage`
//!    (overlay driver) — the image is accessible to podman and shares layers
//!    with Logically Bound Images.
//! 2. **composefs object store** at `/sysroot/composefs/objects/`
//!    (SHA-512 content-addressed) — used by composefs-boot to mount the
//!    rootfs as EROFS.  Populated from containers-storage via `FICLONE`
//!    (`composefs_oci::pull` with `ZeroCopy`).
//! 3. **ostree bare repo** at `/sysroot/ostree/repo/objects/`
//!    (SHA-256 content-addressed) — provides deployment, rollback, fsck, and
//!    delta updates.  Populated from the composefs object store via `FICLONE`
//!    (`import_from_composefs_repo`).
//!
//! Each `FICLONE` ioctl lets the kernel mark source and destination extents as
//! copy-on-write siblings with no userspace data movement. On ext4 (no
//! reflinks), the `enabled-with-copy` storage config falls back to a byte copy.
//!
//! ## Current implementation status
//!
//! The containers-storage → composefs step (arrow 1→2) is implemented for the
//! composefs boot backend in `crates/lib/src/bootc_composefs/repo.rs` via
//! `pull_composefs_unified`.  The composefs → ostree step (arrow 2→3) is
//! implemented via `import_from_composefs_repo`, wiring all three stores
//! together for the ostree backend through `pull_via_composefs`.
//!
//! A reconcile pass (`reconcile_unified_storage` in [`crate::image`]) runs
//! after `set-unified full` and on demand via `bootc image sync`, to ensure all
//! bootloader-pinned deployments (booted, rollback, staged) are present in
//! containers-storage even if they were originally deployed before unified
//! storage was enabled.  The reverse path (composefs → containers-storage) is
//! taken in that case: each layer is exported byte-exactly from the composefs
//! splitstreams and imported via skopeo into bootc's private overlay store.
//!
//! The remaining limitation is that the reverse-path export recompresses layer
//! blobs rather than reflink-sharing them; a native splitfdstream-based writer
//! will eliminate this in a future iteration.
//!
//! ## Long-term: Global composefs store
//!
//! The ultimate planned state (the "composefs-as-storage" plan) is to have
//! podman's composefs backend natively write objects to `/sysroot/composefs`
//! directly, bypassing even `containers-storage`. This would mean flatpak,
//! podman, and bootc all share exactly one global pool of content-addressed,
//! deduplicated files.
//!
//! ## Why composefs in the middle
//!
//! The old unified storage path (containers-storage → skopeo tar → ostree)
//! serialized layers twice. composefs-ctl's `ZeroCopy` pull mode instead walks
//! the overlay `diff/` directories and FICLONEs each file into the composefs
//! object store keyed by SHA-512 fsverity digest — no tar involved.
//! See [container-libs#144](https://github.com/containers/container-libs/issues/144).
//!
//! ## Why reflink and not hardlink between composefs and ostree
//!
//! composefs is content-addressed by SHA-512 of raw bytes: two paths with
//! identical content share one composefs inode. ostree bare mode stores
//! uid/gid/mode/xattrs including `security.selinux` on each inode. Two files
//! with the same bytes but different SELinux labels produce different ostree
//! checksums but share one composefs object. One inode can hold only one
//! `security.selinux` value, so hardlinking would silently corrupt labels.
//! Reflink gives each ostree object its own inode while sharing disk extents.
//!
//! ## Reflink probe
//!
//! The reflink probe is performed lazily and cached. It creates
//! two anonymous temporary files (via `O_TMPFILE`, no
//! cleanup needed), writes one byte to the source, and attempts
//! `ioctl(FICLONE)`. Returns `true` on success, `false` on `EOPNOTSUPP` or
//! `EXDEV`. The probe directory is `composefs/objects` if it already exists,
//! otherwise the physical root itself.
//!
//! # OSTree
//!
//! The default backend for the bootable container store; this
//! lives in `/ostree` in the physical root.
//!
//! # containers-storage:
//!
//! Later, bootc gained support for Logically Bound Images.
//! On ostree systems this is a `containers-storage:` instance that
//! lives in `/ostree/bootc/storage`.  On composefs systems the
//! physical location is `/composefs/bootc/storage` with a compat
//! symlink at `ostree/bootc -> ../composefs/bootc`.
//!
//! # composefs
//!
//! This lives in `/composefs` in the physical root.

use std::cell::OnceCell;
use std::collections::HashSet;
use std::ops::Deref;
use std::sync::Arc;

use anyhow::{Context, Result};
use bootc_mount::tempmount::TempMount;
use camino::Utf8PathBuf;
use cap_std_ext::cap_std;
use cap_std_ext::cap_std::fs::{
    Dir, DirBuilder, DirBuilderExt as _, Permissions, PermissionsExt as _,
};
use cap_std_ext::dirext::CapStdExtDirExt;
use fn_error_context::context;

use ostree_ext::container_utils::ostree_booted;
use ostree_ext::oci_spec::image::Digest;
use ostree_ext::prelude::FileExt;
use ostree_ext::sysroot::SysrootLock;
use ostree_ext::{gio, ostree};
use rustix::fs::{Mode, OFlags};

use composefs::fsverity::Sha512HashValue;
use composefs_ctl::composefs;

use crate::bootc_composefs::backwards_compat::bcompat_boot::prepend_custom_prefix;
use crate::bootc_composefs::boot::{EFI_LINUX, mount_esp};
use crate::bootc_composefs::status::{ComposefsCmdline, composefs_booted, get_bootloader};
use crate::lsm;
use crate::podstorage::CStorage;
use crate::spec::{Bootloader, ImageStatus};
use crate::utils::{deployment_fd, open_dir_remount_rw};

/// See <https://github.com/containers/composefs-rs/issues/159>
pub type ComposefsRepository = composefs::repository::Repository<Sha512HashValue>;

/// Path to the physical root
pub const SYSROOT: &str = "sysroot";

/// The toplevel composefs directory path
pub const COMPOSEFS: &str = "composefs";

/// The mode for the composefs directory; this is intentionally restrictive
/// to avoid leaking information.
pub(crate) const COMPOSEFS_MODE: Mode = Mode::from_raw_mode(0o700);

/// Path to bootc-specific metadata stored alongside the composefs `meta.json`.
///
/// This file records bootc-level configuration for the composefs repository,
/// such as whether unified base-image storage is enabled.  Its absence means
/// the system is not in unified-storage mode.  The path is relative to the
/// physical system root.
pub(crate) const BOOTC_REPO_META: &str = "composefs/bootc.json";

/// bootc-specific metadata stored in `composefs/bootc.json`.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct BootcRepoMeta {
    /// Schema version; currently must be 1.
    #[serde(default)]
    pub version: u32,

    /// Unified storage state for this system.  Matches the `storage.unified`
    /// field in `bootc status --json` and the `[install.storage] unified`
    /// install config.
    ///
    /// `disabled` (the default) means unified storage is not active.
    /// `enabled` means images were imported with FICLONE (reflinks required).
    /// `enabled-with-copy` means unified storage is active but byte-copy fallback
    /// is allowed (e.g. `storage.unified = "enabled-with-copy"` or
    /// onboarded via `bootc image set-unified full`).
    #[serde(default)]
    pub unified: crate::spec::UnifiedStorageState,
}

impl BootcRepoMeta {
    /// Read `composefs/bootc.json` from the physical root, if it exists.
    /// Returns `Ok(None)` when the file is absent (i.e. unified storage
    /// has never been enabled on this system).
    pub(crate) fn read(physical_root: &Dir) -> Result<Option<Self>> {
        match physical_root.open(BOOTC_REPO_META) {
            Ok(f) => {
                let meta: Self = serde_json::from_reader(std::io::BufReader::new(f))
                    .with_context(|| format!("Parsing {BOOTC_REPO_META}"))?;
                Ok(Some(meta))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("Opening {BOOTC_REPO_META}")),
        }
    }

    /// Write `composefs/bootc.json` to the physical root, atomically.
    /// The composefs directory must already exist.
    pub(crate) fn write(&self, physical_root: &Dir) -> Result<()> {
        let json = serde_json::to_string_pretty(self).context("Serializing BootcRepoMeta")?;
        // Write atomically via a temp file.
        let tmp = format!("{BOOTC_REPO_META}.tmp");
        physical_root
            .write(&tmp, json.as_bytes())
            .with_context(|| format!("Writing {tmp}"))?;
        physical_root
            .rename(&tmp, physical_root, BOOTC_REPO_META)
            .with_context(|| format!("Renaming {tmp} -> {BOOTC_REPO_META}"))?;
        Ok(())
    }
}

/// Ensure the composefs directory exists in the given physical root
/// with the correct permissions (mode 0700).
pub(crate) fn ensure_composefs_dir(physical_root: &Dir) -> Result<()> {
    let mut db = DirBuilder::new();
    db.mode(COMPOSEFS_MODE.as_raw_mode());
    physical_root
        .ensure_dir_with(COMPOSEFS, &db)
        .context("Creating composefs directory")?;
    // Always update permissions, in case the directory pre-existed
    // with incorrect mode (e.g. from an older version of bootc).
    physical_root
        .set_permissions(
            COMPOSEFS,
            Permissions::from_mode(COMPOSEFS_MODE.as_raw_mode()),
        )
        .context("Setting composefs directory permissions")?;
    Ok(())
}

/// The path to the bootc root directory, relative to the physical
/// system root.  On ostree systems this is a real directory; on composefs
/// systems it is a symlink to `../composefs/bootc` (see
/// [`ensure_composefs_bootc_link`]).
pub(crate) const BOOTC_ROOT: &str = "ostree/bootc";

/// The "real" bootc root for composefs-native systems, relative to the
/// physical system root.
pub(crate) const COMPOSEFS_BOOTC_ROOT: &str = "composefs/bootc";

/// On a composefs install the containers-storage lives under
/// `composefs/bootc/storage`.  To keep the rest of the code (and the
/// `/usr/lib/bootc/storage` symlink which points through `ostree/bootc`)
/// working, we create:
///
///   `ostree/bootc -> ../composefs/bootc`
///
/// This function is idempotent.
pub(crate) fn ensure_composefs_bootc_link(physical_root: &Dir) -> Result<()> {
    // Ensure the real directory exists
    physical_root
        .create_dir_all(COMPOSEFS_BOOTC_ROOT)
        .with_context(|| format!("Creating {COMPOSEFS_BOOTC_ROOT}"))?;

    // Create the `ostree/` parent if needed (it won't exist on a pure
    // composefs install that never touched ostree).
    physical_root
        .create_dir_all("ostree")
        .context("Creating ostree directory")?;

    // If ostree/bootc already exists as a real directory (e.g. from an
    // older install or from the ostree path), leave it alone — this
    // function is only for fresh composefs installs.
    match physical_root.symlink_metadata(BOOTC_ROOT) {
        Ok(meta) if meta.is_symlink() => {
            // Already a symlink — nothing to do
            return Ok(());
        }
        Ok(_meta) => {
            // It's a real directory.  This shouldn't happen during a fresh
            // composefs install, but if it does just leave it.
            tracing::warn!(
                "{BOOTC_ROOT} already exists as a directory, not replacing with symlink"
            );
            return Ok(());
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Good — doesn't exist yet, we'll create the symlink
        }
        Err(e) => return Err(e).context(format!("Querying {BOOTC_ROOT}")),
    }

    physical_root
        .symlink_contents(format!("../{COMPOSEFS_BOOTC_ROOT}"), BOOTC_ROOT)
        .with_context(|| format!("Creating {BOOTC_ROOT} -> ../{COMPOSEFS_BOOTC_ROOT} symlink"))?;

    tracing::info!("Created {BOOTC_ROOT} -> ../{COMPOSEFS_BOOTC_ROOT}");
    Ok(())
}

/// Storage accessor for a booted system.
///
/// This wraps [`Storage`] and can determine whether the system is booted
/// via ostree or composefs, providing a unified interface for both.
pub(crate) struct BootedStorage {
    pub(crate) storage: Storage,
}

impl Deref for BootedStorage {
    type Target = Storage;

    fn deref(&self) -> &Self::Target {
        &self.storage
    }
}

/// Represents an ostree-based boot environment
pub struct BootedOstree<'a> {
    pub(crate) sysroot: &'a SysrootLock,
    pub(crate) deployment: ostree::Deployment,
}

impl<'a> BootedOstree<'a> {
    /// Get the ostree repository
    pub(crate) fn repo(&self) -> ostree::Repo {
        self.sysroot.repo()
    }

    /// Get the stateroot name
    pub(crate) fn stateroot(&self) -> ostree::glib::GString {
        self.deployment.osname()
    }
}

/// Represents a composefs-based boot environment
#[allow(dead_code)]
pub struct BootedComposefs {
    pub repo: Arc<ComposefsRepository>,
    pub cmdline: &'static ComposefsCmdline,
}

/// Discriminated union representing the boot storage backend.
///
/// The runtime environment in which bootc is executing.
pub(crate) enum Environment {
    /// System booted via ostree
    OstreeBooted,
    /// System booted via composefs
    ComposefsBooted(ComposefsCmdline),
    /// Running in a container
    Container,
    /// Other (not booted via bootc)
    Other,
}

impl Environment {
    /// Detect the current runtime environment.
    pub(crate) fn detect() -> Result<Self> {
        if ostree_ext::container_utils::running_in_container() {
            return Ok(Self::Container);
        }

        if let Some(cmdline) = composefs_booted()? {
            return Ok(Self::ComposefsBooted(cmdline.clone()));
        }

        if ostree_booted()? {
            return Ok(Self::OstreeBooted);
        }

        Ok(Self::Other)
    }

    /// Returns true if this environment requires entering a mount namespace
    /// before loading storage (to avoid leaving /sysroot writable).
    pub(crate) fn needs_mount_namespace(&self) -> bool {
        matches!(self, Self::OstreeBooted | Self::ComposefsBooted(_))
    }
}

/// A system can boot via either ostree or composefs; this enum
/// allows code to handle both cases while maintaining type safety.
pub(crate) enum BootedStorageKind<'a> {
    Ostree(BootedOstree<'a>),
    Composefs(BootedComposefs),
}

/// Open the physical root (/sysroot) and /run directories for a booted system.
fn get_physical_root_and_run() -> Result<(Dir, Dir)> {
    let physical_root = {
        let d = Dir::open_ambient_dir("/sysroot", cap_std::ambient_authority())
            .context("Opening /sysroot")?;
        open_dir_remount_rw(&d, ".".into())?
    };
    let run =
        Dir::open_ambient_dir("/run", cap_std::ambient_authority()).context("Opening /run")?;
    Ok((physical_root, run))
}

impl BootedStorage {
    /// Create a new booted storage accessor for the given environment.
    ///
    /// The caller must have already called `prepare_for_write()` if
    /// `env.needs_mount_namespace()` is true.
    pub(crate) async fn new(env: Environment) -> Result<Option<Self>> {
        let r = match &env {
            Environment::ComposefsBooted(cmdline) => {
                let (physical_root, run) = get_physical_root_and_run()?;
                let mut composefs = ComposefsRepository::open_path(&physical_root, COMPOSEFS)?;
                if cmdline.allow_missing_fsverity {
                    composefs.set_insecure();
                }
                let composefs = Arc::new(composefs);

                // Locate ESP by walking up to the root disk(s)
                let root_dev = bootc_blockdev::list_dev_by_dir(&physical_root)?;
                let esp_dev = root_dev.find_first_colocated_esp()?;
                let esp_mount = mount_esp(&esp_dev.path())?;

                let boot_dir = match get_bootloader()? {
                    Bootloader::Grub => physical_root.open_dir("boot").context("Opening boot")?,
                    // NOTE: Handle XBOOTLDR partitions here if and when we use it
                    Bootloader::Systemd => esp_mount.fd.try_clone().context("Cloning fd")?,
                    Bootloader::None => unreachable!("Checked at install time"),
                };

                let storage = Storage {
                    physical_root,
                    physical_root_path: Utf8PathBuf::from("/sysroot"),
                    run,
                    boot_dir: Some(boot_dir),
                    esp: Some(esp_mount),
                    ostree: Default::default(),
                    composefs: OnceCell::from(composefs.clone()),
                    imgstore: Default::default(),
                    reflinks_supported: Default::default(),
                };

                // prepend_custom_prefix is idempotent: it checks has_prefix on each
                // entry and skips any that already have it, so it's safe to call on
                // every boot. This handles upgrades from older bootc versions that
                // lacked the prefix — we can't use meta.json presence as a trigger
                // because open_upgrade() in the initramfs writes meta.json before
                // userspace ever runs.
                let cmdline = composefs_booted()?
                    .ok_or_else(|| anyhow::anyhow!("Could not get booted composefs cmdline"))?;
                prepend_custom_prefix(&storage, &cmdline).await?;

                Some(Self { storage })
            }
            Environment::OstreeBooted => {
                // The caller must have entered a private mount namespace before
                // calling this function. This is because ostree's sysroot.load() will
                // remount /sysroot as writable, and we call set_mount_namespace_in_use()
                // to indicate we're in a mount namespace. Without actually being in a
                // mount namespace, this would leave the global /sysroot writable.
                let (physical_root, run) = get_physical_root_and_run()?;

                let sysroot = ostree::Sysroot::new_default();
                sysroot.set_mount_namespace_in_use();
                let sysroot = ostree_ext::sysroot::SysrootLock::new_from_sysroot(&sysroot).await?;
                sysroot.load(gio::Cancellable::NONE)?;

                let storage = Storage {
                    physical_root,
                    physical_root_path: Utf8PathBuf::from("/sysroot"),
                    run,
                    boot_dir: None,
                    esp: None,
                    ostree: OnceCell::from(sysroot),
                    composefs: Default::default(),
                    imgstore: Default::default(),
                    reflinks_supported: Default::default(),
                };

                Some(Self { storage })
            }
            // For container or non-bootc environments, there's no storage
            Environment::Container | Environment::Other => None,
        };
        Ok(r)
    }

    /// Determine the boot storage backend kind.
    ///
    /// Returns information about whether the system booted via ostree or composefs,
    /// along with the relevant sysroot/deployment or repository/cmdline data.
    pub(crate) fn kind(&self) -> Result<BootedStorageKind<'_>> {
        if let Some(cmdline) = composefs_booted()? {
            // SAFETY: This must have been set above in new()
            let repo = self.composefs.get().unwrap();
            Ok(BootedStorageKind::Composefs(BootedComposefs {
                repo: Arc::clone(repo),
                cmdline,
            }))
        } else {
            // SAFETY: This must have been set above in new()
            let sysroot = self.ostree.get().unwrap();
            let deployment = sysroot.require_booted_deployment()?;
            Ok(BootedStorageKind::Ostree(BootedOstree {
                sysroot,
                deployment,
            }))
        }
    }
}

/// True if `image_id` (a bare-hex containers-storage image ID) corresponds to
/// one of the composefs config `digests`.
///
/// A containers-storage image ID is the bare encoded value (e.g. the hex of a
/// sha256), whereas a [`Digest`] also carries an algorithm prefix. We compare
/// against [`Digest::digest`], the algorithm-agnostic encoded value, rather
/// than reconstructing an `algorithm:value` string by hand.
pub(crate) fn cstorage_id_matches_digest(digests: &HashSet<Digest>, image_id: &str) -> bool {
    digests.iter().any(|d| d.digest() == image_id)
}

/// A reference to a physical filesystem root, plus
/// accessors for the different types of container storage.
pub(crate) struct Storage {
    /// Directory holding the physical root
    pub physical_root: Dir,

    /// Absolute path to the physical root directory.
    /// This is `/sysroot` on a running system, or the target mount point during install.
    pub physical_root_path: Utf8PathBuf,

    /// The 'boot' directory, useful and `Some` only for composefs systems
    /// For grub booted systems, this points to `/sysroot/boot`
    /// For systemd booted systems, this points to the ESP
    pub boot_dir: Option<Dir>,

    /// The ESP mounted at a tmp location
    pub esp: Option<TempMount>,

    /// Our runtime state
    run: Dir,

    /// The OSTree storage
    ostree: OnceCell<SysrootLock>,
    /// The composefs storage
    composefs: OnceCell<Arc<ComposefsRepository>>,
    /// The containers-image storage used for LBIs
    imgstore: OnceCell<CStorage>,

    /// Cached result of the FICLONE reflink probe on `physical_root`.
    ///
    /// `true`  → the filesystem hosting `physical_root` supports reflinks;
    ///           determined by successfully cloning between two anonymous
    ///           tmpfiles created inside `physical_root` itself.
    /// `false` → FICLONE returned `EOPNOTSUPP`/`EXDEV` (e.g. ext4).
    ///
    /// Populated lazily on first call to [`Storage::reflinks_supported`].
    reflinks_supported: OnceCell<bool>,
}

/// Cached image status data used for optimization.
///
/// This stores the current image status and any cached update information
/// to avoid redundant fetches during status operations.
#[derive(Default)]
pub(crate) struct CachedImageStatus {
    pub image: Option<ImageStatus>,
    pub cached_update: Option<ImageStatus>,
}

impl Storage {
    /// Create a new storage accessor from an existing ostree sysroot.
    ///
    /// This is used for non-booted scenarios (e.g., `bootc install`) where
    /// we're operating on a target filesystem rather than the running system.
    pub fn new_ostree(sysroot: SysrootLock, run: &Dir) -> Result<Self> {
        let run = run.try_clone()?;

        // ostree has historically always relied on
        // having ostree -> sysroot/ostree as a symlink in the image to
        // make it so that code doesn't need to distinguish between booted
        // vs offline target. The ostree code all just looks at the ostree/
        // directory, and will follow the link in the booted case.
        //
        // For composefs we aren't going to do a similar thing, so here
        // we need to explicitly distinguish the two and the storage
        // here hence holds a reference to the physical root.
        let ostree_sysroot_dir = crate::utils::sysroot_dir(&sysroot)?;
        let (physical_root, physical_root_path) = if sysroot.is_booted() {
            (
                ostree_sysroot_dir.open_dir(SYSROOT)?,
                Utf8PathBuf::from("/sysroot"),
            )
        } else {
            // For non-booted case (install), get the path from the sysroot
            let path = sysroot.path();
            let path_str = path.parse_name().to_string();
            let path = Utf8PathBuf::from(path_str);
            (ostree_sysroot_dir, path)
        };

        let ostree_cell = OnceCell::new();
        let _ = ostree_cell.set(sysroot);

        Ok(Self {
            physical_root,
            physical_root_path,
            run,
            boot_dir: None,
            esp: None,
            ostree: ostree_cell,
            composefs: Default::default(),
            imgstore: Default::default(),
            reflinks_supported: Default::default(),
        })
    }

    /// Returns `boot_dir` if it exists
    pub(crate) fn require_boot_dir(&self) -> Result<&Dir> {
        self.boot_dir
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Boot dir not found"))
    }

    /// Returns the mounted `esp` if it exists
    pub(crate) fn require_esp(&self) -> Result<&TempMount> {
        self.esp
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("ESP not found"))
    }

    /// Returns the Directory where the Type1 boot binaries are stored
    /// `/sysroot/boot` for Grub, and ESP/EFI/Linux for systemd-boot
    pub(crate) fn bls_boot_binaries_dir(&self) -> Result<Dir> {
        let boot_dir = self.require_boot_dir()?;

        // boot dir in case of systemd-boot points to the ESP, but we store
        // the actual binaries inside ESP/EFI/Linux
        let boot_dir = match get_bootloader()? {
            Bootloader::Grub => boot_dir.try_clone()?,
            Bootloader::Systemd => {
                let boot_dir = boot_dir
                    .open_dir(EFI_LINUX)
                    .with_context(|| format!("Opening {EFI_LINUX}"))?;

                boot_dir
            }
            Bootloader::None => anyhow::bail!("Unknown bootloader"),
        };

        Ok(boot_dir)
    }

    /// Access the underlying ostree repository
    pub(crate) fn get_ostree(&self) -> Result<&SysrootLock> {
        self.ostree
            .get()
            .ok_or_else(|| anyhow::anyhow!("OSTree storage not initialized"))
    }

    /// Get a cloned reference to the ostree sysroot.
    ///
    /// This is used when code needs an owned `ostree::Sysroot` rather than
    /// a reference to the `SysrootLock`.
    pub(crate) fn get_ostree_cloned(&self) -> Result<ostree::Sysroot> {
        let r = self.get_ostree()?;
        Ok((*r).clone())
    }

    /// Access the image storage; will automatically initialize it if necessary.
    ///
    /// Works on both ostree and composefs-only systems.  On ostree the
    /// SELinux policy is loaded from the booted deployment; on composefs
    /// (where ostree isn't initialized) we fall back to the host root policy.
    pub(crate) fn get_ensure_imgstore(&self) -> Result<&CStorage> {
        if let Some(imgstore) = self.imgstore.get() {
            return Ok(imgstore);
        }

        let (sysroot_dir, sepolicy) = if let Ok(ostree) = self.get_ostree() {
            let sysroot_dir = crate::utils::sysroot_dir(ostree)?;
            let sepolicy = if ostree.booted_deployment().is_none() {
                tracing::trace!("falling back to container root's selinux policy");
                let container_root = Dir::open_ambient_dir("/", cap_std::ambient_authority())?;
                lsm::new_sepolicy_at(&container_root)?
            } else {
                tracing::trace!("loading sepolicy from booted ostree deployment");
                let dep = ostree.booted_deployment().unwrap();
                let dep_fs = deployment_fd(ostree, &dep)?;
                lsm::new_sepolicy_at(&dep_fs)?
            };
            (sysroot_dir, sepolicy)
        } else {
            // Composefs-only: ostree is not initialized. Use the physical
            // root directly and load SELinux policy from the host root.
            let sysroot_dir = self.physical_root.try_clone()?;
            let root = Dir::open_ambient_dir("/", cap_std::ambient_authority())?;
            let sepolicy = lsm::new_sepolicy_at(&root)?;
            (sysroot_dir, sepolicy)
        };

        tracing::trace!("sepolicy in get_ensure_imgstore: {sepolicy:?}");

        let imgstore = CStorage::create(&sysroot_dir, &self.run, sepolicy.as_ref())?;
        Ok(self.imgstore.get_or_init(|| imgstore))
    }

    /// Ensure (mode 0700) and return the absolute path of the OCI export
    /// scratch directory on the persistent sysroot filesystem.
    ///
    /// Used when reconstructing OCI images for export into the bootc
    /// containers-storage (reconcile, `fsck --repair`, push).  It lives inside
    /// the store root so it is on the same filesystem as the destination
    /// (reflinks work, no cross-device copy) and survives a volatile `/var` —
    /// writing to `/var/tmp` overflows when `/var` is a small tmpfs.
    ///
    /// An absolute path is returned (rather than a handle) so callers can hand
    /// a real filesystem path to skopeo, which — along with its forked helpers
    /// — resolves it in bootc's mount namespace rather than relying on fd
    /// inheritance.
    pub(crate) fn oci_scratch_dir(&self) -> Result<Utf8PathBuf> {
        const OCI_SCRATCH_SUBDIR: &str = "ostree/bootc/storage/tmp";
        let mut db = DirBuilder::new();
        db.recursive(true);
        db.mode(0o700);
        self.physical_root
            .ensure_dir_with(OCI_SCRATCH_SUBDIR, &db)
            .with_context(|| format!("Creating {OCI_SCRATCH_SUBDIR}"))?;
        Ok(self.physical_root_path.join(OCI_SCRATCH_SUBDIR))
    }

    /// Ensure the image storage is properly SELinux-labeled. This should be
    /// called after all image pulls are complete.
    pub(crate) fn ensure_imgstore_labeled(&self) -> Result<()> {
        if let Some(imgstore) = self.imgstore.get() {
            imgstore.ensure_labeled()?;
        }
        Ok(())
    }

    /// Access the composefs repository; will automatically initialize it if necessary.
    ///
    /// This lazily opens the composefs repository, creating the directory if needed
    /// and bootstrapping verity settings from the ostree configuration.
    pub(crate) fn get_ensure_composefs(&self) -> Result<Arc<ComposefsRepository>> {
        if let Some(composefs) = self.composefs.get() {
            return Ok(Arc::clone(composefs));
        }

        ensure_composefs_dir(&self.physical_root)?;

        // Bootstrap verity off of the ostree state. In practice this means disabled by
        // default right now.
        let ostree = self.get_ostree()?;
        let ostree_repo = &ostree.repo();
        let ostree_verity = ostree_ext::fsverity::is_verity_enabled(ostree_repo)?;
        let (mut composefs, _created) = ComposefsRepository::init_path(
            self.physical_root.open_dir(COMPOSEFS)?,
            ".",
            composefs::fsverity::Algorithm::SHA512,
            ostree_verity.enabled,
        )?;
        if !ostree_verity.enabled {
            tracing::debug!("Setting insecure mode for composefs repo");
            composefs.set_insecure();
        }
        let composefs = Arc::new(composefs);
        let r = Arc::clone(self.composefs.get_or_init(|| composefs));
        Ok(r)
    }

    /// Return the set of OCI config digests for every composefs-tagged image
    /// (tags prefixed with [`BOOTC_TAG_PREFIX`](crate::composefs_consts::BOOTC_TAG_PREFIX)).
    ///
    /// The config digest equals the containers-storage image ID and is stable
    /// across layer recompression, which is why we cross-reference on it rather
    /// than the manifest digest (which may change when layers are copied
    /// between stores).
    ///
    /// Returns an empty set when the composefs repository cannot be opened
    /// (e.g. an ostree-only / non-unified system); callers treat "no composefs"
    /// as "nothing is composefs-backed".
    pub(crate) fn composefs_config_digests(&self) -> Result<HashSet<Digest>> {
        use composefs_ctl::composefs_oci::{self, OciImage};

        let repo = match self.get_ensure_composefs() {
            Ok(r) => r,
            Err(_) => return Ok(HashSet::new()),
        };
        let digests = composefs_oci::list_refs(&*repo)
            .context("Listing composefs OCI refs")?
            .into_iter()
            .filter(|(tag, _)| tag.starts_with(crate::composefs_consts::BOOTC_TAG_PREFIX))
            .filter_map(|(_tag, manifest_digest)| {
                OciImage::<Sha512HashValue>::open(&*repo, &manifest_digest, None)
                    .ok()
                    .map(|img| img.manifest().config().digest().clone())
            })
            .collect();
        Ok(digests)
    }

    /// Return the set of containers-storage image *names* that must not be
    /// pruned because a composefs splitstream depends on the underlying
    /// containers-storage data.
    ///
    /// An image is protected when its containers-storage ID matches the config
    /// digest of a composefs-tagged image (see [`Self::composefs_config_digests`]).
    /// Names are returned (rather than IDs) because
    /// [`CStorage::prune_except_roots`](crate::podstorage::CStorage::prune_except_roots)
    /// matches prune roots by name.
    ///
    /// This is the reconciliation point for the boot-entry → image binding: the
    /// bootloader/GC logic asks storage which images are still anchored rather
    /// than reaching into the composefs repo itself.
    pub(crate) async fn composefs_protected_image_names(&self) -> Result<HashSet<String>> {
        let digests = self.composefs_config_digests()?;
        // Fast path: no composefs-tagged images means nothing to protect, so
        // avoid an unnecessary containers-storage listing.
        if digests.is_empty() {
            return Ok(HashSet::new());
        }

        let imgstore = self.get_ensure_imgstore()?;
        let names: HashSet<String> = imgstore
            .list_images()
            .await?
            .into_iter()
            .filter(|entry| cstorage_id_matches_digest(&digests, &entry.id))
            .flat_map(|entry| entry.names.into_iter().flatten())
            .collect();
        tracing::debug!("Composefs-protected containers-storage names: {names:?}");
        Ok(names)
    }

    /// Probe whether the filesystem hosting `physical_root` supports reflinks
    /// (FICLONE / copy-on-write extent sharing), caching the result.
    ///
    /// The probe creates two anonymous O_TMPFILE inodes inside `physical_root`
    /// and attempts `ioctl(FICLONE)` between them.  Because both files live on
    /// the same filesystem as the composefs and ostree repositories, a
    /// successful probe guarantees that reflinks will work between those repos.
    ///
    /// Returns `true` on XFS / btrfs, `false` on ext4 and anything else that
    /// returns `EOPNOTSUPP` / `EXDEV`.
    pub(crate) fn reflinks_supported(&self) -> Result<bool> {
        if let Some(&cached) = self.reflinks_supported.get() {
            return Ok(cached);
        }

        // Open the physical root as a plain rustix fd so we can use openat.
        let dir_fd = rustix::fs::open(
            self.physical_root_path.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .context("Opening physical root for reflink probe")?;

        // Source: an anonymous inode we write one byte into.
        let src = rustix::fs::openat(
            &dir_fd,
            c".",
            OFlags::RDWR | OFlags::TMPFILE | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .context("Creating source tmpfile for reflink probe")?;
        rustix::io::write(&src, b"x").context("Writing probe byte")?;

        // Destination: another anonymous inode to clone into.
        let dst = rustix::fs::openat(
            &dir_fd,
            c".",
            OFlags::RDWR | OFlags::TMPFILE | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .context("Creating dest tmpfile for reflink probe")?;

        let supported = match rustix::fs::ioctl_ficlone(&dst, &src) {
            Ok(()) => true,
            Err(rustix::io::Errno::OPNOTSUPP) | Err(rustix::io::Errno::XDEV) => false,
            Err(e) => {
                // Any other error (e.g. EPERM) is unexpected; log and assume not supported.
                tracing::warn!(
                    "Unexpected error probing reflink support: {e}; assuming unsupported"
                );
                false
            }
        };

        tracing::debug!(
            "Reflink probe on {}: {}",
            self.physical_root_path,
            supported
        );
        Ok(*self.reflinks_supported.get_or_init(|| supported))
    }

    /// Update the mtime on the storage root directory.
    ///
    /// This touches `ostree/bootc` (or its symlink target on composefs
    /// systems) so that `bootc-status-updated.path` fires.
    #[context("Updating storage root mtime")]
    pub(crate) fn update_mtime(&self) -> Result<()> {
        // On composefs-only systems ostree is not initialized, so fall
        // back to the physical root directly.
        let sysroot_dir = if let Ok(ostree) = self.get_ostree() {
            crate::utils::sysroot_dir(ostree).context("Reopen sysroot directory")?
        } else {
            self.physical_root.try_clone()?
        };

        sysroot_dir
            .update_timestamps(std::path::Path::new(BOOTC_ROOT))
            .context("update_timestamps")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The raw mode returned by metadata includes file type bits (S_IFDIR,
    /// etc.) in addition to permission bits. This constant masks to only
    /// the permission bits (owner/group/other rwx).
    const PERMS: Mode = Mode::from_raw_mode(0o777);

    #[test]
    fn test_ensure_composefs_dir_mode() -> Result<()> {
        use cap_std_ext::cap_primitives::fs::PermissionsExt as _;

        let td = cap_std_ext::cap_tempfile::TempDir::new(cap_std::ambient_authority())?;

        let assert_mode = || -> Result<()> {
            let perms = td.metadata(COMPOSEFS)?.permissions();
            let mode = Mode::from_raw_mode(perms.mode());
            assert_eq!(mode & PERMS, COMPOSEFS_MODE);
            Ok(())
        };

        ensure_composefs_dir(&td)?;
        assert_mode()?;

        // Calling again should be a no-op (ensure is idempotent)
        ensure_composefs_dir(&td)?;
        assert_mode()?;

        Ok(())
    }

    #[test]
    fn test_ensure_composefs_dir_fixes_existing() -> Result<()> {
        use cap_std_ext::cap_primitives::fs::PermissionsExt as _;

        let td = cap_std_ext::cap_tempfile::TempDir::new(cap_std::ambient_authority())?;

        // Create with overly permissive mode (simulating old bootc behavior)
        let mut db = DirBuilder::new();
        db.mode(0o755);
        td.create_dir_with(COMPOSEFS, &db)?;

        // Verify it starts with wrong permissions
        let perms = td.metadata(COMPOSEFS)?.permissions();
        let mode = Mode::from_raw_mode(perms.mode());
        assert_eq!(mode & PERMS, Mode::from_raw_mode(0o755));

        // ensure_composefs_dir should fix the permissions
        ensure_composefs_dir(&td)?;

        let perms = td.metadata(COMPOSEFS)?.permissions();
        let mode = Mode::from_raw_mode(perms.mode());
        assert_eq!(mode & PERMS, COMPOSEFS_MODE);

        Ok(())
    }
}
