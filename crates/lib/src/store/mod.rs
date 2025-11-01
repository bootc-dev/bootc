//! The [`Store`] holds references to three different types of
//! storage:
//!
//! # OSTree
//!
//! The default backend for the bootable container store; this
//! lives in `/ostree` in the physical root.
//!
//! # containers-storage:
//!
//! Later, bootc gained support for Logically Bound Images.
//! This is a `containers-storage:` instance that lives
//! in `/ostree/bootc/storage`
//!
//! # composefs
//!
//! This lives in `/composefs` in the physical root.

use std::cell::OnceCell;
use std::ops::Deref;
use std::sync::Arc;

use anyhow::{Context, Result};
use cap_std_ext::cap_std;
use cap_std_ext::cap_std::fs::{Dir, DirBuilder, DirBuilderExt as _};
use cap_std_ext::dirext::CapStdExtDirExt;
use fn_error_context::context;

use ostree_ext::sysroot::SysrootLock;
use ostree_ext::{gio, ostree};
use rustix::fs::Mode;

use crate::bootc_composefs::status::{composefs_booted, ComposefsCmdline};
use crate::lsm;
use crate::podstorage::CStorage;
use crate::spec::ImageStatus;
use crate::utils::deployment_fd;

/// See https://github.com/containers/composefs-rs/issues/159
pub type ComposefsRepository =
    composefs::repository::Repository<composefs::fsverity::Sha512HashValue>;
pub type ComposefsFilesystem = composefs::tree::FileSystem<composefs::fsverity::Sha512HashValue>;

/// Path to the physical root
pub const SYSROOT: &str = "sysroot";

/// The toplevel composefs directory path
pub const COMPOSEFS: &str = "composefs";
#[allow(dead_code)]
pub const COMPOSEFS_MODE: Mode = Mode::from_raw_mode(0o700);

/// The path to the bootc root directory, relative to the physical
/// system root
pub(crate) const BOOTC_ROOT: &str = "ostree/bootc";

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
/// A system can boot via either ostree or composefs; this enum
/// allows code to handle both cases while maintaining type safety.
pub(crate) enum BootedStorageKind<'a> {
    Ostree(BootedOstree<'a>),
    Composefs(BootedComposefs),
}

impl BootedStorage {
    /// Create a new booted storage accessor.
    ///
    /// This detects whether the system is booted via composefs or ostree
    /// and initializes the appropriate storage backend.
    pub(crate) async fn new() -> Result<Self> {
        let physical_root = Dir::open_ambient_dir("/sysroot", cap_std::ambient_authority())
            .context("Opening /sysroot")?;
        let run =
            Dir::open_ambient_dir("/run", cap_std::ambient_authority()).context("Opening /run")?;
        if let Some(cmdline) = composefs_booted()? {
            let mut composefs =
                ComposefsRepository::open_path(physical_root.open_dir(COMPOSEFS)?, ".")?;
            if cmdline.insecure {
                composefs.set_insecure(true);
            }
            let composefs = Arc::new(composefs);

            let storage = Storage {
                physical_root,
                run,
                ostree: Default::default(),
                composefs: OnceCell::from(composefs),
                imgstore: Default::default(),
            };
            Ok(Self { storage })
        } else {
            let sysroot = ostree::Sysroot::new_default();
            sysroot.set_mount_namespace_in_use();
            let sysroot = ostree_ext::sysroot::SysrootLock::new_from_sysroot(&sysroot).await?;
            sysroot.load(gio::Cancellable::NONE)?;
            // Verify this is a booted system
            let _ = sysroot.require_booted_deployment()?;

            let storage = Storage {
                physical_root,
                run,
                ostree: OnceCell::from(sysroot),
                composefs: Default::default(),
                imgstore: Default::default(),
            };
            Ok(Self { storage })
        }
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

/// A reference to a physical filesystem root, plus
/// accessors for the different types of container storage.
pub(crate) struct Storage {
    /// Directory holding the physical root
    pub physical_root: Dir,
    /// Our runtime state
    run: Dir,

    /// The OSTree storage
    ostree: OnceCell<SysrootLock>,
    /// The composefs storage
    composefs: OnceCell<Arc<ComposefsRepository>>,
    /// The containers-image storage used foR LBIs
    imgstore: OnceCell<CStorage>,
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
        let physical_root = if sysroot.is_booted() {
            ostree_sysroot_dir.open_dir(SYSROOT)?
        } else {
            ostree_sysroot_dir
        };

        let ostree_cell = OnceCell::new();
        let _ = ostree_cell.set(sysroot);

        Ok(Self {
            physical_root,
            run,
            ostree: ostree_cell,
            composefs: Default::default(),
            imgstore: Default::default(),
        })
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
    pub(crate) fn get_ensure_imgstore(&self) -> Result<&CStorage> {
        if let Some(imgstore) = self.imgstore.get() {
            return Ok(imgstore);
        }
        let ostree = self.get_ostree()?;
        let sysroot_dir = crate::utils::sysroot_dir(ostree)?;

        let sepolicy = if ostree.booted_deployment().is_none() {
            // fallback to policy from container root
            // this should only happen during cleanup of a broken install
            tracing::trace!("falling back to container root's selinux policy");
            let container_root = Dir::open_ambient_dir("/", cap_std::ambient_authority())?;
            lsm::new_sepolicy_at(&container_root)?
        } else {
            // load the sepolicy from the booted ostree deployment so the imgstorage can be
            // properly labeled with /var/lib/container/storage labels
            tracing::trace!("loading sepolicy from booted ostree deployment");
            let dep = ostree.booted_deployment().unwrap();
            let dep_fs = deployment_fd(ostree, &dep)?;
            lsm::new_sepolicy_at(&dep_fs)?
        };

        tracing::trace!("sepolicy in get_ensure_imgstore: {sepolicy:?}");

        let imgstore = CStorage::create(&sysroot_dir, &self.run, sepolicy.as_ref())?;
        Ok(self.imgstore.get_or_init(|| imgstore))
    }

    /// Access the composefs repository; will automatically initialize it if necessary.
    ///
    /// This lazily opens the composefs repository, creating the directory if needed
    /// and bootstrapping verity settings from the ostree configuration.
    pub(crate) fn get_ensure_composefs(&self) -> Result<Arc<ComposefsRepository>> {
        if let Some(composefs) = self.composefs.get() {
            return Ok(Arc::clone(composefs));
        }

        let mut db = DirBuilder::new();
        db.mode(COMPOSEFS_MODE.as_raw_mode());
        self.physical_root.ensure_dir_with(COMPOSEFS, &db)?;

        // Bootstrap verity off of the ostree state. In practice this means disabled by
        // default right now.
        let ostree = self.get_ostree()?;
        let ostree_repo = &ostree.repo();
        let ostree_verity = ostree_ext::fsverity::is_verity_enabled(ostree_repo)?;
        let mut composefs =
            ComposefsRepository::open_path(self.physical_root.open_dir(COMPOSEFS)?, ".")?;
        if !ostree_verity.enabled {
            tracing::debug!("Setting insecure mode for composefs repo");
            composefs.set_insecure(true);
        }
        let composefs = Arc::new(composefs);
        let r = Arc::clone(self.composefs.get_or_init(|| composefs));
        Ok(r)
    }

    /// Update the mtime on the storage root directory
    #[context("Updating storage root mtime")]
    pub(crate) fn update_mtime(&self) -> Result<()> {
        let ostree = self.get_ostree()?;
        let sysroot_dir = crate::utils::sysroot_dir(ostree).context("Reopen sysroot directory")?;

        sysroot_dir
            .update_timestamps(std::path::Path::new(BOOTC_ROOT))
            .context("update_timestamps")
    }
}
