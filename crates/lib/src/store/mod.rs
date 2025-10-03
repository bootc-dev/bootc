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
use std::sync::Arc;

use anyhow::{Context, Result};
use cap_std_ext::cap_std;
use cap_std_ext::cap_std::fs::{Dir, DirBuilder, DirBuilderExt as _};
use cap_std_ext::dirext::CapStdExtDirExt;
use fn_error_context::context;

use ostree_ext::ostree;
use ostree_ext::sysroot::SysrootLock;
use rustix::fs::Mode;

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
pub const COMPOSEFS_MODE: Mode = Mode::from_raw_mode(0o700);

/// The path to the bootc root directory, relative to the physical
/// system root
pub(crate) const BOOTC_ROOT: &str = "ostree/bootc";

/// A reference to a physical filesystem root, plus
/// accessors for the different types of container storage.
pub(crate) struct Storage {
    /// Directory holding the physical root
    pub physical_root: Dir,

    /// The OSTree storage
    ostree: SysrootLock,
    /// The composefs storage
    composefs: OnceCell<Arc<ComposefsRepository>>,
    /// The containers-image storage used foR LBIs
    imgstore: OnceCell<CStorage>,

    /// Our runtime state
    run: Dir,
}

#[derive(Default)]
pub(crate) struct CachedImageStatus {
    pub image: Option<ImageStatus>,
    pub cached_update: Option<ImageStatus>,
}

impl Storage {
    pub fn new(sysroot: SysrootLock, run: &Dir) -> Result<Self> {
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

        Ok(Self {
            physical_root,
            ostree: sysroot,
            run,
            composefs: Default::default(),
            imgstore: Default::default(),
        })
    }

    /// Access the underlying ostree repository
    pub(crate) fn get_ostree(&self) -> Result<&SysrootLock> {
        Ok(&self.ostree)
    }

    /// Access the underlying ostree repository
    pub(crate) fn get_ostree_cloned(&self) -> Result<ostree::Sysroot> {
        let r = self.get_ostree()?;
        Ok((*r).clone())
    }

    /// Access the image storage; will automatically initialize it if necessary.
    pub(crate) fn get_ensure_imgstore(&self) -> Result<&CStorage> {
        if let Some(imgstore) = self.imgstore.get() {
            return Ok(imgstore);
        }
        let sysroot_dir = crate::utils::sysroot_dir(&self.ostree)?;

        let sepolicy = if self.ostree.booted_deployment().is_none() {
            // fallback to policy from container root
            // this should only happen during cleanup of a broken install
            tracing::trace!("falling back to container root's selinux policy");
            let container_root = Dir::open_ambient_dir("/", cap_std::ambient_authority())?;
            lsm::new_sepolicy_at(&container_root)?
        } else {
            // load the sepolicy from the booted ostree deployment so the imgstorage can be
            // properly labeled with /var/lib/container/storage labels
            tracing::trace!("loading sepolicy from booted ostree deployment");
            let dep = self.ostree.booted_deployment().unwrap();
            let dep_fs = deployment_fd(&self.ostree, &dep)?;
            lsm::new_sepolicy_at(&dep_fs)?
        };

        tracing::trace!("sepolicy in get_ensure_imgstore: {sepolicy:?}");

        let imgstore = CStorage::create(&sysroot_dir, &self.run, sepolicy.as_ref())?;
        Ok(self.imgstore.get_or_init(|| imgstore))
    }

    pub(crate) fn get_ensure_composefs(&self) -> Result<Arc<ComposefsRepository>> {
        if let Some(composefs) = self.composefs.get() {
            return Ok(Arc::clone(composefs));
        }

        let mut db = DirBuilder::new();
        db.mode(COMPOSEFS_MODE.as_raw_mode());
        self.physical_root.ensure_dir_with(COMPOSEFS, &db)?;

        let mut composefs =
            ComposefsRepository::open_path(&self.physical_root.open_dir(COMPOSEFS)?, ".")?;

        // Bootstrap verity off of the ostree state. In practice this means disabled by
        // default right now.
        let ostree_repo = &self.ostree.repo();
        let ostree_verity = ostree_ext::fsverity::is_verity_enabled(ostree_repo)?;
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
        let sysroot_dir =
            crate::utils::sysroot_dir(&self.ostree).context("Reopen sysroot directory")?;

        sysroot_dir
            .update_timestamps(std::path::Path::new(BOOTC_ROOT))
            .context("update_timestamps")
    }
}
