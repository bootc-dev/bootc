//! The [`Storage`] type holds references to three different types of
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
use bootc_mount::tempmount::TempMount;
use camino::Utf8PathBuf;
use cap_std_ext::cap_std;
use cap_std_ext::cap_std::fs::{
    Dir, DirBuilder, DirBuilderExt as _, Permissions, PermissionsExt as _,
};
use cap_std_ext::dirext::CapStdExtDirExt;
use fn_error_context::context;

use ocidir::cap_std::ambient_authority;
use ostree_ext::container_utils::ostree_booted;
use ostree_ext::prelude::FileExt;
use ostree_ext::sysroot::SysrootLock;
use ostree_ext::{gio, ostree};
use rustix::fs::Mode;

use crate::bootc_composefs::boot::{get_esp_partition, get_sysroot_parent_dev, mount_esp};
use crate::bootc_composefs::status::{ComposefsCmdline, composefs_booted, get_bootloader};
use crate::lsm;
use crate::podstorage::CStorage;
use crate::spec::{Bootloader, ImageStatus};
use crate::utils::{deployment_fd, open_dir_remount_rw};

/// See <https://github.com/containers/composefs-rs/issues/159>
pub type ComposefsRepository =
    composefs::repository::Repository<composefs::fsverity::Sha512HashValue>;
pub type ComposefsFilesystem = composefs::tree::FileSystem<composefs::fsverity::Sha512HashValue>;

/// Path to the physical root
pub const SYSROOT: &str = "sysroot";

/// The toplevel composefs directory path
pub const COMPOSEFS: &str = "composefs";

/// The mode for the composefs directory; this is intentionally restrictive
/// to avoid leaking information.
pub(crate) const COMPOSEFS_MODE: Mode = Mode::from_raw_mode(0o700);

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
                    composefs.set_insecure(true);
                }
                let composefs = Arc::new(composefs);

                // NOTE: This is assuming that we'll only have composefs in a UEFI system
                // We do have this assumptions in a lot of other places
                let parent = get_sysroot_parent_dev(&physical_root)?;
                let (esp_part, ..) = get_esp_partition(&parent)?;
                let esp_mount = mount_esp(&esp_part)?;

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
                    composefs: OnceCell::from(composefs),
                    imgstore: Default::default(),
                };

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
        })
    }

    /// Returns `boot_dir` if it exists
    pub(crate) fn require_boot_dir(&self) -> Result<&Dir> {
        self.boot_dir
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Boot dir not found"))
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
    pub(crate) fn get_ensure_composefs(
        &self,
        opt_path: Option<Utf8PathBuf>,
    ) -> Result<Arc<ComposefsRepository>> {
        if let Some(composefs) = self.composefs.get() {
            return Ok(Arc::clone(composefs));
        }

        let cfs_root = match opt_path {
            Some(path) => {
                let dir = Dir::open_ambient_dir(&path, ambient_authority())
                    .with_context(|| format!("Opening {path:?}"))?;

                ensure_composefs_dir(&dir)?;

                dir
            }
            None => {
                ensure_composefs_dir(&self.physical_root)?;
                self.physical_root.try_clone()?
            }
        };

        // Bootstrap verity off of the ostree state. In practice this means disabled by
        // default right now.
        let ostree = self.get_ostree()?;
        let ostree_repo = &ostree.repo();
        let ostree_verity = ostree_ext::fsverity::is_verity_enabled(ostree_repo)?;
        let mut composefs = ComposefsRepository::open_path(cfs_root.open_dir(COMPOSEFS)?, ".")?;
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
