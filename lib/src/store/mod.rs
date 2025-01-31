use std::cell::OnceCell;
use std::env;
use std::ops::Deref;

use anyhow::{Context, Result};
use cap_std_ext::cap_std::fs::Dir;
use cap_std_ext::dirext::CapStdExtDirExt;
use clap::ValueEnum;
use fn_error_context::context;

use ostree_ext::container::OstreeImageReference;
use ostree_ext::keyfileext::KeyFileExt;
use ostree_ext::ostree;
use ostree_ext::sysroot::SysrootLock;

use crate::spec::ImageStatus;

mod ostree_container;

/// The path to the bootc root directory, relative to the physical
/// system root
pub(crate) const BOOTC_ROOT: &str = "ostree/bootc";
/// The ostree repo config option to enable fsverity
pub(crate) const REPO_VERITY_CONFIG: &str = "ex-integrity.fsverity";

pub(crate) struct Storage {
    pub sysroot: SysrootLock,
    run: Dir,
    imgstore: OnceCell<crate::imgstorage::Storage>,
    pub store: Box<dyn ContainerImageStoreImpl>,
}

#[derive(Default)]
pub(crate) struct CachedImageStatus {
    pub image: Option<ImageStatus>,
    pub cached_update: Option<ImageStatus>,
}

pub(crate) trait ContainerImageStore {
    fn store(&self) -> Result<Option<Box<dyn ContainerImageStoreImpl>>>;
}

pub(crate) trait ContainerImageStoreImpl {
    fn spec(&self) -> crate::spec::Store;

    fn imagestatus(
        &self,
        sysroot: &SysrootLock,
        deployment: &ostree::Deployment,
        image: OstreeImageReference,
    ) -> Result<CachedImageStatus>;
}

impl Deref for Storage {
    type Target = SysrootLock;

    fn deref(&self) -> &Self::Target {
        &self.sysroot
    }
}

impl Storage {
    pub fn new(sysroot: SysrootLock, run: &Dir) -> Result<Self> {
        let run = run.try_clone()?;
        let store = match env::var("BOOTC_STORAGE") {
            Ok(val) => crate::spec::Store::from_str(&val, true).unwrap_or_else(|_| {
                let default = crate::spec::Store::default();
                tracing::warn!("Unknown BOOTC_STORAGE option {val}, falling back to {default:?}");
                default
            }),
            Err(_) => crate::spec::Store::default(),
        };

        let store = load(store);

        Ok(Self {
            sysroot,
            run,
            store,
            imgstore: Default::default(),
        })
    }

    /// Access the image storage; will automatically initialize it if necessary.
    pub(crate) fn get_ensure_imgstore(&self) -> Result<&crate::imgstorage::Storage> {
        if let Some(imgstore) = self.imgstore.get() {
            return Ok(imgstore);
        }
        let sysroot_dir = crate::utils::sysroot_dir(&self.sysroot)?;
        let imgstore = crate::imgstorage::Storage::create(&sysroot_dir, &self.run)?;
        Ok(self.imgstore.get_or_init(|| imgstore))
    }

    /// Update the mtime on the storage root directory
    #[context("Updating storage root mtime")]
    pub(crate) fn update_mtime(&self) -> Result<()> {
        let sysroot_dir =
            crate::utils::sysroot_dir(&self.sysroot).context("Reopen sysroot directory")?;

        sysroot_dir
            .update_timestamps(std::path::Path::new(BOOTC_ROOT))
            .context("update_timestamps")
            .map_err(Into::into)
    }
}

impl ContainerImageStore for ostree::Deployment {
    fn store<'a>(&self) -> Result<Option<Box<dyn ContainerImageStoreImpl>>> {
        if let Some(origin) = self.origin().as_ref() {
            if let Some(store) = origin.optional_string("bootc", "backend")? {
                let store =
                    crate::spec::Store::from_str(&store, true).map_err(anyhow::Error::msg)?;
                Ok(Some(load(store)))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }
}

pub(crate) fn load(ty: crate::spec::Store) -> Box<dyn ContainerImageStoreImpl> {
    match ty {
        crate::spec::Store::OstreeContainer => Box::new(ostree_container::OstreeContainerStore),
    }
}
