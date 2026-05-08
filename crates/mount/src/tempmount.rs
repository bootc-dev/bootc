use std::os::fd::AsFd;
use std::path::Path;

use anyhow::{Context, Result};

use camino::Utf8Path;
use cap_std_ext::cap_std::{ambient_authority, fs::Dir};
use fn_error_context::context;
use rustix::mount::{MountFlags, MoveMountFlags, UnmountFlags, move_mount, unmount};

/// RAII guard that synchronously unmounts a path on drop, flushing all writes.
///
/// Prefer this over `MNT_DETACH` when the mounted filesystem has received
/// writes (e.g. FAT ESP) and you need them flushed before the guard drops.
#[derive(Debug)]
pub struct MountGuard(std::path::PathBuf);

impl MountGuard {
    /// Mount `dev` at `path` and return a guard that will synchronously
    /// unmount it on drop.
    pub fn mount(
        dev: &str,
        path: std::path::PathBuf,
        fstype: &str,
        flags: MountFlags,
        data: Option<&std::ffi::CStr>,
    ) -> Result<Self> {
        rustix::mount::mount(dev, &path, fstype, flags, data)
            .with_context(|| format!("Mounting {} at {}", dev, path.display()))?;
        Ok(Self(path))
    }
}

impl std::ops::Deref for MountGuard {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for MountGuard {
    fn drop(&mut self) {
        if let Err(e) = unmount(&self.0, UnmountFlags::empty()) {
            // Synchronous unmount failure may mean buffered writes were not
            // flushed to the underlying device (e.g. FAT ESP).  Treat this as
            // an error rather than a warning.
            tracing::error!("Failed to unmount {}: {e:?}", self.0.display());
        }
    }
}

/// RAII wrapper for a temporary mount that is automatically unmounted on drop.
#[derive(Debug)]
pub struct TempMount {
    /// The backing temporary directory.
    pub dir: tempfile::TempDir,
    /// An open handle to the mounted directory.
    pub fd: Dir,
}

impl TempMount {
    /// Mount device/partition on a tempdir which will be automatically unmounted on drop
    #[context("Mounting {dev}")]
    pub fn mount_dev(
        dev: &str,
        fstype: &str,
        flags: MountFlags,
        data: Option<&std::ffi::CStr>,
    ) -> Result<Self> {
        let tempdir = tempfile::TempDir::new()?;

        let utf8path = Utf8Path::from_path(tempdir.path())
            .ok_or(anyhow::anyhow!("Failed to convert path to UTF-8 Path"))?;

        rustix::mount::mount(dev, utf8path.as_std_path(), fstype, flags, data)?;

        let fd = Dir::open_ambient_dir(tempdir.path(), ambient_authority())
            .with_context(|| format!("Opening {:?}", tempdir.path()));

        let fd = match fd {
            Ok(fd) => fd,
            Err(e) => {
                unmount(tempdir.path(), UnmountFlags::DETACH)?;
                Err(e)?
            }
        };

        Ok(Self { dir: tempdir, fd })
    }

    /// Mount and fd acquired with `open_tree` like syscall
    #[context("Mounting fd")]
    pub fn mount_fd(mnt_fd: impl AsFd) -> Result<Self> {
        let tempdir = tempfile::TempDir::new()?;

        move_mount(
            mnt_fd.as_fd(),
            "",
            rustix::fs::CWD,
            tempdir.path(),
            MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
        )
        .context("move_mount")?;

        let fd = Dir::open_ambient_dir(tempdir.path(), ambient_authority())
            .with_context(|| format!("Opening {:?}", tempdir.path()));

        let fd = match fd {
            Ok(fd) => fd,
            Err(e) => {
                unmount(tempdir.path(), UnmountFlags::DETACH)?;
                Err(e)?
            }
        };

        Ok(Self { dir: tempdir, fd })
    }
}

impl Drop for TempMount {
    fn drop(&mut self) {
        match unmount(self.dir.path(), UnmountFlags::DETACH) {
            Ok(_) => {}
            Err(e) => tracing::warn!("Failed to unmount tempdir: {e:?}"),
        }
    }
}
