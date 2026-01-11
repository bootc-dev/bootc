use std::os::fd::AsFd;

use anyhow::{Context, Result};

use camino::Utf8Path;
use cap_std_ext::cap_std::{ambient_authority, fs::Dir};
use fn_error_context::context;
use rustix::mount::{MountFlags, MoveMountFlags, UnmountFlags, move_mount, unmount};

pub struct TempMount {
    pub dir: tempfile::TempDir,
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
