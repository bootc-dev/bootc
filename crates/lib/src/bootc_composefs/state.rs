use std::process::Command;

use anyhow::{Context, Result};
use bootc_utils::CommandRunExt;
use camino::Utf8PathBuf;
use fn_error_context::context;

use rustix::{
    fs::{open, Mode, OFlags, CWD},
    mount::{unmount, UnmountFlags},
    path::Arg,
};

/// Mounts an EROFS image and copies the pristine /etc to the deployment's /etc
#[context("Copying etc")]
pub(crate) fn copy_etc_to_state(
    sysroot_path: &Utf8PathBuf,
    erofs_id: &String,
    state_path: &Utf8PathBuf,
) -> Result<()> {
    let sysroot_fd = open(
        sysroot_path.as_std_path(),
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context("Opening sysroot")?;

    let composefs_fd = bootc_initramfs_setup::mount_composefs_image(&sysroot_fd, &erofs_id, false)?;

    let tempdir = tempfile::tempdir().context("Creating tempdir")?;

    bootc_initramfs_setup::mount_at_wrapper(composefs_fd, CWD, tempdir.path())?;

    // TODO: Replace this with a function to cap_std_ext
    let cp_ret = Command::new("cp")
        .args([
            "-a",
            &format!("{}/etc/.", tempdir.path().as_str()?),
            &format!("{state_path}/etc/."),
        ])
        .run_capture_stderr();

    // Unmount regardless of copy succeeding
    unmount(tempdir.path(), UnmountFlags::DETACH).context("Unmounting composefs")?;

    cp_ret
}
