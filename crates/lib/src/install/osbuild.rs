//! # Helper APIs for interacting with bootc-image-builder
//!
//! See <https://github.com/osbuild/bootc-image-builder>
//!

use std::process::Command;

use anyhow::Result;
use bootc_utils::CommandRunExt as _;
use camino::Utf8Path;
use cap_std_ext::{cap_std::fs::Dir, cmdext::CapStdExtCommandExt};
use fn_error_context::context;

/// Handle /etc/containers readonly mount.
///
/// Ufortunately today podman requires that /etc be writable for
/// `/etc/containers/networks`. bib today creates this as a readonly mount:
/// <https://github.com/osbuild/osbuild/blob/4edbe227d41c767441b9bf4390398afc6dc8f901/osbuild/buildroot.py#L243>
///
/// Work around that by adding a transient, writable overlayfs.
fn adjust_etc_containers(tempdir: &Dir) -> Result<()> {
    let etc_containers = Utf8Path::new("/etc/containers");
    // If there's no /etc/containers, nothing to do
    if !etc_containers.try_exists()? {
        return Ok(());
    }
    if rustix::fs::access(etc_containers.as_std_path(), rustix::fs::Access::WRITE_OK).is_ok() {
        return Ok(());
    }
    // Create dirs for the overlayfs upper and work in the install-global tmpdir.
    tempdir.create_dir_all("etc-ovl/upper")?;
    tempdir.create_dir("etc-ovl/work")?;
    let opts = format!("lowerdir={etc_containers},workdir=etc-ovl/work,upperdir=etc-ovl/upper");
    Command::new("mount")
        .log_debug()
        .args(["-t", "overlay", "overlay", "-o", opts.as_str()])
        .arg(etc_containers)
        .cwd_dir(tempdir.try_clone()?)
        .run_capture_stderr()?;
    Ok(())
}

/// osbuild mounts the host's /var/lib/containers at /run/osbuild/containers; mount
/// it back to /var/lib/containers where the default container stack expects to find it.
fn propagate_run_osbuild_containers(root: &Dir) -> Result<()> {
    let osbuild_run_containers = Utf8Path::new("run/osbuild/containers");
    // If we're not apparently running under osbuild, then we no-op.
    if !root.try_exists(osbuild_run_containers)? {
        return Ok(());
    }
    // If we do seem to have a valid container store though, use that
    if crate::podman::storage_exists_default(root)? {
        return Ok(());
    }
    let relative_storage = Utf8Path::new(crate::podman::CONTAINER_STORAGE.trim_start_matches('/'));
    root.create_dir_all(relative_storage)?;
    Command::new("mount")
        .log_debug()
        .arg("--rbind")
        .args([osbuild_run_containers, relative_storage])
        .cwd_dir(root.try_clone()?)
        .run_capture_stderr()?;
    Ok(())
}

/// bootc-image-builder today does a few things that we need to
/// deal with.
#[context("bootc-image-builder adjustments")]
pub(crate) fn adjust_for_bootc_image_builder(root: &Dir, tempdir: &Dir) -> Result<()> {
    adjust_etc_containers(tempdir)?;
    propagate_run_osbuild_containers(root)?;
    Ok(())
}
