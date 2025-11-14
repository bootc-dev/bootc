//! This module contains the functions to implement the commit
//! procedures as part of building an ostree container image.
//! <https://github.com/ostreedev/ostree-rs-ext/issues/159>

use crate::container_utils::require_ostree_container;
use anyhow::Context;
use anyhow::Result;
use cap_std::fs::Dir;
use cap_std::fs::MetadataExt;
use cap_std_ext::cap_std;
use cap_std_ext::dirext::CapStdExtDirExt;
use std::path::Path;
use std::path::PathBuf;
use tokio::task;

/// Directories for which we will always remove all content.
const FORCE_CLEAN_PATHS: &[&str] = &["run", "tmp", "var/tmp", "var/cache"];

/// Recursively remove the target directory, but avoid traversing across mount points.
fn remove_all_on_mount_recurse(root: &Dir, rootdev: u64, path: &Path) -> Result<bool> {
    let mut skipped = false;
    for entry in root
        .read_dir(path)
        .with_context(|| format!("Reading {path:?}"))?
    {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if metadata.dev() != rootdev {
            skipped = true;
            continue;
        }
        let name = entry.file_name();
        let path = &path.join(name);

        if metadata.is_dir() {
            skipped |= remove_all_on_mount_recurse(root, rootdev, path.as_path())?;
        } else {
            root.remove_file(path)
                .with_context(|| format!("Removing {path:?}"))?;
        }
    }
    if !skipped {
        root.remove_dir(path)
            .with_context(|| format!("Removing {path:?}"))?;
    }
    Ok(skipped)
}

fn clean_subdir(root: &Dir, rootdev: u64) -> Result<()> {
    for entry in root.entries()? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        let dev = metadata.dev();
        let path = PathBuf::from(entry.file_name());
        // Ignore other filesystem mounts, e.g. podman injects /run/.containerenv
        if dev != rootdev {
            tracing::trace!("Skipping entry in foreign dev {path:?}");
            continue;
        }
        // For mount points (e.g., separate LVM volumes under /var), we need to clean
        // their contents but preserve the directory itself. This is critical for cases
        // where subdirectories like /var/log or /var/home are separate logical volumes.
        if root.is_mountpoint(&path)?.unwrap_or_default() {
            if metadata.is_dir() {
                tracing::debug!("Cleaning contents of mount point directory {path:?}");
                // Get the device ID of the mountpoint itself
                let mountpoint_dev = metadata.dev();
                // Open the mountpoint directory and clean its contents
                if let Some(mountpoint_dir) = root.open_dir_optional(&path)? {
                    clean_subdir(&mountpoint_dir, mountpoint_dev)
                        .with_context(|| format!("Cleaning mountpoint {path:?}"))?;
                }
                // Do not remove the directory itself - it's a mount point
            } else {
                tracing::trace!("Skipping non-directory mount point {path:?}");
            }
            continue;
        }
        if metadata.is_dir() {
            remove_all_on_mount_recurse(root, rootdev, &path)?;
        } else {
            root.remove_file(&path)
                .with_context(|| format!("Removing {path:?}"))?;
        }
    }
    Ok(())
}

fn clean_paths_in(root: &Dir, rootdev: u64) -> Result<()> {
    for path in FORCE_CLEAN_PATHS {
        let subdir = if let Some(subdir) = root.open_dir_optional(path)? {
            subdir
        } else {
            continue;
        };
        clean_subdir(&subdir, rootdev).with_context(|| format!("Cleaning {path}"))?;
    }
    Ok(())
}

/// Given a root filesystem, clean out empty directories and warn about
/// files in /var.  /run, /tmp, and /var/tmp have their contents recursively cleaned.
pub fn prepare_ostree_commit_in(root: &Dir) -> Result<()> {
    let rootdev = root.dir_metadata()?.dev();
    clean_paths_in(root, rootdev)
}

/// Like [`prepare_ostree_commit_in`] but only emits warnings about unsupported
/// files in `/var` and will not error.
pub fn prepare_ostree_commit_in_nonstrict(root: &Dir) -> Result<()> {
    let rootdev = root.dir_metadata()?.dev();
    clean_paths_in(root, rootdev)
}

/// Entrypoint to the commit procedures, initially we just
/// have one validation but we expect more in the future.
pub(crate) async fn container_commit() -> Result<()> {
    task::spawn_blocking(move || {
        require_ostree_container()?;
        let rootdir = Dir::open_ambient_dir("/", cap_std::ambient_authority())?;
        prepare_ostree_commit_in(&rootdir)
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;
    use camino::Utf8Path;

    use cap_std_ext::cap_tempfile;

    #[test]
    fn commit() -> Result<()> {
        let td = &cap_tempfile::tempdir(cap_std::ambient_authority())?;

        // Handle the empty case
        prepare_ostree_commit_in(td).unwrap();
        prepare_ostree_commit_in_nonstrict(td).unwrap();

        let var = Utf8Path::new("var");
        let run = Utf8Path::new("run");
        let tmp = Utf8Path::new("tmp");
        let vartmp_foobar = &var.join("tmp/foo/bar");
        let runsystemd = &run.join("systemd");
        let resolvstub = &runsystemd.join("resolv.conf");

        for p in [var, run, tmp] {
            td.create_dir(p)?;
        }

        td.create_dir_all(vartmp_foobar)?;
        td.write(vartmp_foobar.join("a"), "somefile")?;
        td.write(vartmp_foobar.join("b"), "somefile2")?;
        td.create_dir_all(runsystemd)?;
        td.write(resolvstub, "stub resolv")?;
        prepare_ostree_commit_in(td).unwrap();
        assert!(td.try_exists(var)?);
        assert!(td.try_exists(var.join("tmp"))?);
        assert!(!td.try_exists(vartmp_foobar)?);
        assert!(td.try_exists(run)?);
        assert!(!td.try_exists(runsystemd)?);

        let systemd = run.join("systemd");
        td.create_dir_all(&systemd)?;
        prepare_ostree_commit_in(td).unwrap();
        assert!(td.try_exists(var)?);
        assert!(!td.try_exists(&systemd)?);

        td.remove_dir_all(var)?;
        td.create_dir(var)?;
        td.write(var.join("foo"), "somefile")?;
        prepare_ostree_commit_in(td).unwrap();
        // Right now we don't auto-create var/tmp if it didn't exist, but maybe
        // we will in the future.
        assert!(!td.try_exists(var.join("tmp"))?);
        assert!(td.try_exists(var)?);

        td.write(var.join("foo"), "somefile")?;
        prepare_ostree_commit_in_nonstrict(td).unwrap();
        assert!(td.try_exists(var)?);

        let nested = Utf8Path::new("var/lib/nested");
        td.create_dir_all(nested)?;
        td.write(nested.join("foo"), "test1")?;
        td.write(nested.join("foo2"), "test2")?;
        prepare_ostree_commit_in(td).unwrap();
        assert!(td.try_exists(var)?);
        assert!(td.try_exists(nested)?);

        Ok(())
    }
}
