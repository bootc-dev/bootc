//! Pairwise reflink capability probing for storage directories.

use std::io::Write as _;

use anyhow::{Context, Result};
use cap_std_ext::cap_std::fs::{Dir as CapStdDir, File, OpenOptions};
use cap_std_ext::cap_std::io_lifetimes::AsFilelike;
use rustix::fd::AsFd as _;

/// Returns whether a file in `src` can be reflinked into `dst`.
///
/// The result is scoped to this source/destination pair; it is deliberately
/// not cached. Temporary files are created exclusively beneath the supplied
/// directory capabilities and removed before returning.
pub(crate) fn supports_reflink(src: &CapStdDir, dst: &CapStdDir) -> Result<bool> {
    probe_with(src, dst, |destination, source| {
        let source_view = source.as_filelike_view::<std::fs::File>();
        let destination_view = destination.as_filelike_view::<std::fs::File>();
        let source_fd = source_view.as_fd();
        let destination_fd = destination_view.as_fd();
        rustix::fs::ioctl_ficlone(destination_fd, source_fd)
    })
}

fn probe_with(
    src: &CapStdDir,
    dst: &CapStdDir,
    clone: impl FnOnce(&File, &File) -> rustix::io::Result<()>,
) -> Result<bool> {
    let mut source = match create_probe_file(src) {
        Ok(source) => source,
        Err(error) => return source_probe_failure(error),
    };
    let mut destination = match create_probe_file(dst) {
        Ok(destination) => destination,
        Err(error) => {
            source
                .cleanup()
                .context("Removing reflink probe source after destination creation failed")?;
            return Err(error);
        }
    };

    let probe_result = match source
        .file
        .as_mut()
        .expect("probe source file is open")
        .write_all(b"bootc reflink probe")
    {
        Err(error) => {
            source_probe_failure(anyhow::Error::from(error).context("Writing reflink probe source"))
        }
        Ok(()) => match clone(
            destination
                .file
                .as_ref()
                .expect("probe destination file is open"),
            source.file.as_ref().expect("probe source file is open"),
        ) {
            Ok(()) => Ok(true),
            Err(error) if reflink_unsupported(error) => Ok(false),
            Err(error) => Err(anyhow::Error::from(error).context("Probing FICLONE support")),
        },
    };

    // Attempt both removals even if one fails. Drop provides a best-effort
    // fallback if the operation above returned early (for example, a write
    // error).
    let source_cleanup = source.cleanup();
    let destination_cleanup = destination.cleanup();
    source_cleanup.context("Removing reflink probe source")?;
    destination_cleanup.context("Removing reflink probe destination")?;
    probe_result
}

fn reflink_unsupported(error: rustix::io::Errno) -> bool {
    // Both files are newly created regular files, so EINVAL here indicates
    // that FICLONE is unsupported rather than an invalid source type.
    matches!(
        error,
        rustix::io::Errno::OPNOTSUPP | rustix::io::Errno::XDEV | rustix::io::Errno::INVAL
    )
}

fn source_probe_access_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<std::io::Error>().is_some_and(|error| {
            matches!(
                error.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ReadOnlyFilesystem
            )
        })
    })
}

fn source_probe_failure(error: anyhow::Error) -> Result<bool> {
    if source_probe_access_error(&error) {
        tracing::debug!("Cannot prepare reflink probe source, using full copy: {error:#}");
        Ok(false)
    } else {
        Err(error)
    }
}

struct ProbeFile<'a> {
    dir: &'a CapStdDir,
    name: String,
    file: Option<File>,
    removed: bool,
}

impl ProbeFile<'_> {
    fn cleanup(&mut self) -> std::io::Result<()> {
        self.cleanup_with(|dir, name| dir.remove_file(name))
    }

    fn cleanup_with(
        &mut self,
        remove_file: impl FnOnce(&CapStdDir, &str) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        drop(self.file.take());
        match remove_file(self.dir, &self.name) {
            Ok(()) => {
                self.removed = true;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.removed = true;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

impl Drop for ProbeFile<'_> {
    fn drop(&mut self) {
        if !self.removed {
            let _ = self.cleanup();
        }
    }
}

fn create_probe_file(dir: &CapStdDir) -> Result<ProbeFile<'_>> {
    loop {
        let name = format!(".bootc-reflink-probe-{}", uuid::Uuid::new_v4());
        match create_probe_file_with_name(dir, &name) {
            Ok(file) => return Ok(file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("Creating reflink probe file"),
        }
    }
}

fn create_probe_file_with_name<'a>(
    dir: &'a CapStdDir,
    name: &str,
) -> std::io::Result<ProbeFile<'a>> {
    let file = dir.open_with(
        name,
        OpenOptions::new().read(true).write(true).create_new(true),
    )?;
    Ok(ProbeFile {
        dir,
        name: name.to_owned(),
        file: Some(file),
        removed: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std_ext::cap_std::ambient_authority;
    use std::fs;

    fn cap_dir(path: &std::path::Path) -> CapStdDir {
        CapStdDir::open_ambient_dir(path, ambient_authority()).unwrap()
    }

    #[test]
    fn probe_reports_success_and_cleans_up() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let src_path = temp.path().join("src");
        let dst_path = temp.path().join("dst");
        fs::create_dir(&src_path)?;
        fs::create_dir(&dst_path)?;

        let supported = probe_with(&cap_dir(&src_path), &cap_dir(&dst_path), |_, _| Ok(()))?;
        assert!(supported);
        assert!(fs::read_dir(&src_path)?.next().is_none());
        assert!(fs::read_dir(&dst_path)?.next().is_none());
        Ok(())
    }

    #[test]
    fn probe_classifies_unsupported_and_propagates_unexpected_errors() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let src_path = temp.path().join("src");
        let dst_path = temp.path().join("dst");
        fs::create_dir(&src_path)?;
        fs::create_dir(&dst_path)?;
        let src = cap_dir(&src_path);
        let dst = cap_dir(&dst_path);

        assert!(!probe_with(&src, &dst, |_, _| {
            Err(rustix::io::Errno::OPNOTSUPP)
        })?);
        assert!(!probe_with(&src, &dst, |_, _| {
            Err(rustix::io::Errno::INVAL)
        })?);
        assert!(fs::read_dir(&src_path)?.next().is_none());
        assert!(fs::read_dir(&dst_path)?.next().is_none());

        assert!(probe_with(&src, &dst, |_, _| Err(rustix::io::Errno::IO)).is_err());
        assert!(fs::read_dir(&src_path)?.next().is_none());
        assert!(fs::read_dir(&dst_path)?.next().is_none());
        Ok(())
    }

    #[test]
    fn classifies_only_known_unsupported_errors() {
        assert!(reflink_unsupported(rustix::io::Errno::OPNOTSUPP));
        assert!(reflink_unsupported(rustix::io::Errno::XDEV));
        assert!(reflink_unsupported(rustix::io::Errno::INVAL));
        assert!(!reflink_unsupported(rustix::io::Errno::IO));
    }

    #[test]
    fn source_permission_and_read_only_errors_select_full_copy() {
        for error in [
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            std::io::Error::from(std::io::ErrorKind::ReadOnlyFilesystem),
        ] {
            let error = anyhow::Error::from(error).context("Creating reflink probe file");
            assert!(source_probe_access_error(&error));
            assert!(!source_probe_failure(error).unwrap());
        }
        assert!(source_probe_failure(anyhow::anyhow!("unrelated error")).is_err());
    }

    #[test]
    fn cleanup_retries_unlink_on_drop_after_failure() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("src");
        fs::create_dir(&path)?;
        let dir = cap_dir(&path);
        let name = ".bootc-reflink-probe-retry";
        let mut probe = create_probe_file_with_name(&dir, name)?;

        let error = probe
            .cleanup_with(|_, _| Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)))
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(path.join(name).exists());

        drop(probe);
        assert!(!path.join(name).exists());
        Ok(())
    }

    #[test]
    fn probe_file_creation_never_overwrites_existing_files() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("src");
        fs::create_dir(&path)?;
        let existing = path.join(".bootc-reflink-probe-collision");
        fs::write(&existing, b"leave this alone")?;

        let error =
            match create_probe_file_with_name(&cap_dir(&path), ".bootc-reflink-probe-collision") {
                Ok(_) => panic!("create_new unexpectedly replaced an existing probe file"),
                Err(error) => error,
            };
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(existing)?, b"leave this alone");
        Ok(())
    }
}
