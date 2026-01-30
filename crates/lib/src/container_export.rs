//! # Container Export Functionality
//!
//! This module implements the `bootc container export` command which exports
//! container filesystems as bootable tar archives with proper SELinux labeling
//! and legacy boot compatibility.

use anyhow::{Context, Result};
use camino::Utf8Path;
use cap_std_ext::dirext::{CapStdExtDirExt, WalkConfiguration};
use fn_error_context::context;
use ostree_ext::ostree;
use std::fs::File;
use std::io::{self, Write};
use std::ops::ControlFlow;

use crate::cli::ExportFormat;

/// Export a container filesystem to tar format with bootc-specific features.
#[context("Exporting container")]
pub(crate) async fn export(
    format: &ExportFormat,
    target_path: &Utf8Path,
    output_path: Option<&Utf8Path>,
) -> Result<()> {
    use cap_std_ext::cap_std;
    use cap_std_ext::cap_std::fs::Dir;

    // Verify the target path exists and is accessible
    if !target_path.exists() {
        anyhow::bail!("Target path does not exist: {}", target_path);
    }

    if !target_path.is_dir() {
        anyhow::bail!("Target path must be a directory: {}", target_path);
    }

    // Open the target directory with cap-std
    let root_dir = Dir::open_ambient_dir(target_path, cap_std::ambient_authority())
        .with_context(|| format!("Failed to open directory with cap-std: {}", target_path))?;

    tracing::debug!(
        "Successfully opened directory with cap-std: {}",
        target_path
    );

    match format {
        ExportFormat::Tar => export_tar(&root_dir, output_path).await,
    }
}

/// Export container filesystem as tar archive.
#[context("Exporting to tar")]
async fn export_tar(
    root_dir: &cap_std_ext::cap_std::fs::Dir,
    output_path: Option<&Utf8Path>,
) -> Result<()> {
    // Create output writer - either file or stdout
    let output: Box<dyn Write> = match output_path {
        Some(path) => {
            let file = File::create(path)
                .with_context(|| format!("Failed to create output file: {}", path))?;
            Box::new(file)
        }
        None => Box::new(io::stdout()),
    };

    // Export the filesystem with bootc-specific features
    export_filesystem_with_bootc_features(root_dir, output).await?;

    Ok(())
}

/// Export filesystem with bootc-specific features like SELinux labeling and kernel relocation.
#[context("Exporting filesystem with bootc features")]
async fn export_filesystem_with_bootc_features<W: Write>(
    root_dir: &cap_std_ext::cap_std::fs::Dir,
    output: W,
) -> Result<()> {
    // Create tar builder
    let mut tar_builder = tar::Builder::new(output);

    tracing::debug!("Starting filesystem export");

    // Export filesystem using cap-std
    export_filesystem(&mut tar_builder, root_dir)?;

    // Finalize the tar archive
    tar_builder.finish().context("Finalizing tar archive")?;

    Ok(())
}

/// Export filesystem using cap-std
fn export_filesystem<W: Write>(
    tar_builder: &mut tar::Builder<W>,
    root_dir: &cap_std_ext::cap_std::fs::Dir,
) -> Result<()> {
    tracing::debug!("Exporting filesystem using cap-std");

    let sepolicy = crate::lsm::new_sepolicy_at(root_dir)?;

    tracing::debug!("SELinux status: have_policy={}", sepolicy.is_some());

    // Export the directory using walk API
    export_filesystem_walk(tar_builder, root_dir, sepolicy.as_ref())?;

    // Handle kernel relocation
    handle_kernel_relocation(tar_builder, root_dir)?;

    Ok(())
}

/// Export filesystem using the cap-std-ext walk API
fn export_filesystem_walk<W: Write>(
    tar_builder: &mut tar::Builder<W>,
    root_dir: &cap_std_ext::cap_std::fs::Dir,
    sepolicy: Option<&ostree::SePolicy>,
) -> Result<()> {
    use std::path::Path;

    tracing::debug!("Starting filesystem walk export");

    // Use WalkConfiguration with noxdev to avoid crossing mount points
    let walk_config = WalkConfiguration::default()
        .noxdev()
        .path_base(Path::new("/"));

    root_dir.walk(&walk_config, |entry| -> anyhow::Result<ControlFlow<()>> {
        let path_str = entry.path.to_string_lossy();
        tracing::debug!("Walking entry: {}", path_str);

        // Convert path to relative path (remove leading /)
        let relative_path = path_str.strip_prefix('/').unwrap_or(&path_str);

        // Skip the root directory itself
        if relative_path.is_empty() {
            return Ok(ControlFlow::Continue(()));
        }

        let path = Utf8Path::new(relative_path);

        // Get the filename component
        let filename = entry
            .filename
            .to_str()
            .with_context(|| format!("Non-UTF8 filename: {:?}", entry.filename))?;

        // Get the file type to determine how to handle this entry
        let file_type = entry
            .dir
            .metadata(entry.filename)
            .with_context(|| format!("Getting metadata for: {}", filename))?
            .file_type();

        if file_type.is_dir() {
            // Add directory to tar
            add_directory_to_tar_from_walk(tar_builder, entry.dir, path, sepolicy)?;
        } else if file_type.is_file() {
            // Add file to tar
            add_file_to_tar_from_walk(tar_builder, entry.dir, filename, path, sepolicy)?;
        } else if file_type.is_symlink() {
            // Add symlink to tar
            add_symlink_to_tar_from_walk(tar_builder, entry.dir, filename, path, sepolicy)?;
        } else {
            tracing::debug!("Skipping other file type: {}", path);
        }

        Ok(ControlFlow::Continue(()))
    })?;

    tracing::debug!("Completed filesystem walk export");
    Ok(())
}

/// Add directory to tar from walk entry
fn add_directory_to_tar_from_walk<W: Write>(
    tar_builder: &mut tar::Builder<W>,
    dir: &cap_std_ext::cap_std::fs::Dir,
    relative_path: &Utf8Path,
    sepolicy: Option<&ostree::SePolicy>,
) -> Result<()> {
    use cap_std_ext::cap_primitives::fs::{MetadataExt, PermissionsExt};

    let metadata = dir.dir_metadata()?;

    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_size(0);
    header.set_mode(metadata.permissions().mode() & !libc::S_IFMT);
    header.set_uid(metadata.uid() as u64);
    header.set_gid(metadata.gid() as u64);

    // Add SELinux context as PAX extension if available
    if let Some(policy) = sepolicy {
        let abs_path = if relative_path.as_str() == "." {
            "/".into()
        } else {
            format!("/{}", relative_path)
        };

        let selinux_context =
            crate::lsm::require_label(policy, abs_path.as_ref(), libc::S_IFDIR | 0o755)
                .with_context(|| {
                    format!("Getting SELinux label for directory {}", relative_path)
                })?;
        tracing::debug!(
            "Adding SELinux context for {}: {}",
            relative_path,
            selinux_context
        );
        add_selinux_pax_extension(tar_builder, &selinux_context)?;
    }

    tar_builder
        .append_data(&mut header, relative_path, &mut std::io::empty())
        .with_context(|| format!("Failed to add directory: {}", relative_path))?;

    Ok(())
}

/// Add file to tar from walk entry
fn add_file_to_tar_from_walk<W: Write>(
    tar_builder: &mut tar::Builder<W>,
    dir: &cap_std_ext::cap_std::fs::Dir,
    filename: &str,
    relative_path: &Utf8Path,
    sepolicy: Option<&ostree::SePolicy>,
) -> Result<()> {
    use cap_std_ext::cap_primitives::fs::{MetadataExt, PermissionsExt};

    let metadata = dir.metadata(filename)?;

    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_size(metadata.size());
    header.set_mode(metadata.permissions().mode() & !libc::S_IFMT);
    header.set_uid(metadata.uid() as u64);
    header.set_gid(metadata.gid() as u64);

    // Add SELinux context as PAX extension if available
    if let Some(policy) = sepolicy {
        let abs_path = format!("/{}", relative_path);
        let mode = libc::S_IFREG | (metadata.permissions().mode() & 0o777);

        let selinux_context = crate::lsm::require_label(policy, abs_path.as_ref(), mode)
            .with_context(|| format!("Getting SELinux label for file {}", relative_path))?;
        tracing::debug!(
            "Adding SELinux context for {}: {}",
            relative_path,
            selinux_context
        );
        add_selinux_pax_extension(tar_builder, &selinux_context)?;
    }

    let mut file = dir.open(filename)?;

    tar_builder
        .append_data(&mut header, relative_path, &mut file)
        .with_context(|| format!("Failed to add file: {}", relative_path))?;

    Ok(())
}

/// Add symlink to tar from walk entry
fn add_symlink_to_tar_from_walk<W: Write>(
    tar_builder: &mut tar::Builder<W>,
    dir: &cap_std_ext::cap_std::fs::Dir,
    filename: &str,
    relative_path: &Utf8Path,
    sepolicy: Option<&ostree::SePolicy>,
) -> Result<()> {
    use cap_std_ext::cap_primitives::fs::{MetadataExt, PermissionsExt};

    let link_target = dir
        .read_link(filename)
        .with_context(|| format!("Reading symlink: {}", filename))?;

    let metadata = dir.symlink_metadata(filename)?;

    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_size(0);
    header.set_mode(metadata.permissions().mode() & !libc::S_IFMT);
    header.set_uid(metadata.uid() as u64);
    header.set_gid(metadata.gid() as u64);

    // Add SELinux context as PAX extension if available
    if let Some(policy) = sepolicy {
        let abs_path = format!("/{}", relative_path);
        let mode = libc::S_IFLNK | (metadata.permissions().mode() & 0o777);

        let selinux_context = crate::lsm::require_label(policy, abs_path.as_ref(), mode)
            .with_context(|| format!("Getting SELinux label for symlink {}", relative_path))?;
        tracing::debug!(
            "Adding SELinux context for symlink {}: {}",
            relative_path,
            selinux_context
        );
        add_selinux_pax_extension(tar_builder, &selinux_context)?;
    }

    tar_builder
        .append_link(&mut header, relative_path, &link_target)
        .with_context(|| format!("Failed to add symlink: {}", relative_path))?;

    Ok(())
}

/// Handle kernel relocation for Anaconda compatibility using existing kernel detection
fn handle_kernel_relocation<W: Write>(
    tar_builder: &mut tar::Builder<W>,
    root_dir: &cap_std_ext::cap_std::fs::Dir,
) -> Result<()> {
    use cap_std_ext::cap_primitives::fs::{MetadataExt, PermissionsExt};

    // Use the existing kernel finding logic from the kernel module
    let kernel_info = crate::kernel::find_kernel(root_dir)?.ok_or_else(|| {
        anyhow::anyhow!("No kernel found in container; a kernel is required for export")
    })?;

    tracing::debug!(
        "Found kernel version: {}, unified: {}, implementing relocation for Anaconda compatibility",
        kernel_info.kernel.version,
        kernel_info.kernel.unified
    );

    // Create /boot directory in tar
    ensure_boot_directory_in_tar(tar_builder)?;

    // For UKI (Unified Kernel Images), no relocation is needed
    if kernel_info.kernel.unified {
        tracing::debug!("UKI kernel found, no relocation needed");
        return Ok(());
    }

    // Handle traditional kernel relocation
    if let Some(vmlinuz_path) = &kernel_info.vmlinuz {
        if root_dir.try_exists(vmlinuz_path)? {
            let metadata = root_dir.metadata(vmlinuz_path)?;
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(metadata.len());
            header.set_mode(metadata.permissions().mode() & !libc::S_IFMT);
            header.set_uid(metadata.uid() as u64);
            header.set_gid(metadata.gid() as u64);

            let mut vmlinuz_file = root_dir.open(vmlinuz_path)?;
            let boot_path = format!("boot/vmlinuz-{}", kernel_info.kernel.version);

            tar_builder
                .append_data(&mut header, &boot_path, &mut vmlinuz_file)
                .with_context(|| format!("Failed to add kernel: {}", boot_path))?;

            tracing::debug!("Relocated kernel: {} → {}", vmlinuz_path, boot_path);
        }
    }

    // Handle initramfs relocation
    if let Some(initramfs_path) = &kernel_info.initramfs {
        if root_dir.try_exists(initramfs_path)? {
            let metadata = root_dir.metadata(initramfs_path)?;
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(metadata.len());
            header.set_mode(metadata.permissions().mode() & !libc::S_IFMT);
            header.set_uid(metadata.uid() as u64);
            header.set_gid(metadata.gid() as u64);

            let mut initramfs_file = root_dir.open(initramfs_path)?;
            let boot_path = format!("boot/initramfs-{}.img", kernel_info.kernel.version);

            tar_builder
                .append_data(&mut header, &boot_path, &mut initramfs_file)
                .with_context(|| format!("Failed to add initramfs: {}", boot_path))?;

            tracing::debug!("Relocated initramfs: {} → {}", initramfs_path, boot_path);
        }
    }

    tracing::debug!("Kernel relocation completed");
    Ok(())
}

/// Ensure /boot directory exists in the tar stream.
fn ensure_boot_directory_in_tar<W: Write>(tar_builder: &mut tar::Builder<W>) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_size(0);
    header.set_mode(0o755);
    header.set_uid(0);
    header.set_gid(0);

    tar_builder
        .append_data(&mut header, "boot", &mut std::io::empty())
        .context("Failed to create /boot directory in tar")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_export_format_parsing() {
        use crate::cli::ExportFormat;

        // Test that ExportFormat::Tar exists and can be created
        let format = ExportFormat::Tar;
        match format {
            ExportFormat::Tar => {
                // Expected
            }
        }
    }

    #[test]
    fn test_ensure_boot_directory_in_tar() {
        let mut buffer = Vec::new();
        {
            let mut tar_builder = tar::Builder::new(&mut buffer);
            ensure_boot_directory_in_tar(&mut tar_builder).unwrap();
            tar_builder.finish().unwrap();
        }

        // Verify the boot directory was added to the tar
        let cursor = Cursor::new(buffer);
        let mut archive = tar::Archive::new(cursor);
        let entries: Result<Vec<_>, _> = archive.entries().unwrap().collect();
        let entries = entries.unwrap();

        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.path().unwrap(), std::path::Path::new("boot"));
        assert!(entry.header().entry_type().is_dir());
    }

    #[tokio::test]
    async fn test_export_nonexistent_path() {
        let result = export(&ExportFormat::Tar, Utf8Path::new("/nonexistent/path"), None).await;

        assert!(result.is_err());
        let error = result.unwrap_err();

        // Check the full error chain for our message
        let error_string = format!("{:#}", error);
        assert!(error_string.contains("Target path does not exist"));
    }

    #[tokio::test]
    async fn test_export_file_instead_of_directory() {
        // Create a temporary file
        let tmpfile = tempfile::NamedTempFile::new().unwrap();
        let file_path = Utf8Path::from_path(tmpfile.path()).unwrap();

        let result = export(&ExportFormat::Tar, file_path, None).await;

        assert!(result.is_err());
        let error = result.unwrap_err();

        // Check the full error chain for our message
        let error_string = format!("{:#}", error);
        assert!(error_string.contains("Target path must be a directory"));
    }
}

/// Add SELinux context as PAX extension to tar
fn add_selinux_pax_extension<W: Write>(
    tar_builder: &mut tar::Builder<W>,
    selinux_context: &str,
) -> Result<()> {
    // Add SELinux context as SCHILY.xattr.security.selinux PAX extension
    let pax_extensions = [(
        "SCHILY.xattr.security.selinux".to_string(),
        selinux_context.as_bytes().to_vec(),
    )];

    tar_builder
        .append_pax_extensions(pax_extensions.iter().map(|(k, v)| (k.as_str(), &v[..])))
        .context("Failed to add SELinux PAX extension")?;

    Ok(())
}
