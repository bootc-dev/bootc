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

/// Options for container export.
#[derive(Debug, Default)]
struct ExportOptions {
    /// Copy kernel and initramfs to /boot for legacy compatibility.
    kernel_in_boot: bool,
    /// Disable SELinux labeling.
    disable_selinux: bool,
}

/// Export a container filesystem to tar format with bootc-specific features.
#[context("Exporting container")]
pub(crate) async fn export(
    format: &ExportFormat,
    target_path: &Utf8Path,
    output_path: Option<&Utf8Path>,
    kernel_in_boot: bool,
    disable_selinux: bool,
) -> Result<()> {
    use cap_std_ext::cap_std;
    use cap_std_ext::cap_std::fs::Dir;

    let options = ExportOptions {
        kernel_in_boot,
        disable_selinux,
    };

    let root_dir = Dir::open_ambient_dir(target_path, cap_std::ambient_authority())
        .with_context(|| format!("Failed to open directory: {}", target_path))?;

    match format {
        ExportFormat::Tar => export_tar(&root_dir, output_path, &options).await,
    }
}

/// Export container filesystem as tar archive.
#[context("Exporting to tar")]
async fn export_tar(
    root_dir: &cap_std_ext::cap_std::fs::Dir,
    output_path: Option<&Utf8Path>,
    options: &ExportOptions,
) -> Result<()> {
    let output: Box<dyn Write> = match output_path {
        Some(path) => {
            let file = File::create(path)
                .with_context(|| format!("Failed to create output file: {}", path))?;
            Box::new(file)
        }
        None => Box::new(io::stdout()),
    };

    let mut tar_builder = tar::Builder::new(output);
    export_filesystem(&mut tar_builder, root_dir, options)?;
    tar_builder.finish().context("Finalizing tar archive")?;

    Ok(())
}

fn export_filesystem<W: Write>(
    tar_builder: &mut tar::Builder<W>,
    root_dir: &cap_std_ext::cap_std::fs::Dir,
    options: &ExportOptions,
) -> Result<()> {
    // Load SELinux policy from the image filesystem.
    // We use the policy to compute labels rather than reading xattrs from the
    // mounted filesystem, because OCI images don't usually include selinux xattrs,
    // and the mounted runtime will have e.g. container_t
    let sepolicy = if options.disable_selinux {
        None
    } else {
        crate::lsm::new_sepolicy_at(root_dir)?
    };

    export_filesystem_walk(tar_builder, root_dir, sepolicy.as_ref())?;

    if options.kernel_in_boot {
        handle_kernel_relocation(tar_builder, root_dir)?;
    }

    Ok(())
}

/// Create a tar header from filesystem metadata.
fn tar_header_from_meta(
    entry_type: tar::EntryType,
    size: u64,
    meta: &cap_std_ext::cap_std::fs::Metadata,
) -> tar::Header {
    use cap_std_ext::cap_primitives::fs::{MetadataExt, PermissionsExt};

    let mut header = tar::Header::new_gnu();
    header.set_entry_type(entry_type);
    header.set_size(size);
    header.set_mode(meta.permissions().mode() & !libc::S_IFMT);
    header.set_uid(meta.uid() as u64);
    header.set_gid(meta.gid() as u64);
    header
}

/// Create a tar header for a root-owned directory with mode 0755.
fn tar_header_dir_root() -> tar::Header {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_size(0);
    header.set_mode(0o755);
    header.set_uid(0);
    header.set_gid(0);
    header
}

fn export_filesystem_walk<W: Write>(
    tar_builder: &mut tar::Builder<W>,
    root_dir: &cap_std_ext::cap_std::fs::Dir,
    sepolicy: Option<&ostree::SePolicy>,
) -> Result<()> {
    use std::path::Path;

    // The target mount shouldn't have submounts, but just in case we use noxdev
    let walk_config = WalkConfiguration::default()
        .noxdev()
        .path_base(Path::new("/"));

    root_dir.walk(&walk_config, |entry| -> std::io::Result<ControlFlow<()>> {
        let path = entry.path;

        // Skip the root directory itself - it is meaningless in OCI right now
        // https://github.com/containers/composefs-rs/pull/209
        // The root is represented as "/" which has one component
        if path == Path::new("/") {
            return Ok(ControlFlow::Continue(()));
        }

        // Ensure the path is relative by default
        let relative_path = path.strip_prefix("/").unwrap_or(path);

        // Skip empty paths (shouldn't happen but be safe)
        if relative_path == Path::new("") {
            return Ok(ControlFlow::Continue(()));
        }

        let file_type = entry.file_type;
        if file_type.is_dir() {
            add_directory_to_tar_from_walk(tar_builder, entry.dir, path, relative_path, sepolicy)
                .map_err(std::io::Error::other)?;
        } else if file_type.is_file() {
            add_file_to_tar_from_walk(
                tar_builder,
                entry.dir,
                entry.filename,
                path,
                relative_path,
                sepolicy,
            )
            .map_err(std::io::Error::other)?;
        } else if file_type.is_symlink() {
            add_symlink_to_tar_from_walk(
                tar_builder,
                entry.dir,
                entry.filename,
                path,
                relative_path,
                sepolicy,
            )
            .map_err(std::io::Error::other)?;
        } else {
            return Err(std::io::Error::other(format!(
                "Unsupported file type: {}",
                relative_path.display()
            )));
        }

        Ok(ControlFlow::Continue(()))
    })?;

    Ok(())
}

fn add_directory_to_tar_from_walk<W: Write>(
    tar_builder: &mut tar::Builder<W>,
    dir: &cap_std_ext::cap_std::fs::Dir,
    absolute_path: &std::path::Path,
    relative_path: &std::path::Path,
    sepolicy: Option<&ostree::SePolicy>,
) -> Result<()> {
    use cap_std_ext::cap_primitives::fs::PermissionsExt;

    let metadata = dir.dir_metadata()?;
    let mut header = tar_header_from_meta(tar::EntryType::Directory, 0, &metadata);

    if let Some(policy) = sepolicy {
        let label = compute_selinux_label(policy, absolute_path, metadata.permissions().mode())?;
        add_selinux_pax_extension(tar_builder, &label)?;
    }

    tar_builder
        .append_data(&mut header, relative_path, &mut std::io::empty())
        .with_context(|| format!("Failed to add directory: {}", relative_path.display()))?;

    Ok(())
}

fn add_file_to_tar_from_walk<W: Write>(
    tar_builder: &mut tar::Builder<W>,
    dir: &cap_std_ext::cap_std::fs::Dir,
    filename: &std::ffi::OsStr,
    absolute_path: &std::path::Path,
    relative_path: &std::path::Path,
    sepolicy: Option<&ostree::SePolicy>,
) -> Result<()> {
    use cap_std_ext::cap_primitives::fs::PermissionsExt;
    use std::path::Path;

    let filename_path = Path::new(filename);
    let metadata = dir.metadata(filename_path)?;
    let mut header = tar_header_from_meta(tar::EntryType::Regular, metadata.len(), &metadata);

    if let Some(policy) = sepolicy {
        let label = compute_selinux_label(policy, absolute_path, metadata.permissions().mode())?;
        add_selinux_pax_extension(tar_builder, &label)?;
    }

    let mut file = dir.open(filename_path)?;
    tar_builder
        .append_data(&mut header, relative_path, &mut file)
        .with_context(|| format!("Failed to add file: {}", relative_path.display()))?;

    Ok(())
}

fn add_symlink_to_tar_from_walk<W: Write>(
    tar_builder: &mut tar::Builder<W>,
    dir: &cap_std_ext::cap_std::fs::Dir,
    filename: &std::ffi::OsStr,
    absolute_path: &std::path::Path,
    relative_path: &std::path::Path,
    sepolicy: Option<&ostree::SePolicy>,
) -> Result<()> {
    use cap_std_ext::cap_primitives::fs::PermissionsExt;
    use std::path::Path;

    let filename_path = Path::new(filename);
    let link_target = dir
        .read_link_contents(filename_path)
        .with_context(|| format!("Failed to read symlink: {:?}", filename))?;
    let metadata = dir.symlink_metadata(filename_path)?;
    let mut header = tar_header_from_meta(tar::EntryType::Symlink, 0, &metadata);

    if let Some(policy) = sepolicy {
        // For symlinks, combine S_IFLNK with mode for proper label lookup
        let symlink_mode = libc::S_IFLNK | (metadata.permissions().mode() & !libc::S_IFMT);
        let label = compute_selinux_label(policy, absolute_path, symlink_mode)?;
        add_selinux_pax_extension(tar_builder, &label)?;
    }

    tar_builder
        .append_link(&mut header, relative_path, &link_target)
        .with_context(|| format!("Failed to add symlink: {}", relative_path.display()))?;

    Ok(())
}

/// Copy kernel and initramfs to /boot for legacy installers (e.g. Anaconda liveimg).
fn handle_kernel_relocation<W: Write>(
    tar_builder: &mut tar::Builder<W>,
    root_dir: &cap_std_ext::cap_std::fs::Dir,
) -> Result<()> {
    use crate::kernel::KernelType;

    let kernel_info = match crate::kernel::find_kernel(root_dir)? {
        Some(kernel) => kernel,
        None => return Ok(()),
    };

    append_dir_entry(tar_builder, "boot")?;
    append_dir_entry(tar_builder, "boot/grub2")?;

    // UKIs don't need relocation - they're already in /boot/EFI/Linux
    if kernel_info.kernel.unified {
        return Ok(());
    }

    // Traditional vmlinuz kernels need to be copied to /boot
    if let KernelType::Vmlinuz { path, initramfs } = &kernel_info.k_type {
        let version = &kernel_info.kernel.version;

        // Copy vmlinuz
        if root_dir.try_exists(path)? {
            let metadata = root_dir.metadata(path)?;
            let mut header =
                tar_header_from_meta(tar::EntryType::Regular, metadata.len(), &metadata);
            let mut file = root_dir.open(path)?;
            let boot_path = format!("boot/vmlinuz-{}", version);
            tar_builder
                .append_data(&mut header, &boot_path, &mut file)
                .with_context(|| format!("Failed to add kernel: {}", boot_path))?;
        }

        // Copy initramfs
        if root_dir.try_exists(initramfs)? {
            let metadata = root_dir.metadata(initramfs)?;
            let mut header =
                tar_header_from_meta(tar::EntryType::Regular, metadata.len(), &metadata);
            let mut file = root_dir.open(initramfs)?;
            let boot_path = format!("boot/initramfs-{}.img", version);
            tar_builder
                .append_data(&mut header, &boot_path, &mut file)
                .with_context(|| format!("Failed to add initramfs: {}", boot_path))?;
        }

        // Create BLS directory structure (entries are generated by kernel-install
        // during installation when the actual root device is known)
        create_bls_directories(tar_builder)?;
    }

    Ok(())
}

fn append_dir_entry<W: Write>(tar_builder: &mut tar::Builder<W>, path: &str) -> Result<()> {
    let mut header = tar_header_dir_root();
    tar_builder
        .append_data(&mut header, path, &mut std::io::empty())
        .with_context(|| format!("Failed to create {} directory", path))?;
    Ok(())
}

/// Create Boot Loader Specification (BLS) directory structure.
///
/// BLS entries are stored in `/boot/loader/entries/` and describe available
/// boot options. The actual entries are generated by kernel-install during
/// installation when the root device is known.
fn create_bls_directories<W: Write>(tar_builder: &mut tar::Builder<W>) -> Result<()> {
    append_dir_entry(tar_builder, "boot/loader")?;
    append_dir_entry(tar_builder, "boot/loader/entries")?;
    Ok(())
}

fn compute_selinux_label(
    policy: &ostree::SePolicy,
    path: &std::path::Path,
    mode: u32,
) -> Result<String> {
    use camino::Utf8Path;

    // Convert path to UTF-8 for policy lookup - non-UTF8 paths are not supported
    let path_str = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Non-UTF8 path not supported: {:?}", path))?;
    let utf8_path = Utf8Path::new(path_str);

    let label = crate::lsm::require_label(policy, utf8_path, mode)?;
    Ok(label.to_string())
}

fn add_selinux_pax_extension<W: Write>(
    tar_builder: &mut tar::Builder<W>,
    selinux_context: &str,
) -> Result<()> {
    tar_builder
        .append_pax_extensions([("SCHILY.xattr.security.selinux", selinux_context.as_bytes())])
        .context("Failed to add SELinux PAX extension")?;
    Ok(())
}
