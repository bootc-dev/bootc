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
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Write};
use std::ops::ControlFlow;

use crate::cli::{ExportFormat, ExportSelinuxMode};

/// Options for container export.
#[derive(Debug)]
struct ExportOptions<'a> {
    kernel_in_boot: bool,
    selinux: &'a ExportSelinuxMode,
}

/// Export a container filesystem to tar format with bootc-specific features.
#[context("Exporting container")]
pub(crate) async fn export(
    format: &ExportFormat,
    target_path: &Utf8Path,
    output_path: Option<&Utf8Path>,
    kernel_in_boot: bool,
    selinux: &ExportSelinuxMode,
) -> Result<()> {
    use cap_std_ext::cap_std;
    use cap_std_ext::cap_std::fs::Dir;

    let options = ExportOptions {
        kernel_in_boot,
        selinux,
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
    options: &ExportOptions<'_>,
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

/// How to handle SELinux labeling during export.
enum SepolicyState {
    /// SELinux labeling is disabled (--selinux=disabled).
    Disabled,
    /// Missing labels are a hard error (--selinux=enabled, default).
    Required(ostree::SePolicy),
    /// Missing labels emit a warning and export continues (--selinux=warn-on-missing).
    WarnOnMissing(ostree::SePolicy),
}

fn export_filesystem<W: Write>(
    tar_builder: &mut tar::Builder<W>,
    root_dir: &cap_std_ext::cap_std::fs::Dir,
    options: &ExportOptions<'_>,
) -> Result<()> {
    // Load SELinux policy from the image filesystem.
    // We use the policy to compute labels rather than reading xattrs from the
    // mounted filesystem, because OCI images don't usually include selinux xattrs,
    // and the mounted runtime will have e.g. container_t
    let sepolicy_state = if *options.selinux == ExportSelinuxMode::Disabled {
        SepolicyState::Disabled
    } else {
        match crate::lsm::new_sepolicy_at(root_dir)? {
            Some(policy) => match options.selinux {
                ExportSelinuxMode::Enabled => SepolicyState::Required(policy),
                ExportSelinuxMode::WarnOnMissing => SepolicyState::WarnOnMissing(policy),
                ExportSelinuxMode::Disabled => unreachable!(),
            },
            None => {
                tracing::warn!("SELinux labeling requested but no policy found in image");
                SepolicyState::Disabled
            }
        }
    };

    let mut unlabeled_count = 0u64;
    export_filesystem_walk(tar_builder, root_dir, &sepolicy_state, &mut unlabeled_count)?;

    if unlabeled_count > 0 {
        tracing::warn!(
            "{unlabeled_count} file(s) exported without SELinux labels (no policy match)"
        );
    }

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

/// Paths that should be skipped during export.
/// - `sysroot/ostree` is bootc/ostree-specific and shouldn't be in the exported tarball.
/// - `tmp` and `var/tmp` are meant to hold only ephemeral, runtime-created content (the
///   same paths `ostree-ext::commit` always cleans before committing). They can end up
///   containing arbitrary files dropped by package post-install scripts (e.g. `rhc`)
///   that the SELinux policy has no file-context entry for, which would otherwise turn
///   into a hard failure when computing labels for the tar entries.
const SKIP_PATHS: &[&str] = &["sysroot/ostree", "tmp", "var/tmp"];

fn export_filesystem_walk<W: Write>(
    tar_builder: &mut tar::Builder<W>,
    root_dir: &cap_std_ext::cap_std::fs::Dir,
    sepolicy_state: &SepolicyState,
    unlabeled_count: &mut u64,
) -> Result<()> {
    use std::path::Path;

    // Track hardlinks: maps (dev, inode) -> first path seen.
    // We key on (dev, ino) because overlay filesystems may present
    // different device numbers for directories vs regular files.
    let mut hardlinks: HashMap<(u64, u64), std::path::PathBuf> = HashMap::new();

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

        // Skip paths that shouldn't be in the exported tarball
        for skip_path in SKIP_PATHS {
            if relative_path.starts_with(skip_path) {
                // For directories, skip the entire subtree
                if entry.file_type.is_dir() {
                    return Ok(ControlFlow::Break(()));
                }
                return Ok(ControlFlow::Continue(()));
            }
        }

        let file_type = entry.file_type;
        if file_type.is_dir() {
            add_directory_to_tar_from_walk(
                tar_builder,
                entry.entry,
                path,
                relative_path,
                sepolicy_state,
                unlabeled_count,
            )
            .map_err(std::io::Error::other)?;
        } else if file_type.is_file() {
            add_file_to_tar_from_walk(
                tar_builder,
                entry.dir,
                entry.filename,
                path,
                relative_path,
                sepolicy_state,
                unlabeled_count,
                &mut hardlinks,
            )
            .map_err(std::io::Error::other)?;
        } else if file_type.is_symlink() {
            add_symlink_to_tar_from_walk(
                tar_builder,
                entry.dir,
                entry.filename,
                path,
                relative_path,
                sepolicy_state,
                unlabeled_count,
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
    entry: &cap_std_ext::cap_std::fs::DirEntry,
    absolute_path: &std::path::Path,
    relative_path: &std::path::Path,
    sepolicy_state: &SepolicyState,
    unlabeled_count: &mut u64,
) -> Result<()> {
    use cap_std_ext::cap_primitives::fs::PermissionsExt;

    let metadata = entry.metadata().with_context(|| {
        format!(
            "Failed to read directory metadata: {}",
            relative_path.display()
        )
    })?;
    let mut header = tar_header_from_meta(tar::EntryType::Directory, 0, &metadata);

    maybe_add_selinux_label(
        tar_builder,
        sepolicy_state,
        absolute_path,
        metadata.permissions().mode(),
        unlabeled_count,
    )?;

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
    sepolicy_state: &SepolicyState,
    unlabeled_count: &mut u64,
    hardlinks: &mut HashMap<(u64, u64), std::path::PathBuf>,
) -> Result<()> {
    use cap_std_ext::cap_primitives::fs::{MetadataExt, PermissionsExt};
    use std::path::Path;

    let filename_path = Path::new(filename);
    let metadata = dir.metadata(filename_path)?;

    // Check for hardlinks: if nlink > 1, this file may have other links.
    // We key on (dev, ino) because overlay filesystems may present
    // different device numbers for directories vs regular files.
    let nlink = metadata.nlink();
    if nlink > 1 {
        let key = (metadata.dev(), metadata.ino());
        if let Some(first_path) = hardlinks.get(&key) {
            let mut header = tar_header_from_meta(tar::EntryType::Link, 0, &metadata);

            maybe_add_selinux_label(
                tar_builder,
                sepolicy_state,
                absolute_path,
                metadata.permissions().mode(),
                unlabeled_count,
            )?;

            tar_builder
                .append_link(&mut header, relative_path, first_path)
                .with_context(|| format!("Failed to add hardlink: {}", relative_path.display()))?;
            return Ok(());
        } else {
            hardlinks.insert(key, relative_path.to_path_buf());
        }
    }

    let mut header = tar_header_from_meta(tar::EntryType::Regular, metadata.len(), &metadata);

    maybe_add_selinux_label(
        tar_builder,
        sepolicy_state,
        absolute_path,
        metadata.permissions().mode(),
        unlabeled_count,
    )?;

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
    sepolicy_state: &SepolicyState,
    unlabeled_count: &mut u64,
) -> Result<()> {
    use cap_std_ext::cap_primitives::fs::PermissionsExt;
    use std::path::Path;

    let filename_path = Path::new(filename);
    let link_target = dir
        .read_link_contents(filename_path)
        .with_context(|| format!("Failed to read symlink: {:?}", filename))?;
    let metadata = dir.symlink_metadata(filename_path)?;
    let mut header = tar_header_from_meta(tar::EntryType::Symlink, 0, &metadata);

    let symlink_mode = libc::S_IFLNK | (metadata.permissions().mode() & !libc::S_IFMT);
    maybe_add_selinux_label(
        tar_builder,
        sepolicy_state,
        absolute_path,
        symlink_mode,
        unlabeled_count,
    )?;

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

fn maybe_add_selinux_label<W: Write>(
    tar_builder: &mut tar::Builder<W>,
    sepolicy_state: &SepolicyState,
    absolute_path: &std::path::Path,
    mode: u32,
    unlabeled_count: &mut u64,
) -> Result<()> {
    let (policy, warn) = match sepolicy_state {
        SepolicyState::Disabled => return Ok(()),
        SepolicyState::Required(p) => (p, false),
        SepolicyState::WarnOnMissing(p) => (p, true),
    };

    let path_str = absolute_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Non-UTF8 path not supported: {:?}", absolute_path))?;
    let utf8_path = Utf8Path::new(path_str);

    match crate::lsm::optional_label(policy, utf8_path, mode)? {
        Some(label) if !label.is_empty() => {
            add_selinux_pax_extension(tar_builder, &label)?;
        }
        _ if !warn => {
            anyhow::bail!(
                "No label found in policy '{:?}' for {}",
                policy.csum(),
                absolute_path.display()
            );
        }
        _ => {
            *unlabeled_count += 1;
            tracing::debug!("No SELinux label for: {}", absolute_path.display());
        }
    }

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std_ext::cap_std::{ambient_authority, fs::Dir};
    use std::os::unix::fs::PermissionsExt;

    /// Walk `root` (with SELinux labeling disabled) and return the set of
    /// relative paths that ended up in the resulting tar archive.
    fn exported_paths(root: &std::path::Path) -> Result<std::collections::BTreeSet<String>> {
        let dir = Dir::open_ambient_dir(root, ambient_authority())?;
        let mut buf = Vec::new();
        {
            let mut tar_builder = tar::Builder::new(&mut buf);
            let mut unlabeled_count = 0u64;
            export_filesystem_walk(
                &mut tar_builder,
                &dir,
                &SepolicyState::Disabled,
                &mut unlabeled_count,
            )?;
            tar_builder.finish()?;
        }
        tar::Archive::new(buf.as_slice())
            .entries()?
            .map(|e| Ok(e?.path()?.to_string_lossy().into_owned()))
            .collect()
    }

    /// Walk `root` (with SELinux labeling disabled) and return modes for tar directories.
    fn exported_directory_modes(
        root: &std::path::Path,
    ) -> Result<std::collections::BTreeMap<String, u32>> {
        let dir = Dir::open_ambient_dir(root, ambient_authority())?;
        let mut buf = Vec::new();
        {
            let mut tar_builder = tar::Builder::new(&mut buf);
            export_filesystem_walk(&mut tar_builder, &dir, &SepolicyState::Disabled, &mut 0)?;
            tar_builder.finish()?;
        }

        let mut modes = std::collections::BTreeMap::new();
        for entry in tar::Archive::new(buf.as_slice()).entries()? {
            let entry = entry?;
            if entry.header().entry_type() != tar::EntryType::Directory {
                continue;
            }
            let path = entry
                .path()?
                .to_string_lossy()
                .trim_end_matches('/')
                .to_owned();
            modes.insert(path, entry.header().mode()? & 0o7777);
        }
        Ok(modes)
    }

    #[test]
    fn test_export_skips_tmp_and_var_tmp() -> Result<()> {
        let tmpdir = tempfile::tempdir()?;
        let root = tmpdir.path();

        // Content that must be skipped, including a stand-in for the
        // `/var/tmp/rhc` file dropped by package post-install scripts that
        // the SELinux policy has no file-context entry for.
        std::fs::create_dir_all(root.join("tmp/nested"))?;
        std::fs::write(root.join("tmp/nested/junk"), b"junk")?;
        std::fs::create_dir_all(root.join("var/tmp"))?;
        std::fs::write(root.join("var/tmp/rhc"), b"rhc-state")?;

        // Content that must be preserved.
        std::fs::create_dir_all(root.join("usr/bin"))?;
        std::fs::write(root.join("usr/bin/keep-me"), b"binary")?;
        std::fs::create_dir_all(root.join("var/lib"))?;
        std::fs::write(root.join("var/lib/keep-me-too"), b"state")?;

        let paths = exported_paths(root)?;

        assert!(paths.contains("usr/bin/keep-me"));
        assert!(paths.contains("var/lib/keep-me-too"));
        assert!(
            !paths.iter().any(|p| p == "tmp" || p.starts_with("tmp/")),
            "expected no /tmp entries, got: {paths:?}"
        );
        assert!(
            !paths
                .iter()
                .any(|p| p == "var/tmp" || p.starts_with("var/tmp/")),
            "expected no /var/tmp entries, got: {paths:?}"
        );

        Ok(())
    }

    #[test]
    fn test_export_preserves_directory_modes() -> Result<()> {
        let tmpdir = tempfile::tempdir()?;
        let root = tmpdir.path();
        let directories = [
            ("var", 0o2750),
            ("var/lib", 0o0711),
            ("var/lib/nested", 0o0751),
            ("var/cache", 0o0700),
        ];

        for (path, mode) in directories {
            let path = root.join(path);
            std::fs::create_dir_all(&path)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
        }

        let modes = exported_directory_modes(root)?;
        for (path, expected) in directories {
            assert_eq!(modes.get(path), Some(&expected), "mode for {path}");
        }

        Ok(())
    }
}
