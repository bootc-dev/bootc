use anyhow::{Context, Result, anyhow};
use camino::Utf8Path;
use ostree::gio;
use ostree::glib;
use ostree::prelude::*;
use std::collections::BTreeMap;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;

use crate::tar::EXCLUDED_TOPLEVEL_PATHS;

/// Configuration for filesystem filtering operations
#[derive(Debug, Clone, Default)]
pub struct FilesystemFilterConfig {
    /// Allow content outside /usr (for transient rootfs with overlayfs)
    pub allow_nonusr: bool,
    /// Remap /var to /usr/share/factory/var
    pub remap_factory_var: bool,
    /// Base commit to get SELinux policy from (unused for layer import -
    /// SELinux labeling happens during the merge step)
    pub base: Option<String>,
}

impl FilesystemFilterConfig {
    /// Create from WriteTarOptions
    pub fn from_tar_options(opts: &crate::tar::WriteTarOptions) -> Self {
        Self {
            allow_nonusr: opts.allow_nonusr,
            remap_factory_var: !opts.retain_var,
            base: opts.base.clone(),
        }
    }
}

/// Describes how a toplevel directory should be handled during import
enum ToplevelAction {
    /// Import directly using write_dfd_to_mtree at the given destination path
    Import { dest_path: &'static [&'static str] },
    /// Skip this directory entirely
    Skip,
}

/// Determine how to handle a toplevel directory entry
fn classify_toplevel(name: &str, config: &FilesystemFilterConfig) -> ToplevelAction {
    match name {
        "usr" => ToplevelAction::Import {
            dest_path: &["usr"],
        },
        "etc" => ToplevelAction::Import {
            dest_path: &["usr", "etc"],
        },
        "var" if config.remap_factory_var => ToplevelAction::Import {
            dest_path: &["usr", "share", "factory", "var"],
        },
        "var" => ToplevelAction::Import {
            dest_path: &["var"],
        },
        name if EXCLUDED_TOPLEVEL_PATHS.contains(&name) => ToplevelAction::Skip,
        _ if config.allow_nonusr => ToplevelAction::Import {
            // For non-usr paths when allowed, we need to handle dynamically
            // This case requires special handling since we can't return a static slice
            dest_path: &[],
        },
        _ => ToplevelAction::Skip,
    }
}

/// Check if a file is an overlay whiteout (character device with major/minor 0/0)
fn is_overlay_whiteout(metadata: &std::fs::Metadata) -> bool {
    let file_type = metadata.file_type();
    if !file_type.is_char_device() {
        return false;
    }
    // Check if rdev is 0 (major 0, minor 0)
    metadata.rdev() == 0
}

/// Import a filesystem directory directly to OSTree with path transformations.
///
/// Uses `write_dfd_to_mtree` for each file individually, enabling reflinks while
/// handling overlay whiteouts by converting them to OCI format.
///
/// Overlay whiteouts (char device 0/0) are converted to OCI-format whiteout files
/// (`.wh.<filename>`) to match the behavior of the tar import path.
///
/// Note: SELinux labeling is NOT performed here. It happens during the merge step
/// in the container import flow, where all layers are combined and labeled together
/// with the correct destination paths.
///
/// Returns the commit checksum. The caller is responsible for setting the ref
/// within a transaction.
pub fn import_filesystem_to_ostree(
    repo: &ostree::Repo,
    src_path: &Utf8Path,
    config: &FilesystemFilterConfig,
) -> Result<crate::tar::WriteTarResult> {
    let cancellable = gio::Cancellable::NONE;

    // Create the root MutableTree
    let root_mtree = ostree::MutableTree::new();
    let mut filtered_stats = BTreeMap::new();

    // Create a commit modifier - no SELinux here, it's applied during merge
    let modifier = ostree::RepoCommitModifier::new(ostree::RepoCommitModifierFlags::CONSUME, None);

    // Create default dirmeta for directories we create
    let dirmeta_checksum = create_default_dirmeta(repo)?;

    // Set the root tree's metadata checksum - required before write_mtree
    root_mtree.set_metadata_checksum(&dirmeta_checksum);

    // Read toplevel entries and process each according to its classification
    let entries =
        std::fs::read_dir(src_path).with_context(|| format!("Reading directory: {}", src_path))?;

    for entry in entries {
        let entry = entry.context("Reading directory entry")?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let file_type = entry.file_type().context("Getting file type")?;

        // Only process directories at toplevel
        if !file_type.is_dir() {
            continue;
        }

        let action = classify_toplevel(&name_str, config);

        match action {
            ToplevelAction::Import { dest_path } => {
                // Handle the special case of dynamic non-usr paths
                let dest_parts: Vec<&str> = if dest_path.is_empty() {
                    vec![&name_str]
                } else {
                    dest_path.to_vec()
                };

                // Ensure the destination directory exists in the MutableTree
                let dest_mtree = if dest_parts.len() == 1 {
                    root_mtree
                        .ensure_dir(dest_parts[0])
                        .with_context(|| format!("Creating directory: {}", dest_parts[0]))?
                } else {
                    // For nested paths like usr/etc or usr/share/factory/var,
                    // we need to ensure all parent directories exist
                    root_mtree
                        .ensure_parent_dirs(&dest_parts, &dirmeta_checksum)
                        .with_context(|| {
                            format!("Creating directory path: {}", dest_parts.join("/"))
                        })?
                };

                // Set metadata checksum on the destination directory
                dest_mtree.set_metadata_checksum(&dirmeta_checksum);

                let src_dir_path = src_path.join(&*name_str);

                // Import the directory recursively, handling whiteouts
                import_directory_recursive(
                    repo,
                    src_dir_path.as_std_path(),
                    &dest_mtree,
                    &modifier,
                    &dirmeta_checksum,
                    cancellable,
                )
                .with_context(|| {
                    format!(
                        "Importing directory '{}' to '{}'",
                        name_str,
                        dest_parts.join("/")
                    )
                })?;
            }
            ToplevelAction::Skip => {
                *filtered_stats.entry(name_str.to_string()).or_insert(0) += 1;
            }
        }
    }

    // Convert MutableTree to a RepoFile
    let root = repo
        .write_mtree(&root_mtree, cancellable)
        .context("Writing mtree")?;
    let root = root
        .downcast::<ostree::RepoFile>()
        .map_err(|_| anyhow!("Expected RepoFile"))?;

    // Create commit metadata
    let metadata = glib::VariantDict::new(None);
    metadata.insert(
        "ostree.importer.version",
        env!("CARGO_PKG_VERSION").to_variant(),
    );
    let metadata = metadata.to_variant();

    // Write the commit
    let commit = repo
        .write_commit(None, None, None, Some(&metadata), &root, cancellable)
        .context("Writing commit")?;

    Ok(crate::tar::WriteTarResult {
        commit: commit.to_string(),
        filtered: filtered_stats,
    })
}

/// Recursively import a directory, using write_dfd_to_mtree for each file
/// and converting overlay whiteouts to OCI format.
fn import_directory_recursive(
    repo: &ostree::Repo,
    src_dir: &Path,
    mtree: &ostree::MutableTree,
    modifier: &ostree::RepoCommitModifier,
    dirmeta_checksum: &str,
    cancellable: Option<&gio::Cancellable>,
) -> Result<()> {
    // Open the source directory for use with write_dfd_to_mtree
    let src_fd = rustix::fs::openat(
        rustix::fs::CWD,
        src_dir,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )
    .with_context(|| format!("Opening directory: {}", src_dir.display()))?;

    let entries = std::fs::read_dir(src_dir)
        .with_context(|| format!("Reading directory: {}", src_dir.display()))?;

    for entry in entries {
        let entry = entry.context("Reading directory entry")?;
        let file_name = entry.file_name();
        let file_name_str = file_name.to_string_lossy();
        let file_path = entry.path();

        let metadata = std::fs::symlink_metadata(&file_path)
            .with_context(|| format!("Getting metadata for: {}", file_path.display()))?;
        let file_type = metadata.file_type();

        if file_type.is_dir() {
            // Create subdirectory in mtree and recurse
            let sub_mtree = mtree
                .ensure_dir(&file_name_str)
                .with_context(|| format!("Creating directory: {}", file_name_str))?;
            sub_mtree.set_metadata_checksum(dirmeta_checksum);

            import_directory_recursive(
                repo,
                &file_path,
                &sub_mtree,
                modifier,
                dirmeta_checksum,
                cancellable,
            )?;
        } else if file_type.is_file() || file_type.is_symlink() {
            // Use write_dfd_to_mtree for the individual file - this enables reflinks
            repo.write_dfd_to_mtree(
                src_fd.as_raw_fd(),
                &file_name_str,
                mtree,
                Some(modifier),
                cancellable,
            )
            .with_context(|| format!("Importing file: {}", file_path.display()))?;
        } else if is_overlay_whiteout(&metadata) {
            // Convert overlay whiteout to OCI format (.wh.<filename>)
            let whiteout_name = format!(".wh.{}", file_name_str);
            let checksum = create_empty_file(repo)?;
            mtree
                .replace_file(&whiteout_name, &checksum)
                .with_context(|| format!("Adding whiteout file: {}", whiteout_name))?;
            tracing::debug!(
                src = %file_path.display(),
                dest = %whiteout_name,
                "Converted overlay whiteout to OCI format"
            );
        } else {
            // Skip other special files (sockets, fifos, block devices)
            tracing::debug!(path = %file_path.display(), "Skipping special file");
        }
    }

    Ok(())
}

/// Create default directory metadata and return its checksum
fn create_default_dirmeta(repo: &ostree::Repo) -> Result<String> {
    let cancellable = gio::Cancellable::NONE;

    let finfo = gio::FileInfo::new();
    finfo.set_file_type(gio::FileType::Directory);
    finfo.set_attribute_uint32("unix::uid", 0);
    finfo.set_attribute_uint32("unix::gid", 0);
    finfo.set_attribute_uint32("unix::mode", libc::S_IFDIR | 0o755);

    let dirmeta = ostree::create_directory_metadata(&finfo, None);
    let checksum = repo
        .write_metadata(ostree::ObjectType::DirMeta, None, &dirmeta, cancellable)?
        .to_hex();

    Ok(checksum)
}

/// Create an empty file and return its checksum (for whiteout files)
fn create_empty_file(repo: &ostree::Repo) -> Result<String> {
    let cancellable = gio::Cancellable::NONE;

    let checksum =
        repo.write_regfile_inline(None, 0, 0, libc::S_IFREG | 0o644, None, &[], cancellable)?;

    Ok(checksum.to_string())
}
