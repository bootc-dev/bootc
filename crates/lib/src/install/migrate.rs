//! # Package-mode to image-mode migration helpers
//!
//! This module implements the post-install state-preservation steps that make
//! `bootc install to-existing-root` useful for converting a live package-mode
//! (RPM/DEB) system to a bootc image-mode deployment without losing data.
//!
//! This migration is triggered by passing `--preserve-var` to
//! `bootc install to-existing-root`. It runs **after** the core install
//! (ostree deploy + bootupd) completes but **before** the first reboot, while
//! the package-mode environment is still the running OS.
//!
//! ## `/var` preservation (`--preserve-var`)
//!
//! After a plain `bootc install to-existing-root`, the new deployment's `/var`
//! is bound from `<sysroot>/ostree/deploy/<stateroot>/var/` — an initially-empty
//! directory.  The old package-mode `/var` is stranded at `<root_path>/var`
//! (inside the container, the host root is mounted at `root_path`).
//!
//! Two strategies are tried in order:
//!
//! - **Strategy C — reflink copy** (btrfs / XFS with reflinks): `cp --reflink=auto`
//!   clones files copy-on-write where possible and falls back to a regular copy
//!   for individual files that cannot be cloned. Files are handled individually,
//!   so this is not an atomic snapshot of the `/var` tree or of a live database.
//!
//! - **Strategy D — plain copy** (ext4 and other non-reflink filesystems):
//!   `cp -a` copies each non-ephemeral subdirectory of `/var` into the new
//!   deployment's stateroot `var/`.  This is correct but slow for large `/var`
//!   trees, and **unsafe for live databases** (see the known-limitation comment
//!   on `preserve_var_copy_mounts`).
//!
//! Nested mountpoints are selected from one `/proc/self/mountinfo` snapshot
//! before the copy. This is a point-in-time, best-effort snapshot, not a
//! race-free guard: mounts added or removed beneath `/var` during copying can
//! race with the copy, just like concurrent file changes.
//! Each missing entry is copied to a unique sibling staging directory and
//! published atomically without replacing an existing destination. A failed
//! entry leaves no partial final entry and can be retried; there is no global
//! rollback, so entries completely published before a later failure remain.
//!
//! The built-in exclusions are `tmp`, `cache`, `log/journal`, and
//! `lib/containers`. Additional exclusions can be supplied through
//! configuration or repeated `--preserve-var-skip` options; `lib/rpm` is not
//! excluded unless explicitly configured.
//!
//! Staging directories use names beginning `.bootc-preserve-var.` beneath the
//! destination `/var`. They are cleaned up during normal success and error
//! handling, but an abrupt termination can leave them behind. They are not
//! automatically removed on a later run because a matching entry could be
//! unrelated. Before manually removing one, ensure no migration is running and
//! verify the individual entry is an artifact of an interrupted migration; do
//! not blindly remove every similarly named entry.
//!
//! Staged rename publication is atomic for namespace visibility, but this code
//! does not fsync copied files or directories. It therefore makes no guarantee
//! that a published entry survives sudden power loss or kernel failure. This is
//! per-entry publication, not a transaction: entries published before a later
//! error remain.
//!
//! Rollback preservation is intentionally independent from `/var` migration.

mod mountinfo;

use std::path::{Component, Path};
use std::{
    collections::BTreeSet,
    ffi::OsStr,
    os::fd::AsFd,
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use crate::store::reflink::supports_reflink;
use anyhow::{Context, Result};
use cap_std_ext::cap_std::ambient_authority;
use cap_std_ext::cap_std::fs::{Dir as CapStdDir, Metadata, MetadataExt};
use cap_std_ext::cap_std::io_lifetimes::AsFilelike;
use cap_std_ext::cmdext::{CapStdExtCommandExt, CmdFds};
#[cfg(test)]
use fn_error_context::context;

/// Paths below `/var` which `--preserve-var` never copies.
const ALWAYS_EXCLUDED: &[&str] = &["tmp", "cache", "log/journal", "lib/containers"];

/// Source-side work identified before the install starts. Copying remains a
/// post-install operation and can still fail (for example, due to space or
/// concurrent source changes).
#[derive(Debug)]
pub(crate) struct VarMigrationPlan {
    /// Canonical path of the running system's `/var`.
    src_var: PathBuf,
    /// Mounts below `src_var`, relative to it, which get empty placeholders.
    nested_mounts: BTreeSet<PathBuf>,
    /// Built-in and requested exclusions, relative to `src_var`.
    exclusions: Vec<String>,
}

impl VarMigrationPlan {
    /// Resolve and inspect source `/var` before installation touches the target.
    pub(crate) fn prepare(src_var: &Path, exclusions: &[String]) -> Result<Self> {
        let canonical_src_var = std::fs::canonicalize(src_var)
            .with_context(|| format!("Canonicalizing source /var {}", src_var.display()))?;
        let source = CapStdDir::open_ambient_dir(&canonical_src_var, ambient_authority())
            .with_context(|| format!("Opening source {}", canonical_src_var.display()))?;
        for entry in source
            .entries()
            .with_context(|| format!("Listing source {}", canonical_src_var.display()))?
        {
            entry.with_context(|| format!("Reading source {}", canonical_src_var.display()))?;
        }

        let nested_mounts = mountinfo::nested_mountpoints_for(&canonical_src_var)?;
        let exclusions = ALWAYS_EXCLUDED
            .iter()
            .map(|path| (*path).to_string())
            .chain(exclusions.iter().cloned())
            .collect::<Vec<_>>();

        validate_mountpoint_types(&canonical_src_var, &exclusions, &nested_mounts)?;

        Ok(Self {
            src_var: canonical_src_var,
            nested_mounts,
            exclusions,
        })
    }
}

/// Only directories and regular files can receive safe placeholders. Do not
/// inspect mountpoints the filtered copy will never reach.
fn validate_mountpoint_types(
    src_var: &Path,
    exclusions: &[String],
    nested_mounts: &BTreeSet<PathBuf>,
) -> Result<()> {
    for mount in nested_mounts {
        let is_excluded = exclusions
            .iter()
            .any(|excluded| mount.starts_with(excluded));
        let is_below_another_mount = nested_mounts
            .iter()
            .any(|other| other != mount && mount.starts_with(other));
        if is_excluded || is_below_another_mount {
            continue;
        }
        let metadata = std::fs::symlink_metadata(src_var.join(mount))
            .with_context(|| format!("Inspecting mountpoint /var/{}", mount.display()))?;
        anyhow::ensure!(
            metadata.is_dir() || metadata.is_file(),
            "/var/{} is a mountpoint that is neither a directory nor a file; exclude it with --preserve-var-skip",
            mount.display()
        );
    }
    Ok(())
}

/// Preserve the running `/var` into the new deployment's `var/` directory.
///
/// `new_var` is the new deployment's `var/` directory, which may have
/// image-seeded content.
pub(crate) fn preserve_var(plan: &VarMigrationPlan, new_var: &Path) -> Result<()> {
    let src_var = CapStdDir::open_ambient_dir(&plan.src_var, ambient_authority())
        .with_context(|| format!("Opening source {}", plan.src_var.display()))?;
    let new_var = open_or_create_var_dir(new_var)?;

    let effective_exclusions = &plan.exclusions;
    let nested_mounts = &plan.nested_mounts;

    let copy_result = if supports_reflink(&src_var, &new_var)? {
        println!("  Filesystem supports reflinks — using copy-on-write clone (Strategy C)");
        preserve_var_reflink_mounts(&src_var, &new_var, effective_exclusions, nested_mounts)
    } else {
        println!("  Filesystem does not support reflinks — falling back to full copy (Strategy D)");
        preserve_var_copy_mounts(&src_var, &new_var, effective_exclusions, nested_mounts)
    };
    copy_result?;

    Ok(())
}

/// Open the destination through its parent capability, creating just the
/// final `/var` directory if needed. The caller-supplied parent is the initial
/// ambient authority; all subsequent traversal is relative to opened handles.
fn open_or_create_var_dir(path: &Path) -> Result<CapStdDir> {
    let parent = path.parent().context("Destination /var has no parent")?;
    let name = path
        .file_name()
        .context("Destination /var has no final path component")?;
    let parent = CapStdDir::open_ambient_dir(parent, ambient_authority())
        .with_context(|| format!("Opening destination parent {}", parent.display()))?;
    match parent.create_dir(name) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            anyhow::ensure!(
                parent.symlink_metadata(name)?.is_dir(),
                "Destination {} exists and is not a directory",
                path.display()
            );
        }
        Err(e) => return Err(e).with_context(|| format!("Creating {}", path.display())),
    }
    open_child_dir_nofollow(&parent, name)
        .with_context(|| format!("Opening destination {}", path.display()))
}

pub(crate) fn deployment_var_path(deploy_dir: &Path) -> Result<std::path::PathBuf> {
    let deploy_parent = deploy_dir
        .parent()
        .context("Deployment path has no parent")?;
    let stateroot = deploy_parent
        .parent()
        .context("Deployment path has no stateroot")?;
    Ok(stateroot.join("var"))
}

/// Run GNU cp with directory handles inherited as fixed descriptors. Each
/// operand is `/proc/self/fd/N[/entry]`; cp's top-level paths therefore remain
/// rooted in the opened capabilities even if the original paths are renamed.
/// GNU cp still performs its own recursive traversal beneath each operand, so
/// this is not race-safe against a concurrent writer replacing entries while
/// the copy is in progress.
fn run_cp(
    cp_program: &OsStr,
    src_root: &CapStdDir,
    src_names: &[&OsStr],
    dst_root: &CapStdDir,
    dst_name: Option<&OsStr>,
    options: &[&str],
    stdout: Stdio,
    stderr: Stdio,
) -> Result<std::process::ExitStatus> {
    let src_fd = Arc::new(
        src_root
            .as_filelike_view::<std::fs::File>()
            .as_fd()
            .try_clone_to_owned()?,
    );
    let dst_fd = Arc::new(
        dst_root
            .as_filelike_view::<std::fs::File>()
            .as_fd()
            .try_clone_to_owned()?,
    );
    let mut fds = CmdFds::new();
    fds.take_fd_n(src_fd, 3);
    fds.take_fd_n(dst_fd, 4);

    let src_paths = src_names.iter().map(|name| {
        let mut path = PathBuf::from("/proc/self/fd/3");
        path.push(name);
        path
    });
    let mut dst_path = PathBuf::from("/proc/self/fd/4");
    if let Some(name) = dst_name {
        dst_path.push(name);
    }

    let status = Command::new(cp_program)
        .args(options)
        .arg("--")
        .args(src_paths)
        .arg(dst_path)
        .stdout(stdout)
        .stderr(stderr)
        .take_fds(fds)
        .status()
        .context("Running cp")?;
    Ok(status)
}

/// Strategy C: reflink-copy each top-level entry under `src_var` into `new_var`.
///
/// Skips well-known ephemeral subdirectories.
#[cfg(test)]
#[context("Reflink-copying /var into new deployment (Strategy C)")]
fn preserve_var_reflink(
    src_var: &CapStdDir,
    new_var: &CapStdDir,
    exclusions: &[String],
) -> Result<()> {
    preserve_var_reflink_mounts(src_var, new_var, exclusions, &BTreeSet::new())
}

fn preserve_var_reflink_mounts(
    src_var: &CapStdDir,
    new_var: &CapStdDir,
    exclusions: &[String],
    mountpoints: &BTreeSet<PathBuf>,
) -> Result<()> {
    copy_var_filtered(
        src_var,
        new_var,
        Path::new(""),
        exclusions,
        mountpoints,
        true,
        false,
        OsStr::new(GNU_CP),
    )
    .context("Reflink-copying /var into new deployment (Strategy C)")?;
    println!("  /var reflink copy complete.");
    Ok(())
}

/// Copy a directory's ordinary children together with cp -a, recursing only
/// into directories whose descendants contain a mountpoint or exclusion.
/// Batching ordinary siblings in one cp invocation retains hardlinks between
/// those entries. Hardlinks crossing a mountpoint or exclusion split, or
/// crossing separate copies while merging into an existing destination
/// directory, may not remain linked. Untouched subtrees remain entirely under
/// cp -a's control.
fn copy_var_filtered(
    src_dir: &CapStdDir,
    dst_dir: &CapStdDir,
    relative_dir: &Path,
    exclusions: &[String],
    mountpoints: &BTreeSet<PathBuf>,
    reflink: bool,
    destination_created: bool,
    cp_program: &OsStr,
) -> Result<()> {
    // Existing directories are merged in place, so capture their own metadata
    // before reading or copying children can alter their atime/mtime. The same
    // wrapper restores source metadata on newly-created destination directories.
    let source_metadata = if destination_created {
        Some(snapshot_directory_metadata(src_dir).with_context(|| {
            format!(
                "Snapshotting source metadata for /var/{}",
                relative_dir.display()
            )
        })?)
    } else {
        None
    };
    let destination_metadata = if destination_created {
        None
    } else {
        Some(dst_dir.metadata(".").with_context(|| {
            format!(
                "Snapshotting existing destination timestamps for /var/{}",
                relative_dir.display()
            )
        })?)
    };

    let copy_result = copy_var_filtered_inner(
        src_dir,
        dst_dir,
        relative_dir,
        exclusions,
        mountpoints,
        reflink,
        cp_program,
    );
    let restore_result = match (source_metadata.as_ref(), destination_metadata.as_ref()) {
        (Some(metadata), _) => restore_directory_metadata(dst_dir, metadata),
        (None, Some(metadata)) => restore_directory_timestamps(dst_dir, metadata),
        (None, None) => Ok(()),
    }
    .with_context(|| {
        format!(
            "Restoring directory metadata for /var/{}",
            relative_dir.display()
        )
    });

    match (copy_result, restore_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(restore_error)) => Err(restore_error),
        (Err(copy_error), Ok(())) => Err(copy_error),
        (Err(copy_error), Err(restore_error)) => Err(copy_error.context(format!(
            "Additionally failed to restore /var/{} metadata: {restore_error:#}",
            relative_dir.display()
        ))),
    }
}

fn copy_var_filtered_inner(
    src_dir: &CapStdDir,
    dst_dir: &CapStdDir,
    relative_dir: &Path,
    exclusions: &[String],
    mountpoints: &BTreeSet<PathBuf>,
    reflink: bool,
    cp_program: &OsStr,
) -> Result<()> {
    let entries = src_dir
        .read_dir(".")
        .with_context(|| format!("Reading /var/{}", relative_dir.display()))?;

    let mut included_entries = Vec::new();
    for entry in entries {
        let entry = entry.context("Reading entry in /var during migration")?;
        let name = entry.file_name();
        let relative = relative_dir.join(&name);

        if exclusions
            .iter()
            .any(|excluded| Path::new(excluded) == relative)
        {
            println!("    Skipping {} (excluded)", relative.display());
            continue;
        }

        if mountpoints.contains(&relative) {
            println!(
                "    Creating empty mountpoint placeholder for {}",
                relative.display()
            );
            create_staged_placeholder(src_dir, dst_dir, &name, &relative)?;
            continue;
        }

        let has_nested_mount = mountpoints
            .iter()
            .any(|mountpoint| mountpoint != &relative && mountpoint.starts_with(&relative));
        let has_nested_exclusion = exclusions.iter().any(|excluded| {
            let excluded = Path::new(excluded);
            excluded != relative && excluded.starts_with(&relative)
        });
        let source_metadata = src_dir.symlink_metadata(&name)?;
        if source_metadata.is_dir() {
            let child_src = open_child_dir_nofollow(src_dir, &name)
                .with_context(|| format!("Opening /var/{}", relative.display()))?;
            // Use the opened directory as the source of truth for metadata.
            // This keeps the directory metadata and xattrs tied to the same
            // inode even if its parent entry is replaced after the open.
            let existing_dst = open_existing_child_dir(dst_dir, &name)?;
            if let Some(child_dst) = existing_dst {
                copy_var_filtered(
                    &child_src,
                    &child_dst,
                    &relative,
                    exclusions,
                    mountpoints,
                    reflink,
                    false,
                    cp_program,
                )?;
            } else if destination_entry_exists(dst_dir, &name)? {
                // A destination of a different type is an existing entry, not
                // permission to replace it with the source directory.
                println!(
                    "    Skipping destination collision at /var path {:?}",
                    relative
                );
                continue;
            } else if has_nested_mount || has_nested_exclusion {
                copy_filtered_directory_staged(
                    &child_src,
                    dst_dir,
                    &name,
                    &relative,
                    exclusions,
                    mountpoints,
                    reflink,
                    cp_program,
                )?;
            } else {
                included_entries.push(name);
            }
            continue;
        }
        if destination_entry_exists(dst_dir, &name)? {
            // Match cp --no-clobber without ever opening the existing object.
            println!(
                "    Skipping destination collision at /var path {:?}",
                relative
            );
            continue;
        }
        included_entries.push(name);
    }

    if !included_entries.is_empty() {
        let names = included_entries
            .iter()
            .map(|name| name.as_os_str())
            .collect::<Vec<_>>();
        copy_batch_staged(cp_program, src_dir, &names, dst_dir, reflink, relative_dir)?;
    }

    Ok(())
}

static NEXT_STAGING_ID: AtomicU64 = AtomicU64::new(0);
// Bound collision retries so a pathological destination cannot make staging
// allocation loop forever. The process id plus monotonic id makes collisions
// exceptional; one hundred attempts leave room for stale entries while still
// failing promptly if the namespace is obstructed.
const STAGING_NAME_ATTEMPTS: u32 = 100;

// Do not resolve privileged copy commands through a caller-controlled PATH.
// Lower-level helpers still accept an executable parameter for test injection.
const GNU_CP: &str = "/usr/bin/cp";
const CP_REFLINK_OPTIONS: &[&str] = &["--reflink=auto", "-a"];

/// Make an empty, uniquely-named staging directory beneath the destination
/// capability. Publishing from the same parent keeps the final rename atomic.
fn create_staging_dir(parent: &CapStdDir) -> Result<(std::ffi::OsString, CapStdDir)> {
    use rustix::fs::{Mode, mkdirat};

    let parent_fd = parent.as_filelike_view::<std::fs::File>();
    for _ in 0..STAGING_NAME_ATTEMPTS {
        let id = NEXT_STAGING_ID.fetch_add(1, Ordering::Relaxed);
        let name =
            std::ffi::OsString::from(format!(".bootc-preserve-var.{}.{}", std::process::id(), id));
        match mkdirat(parent_fd.as_fd(), &name, Mode::from_bits_truncate(0o700)) {
            Ok(()) => match open_child_dir_nofollow(parent, &name) {
                Ok(directory) => return Ok((name, directory)),
                Err(error) => {
                    parent.remove_dir_all(&name).with_context(|| {
                        format!("Cleaning staging directory after open failure: {error}")
                    })?;
                    return Err(error).context("Opening /var migration staging directory");
                }
            },
            Err(error) if error == rustix::io::Errno::EXIST => continue,
            Err(error) => {
                return Err(error).context("Creating /var migration staging directory");
            }
        }
    }
    anyhow::bail!("Unable to allocate a unique /var migration staging directory")
}

/// Ensure temporary staging entries are removed on both success and failure.
/// Any entries already published remain complete; there is no global rollback
/// of earlier successful publications.
fn with_staging_dir<T>(
    parent: &CapStdDir,
    operation: impl FnOnce(&OsStr, &CapStdDir) -> Result<T>,
) -> Result<T> {
    let (name, directory) = create_staging_dir(parent)?;
    let result = operation(&name, &directory);
    drop(directory);
    let cleanup = parent
        .remove_dir_all(&name)
        .context("Removing /var migration staging data");
    match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup_error)) => Err(error.context(format!(
            "Additionally failed to clean migration staging data: {cleanup_error:#}"
        ))),
    }
}

fn destination_entry_exists(parent: &CapStdDir, name: &OsStr) -> Result<bool> {
    match parent.symlink_metadata(name) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn publish_staged_entry(
    staging: &CapStdDir,
    destination: &CapStdDir,
    name: &OsStr,
    relative: &Path,
) -> Result<bool> {
    use rustix::fs::{RenameFlags, renameat_with};

    match renameat_with(staging, name, destination, name, RenameFlags::NOREPLACE) {
        Ok(()) => Ok(true),
        // A destination can appear after the initial no-clobber check. Merge
        // staged directories into a same-type destination without replacing
        // existing children; other collisions remain untouched.
        Err(error) if error == rustix::io::Errno::EXIST => {
            println!(
                "    Destination collision at /var path {:?}; keeping existing entries",
                relative
            );
            if staging.symlink_metadata(name)?.is_dir() {
                if let Some(destination_dir) = open_existing_child_dir(destination, name)? {
                    let staging_dir = open_child_dir_nofollow(staging, name)
                        .context("Opening staged directory after publish collision")?;
                    merge_staged_directory(&staging_dir, &destination_dir, relative)?;
                }
            }
            Ok(false)
        }
        Err(error) => Err(error.into()),
    }
}

/// Move staged children into an existing destination directory without
/// replacing entries already present there. Keep the destination directory's
/// metadata unchanged; moving children updates its timestamps, so restore its
/// original metadata after the merge.
fn merge_staged_directory(
    staging: &CapStdDir,
    destination: &CapStdDir,
    relative_dir: &Path,
) -> Result<()> {
    let metadata = snapshot_directory_metadata(destination)?;
    let names = staging
        .read_dir(".")?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;

    let merge_result = (|| {
        for name in names {
            publish_staged_entry(staging, destination, &name, &relative_dir.join(&name))?;
        }
        Ok(())
    })();
    let restore_result = restore_directory_metadata(destination, &metadata);

    match (merge_result, restore_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(restore_error)) => Err(error.context(format!(
            "Additionally failed to restore merged destination directory metadata: {restore_error:#}"
        ))),
    }
}

fn copy_batch_staged(
    cp_program: &OsStr,
    source: &CapStdDir,
    names: &[&OsStr],
    destination: &CapStdDir,
    reflink: bool,
    relative_dir: &Path,
) -> Result<()> {
    with_staging_dir(destination, |_, staging| {
        let options = if reflink {
            CP_REFLINK_OPTIONS
        } else {
            &["-a"][..]
        };
        let status = run_cp(
            cp_program,
            source,
            names,
            staging,
            None,
            options,
            Stdio::inherit(),
            Stdio::inherit(),
        )?;
        anyhow::ensure!(
            status.success(),
            "cp failed while copying /var/{}",
            relative_dir.display()
        );

        for name in names {
            publish_staged_entry(staging, destination, name, &relative_dir.join(name))?;
        }
        Ok(())
    })
}

fn copy_filtered_directory_staged(
    source: &CapStdDir,
    destination_parent: &CapStdDir,
    name: &OsStr,
    relative: &Path,
    exclusions: &[String],
    mountpoints: &BTreeSet<PathBuf>,
    reflink: bool,
    cp_program: &OsStr,
) -> Result<()> {
    with_staging_dir(destination_parent, |_, staging| {
        staging.create_dir(name)?;
        let destination = open_child_dir_nofollow(staging, name)?;
        copy_var_filtered(
            source,
            &destination,
            relative,
            exclusions,
            mountpoints,
            reflink,
            true,
            cp_program,
        )?;
        publish_staged_entry(staging, destination_parent, name, relative)?;
        Ok(())
    })
}

fn create_staged_placeholder(
    src_parent: &CapStdDir,
    dst_parent: &CapStdDir,
    name: &OsStr,
    relative: &Path,
) -> Result<()> {
    with_staging_dir(dst_parent, |_, staging| {
        create_mountpoint_placeholder(src_parent, staging, name)?;
        if !publish_staged_entry(staging, dst_parent, name, relative)? {
            validate_existing_placeholder(
                dst_parent,
                name,
                relative,
                src_parent.symlink_metadata(name)?,
            )?;
        }
        Ok(())
    })
}

fn validate_existing_placeholder(
    destination_parent: &CapStdDir,
    name: &OsStr,
    relative: &Path,
    source_metadata: Metadata,
) -> Result<()> {
    let destination_metadata = destination_parent.symlink_metadata(name)?;
    let same_type = (source_metadata.is_dir() && destination_metadata.is_dir())
        || (source_metadata.is_file() && destination_metadata.is_file());
    anyhow::ensure!(
        same_type,
        "Mountpoint placeholder /var/{} already exists in the new deployment with a different type",
        relative.display()
    );
    let has_content = if destination_metadata.is_dir() {
        open_child_dir_nofollow(destination_parent, name)?
            .entries()?
            .next()
            .is_some()
    } else {
        destination_metadata.len() > 0
    };
    if has_content {
        println!(
            "    Keeping the image's content at mountpoint /var/{}; the mount hides it at boot",
            relative.display()
        );
    }
    Ok(())
}

fn create_mountpoint_placeholder(
    src_parent: &CapStdDir,
    dst_parent: &CapStdDir,
    name: &OsStr,
) -> Result<()> {
    let metadata = src_parent.symlink_metadata(name)?;
    if metadata.is_dir() {
        let src_dir = open_child_dir_nofollow(src_parent, name)
            .context("Opening mountpoint source directory")?;
        let directory_metadata = src_dir
            .metadata(".")
            .context("Reading mountpoint source directory metadata")?;
        dst_parent.create_dir(name).with_context(|| {
            format!(
                "Creating mountpoint directory placeholder {}",
                name.to_string_lossy()
            )
        })?;
        let dst_dir = open_child_dir_nofollow(dst_parent, name)
            .context("Opening mountpoint directory placeholder")?;
        preserve_directory_metadata(&src_dir, &dst_dir, &directory_metadata)
            .context("Preserving mountpoint directory metadata")?;
        return Ok(());
    }
    anyhow::ensure!(
        metadata.is_file(),
        "Cannot create safe placeholder for non-file mountpoint {}",
        name.to_string_lossy()
    );
    use cap_std_ext::cap_std::fs::OpenOptions;
    let dst_file = dst_parent
        .open_with(name, OpenOptions::new().write(true).create_new(true))
        .context("Creating empty mountpoint file placeholder")?;
    preserve_metadata(
        src_parent,
        name,
        &metadata,
        dst_file.as_filelike_view::<std::fs::File>().as_fd(),
    )
    .context("Preserving mountpoint file metadata")
}

/// Reproduce metadata for a directory which was split into filtered children
/// instead of being copied by `cp -a` as one subtree.
fn preserve_directory_metadata(
    src_dir: &CapStdDir,
    dst_dir: &CapStdDir,
    metadata: &Metadata,
) -> Result<()> {
    restore_directory_metadata(
        dst_dir,
        &snapshot_directory_metadata_from_source(src_dir, metadata)?,
    )
}

struct DirectoryMetadataSnapshot {
    metadata: Metadata,
    xattrs: Vec<(std::ffi::OsString, Vec<u8>)>,
}

fn snapshot_directory_metadata(directory: &CapStdDir) -> Result<DirectoryMetadataSnapshot> {
    let metadata = directory.metadata(".")?;
    snapshot_directory_metadata_from_source(directory, &metadata)
}

fn snapshot_directory_metadata_from_source(
    directory: &CapStdDir,
    metadata: &Metadata,
) -> Result<DirectoryMetadataSnapshot> {
    use cap_std_ext::dirext::CapStdExtDirExt;

    let mut xattrs = Vec::new();
    for attribute in directory.listxattrs(".")?.iter() {
        if let Some(value) = directory.getxattr(".", attribute)? {
            xattrs.push((attribute.to_os_string(), value));
        }
    }
    Ok(DirectoryMetadataSnapshot {
        metadata: metadata.clone(),
        xattrs,
    })
}

fn restore_directory_metadata(
    directory: &CapStdDir,
    snapshot: &DirectoryMetadataSnapshot,
) -> Result<()> {
    use rustix::fs::{Mode, fchmod};

    let dst_fd = open_directory_for_metadata(directory)?;
    let mut errors = Vec::new();
    if let Err(error) = preserve_metadata_owner(&snapshot.metadata, &dst_fd) {
        errors.push(format!("owner/group: {error:#}"));
    }
    if let Err(error) = fchmod(
        &dst_fd,
        Mode::from_bits_truncate(snapshot.metadata.mode() & 0o7777),
    ) {
        errors.push(format!("mode: {error:#}"));
    }
    if let Err(error) = apply_xattrs_exact(&dst_fd, &snapshot.xattrs) {
        errors.push(format!("xattrs: {error:#}"));
    }
    if let Err(error) = preserve_metadata_timestamps(&snapshot.metadata, &dst_fd) {
        errors.push(format!("timestamps: {error:#}"));
    }
    if !errors.is_empty() {
        anyhow::bail!("restoring directory metadata failed: {}", errors.join("; "));
    }
    Ok(())
}

fn restore_directory_timestamps(directory: &CapStdDir, metadata: &Metadata) -> Result<()> {
    let dst_fd = open_directory_for_metadata(directory)?;
    preserve_metadata_timestamps(metadata, &dst_fd)
}

/// Open a usable fd for fd-based metadata operations while remaining anchored
/// to the pinned directory capability. CapStdDir may hold an O_PATH fd, which
/// cannot be used with fchmod, xattr, or timestamp operations.
fn open_directory_for_metadata(directory: &CapStdDir) -> Result<std::os::fd::OwnedFd> {
    use rustix::fs::{Mode, OFlags, openat};

    let directory_file = directory.as_filelike_view::<std::fs::File>();
    Ok(openat(
        directory_file.as_fd(),
        ".",
        OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::RDONLY,
        Mode::empty(),
    )?)
}

/// Preserve ownership, mode, timestamps, and available xattrs (including ACL
/// and SELinux labels) on a newly-created destination object. Callers only use
/// this for objects created by this migration, preserving the no-clobber rule.
/// For mountpoint file placeholders, source metadata and xattrs still use the
/// parent/name pair captured before the destination is opened; replacing that
/// source entry concurrently can therefore race those reads. Destination
/// updates remain anchored to the opened destination fd. Split directory
/// metadata and xattrs instead use the opened source directory handle.
fn preserve_metadata<Fd: AsFd>(
    src_parent: &CapStdDir,
    src_name: &OsStr,
    metadata: &Metadata,
    dst_fd: Fd,
) -> Result<()> {
    use cap_std_ext::dirext::CapStdExtDirExt;

    let mut source_xattrs = Vec::new();
    for attribute in src_parent.listxattrs(src_name)?.iter() {
        if let Some(value) = src_parent.getxattr(src_name, attribute)? {
            source_xattrs.push((attribute.to_os_string(), value));
        }
    }
    preserve_metadata_owner_and_mode(metadata, &dst_fd)?;
    apply_xattrs_exact(&dst_fd, &source_xattrs)?;
    preserve_metadata_timestamps(metadata, &dst_fd)
}

const SELINUX_XATTR: &str = "security.selinux";

/// Make the destination xattr set match the source snapshot, except that a
/// destination SELinux label is retained when the source has no label.
/// Removing extras first matters for inherited ACLs and labels as well as user
/// xattrs.
fn apply_xattrs_exact<Fd: AsFd>(
    destination: Fd,
    source_xattrs: &[(std::ffi::OsString, Vec<u8>)],
) -> Result<()> {
    use rustix::fs::{fremovexattr, fsetxattr};
    use std::collections::BTreeSet;

    let destination_names = list_fd_xattrs(&destination)?;
    let source_names = source_xattrs
        .iter()
        .map(|(name, _)| name.as_os_str())
        .collect::<BTreeSet<_>>();
    for name in destination_names {
        if !source_names.contains(name.as_os_str()) && name.as_os_str() != OsStr::new(SELINUX_XATTR)
        {
            fremovexattr(&destination, &name).with_context(|| {
                format!("Removing destination xattr {}", name.to_string_lossy())
            })?;
        }
    }
    for (name, value) in source_xattrs {
        fsetxattr(&destination, name, value, rustix::fs::XattrFlags::empty())
            .with_context(|| format!("Setting source xattr {}", name.to_string_lossy()))?;
    }
    Ok(())
}

fn list_fd_xattrs<Fd: AsFd>(fd: Fd) -> Result<Vec<std::ffi::OsString>> {
    use std::os::unix::ffi::OsStringExt;

    // Linux caps the complete xattr-name list at XATTR_LIST_MAX (64 KiB).
    let mut names = vec![0; 64 * 1024];
    let length = rustix::fs::flistxattr(fd, &mut names[..])?;
    names.truncate(length);
    if names.is_empty() {
        return Ok(Vec::new());
    }
    anyhow::ensure!(names.last() == Some(&0), "Malformed xattr name list");
    names.pop();
    names
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .map(|name| Ok(std::ffi::OsString::from_vec(name.to_vec())))
        .collect()
}

fn preserve_metadata_owner_and_mode<Fd: AsFd>(metadata: &Metadata, dst_fd: Fd) -> Result<()> {
    use rustix::fs::{Mode, fchmod};

    preserve_metadata_owner(metadata, &dst_fd)?;
    fchmod(&dst_fd, Mode::from_bits_truncate(metadata.mode() & 0o7777))?;
    Ok(())
}

fn preserve_metadata_owner<Fd: AsFd>(metadata: &Metadata, dst_fd: Fd) -> Result<()> {
    use rustix::fs::{Gid, Uid, fchown};

    let destination_metadata = rustix::fs::fstat(&dst_fd)?;
    if destination_metadata.st_uid != metadata.uid()
        || destination_metadata.st_gid != metadata.gid()
    {
        fchown(
            &dst_fd,
            Some(Uid::from_raw(metadata.uid())),
            Some(Gid::from_raw(metadata.gid())),
        )?;
    }
    Ok(())
}

fn preserve_metadata_timestamps<Fd: AsFd>(metadata: &Metadata, dst_fd: Fd) -> Result<()> {
    use rustix::fs::{Timestamps, futimens};
    use rustix::time::Timespec;

    futimens(
        &dst_fd,
        &Timestamps {
            last_access: Timespec {
                tv_sec: metadata.atime(),
                tv_nsec: metadata.atime_nsec() as _,
            },
            last_modification: Timespec {
                tv_sec: metadata.mtime(),
                tv_nsec: metadata.mtime_nsec() as _,
            },
        },
    )?;
    Ok(())
}

#[cfg(test)]
#[context("Copying /var into new deployment (Strategy D)")]
fn preserve_var_copy(
    src_var: &CapStdDir,
    new_var: &CapStdDir,
    exclusions: &[String],
) -> Result<()> {
    preserve_var_copy_mounts(src_var, new_var, exclusions, &BTreeSet::new())
}

/// Strategy D: plain recursive copy of `/var` for filesystems without reflink support.
///
/// This performs `cp -a` for included state and is **unsafe for databases and
/// other applications with open write handles into `/var`** (for example,
/// PostgreSQL in `/var/lib/pgsql`, MySQL/MariaDB in `/var/lib/mysql`, or SQLite
/// databases under `/var/lib/*`). A live database copy may be corrupted.
/// Stop stateful services before copying, or use a consistent snapshot.
/// Reflinks (Strategy C) also clone files individually and are not an atomic
/// snapshot of `/var` or a live database.
///
/// Additional exclusions can be configured or supplied with repeated
/// `--preserve-var-skip` options. Paths are relative to `/var`, with one
/// component or exactly one child component allowed. Excluded state is not
/// migrated and must be handled separately. Exclusions do not make a copied
/// live database consistent.
///
/// See: <https://github.com/bootc-dev/bootc/issues/2220>
fn preserve_var_copy_mounts(
    src_var: &CapStdDir,
    new_var: &CapStdDir,
    exclusions: &[String],
    mountpoints: &BTreeSet<PathBuf>,
) -> Result<()> {
    copy_var_filtered(
        src_var,
        new_var,
        Path::new(""),
        exclusions,
        mountpoints,
        false,
        false,
        OsStr::new(GNU_CP),
    )
    .context("Copying /var into new deployment (Strategy D)")?;
    println!("  /var copy complete.");
    Ok(())
}

/// Open a single source child directory without following a symlink swapped
/// into place after the caller's metadata check. The entry name comes directly
/// from `read_dir`, so this is one path component beneath the capability root.
fn open_child_dir_nofollow(parent: &CapStdDir, name: &OsStr) -> std::io::Result<CapStdDir> {
    use rustix::fs::{Mode, OFlags};

    let fd = rustix::fs::openat(
        parent.as_filelike_view::<std::fs::File>().as_fd(),
        name,
        OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::RDONLY,
        Mode::empty(),
    )?;
    Ok(CapStdDir::from_std_file(std::fs::File::from(fd)))
}

#[cfg(test)]
fn open_or_create_child_dir(parent: &CapStdDir, name: &OsStr) -> Result<(CapStdDir, bool)> {
    let created = match parent.create_dir(name) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            anyhow::ensure!(
                parent.symlink_metadata(name)?.is_dir(),
                "Destination child {} exists and is not a directory",
                name.to_string_lossy()
            );
            false
        }
        Err(e) => return Err(e).context("Creating destination child directory"),
    };
    let dir =
        open_child_dir_nofollow(parent, name).context("Opening destination child directory")?;
    Ok((dir, created))
}

/// Open an existing destination directory without following symlinks. The
/// opened handle pins the directory used for the recursive merge.
fn open_existing_child_dir(parent: &CapStdDir, name: &OsStr) -> Result<Option<CapStdDir>> {
    let existing: Result<Option<CapStdDir>> = match open_child_dir_nofollow(parent, name) {
        Ok(directory) => Ok(Some(directory)),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) || error.raw_os_error() == Some(libc::ELOOP) =>
        {
            Ok(None)
        }
        Err(error) => Err(error.into()),
    };
    existing.with_context(|| {
        format!(
            "Opening existing destination directory {}",
            name.to_string_lossy()
        )
    })
}

/// Validate exclusions before touching either tree. Paths are relative to `/var`.
pub(crate) fn validate_exclusions(exclusions: &[String]) -> Result<Vec<String>> {
    exclusions
        .iter()
        .map(|path| {
            let path = path.trim_end_matches('/');
            anyhow::ensure!(!path.is_empty(), "empty /var exclusion");
            anyhow::ensure!(
                Path::new(path)
                    .components()
                    .all(|component| matches!(component, Component::Normal(_))),
                "invalid /var exclusion {path:?}; expected a relative path"
            );
            anyhow::ensure!(
                Path::new(path).components().count() <= 2,
                "unsupported nested /var exclusion {path:?}; use at most one child path"
            );
            Ok(path.to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std_ext::dirext::CapStdExtDirExt;
    use std::{
        fs,
        os::unix::fs::{MetadataExt as StdMetadataExt, PermissionsExt, symlink},
        time::{Duration, SystemTime},
    };

    fn cap_dir(path: &Path) -> CapStdDir {
        CapStdDir::open_ambient_dir(path, ambient_authority()).unwrap()
    }

    fn cap_dir_path(path: &Path) -> CapStdDir {
        use rustix::fs::{Mode, OFlags, openat};

        let directory = cap_dir(path);
        let fd = openat(
            directory.as_filelike_view::<std::fs::File>().as_fd(),
            ".",
            OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::PATH,
            Mode::empty(),
        )
        .unwrap();
        CapStdDir::from_std_file(std::fs::File::from(fd))
    }

    #[test]
    fn exclusions_are_relative_and_normalized() {
        assert_eq!(
            validate_exclusions(&["lib/rpm/".into()]).unwrap(),
            ["lib/rpm"]
        );
        assert!(validate_exclusions(&["../etc".into()]).is_err());
        assert!(validate_exclusions(&["/etc".into()]).is_err());
        assert!(validate_exclusions(&["lib/containers/storage".into()]).is_err());
    }

    #[test]
    fn migration_plan_preflights_source_and_combines_exclusions() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let src_var = temp.path().join("var");
        fs::create_dir(&src_var)?;
        fs::write(src_var.join("sentinel"), b"source remains untouched")?;

        let plan = VarMigrationPlan::prepare(&src_var, &["lib/rpm".to_string()])?;
        assert_eq!(plan.src_var, fs::canonicalize(&src_var)?);
        assert_eq!(
            plan.exclusions,
            ["tmp", "cache", "log/journal", "lib/containers", "lib/rpm"]
        );
        assert_eq!(
            fs::read(src_var.join("sentinel"))?,
            b"source remains untouched"
        );

        let error = VarMigrationPlan::prepare(&temp.path().join("missing"), &[]).unwrap_err();
        assert!(
            format!("{error:#}").contains("Canonicalizing source /var"),
            "{error:#}"
        );
        Ok(())
    }

    #[test]
    fn preflight_checks_only_reachable_mountpoint_types() -> Result<()> {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir()?;
        let src_var = temp.path().join("var");
        fs::create_dir_all(src_var.join("directory"))?;
        fs::write(src_var.join("file"), b"")?;
        symlink("file", src_var.join("symlink"))?;
        let mounts = BTreeSet::from([
            PathBuf::from("directory"),
            PathBuf::from("file"),
            PathBuf::from("symlink"),
            PathBuf::from("tmp/excluded"),
            PathBuf::from("directory/nested"),
        ]);

        let error = validate_mountpoint_types(&src_var, &["tmp".to_string()], &mounts).unwrap_err();
        assert!(format!("{error:#}").contains("/var/symlink"));
        validate_mountpoint_types(
            &src_var,
            &["tmp".to_string(), "symlink".to_string()],
            &mounts,
        )?;
        Ok(())
    }

    #[test]
    fn deployment_var_is_stateroot_var() {
        let deploy = Path::new("/sysroot/ostree/deploy/default/deploy/checksum.0");
        assert_eq!(
            deployment_var_path(deploy).unwrap(),
            Path::new("/sysroot/ostree/deploy/default/var")
        );
    }

    #[test]
    fn directory_metadata_restoration_accepts_path_capability() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let src_path = temp.path().join("src");
        let dst_path = temp.path().join("dst");
        fs::create_dir(&src_path)?;
        fs::create_dir(&dst_path)?;
        fs::set_permissions(&src_path, fs::Permissions::from_mode(0o751))?;

        let source = cap_dir(&src_path);
        let has_user_xattr = source
            .setxattr(".", "user.bootc_path_fd", b"metadata")
            .is_ok();
        let destination = cap_dir_path(&dst_path);
        let snapshot = snapshot_directory_metadata(&source)?;
        restore_directory_metadata(&destination, &snapshot)?;
        assert_eq!(
            fs::metadata(&dst_path)?.permissions().mode() & 0o7777,
            snapshot.metadata.mode() & 0o7777
        );
        if has_user_xattr {
            assert_eq!(
                destination.getxattr(".", "user.bootc_path_fd")?,
                Some(b"metadata".to_vec())
            );
        }

        restore_directory_timestamps(&destination, &snapshot.metadata)?;
        let restored = fs::metadata(&dst_path)?;
        assert_eq!(restored.atime(), snapshot.metadata.atime());
        assert_eq!(restored.atime_nsec(), snapshot.metadata.atime_nsec());
        assert_eq!(restored.mtime(), snapshot.metadata.mtime());
        assert_eq!(restored.mtime_nsec(), snapshot.metadata.mtime_nsec());
        Ok(())
    }

    #[test]
    fn both_copy_strategies_leave_nested_mountpoints_empty() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let src_path = temp.path().join("src");
        let dst_path = temp.path().join("dst");
        fs::create_dir_all(src_path.join("lib/bound"))?;
        fs::create_dir_all(src_path.join("lib/sibling"))?;
        fs::write(src_path.join("lib/file-bound"), b"do not migrate")?;
        fs::write(
            src_path.join("lib/bound/mounted-sentinel"),
            b"do not migrate",
        )?;
        fs::write(src_path.join("lib/sibling/sentinel"), b"migrate")?;
        fs::create_dir(&dst_path)?;
        let mounts = BTreeSet::from([PathBuf::from("lib/bound"), PathBuf::from("lib/file-bound")]);
        let src = cap_dir(&src_path);
        let dst = cap_dir(&dst_path);

        preserve_var_copy_mounts(&src, &dst, &[], &mounts)?;
        assert!(dst_path.join("lib/bound").is_dir());
        assert_eq!(fs::read_dir(dst_path.join("lib/bound"))?.count(), 0);
        assert_eq!(fs::read(dst_path.join("lib/file-bound"))?, b"");
        assert_eq!(fs::read(dst_path.join("lib/sibling/sentinel"))?, b"migrate");

        let excluded_dst_path = temp.path().join("excluded-dst");
        fs::create_dir(&excluded_dst_path)?;
        preserve_var_copy_mounts(
            &src,
            &cap_dir(&excluded_dst_path),
            &["lib/bound".into()],
            &mounts,
        )?;
        assert!(!excluded_dst_path.join("lib/bound").exists());

        let reflink_dst = temp.path().join("reflink-dst");
        fs::create_dir(&reflink_dst)?;
        let reflink_dst = cap_dir(&reflink_dst);
        if supports_reflink(&src, &reflink_dst)? {
            preserve_var_reflink_mounts(&src, &reflink_dst, &[], &mounts)?;
            assert!(reflink_dst.symlink_metadata("lib/bound")?.is_dir());
            assert_eq!(
                fs::read_dir(temp.path().join("reflink-dst/lib/bound"))?.count(),
                0
            );
            assert_eq!(
                fs::read(temp.path().join("reflink-dst/lib/file-bound"))?,
                b""
            );
            assert_eq!(
                fs::read(temp.path().join("reflink-dst/lib/sibling/sentinel"))?,
                b"migrate"
            );
        }
        Ok(())
    }

    #[test]
    fn split_directories_and_mountpoint_placeholders_keep_metadata() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let src_path = temp.path().join("src");
        let dst_path = temp.path().join("dst");
        fs::create_dir_all(src_path.join("lib/bound"))?;
        fs::create_dir(&dst_path)?;
        fs::set_permissions(src_path.join("lib"), fs::Permissions::from_mode(0o751))?;
        fs::set_permissions(
            src_path.join("lib/bound"),
            fs::Permissions::from_mode(0o711),
        )?;
        // Old atimes make traversal update them on relatime filesystems; the
        // copy must use the metadata captured before reading child entries.
        let expected_atime = SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_001);
        let expected_mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_002);
        for path in [src_path.join("lib"), src_path.join("lib/bound")] {
            fs::File::open(path)?.set_times(
                fs::FileTimes::new()
                    .set_accessed(expected_atime)
                    .set_modified(expected_mtime),
            )?;
        }

        let src = cap_dir(&src_path);
        let dst = cap_dir(&dst_path);
        let xattrs_supported = src
            .setxattr("lib", "user.bootc_migrate_test", b"parent")
            .is_ok()
            && src
                .setxattr("lib/bound", "user.bootc_migrate_test", b"placeholder")
                .is_ok();
        preserve_var_copy_mounts(
            &src,
            &dst,
            &[],
            &BTreeSet::from([PathBuf::from("lib/bound")]),
        )?;

        for (source, destination, expected_mode, expected_xattr) in [
            ("lib", "lib", 0o751, b"parent".as_slice()),
            ("lib/bound", "lib/bound", 0o711, b"placeholder".as_slice()),
        ] {
            let source_metadata = fs::metadata(src_path.join(source))?;
            let destination_metadata = fs::metadata(dst_path.join(destination))?;
            assert_eq!(destination_metadata.mode() & 0o7777, expected_mode);
            assert_eq!(destination_metadata.uid(), source_metadata.uid());
            assert_eq!(destination_metadata.gid(), source_metadata.gid());
            assert_eq!(
                destination_metadata.atime(),
                expected_atime
                    .duration_since(SystemTime::UNIX_EPOCH)?
                    .as_secs() as i64
            );
            assert_eq!(
                destination_metadata.mtime(),
                expected_mtime
                    .duration_since(SystemTime::UNIX_EPOCH)?
                    .as_secs() as i64
            );
            assert_eq!(destination_metadata.atime_nsec(), 0);
            assert_eq!(destination_metadata.mtime_nsec(), 0);
            if xattrs_supported {
                assert_eq!(
                    dst.getxattr(destination, "user.bootc_migrate_test")?,
                    Some(expected_xattr.to_vec())
                );
            }
        }
        Ok(())
    }

    #[test]
    fn split_directory_xattrs_match_source_exactly_when_supported() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let src_path = temp.path().join("src");
        let dst_path = temp.path().join("dst");
        fs::create_dir(&src_path)?;
        fs::create_dir(&dst_path)?;
        let source = cap_dir(&src_path);
        let destination = cap_dir(&dst_path);
        if source
            .setxattr(".", "user.bootc_expected", b"source")
            .is_err()
            || destination
                .setxattr(".", "user.bootc_inherited", b"extra")
                .is_err()
        {
            return Ok(());
        }

        let snapshot = snapshot_directory_metadata(&source)?;
        restore_directory_metadata(&destination, &snapshot)?;

        assert_eq!(
            destination.getxattr(".", "user.bootc_expected")?,
            Some(b"source".to_vec())
        );
        assert_eq!(destination.getxattr(".", "user.bootc_inherited")?, None);
        Ok(())
    }

    #[test]
    fn apply_xattrs_exact_preserves_destination_selinux_when_source_lacks_it() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("destination");
        fs::write(&path, b"")?;
        let destination = cap_dir(temp.path());
        if destination
            .setxattr("destination", SELINUX_XATTR, b"test-label")
            .is_err()
        {
            // Some test filesystems or unprivileged environments cannot set
            // security.selinux; exercise the behavior where supported.
            return Ok(());
        }

        let file = fs::File::open(&path)?;
        apply_xattrs_exact(&file, &[])?;
        assert_eq!(
            destination.getxattr("destination", SELINUX_XATTR)?,
            Some(b"test-label".to_vec())
        );
        Ok(())
    }

    #[test]
    fn filtered_copy_does_not_change_existing_destination_directory() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let src_path = temp.path().join("src");
        let dst_path = temp.path().join("dst");
        fs::create_dir_all(src_path.join("tree/excluded"))?;
        fs::write(src_path.join("tree/sentinel"), b"source")?;
        fs::write(src_path.join("tree/new-child"), b"new child")?;
        fs::write(src_path.join("root-new-child"), b"new root child")?;
        fs::create_dir_all(dst_path.join("tree"))?;
        fs::write(dst_path.join("tree/sentinel"), b"destination")?;
        fs::set_permissions(src_path.join("tree"), fs::Permissions::from_mode(0o751))?;
        fs::set_permissions(&dst_path, fs::Permissions::from_mode(0o710))?;
        fs::set_permissions(dst_path.join("tree"), fs::Permissions::from_mode(0o700))?;
        let expected_atime = SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_101);
        let expected_mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_102);
        let expected_root_atime = SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_104);
        let expected_root_mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_103);
        fs::File::open(dst_path.join("tree"))?.set_times(
            fs::FileTimes::new()
                .set_accessed(expected_atime)
                .set_modified(expected_mtime),
        )?;
        fs::File::open(&dst_path)?.set_times(
            fs::FileTimes::new()
                .set_accessed(expected_root_atime)
                .set_modified(expected_root_mtime),
        )?;
        let destination = cap_dir(&dst_path);
        let xattrs_supported = destination
            .setxattr("tree", "user.bootc_migrate_test", b"existing")
            .is_ok();
        let expected_owner = fs::metadata(dst_path.join("tree"))?;

        preserve_var_copy_mounts(
            &cap_dir(&src_path),
            &destination,
            &["tree/excluded".into()],
            &BTreeSet::new(),
        )?;

        let destination_metadata = fs::metadata(dst_path.join("tree"))?;
        assert_eq!(destination_metadata.mode() & 0o7777, 0o700);
        assert_eq!(destination_metadata.uid(), expected_owner.uid());
        assert_eq!(destination_metadata.gid(), expected_owner.gid());
        assert_eq!(
            destination_metadata.atime(),
            expected_atime
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs() as i64
        );
        assert_eq!(
            destination_metadata.mtime(),
            expected_mtime
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs() as i64
        );
        assert_eq!(fs::read(dst_path.join("tree/sentinel"))?, b"destination");
        assert_eq!(fs::read(dst_path.join("tree/new-child"))?, b"new child");
        assert_eq!(
            fs::read(dst_path.join("root-new-child"))?,
            b"new root child"
        );
        assert_eq!(fs::read_dir(dst_path.join("tree"))?.count(), 2);
        assert_eq!(destination_metadata.modified()?, expected_mtime);

        let root_metadata = fs::metadata(&dst_path)?;
        assert_eq!(root_metadata.mode() & 0o7777, 0o710);
        assert_eq!(
            root_metadata.atime(),
            expected_root_atime
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs() as i64
        );
        assert_eq!(root_metadata.modified()?, expected_root_mtime);
        if xattrs_supported {
            assert_eq!(
                destination.getxattr("tree", "user.bootc_migrate_test")?,
                Some(b"existing".to_vec())
            );
        }
        Ok(())
    }

    #[test]
    fn staged_directory_collision_merges_missing_children_without_clobbering() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let destination_path = temp.path().join("destination");
        fs::create_dir(&destination_path)?;
        let destination = cap_dir(&destination_path);
        with_staging_dir(&destination, |_, staging| {
            staging.create_dir("tree")?;
            staging.write("tree/existing", b"staged collision")?;
            staging.write("tree/missing", b"new child")?;

            // Simulate a concurrent creator winning after staging completed.
            fs::create_dir(destination_path.join("tree"))?;
            fs::write(destination_path.join("tree/existing"), b"destination")?;
            fs::set_permissions(
                destination_path.join("tree"),
                fs::Permissions::from_mode(0o700),
            )?;
            let destination_mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_301);
            fs::File::open(destination_path.join("tree"))?
                .set_times(fs::FileTimes::new().set_modified(destination_mtime))?;
            let expected_owner = fs::metadata(destination_path.join("tree"))?;

            assert!(!publish_staged_entry(
                staging,
                &destination,
                OsStr::new("tree"),
                Path::new("tree")
            )?);
            assert_eq!(
                fs::read(destination_path.join("tree/existing"))?,
                b"destination"
            );
            assert_eq!(
                fs::read(destination_path.join("tree/missing"))?,
                b"new child"
            );

            let metadata = fs::metadata(destination_path.join("tree"))?;
            assert_eq!(metadata.mode() & 0o7777, 0o700);
            assert_eq!(metadata.uid(), expected_owner.uid());
            assert_eq!(metadata.gid(), expected_owner.gid());
            assert_eq!(metadata.modified()?, destination_mtime);
            Ok(())
        })?;
        Ok(())
    }

    #[test]
    fn unfiltered_directory_collisions_preserve_destination_metadata() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let src_path = temp.path().join("src");
        fs::create_dir_all(src_path.join("state"))?;
        fs::write(src_path.join("state/existing"), b"source")?;
        fs::write(src_path.join("state/new"), b"new")?;
        fs::write(src_path.join("collision-file"), b"source collision")?;
        fs::create_dir(src_path.join("directory-vs-file"))?;
        fs::write(src_path.join("directory-vs-file/new"), b"must not replace")?;
        fs::set_permissions(src_path.join("state"), fs::Permissions::from_mode(0o751))?;
        let source_mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_201);
        fs::File::open(src_path.join("state"))?
            .set_times(fs::FileTimes::new().set_modified(source_mtime))?;

        let src = cap_dir(&src_path);
        for (strategy, reflink) in [("copy", false), ("reflink", true)] {
            let dst_path = temp.path().join(format!("dst-{strategy}"));
            fs::create_dir_all(dst_path.join("state"))?;
            fs::write(dst_path.join("state/existing"), b"destination")?;
            fs::write(dst_path.join("collision-file"), b"keep collision")?;
            fs::write(dst_path.join("directory-vs-file"), b"keep file")?;
            fs::set_permissions(dst_path.join("state"), fs::Permissions::from_mode(0o700))?;
            let destination_mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_202);
            fs::File::open(dst_path.join("state"))?
                .set_times(fs::FileTimes::new().set_modified(destination_mtime))?;
            let dst = cap_dir(&dst_path);
            if reflink && !supports_reflink(&src, &dst)? {
                continue;
            }

            if reflink {
                preserve_var_reflink(&src, &dst, &[])?;
            } else {
                preserve_var_copy(&src, &dst, &[])?;
            }

            let destination_metadata = fs::metadata(dst_path.join("state"))?;
            assert_eq!(destination_metadata.mode() & 0o7777, 0o700);
            assert_eq!(destination_metadata.modified()?, destination_mtime);
            assert_eq!(fs::read(dst_path.join("state/existing"))?, b"destination");
            assert_eq!(fs::read(dst_path.join("state/new"))?, b"new");
            assert_eq!(
                fs::read(dst_path.join("collision-file"))?,
                b"keep collision"
            );
            assert_eq!(fs::read(dst_path.join("directory-vs-file"))?, b"keep file");
            assert!(!dst_path.join("directory-vs-file/new").exists());
        }
        Ok(())
    }

    #[test]
    fn failed_copy_batch_is_cleaned_and_can_be_retried() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let src_path = temp.path().join("src");
        fs::create_dir(&src_path)?;
        fs::write(src_path.join("first"), b"linked data")?;
        fs::hard_link(src_path.join("first"), src_path.join("second"))?;
        let src = cap_dir(&src_path);

        let failing_cp = temp.path().join("cp-fails-after-copy");
        fs::write(
            &failing_cp,
            b"#!/bin/sh\nreflink=no\nwhile [ \"$1\" != -- ]; do\n  [ \"$1\" = --reflink=auto ] && reflink=yes\n  shift\ndone\nshift\nsource=$1\nshift\nwhile [ \"$#\" -gt 1 ]; do shift; done\ndestination=$1\nif [ \"$reflink\" = yes ]; then\n  /bin/cp --reflink=auto -a -- \"$source\" \"$destination\"\nelse\n  /bin/cp -a -- \"$source\" \"$destination\"\nfi\nexit 1\n",
        )?;
        fs::set_permissions(&failing_cp, fs::Permissions::from_mode(0o755))?;

        for (strategy, reflink) in [("copy", false), ("reflink", true)] {
            let dst_path = temp.path().join(format!("dst-{strategy}"));
            fs::create_dir(&dst_path)?;
            let dst = cap_dir(&dst_path);
            if reflink && !supports_reflink(&src, &dst)? {
                continue;
            }

            let error = copy_var_filtered(
                &src,
                &dst,
                Path::new(""),
                &[],
                &BTreeSet::new(),
                reflink,
                false,
                failing_cp.as_os_str(),
            );
            assert!(error.is_err());
            assert_eq!(fs::read_dir(&dst_path)?.count(), 0);

            if reflink {
                preserve_var_reflink(&src, &dst, &[])?;
            } else {
                preserve_var_copy(&src, &dst, &[])?;
            }
            let first = fs::metadata(dst_path.join("first"))?;
            let second = fs::metadata(dst_path.join("second"))?;
            assert_eq!(first.ino(), second.ino());
            assert_eq!(fs::read(dst_path.join("first"))?, b"linked data");
        }
        Ok(())
    }

    #[test]
    fn reflink_copy_uses_auto_fallback_for_individual_files() {
        assert_eq!(CP_REFLINK_OPTIONS, ["--reflink=auto", "-a"]);
    }

    #[test]
    fn mountpoint_placeholders_reuse_seeded_destinations_and_check_type() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let src_path = temp.path().join("src");
        fs::create_dir_all(src_path.join("directory-mount"))?;
        fs::write(src_path.join("file-mount"), b"mounted data")?;
        let src = cap_dir(&src_path);

        for (strategy, reflink) in [("copy", false), ("reflink", true)] {
            let dst_path = temp.path().join(format!("dst-{strategy}"));
            fs::create_dir(&dst_path)?;
            let dst = cap_dir(&dst_path);
            if reflink && !supports_reflink(&src, &dst)? {
                continue;
            }

            fs::create_dir(dst_path.join("directory-mount"))?;
            fs::write(dst_path.join("file-mount"), b"")?;
            let mounts = BTreeSet::from([
                PathBuf::from("directory-mount"),
                PathBuf::from("file-mount"),
            ]);
            if reflink {
                preserve_var_reflink_mounts(&src, &dst, &[], &mounts)?;
                preserve_var_reflink_mounts(&src, &dst, &[], &mounts)?;
            } else {
                preserve_var_copy_mounts(&src, &dst, &[], &mounts)?;
                preserve_var_copy_mounts(&src, &dst, &[], &mounts)?;
            }
            assert_eq!(fs::read_dir(dst_path.join("directory-mount"))?.count(), 0);
            assert_eq!(fs::metadata(dst_path.join("file-mount"))?.len(), 0);

            // Image-seeded content at a destination that will be hidden by
            // the mount is safe to retain when its type matches.
            fs::write(dst_path.join("directory-mount/sentinel"), b"keep")?;
            fs::write(dst_path.join("file-mount"), b"keep file")?;
            if reflink {
                preserve_var_reflink_mounts(&src, &dst, &[], &mounts)?;
            } else {
                preserve_var_copy_mounts(&src, &dst, &[], &mounts)?;
            }
            assert_eq!(
                fs::read(dst_path.join("directory-mount/sentinel"))?,
                b"keep"
            );
            assert_eq!(fs::read(dst_path.join("file-mount"))?, b"keep file");

            let wrong_type = temp.path().join(format!("wrong-type-{strategy}"));
            fs::create_dir(&wrong_type)?;
            fs::write(wrong_type.join("directory-mount"), b"keep wrong type")?;
            fs::create_dir(wrong_type.join("file-mount"))?;
            fs::write(wrong_type.join("file-mount/sentinel"), b"keep wrong type")?;
            let wrong_dst = cap_dir(&wrong_type);
            let error = if reflink {
                preserve_var_reflink_mounts(&src, &wrong_dst, &[], &mounts)
            } else {
                preserve_var_copy_mounts(&src, &wrong_dst, &[], &mounts)
            };
            assert!(error.is_err());
            assert_eq!(
                fs::read(wrong_type.join("directory-mount"))?,
                b"keep wrong type"
            );
            assert_eq!(
                fs::read(wrong_type.join("file-mount/sentinel"))?,
                b"keep wrong type"
            );
        }
        Ok(())
    }

    #[test]
    fn mountpoint_placeholders_fail_without_reusing_existing_destinations() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let src_path = temp.path().join("src");
        let dst_path = temp.path().join("dst");
        fs::create_dir_all(src_path.join("directory-mount"))?;
        fs::write(src_path.join("file-mount"), b"source")?;
        fs::create_dir_all(dst_path.join("directory-mount"))?;
        fs::write(dst_path.join("directory-mount/sentinel"), b"keep")?;
        fs::create_dir(dst_path.join("file-mount"))?;
        fs::write(dst_path.join("file-mount/sentinel"), b"also keep")?;

        let src = cap_dir(&src_path);
        let dst = cap_dir(&dst_path);
        assert!(create_mountpoint_placeholder(&src, &dst, OsStr::new("directory-mount")).is_err());
        assert!(create_mountpoint_placeholder(&src, &dst, OsStr::new("file-mount")).is_err());
        assert_eq!(
            fs::read(dst_path.join("directory-mount/sentinel"))?,
            b"keep"
        );
        assert_eq!(
            fs::read(dst_path.join("file-mount/sentinel"))?,
            b"also keep"
        );
        Ok(())
    }

    #[test]
    fn destination_directory_symlinks_are_rejected_without_following() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let target = temp.path().join("target");
        fs::create_dir(&target)?;
        fs::write(target.join("sentinel"), b"unchanged")?;

        let var_link = temp.path().join("var-link");
        symlink(&target, &var_link)?;
        assert!(open_or_create_var_dir(&var_link).is_err());

        let parent_path = temp.path().join("parent");
        fs::create_dir(&parent_path)?;
        symlink(&target, parent_path.join("child-link"))?;
        let parent = cap_dir(&parent_path);
        assert!(open_or_create_child_dir(&parent, OsStr::new("child-link")).is_err());

        let src_path = temp.path().join("src");
        fs::create_dir(&src_path)?;
        fs::create_dir(src_path.join("mount"))?;
        symlink(&target, parent_path.join("mount"))?;
        assert!(
            create_mountpoint_placeholder(&cap_dir(&src_path), &parent, OsStr::new("mount"))
                .is_err()
        );

        assert_eq!(fs::read(target.join("sentinel"))?, b"unchanged");
        assert_eq!(fs::read_dir(target)?.count(), 1);
        Ok(())
    }

    #[test]
    fn plain_copy_skips_multiple_children_under_parent() -> Result<()> {
        let exclusions = ["tmp".into(), "log/journal".into(), "log/private".into()];

        let temp = tempfile::tempdir()?;
        let src_path = temp.path().join("src");
        let dst_path = temp.path().join("dst");
        fs::create_dir_all(src_path.join("tmp"))?;
        fs::create_dir_all(src_path.join("log/journal"))?;
        fs::create_dir_all(src_path.join("log/private"))?;
        fs::create_dir_all(src_path.join("log/keep"))?;
        fs::write(src_path.join("tmp/ignored"), b"tmp")?;
        fs::write(src_path.join("log/journal/ignored"), b"journal")?;
        fs::write(src_path.join("log/private/ignored"), b"private")?;
        fs::write(src_path.join("log/keep/preserved"), b"keep")?;
        fs::hard_link(
            src_path.join("log/keep/preserved"),
            src_path.join("log/keep/preserved-hardlink"),
        )?;
        fs::create_dir(&dst_path)?;

        preserve_var_copy(&cap_dir(&src_path), &cap_dir(&dst_path), &exclusions)?;

        assert!(!dst_path.join("tmp").exists());
        assert!(!dst_path.join("log/journal").exists());
        assert!(!dst_path.join("log/private").exists());
        assert_eq!(fs::read(dst_path.join("log/keep/preserved"))?, b"keep");
        assert_eq!(
            fs::metadata(dst_path.join("log/keep/preserved"))?.ino(),
            fs::metadata(dst_path.join("log/keep/preserved-hardlink"))?.ino()
        );
        Ok(())
    }

    #[test]
    fn reflink_strategy_skips_multiple_children_under_parent() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let src_path = temp.path().join("src");
        let dst_path = temp.path().join("dst");
        fs::create_dir_all(src_path.join("log/journal"))?;
        fs::create_dir_all(src_path.join("log/private"))?;
        fs::create_dir_all(src_path.join("log/keep"))?;
        fs::write(src_path.join("log/journal/ignored"), b"journal")?;
        fs::write(src_path.join("log/private/ignored"), b"private")?;
        fs::write(src_path.join("log/keep/preserved"), b"keep")?;
        fs::create_dir(&dst_path)?;
        let src = cap_dir(&src_path);
        let dst = cap_dir(&dst_path);
        let supports_reflink = supports_reflink(&src, &dst)?;
        if !supports_reflink {
            fs::remove_file(src_path.join("log/keep/preserved"))?;
            fs::remove_dir(src_path.join("log/keep"))?;
        }

        // Exercise Strategy C's exclusion routing on every filesystem and, if
        // available, its reflink copy of a retained sibling.
        preserve_var_reflink(&src, &dst, &["log/journal".into(), "log/private".into()])?;

        assert!(!dst_path.join("log/journal").exists());
        assert!(!dst_path.join("log/private").exists());
        assert_eq!(
            dst_path.join("log/keep/preserved").exists(),
            supports_reflink
        );
        Ok(())
    }

    #[test]
    fn copy_preserves_symlink_without_traversing_target() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let src_path = temp.path().join("src");
        let dst_path = temp.path().join("dst");
        let outside = temp.path().join("outside");
        fs::create_dir(&src_path)?;
        fs::create_dir(&dst_path)?;
        fs::create_dir(&outside)?;
        fs::write(outside.join("sentinel"), b"outside")?;
        symlink(&outside, src_path.join("escape"))?;

        preserve_var_copy(
            &cap_dir(&src_path),
            &cap_dir(&dst_path),
            &["escape/sentinel".into()],
        )?;

        let copied = fs::symlink_metadata(dst_path.join("escape"))?;
        assert!(copied.file_type().is_symlink());
        assert_eq!(fs::read_link(dst_path.join("escape"))?, outside);
        // The target remains outside the destination tree; it was not copied.
        assert!(!dst_path.join("sentinel").exists());
        Ok(())
    }

    #[test]
    fn copy_preserves_archive_metadata_and_hardlinks() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let src_path = temp.path().join("src");
        let dst_path = temp.path().join("dst");
        let src_state = src_path.join("state");
        fs::create_dir_all(&src_state)?;
        fs::create_dir(&dst_path)?;
        fs::write(src_state.join("one"), b"contents")?;
        fs::hard_link(src_state.join("one"), src_state.join("two"))?;
        fs::set_permissions(&src_state, fs::Permissions::from_mode(0o751))?;
        fs::set_permissions(src_state.join("one"), fs::Permissions::from_mode(0o640))?;
        let src_cap = cap_dir(&src_path);
        let dst_cap = cap_dir(&dst_path);
        let xattr_supported = src_cap
            .setxattr("state/one", "user.bootc_migrate_test", b"xattr")
            .is_ok();
        let expected_mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        fs::File::open(&src_state)?.set_times(fs::FileTimes::new().set_modified(expected_mtime))?;

        preserve_var_copy(&src_cap, &dst_cap, &[])?;

        let copied_dir = fs::metadata(dst_path.join("state"))?;
        let copied_one = fs::metadata(dst_path.join("state/one"))?;
        let copied_two = fs::metadata(dst_path.join("state/two"))?;
        assert_eq!(copied_dir.permissions().mode() & 0o7777, 0o751);
        assert_eq!(copied_one.permissions().mode() & 0o7777, 0o640);
        assert_eq!(copied_dir.modified()?, expected_mtime);
        assert_eq!(copied_one.ino(), copied_two.ino());
        assert_eq!(copied_one.nlink(), 2);
        assert_eq!(copied_one.uid(), fs::metadata(src_state.join("one"))?.uid());
        assert_eq!(copied_one.gid(), fs::metadata(src_state.join("one"))?.gid());
        if xattr_supported {
            assert_eq!(
                dst_cap.getxattr("state/one", "user.bootc_migrate_test")?,
                Some(b"xattr".to_vec())
            );
        }
        Ok(())
    }

    #[test]
    fn copy_keeps_existing_collisions_untouched() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let src_path = temp.path().join("src");
        let dst_path = temp.path().join("dst");
        fs::create_dir_all(src_path.join("state"))?;
        fs::create_dir_all(dst_path.join("state"))?;
        fs::write(src_path.join("state/existing"), b"source")?;
        fs::write(src_path.join("state/new"), b"new")?;
        fs::write(dst_path.join("state/existing"), b"destination")?;

        preserve_var_copy(&cap_dir(&src_path), &cap_dir(&dst_path), &[])?;

        assert_eq!(fs::read(dst_path.join("state/existing"))?, b"destination");
        assert_eq!(fs::read(dst_path.join("state/new"))?, b"new");
        Ok(())
    }
}
