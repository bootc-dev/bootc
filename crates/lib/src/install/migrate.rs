//! # Package-mode to image-mode migration helpers
//!
//! This module implements the post-install state-preservation steps that make
//! `bootc install to-existing-root` useful for converting a live package-mode
//! (RPM/DEB) system to a bootc image-mode deployment without losing data.
//!
//! These steps are triggered by passing `--preserve-var` and/or `--merge-etc`
//! to `bootc install to-existing-root`.  They run **after** the core install
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
//! - **Strategy C — reflink copy** (btrfs / XFS with reflinks): `cp --reflink=always`
//!   clones files copy-on-write, avoiding an immediate second copy of their data.
//!   Files are cloned individually, so this is not an atomic snapshot of the
//!   `/var` tree or of a live database.
//!
//! - **Strategy D — plain copy** (ext4 and other non-reflink filesystems):
//!   `cp -a` copies each non-ephemeral subdirectory of `/var` into the new
//!   deployment's stateroot `var/`.  This is correct but slow for large `/var`
//!   trees, and **unsafe for live databases** (see the known-limitation comment
//!   on `preserve_var_copy`).
//!
//! Nested mountpoints are selected from one `/proc/self/mountinfo` snapshot
//! before the copy. This is a point-in-time, best-effort snapshot, not a
//! race-free guard: mounts added or removed beneath `/var` during copying can
//! race with the copy, just like concurrent file changes.
//! Each missing entry is copied to a unique sibling staging directory and
//! published atomically without replacing an existing destination. A failed
//! entry leaves no partial final entry and can be retried; this is not a global
//! transaction, so entries completely published before a later failure remain.
//!
//! Exclusions such as `tmp`, `log/journal`, `lib/containers`, or `lib/rpm`
//! can be supplied through configuration or repeated `--preserve-var-skip`
//! options.
//!
//! ## `/etc` merge (`--merge-etc`)
//!
//! A plain `bootc install to-existing-root` populates the new deployment's `/etc`
//! from the image.  The running system's admin customisations (NIC profiles, SSH
//! host keys, secrets, etc.) end up at `<root_path>/etc` but are not applied to
//! the new `/etc`.
//!
//! `--merge-etc` runs the 3-way merge from the `etc-merge` crate at install time:
//!
//! | Input | Source |
//! |-------|--------|
//! | A — pristine baseline | `<deploy_dir>/usr/etc` (image's shipped defaults) |
//! | B — current live      | `<root_path>/etc` (running admin customisations)  |
//! | C — new deployment    | `<deploy_dir>/etc` (deploy target, written by image) |
//!
//! The diff A→B captures everything the admin changed relative to the image
//! defaults and applies those changes onto C.  Machine-specific files (SSH host
//! keys, machine-id, NIC profiles) are included because they are precisely what
//! needs to be transferred to make the migrated system functional.
//!
//! Rollback preservation is intentionally independent from `/var` migration.

use std::path::{Component, Path};
use std::{
    collections::BTreeSet,
    ffi::OsStr,
    os::fd::AsFd,
    os::unix::ffi::OsStringExt,
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::{Context, Result};
use cap_std_ext::cap_std::ambient_authority;
use cap_std_ext::cap_std::fs::{Dir as CapStdDir, Metadata, MetadataExt};
use cap_std_ext::cap_std::io_lifetimes::AsFilelike;
use cap_std_ext::cmdext::{CapStdExtCommandExt, CmdFds};
use composefs_ctl::composefs::generic_tree::{FileSystem, Stat};
use etc_merge::{compute_diff_without_deletions, merge, traverse_etc};
use fn_error_context::context;

use crate::store::reflink::supports_reflink;

// ── Top-level entry points ────────────────────────────────────────────────────

/// Run the 3-way `/etc` merge on the new deployment.
///
/// Inputs:
///   - **A (pristine)** = `<deploy_dir>/usr/etc`
///   - **B (current)**  = `<root_path>/etc`
///   - **C (new)**      = `<deploy_dir>/etc`
///
/// `root_path` is the host root as seen from inside the install container.
#[context("Running 3-way /etc merge into new deployment")]
pub(crate) fn merge_etc_into_deployment(root_path: &Path, deploy_dir: &Path) -> Result<()> {
    let deploy_usr_etc = deploy_dir.join("usr/etc");
    let deploy_etc = deploy_dir.join("etc");
    let host_etc = root_path.join("etc");

    merge_etc(&host_etc, &deploy_usr_etc, &deploy_etc)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Preserve the running `/var` into the new deployment's `var/` directory.
///
/// `src_var` is the running system's `/var` (at `<root_path>/var`).
/// `new_var` is the new deployment's empty `var/` directory.
pub(crate) fn preserve_var(src_var: &Path, new_var: &Path, exclusions: &[String]) -> Result<()> {
    // Resolve symlink aliases and path components before comparing against the
    // absolute, kernel-resolved mountpoints in mountinfo.
    let canonical_src_var = std::fs::canonicalize(src_var)
        .with_context(|| format!("Canonicalizing source /var {}", src_var.display()))?;
    let mountinfo_snapshot = read_mountinfo_snapshot()?;
    let nested_mounts =
        nested_mountpoints(&canonical_src_var, parse_mountinfo(&mountinfo_snapshot)?)?;
    let src_var = CapStdDir::open_ambient_dir(&canonical_src_var, ambient_authority())
        .with_context(|| format!("Opening source {}", canonical_src_var.display()))?;
    let new_var = open_or_create_var_dir(new_var)?;

    let mut effective_exclusions = ["tmp", "cache", "log/journal", "lib/containers"]
        .into_iter()
        .map(String::from)
        .collect::<Vec<_>>();
    effective_exclusions.extend(exclusions.iter().cloned());

    let copy_result = if supports_reflink(&src_var, &new_var)? {
        println!("  Filesystem supports reflinks — using copy-on-write clone (Strategy C)");
        preserve_var_reflink_mounts(&src_var, &new_var, &effective_exclusions, &nested_mounts)
    } else {
        println!("  Filesystem does not support reflinks — falling back to full copy (Strategy D)");
        preserve_var_copy_mounts(&src_var, &new_var, &effective_exclusions, &nested_mounts)
    };
    copy_result?;

    Ok(())
}

/// Read one complete installer mount namespace snapshot. The initial snapshot
/// is used to select nested mounts for this copy; changes during copying can
/// race with it, just like concurrent changes to files beneath `/var`.
fn read_mountinfo_snapshot() -> Result<Vec<u8>> {
    std::fs::read("/proc/self/mountinfo")
        .context("Reading installer /proc/self/mountinfo for /var migration")
}

fn nested_mountpoints(
    src_var: &Path,
    mountpoints: impl IntoIterator<Item = PathBuf>,
) -> Result<BTreeSet<PathBuf>> {
    anyhow::ensure!(src_var.is_absolute(), "Source /var path must be absolute");
    let canonical_src_var = std::fs::canonicalize(src_var)
        .with_context(|| format!("Canonicalizing source /var {}", src_var.display()))?;
    let mut nested = BTreeSet::new();
    for mountpoint in mountpoints {
        let Ok(relative) = mountpoint.strip_prefix(&canonical_src_var) else {
            continue;
        };
        // The mount on /var itself is not a nested mount. Only child paths are
        // filtered; Path::strip_prefix provides component-safe containment.
        if relative.as_os_str().is_empty() {
            continue;
        }
        anyhow::ensure!(
            relative
                .components()
                .all(|component| matches!(component, Component::Normal(_))),
            "Invalid nested mountpoint below {}: {}",
            canonical_src_var.display(),
            mountpoint.display()
        );
        nested.insert(relative.to_path_buf());
    }
    Ok(nested)
}

/// Parse the byte-oriented Linux mountinfo format without requiring UTF-8.
/// Kernel pathname escapes are decoded before paths are constructed.
fn parse_mountinfo(data: &[u8]) -> Result<Vec<PathBuf>> {
    let mut mountpoints = Vec::new();
    let lines = data.split(|byte| *byte == b'\n');
    let line_count = lines.clone().count();
    for (index, line) in lines.enumerate() {
        if line.is_empty() && index + 1 == line_count {
            continue; // A final newline is conventional.
        }
        anyhow::ensure!(!line.is_empty(), "Empty mountinfo line {}", index + 1);
        anyhow::ensure!(
            !line.contains(&0),
            "NUL byte in mountinfo line {}",
            index + 1
        );
        let fields = line
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|field| !field.is_empty())
            .collect::<Vec<_>>();
        let separator = fields
            .iter()
            .enumerate()
            .skip(6)
            .find_map(|(index, field)| (*field == b"-").then_some(index))
            .with_context(|| {
                format!("Malformed mountinfo line {}: missing separator", index + 1)
            })?;
        anyhow::ensure!(
            separator >= 6 && fields.len() == separator + 4,
            "Malformed mountinfo line {}: invalid field count",
            index + 1
        );
        anyhow::ensure!(
            is_positive_decimal(fields[0])
                && is_decimal(fields[1])
                && is_device_number(fields[2])
                && !fields[5].is_empty()
                && !fields[separator + 1].is_empty()
                && !fields[separator + 2].is_empty()
                && !fields[separator + 3].is_empty(),
            "Malformed mountinfo line {}: invalid required field",
            index + 1
        );
        // The root field is not used for mount selection. Decode it to ensure
        // its escape syntax is valid, but don't impose pathname constraints:
        // unlike the mountpoint, it may be relative or noncanonical.
        decode_mountinfo_escapes(fields[3])
            .with_context(|| format!("Malformed root path on mountinfo line {}", index + 1))?;
        let mountpoint = decode_mountinfo_path(fields[4])
            .with_context(|| format!("Malformed mountpoint on mountinfo line {}", index + 1))?;
        decode_mountinfo_escapes(fields[separator + 2])
            .with_context(|| format!("Malformed source path on mountinfo line {}", index + 1))?;
        mountpoints.push(mountpoint);
    }
    anyhow::ensure!(!mountpoints.is_empty(), "Mountinfo contained no records");
    Ok(mountpoints)
}

fn is_decimal(value: &[u8]) -> bool {
    !value.is_empty()
        && value.iter().all(u8::is_ascii_digit)
        && std::str::from_utf8(value)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .is_some()
}

fn is_positive_decimal(value: &[u8]) -> bool {
    is_decimal(value)
        && std::str::from_utf8(value)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|value| value > 0)
}

fn is_device_number(value: &[u8]) -> bool {
    let Some(separator) = value.iter().position(|byte| *byte == b':') else {
        return false;
    };
    is_decimal(&value[..separator]) && is_decimal(&value[separator + 1..])
}

fn decode_mountinfo_path(value: &[u8]) -> Result<PathBuf> {
    let decoded = decode_mountinfo_escapes(value)?;
    anyhow::ensure!(
        decoded.first() == Some(&b'/'),
        "Mountinfo path is not absolute"
    );
    let mut components = decoded[1..].split(|byte| *byte == b'/');
    anyhow::ensure!(
        decoded.len() == 1
            || components.all(|component| {
                !component.is_empty() && component != b"." && component != b".."
            }),
        "Mountinfo path is not canonical"
    );
    Ok(PathBuf::from(std::ffi::OsString::from_vec(decoded)))
}

fn decode_mountinfo_escapes(value: &[u8]) -> Result<Vec<u8>> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        if value[index] != b'\\' {
            decoded.push(value[index]);
            index += 1;
            continue;
        }
        anyhow::ensure!(
            index + 3 < value.len()
                && value[index + 1..index + 4]
                    .iter()
                    .all(|byte| (b'0'..=b'7').contains(byte)),
            "Invalid octal escape in mountinfo path"
        );
        // Mountinfo escapes are three octal digits. Decode wider than a byte
        // so malformed values such as `\\777` cannot overflow or wrap.
        let escaped = u16::from(value[index + 1] - b'0') * 64
            + u16::from(value[index + 2] - b'0') * 8
            + u16::from(value[index + 3] - b'0');
        anyhow::ensure!(
            escaped <= u16::from(u8::MAX),
            "Octal escape exceeds one byte"
        );
        anyhow::ensure!(
            matches!(escaped, 0o11 | 0o12 | 0o40 | 0o134),
            "Unsupported octal escape in mountinfo path"
        );
        decoded.push(escaped as u8);
        index += 4;
    }
    Ok(decoded)
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
        OsStr::new("cp"),
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
            create_staged_placeholder(src_dir, dst_dir, &name)?;
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
            continue;
        }
        included_entries.push(name);
    }

    if !included_entries.is_empty() {
        let names = included_entries
            .iter()
            .map(|name| name.as_os_str())
            .collect::<Vec<_>>();
        copy_batch_staged(
            cp_program,
            src_dir,
            &names,
            dst_dir,
            reflink,
            &format!("/var/{}", relative_dir.display()),
        )?;
    }

    Ok(())
}

static NEXT_STAGING_ID: AtomicU64 = AtomicU64::new(0);

/// Make an empty, uniquely-named staging directory beneath the destination
/// capability. Publishing from the same parent keeps the final rename atomic.
fn create_staging_dir(parent: &CapStdDir) -> Result<(std::ffi::OsString, CapStdDir)> {
    use rustix::fs::{Mode, mkdirat};

    let parent_fd = parent.as_filelike_view::<std::fs::File>();
    for _ in 0..100 {
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
/// Any entries already published remain complete; transactions are per entry,
/// not a global rollback of earlier successful publications.
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
) -> Result<bool> {
    use rustix::fs::{RenameFlags, renameat_with};

    match renameat_with(staging, name, destination, name, RenameFlags::NOREPLACE) {
        Ok(()) => Ok(true),
        // A destination can appear after the initial no-clobber check. Merge
        // staged directories into a same-type destination without replacing
        // existing children; other collisions remain untouched.
        Err(error) if error == rustix::io::Errno::EXIST => {
            if staging.symlink_metadata(name)?.is_dir() {
                if let Some(destination_dir) = open_existing_child_dir(destination, name)? {
                    let staging_dir = open_child_dir_nofollow(staging, name)
                        .context("Opening staged directory after publish collision")?;
                    merge_staged_directory(&staging_dir, &destination_dir)?;
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
fn merge_staged_directory(staging: &CapStdDir, destination: &CapStdDir) -> Result<()> {
    let metadata = snapshot_directory_metadata(destination)?;
    let names = staging
        .read_dir(".")?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;

    let merge_result = (|| {
        for name in names {
            publish_staged_entry(staging, destination, &name)?;
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
    description: &str,
) -> Result<()> {
    with_staging_dir(destination, |_, staging| {
        let options = if reflink {
            &["--reflink=always", "-a"][..]
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
        anyhow::ensure!(status.success(), "cp failed while copying {description}");

        for name in names {
            publish_staged_entry(staging, destination, name)?;
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
        publish_staged_entry(staging, destination_parent, name)?;
        Ok(())
    })
}

fn create_staged_placeholder(
    src_parent: &CapStdDir,
    dst_parent: &CapStdDir,
    name: &OsStr,
) -> Result<()> {
    with_staging_dir(dst_parent, |_, staging| {
        create_mountpoint_placeholder(src_parent, staging, name)?;
        if !publish_staged_entry(staging, dst_parent, name)? {
            validate_empty_placeholder(dst_parent, name, src_parent.symlink_metadata(name)?)?;
        }
        Ok(())
    })
}

fn validate_empty_placeholder(
    destination_parent: &CapStdDir,
    name: &OsStr,
    source_metadata: Metadata,
) -> Result<()> {
    let destination_metadata = destination_parent.symlink_metadata(name)?;
    if source_metadata.is_dir() {
        anyhow::ensure!(
            destination_metadata.is_dir(),
            "Mountpoint placeholder {} exists with the wrong type",
            name.to_string_lossy()
        );
        let destination = open_child_dir_nofollow(destination_parent, name)?;
        let mut entries = destination.read_dir(".")?;
        anyhow::ensure!(
            entries.next().transpose()?.is_none(),
            "Mountpoint placeholder {} is not empty",
            name.to_string_lossy()
        );
    } else {
        anyhow::ensure!(
            source_metadata.is_file() && destination_metadata.is_file(),
            "Mountpoint placeholder {} exists with the wrong type",
            name.to_string_lossy()
        );
        anyhow::ensure!(
            destination_metadata.len() == 0,
            "Mountpoint placeholder {} is not empty",
            name.to_string_lossy()
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

/// Make the destination xattr set exactly match the source snapshot. Removing
/// extras first matters for inherited ACLs and labels as well as user xattrs.
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
        if !source_names.contains(name.as_os_str()) {
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

/// Strategy D: plain recursive copy of `/var` for filesystems without reflink support.
///
/// # Known limitation
///
/// This performs a full `cp -a` of every included subdirectory of the running
/// `/var` into the new deployment's ostree stateroot `var/`.  For most workloads
/// this is fine, but it is **unsafe for databases and other applications that
/// keep open write handles into `/var`** (e.g. PostgreSQL in `/var/lib/pgsql`,
/// MySQL/MariaDB in `/var/lib/mysql`, SQLite databases under `/var/lib/*`).
/// Copying a live database with `cp -a` will almost certainly produce a
/// corrupted copy.
///
/// The correct fix is to run this migration only after stopping all stateful
/// services that write to `/var`, or — better — to migrate the filesystem to
/// btrfs or XFS (which support reflinks, Strategy C) to avoid copying every
/// file's data immediately. Reflinks clone files individually; they do not
/// provide an atomic snapshot of the `/var` tree or of a live database.
///
/// Exclusions can be configured with install configuration or repeated
/// `--preserve-var-skip` options. Paths are relative to `/var` and may be one
/// component (such as `lib`) or exactly one child (such as `lib/pgsql`). `/var`
/// itself and deeper paths are not accepted. Excluded state is not migrated by
/// this command and must be handled separately. Exclusions do not make a live database copy
/// consistent: any database state that is copied while it is being written can
/// still be corrupted. Stop stateful services before copying their data, or use
/// a consistent snapshot.
///
/// See: <https://github.com/bootc-dev/bootc/issues/2220>
#[cfg(test)]
#[context("Copying /var into new deployment (Strategy D)")]
fn preserve_var_copy(
    src_var: &CapStdDir,
    new_var: &CapStdDir,
    exclusions: &[String],
) -> Result<()> {
    preserve_var_copy_mounts(src_var, new_var, exclusions, &BTreeSet::new())
}

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
        OsStr::new("cp"),
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

/// 3-way `/etc` merge.
///
/// - `host_etc`       = `<root_path>/etc`      (running system, input B)
/// - `deploy_usr_etc` = `<deploy_dir>/usr/etc` (image defaults, input A)
/// - `deploy_etc`     = `<deploy_dir>/etc`     (new deploy target, input C)
#[context("Merging running /etc into new deployment")]
fn merge_etc(host_etc: &Path, deploy_usr_etc: &Path, deploy_etc: &Path) -> Result<()> {
    let pristine_fd = CapStdDir::open_ambient_dir(deploy_usr_etc, ambient_authority())
        .with_context(|| format!("Opening pristine etc: {}", deploy_usr_etc.display()))?;
    let current_fd = CapStdDir::open_ambient_dir(host_etc, ambient_authority())
        .with_context(|| format!("Opening running etc: {}", host_etc.display()))?;
    let new_fd = CapStdDir::open_ambient_dir(deploy_etc, ambient_authority())
        .with_context(|| format!("Opening deploy etc: {}", deploy_etc.display()))?;

    let (pristine_tree, current_tree, new_tree_opt) =
        traverse_etc(&pristine_fd, &current_fd, Some(&new_fd))
            .context("Traversing /etc trees for 3-way merge")?;

    let new_tree = new_tree_opt.unwrap_or_else(|| FileSystem::new(Stat::uninitialized()));

    let diff = compute_diff_without_deletions(&pristine_tree, &current_tree, &new_tree)
        .context("Computing /etc diff")?;

    println!("  /etc diff (changes being applied from running system):");
    etc_merge::print_diff(&diff, &mut std::io::stdout());

    merge(&current_fd, &current_tree, &new_fd, &new_tree, &diff)
        .context("Applying /etc 3-way merge")?;

    println!("  /etc merge complete.");
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std_ext::dirext::CapStdExtDirExt;
    use std::{
        fs,
        os::unix::{
            ffi::OsStrExt,
            fs::{MetadataExt as StdMetadataExt, PermissionsExt, symlink},
        },
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
    fn deployment_var_is_stateroot_var() {
        let deploy = Path::new("/sysroot/ostree/deploy/default/deploy/checksum.0");
        assert_eq!(
            deployment_var_path(deploy).unwrap(),
            Path::new("/sysroot/ostree/deploy/default/var")
        );
    }

    #[test]
    fn mountinfo_decodes_escaped_and_non_utf8_paths() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let src_var = temp.path().join("var");
        fs::create_dir(&src_var)?;
        let source = src_var.as_os_str().as_bytes();
        let mut mountinfo = format!(
            "36 0 0:32 / {0} rw,relatime - tmpfs tmpfs rw\n37 25 0:33 / {0}/rpc\\040pipefs rw - nfs nfs rw\n",
            src_var.display()
        )
        .into_bytes();
        mountinfo.extend_from_slice(b"38 25 0:34 / ");
        mountinfo.extend_from_slice(source);
        mountinfo.extend_from_slice(b"/\xffstate rw - tmpfs tmpfs rw\n");
        let parsed = parse_mountinfo(&mountinfo)?;
        let escaped_name = src_var.join("rpc pipefs");
        assert_eq!(parsed[1], escaped_name);
        let mut non_utf8 = source.to_vec();
        non_utf8.extend_from_slice(b"/\xffstate");
        assert_eq!(parsed[2].as_os_str().as_bytes(), non_utf8);

        let nested = nested_mountpoints(&src_var, parsed)?;
        assert_eq!(
            nested,
            BTreeSet::from([
                PathBuf::from("rpc pipefs"),
                PathBuf::from(OsStr::from_bytes(b"\xffstate"))
            ])
        );
        Ok(())
    }

    #[test]
    fn unrelated_mount_records_do_not_change_nested_mount_selection() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let src_var = temp.path().join("target/var");
        fs::create_dir_all(&src_var)?;
        let base = format!(
            "36 0 0:32 / {0} rw - tmpfs tmpfs rw\n37 25 0:33 / {0}/lib/data rw - nfs nfs rw\n",
            src_var.display()
        );
        let with_unrelated = format!(
            "21 0 0:21 / / rw - overlay overlay rw\n{base}38 25 0:34 / /unrelated rw - tmpfs tmpfs rw\n"
        );

        let selected = |mountinfo: &str| -> Result<BTreeSet<PathBuf>> {
            nested_mountpoints(&src_var, parse_mountinfo(mountinfo.as_bytes())?)
        };
        assert_eq!(
            selected(&base)?,
            BTreeSet::from([PathBuf::from("lib/data")])
        );
        assert_eq!(selected(&with_unrelated)?, selected(&base)?);
        Ok(())
    }

    #[test]
    fn mountinfo_allows_relative_and_noncanonical_roots_with_valid_nested_mountpoints() -> Result<()>
    {
        let temp = tempfile::tempdir()?;
        let src_var = temp.path().join("target/var");
        fs::create_dir_all(&src_var)?;

        for root in ["/some/../root", "relative/root"] {
            let mountinfo = format!(
                "36 0 0:32 / {0} rw - tmpfs tmpfs rw\n37 25 0:33 {1} {0}/lib/data rw - nfs nfs rw\n",
                src_var.display(),
                root
            );

            assert_eq!(
                nested_mountpoints(&src_var, parse_mountinfo(mountinfo.as_bytes())?)?,
                BTreeSet::from([PathBuf::from("lib/data")]),
                "root field {root:?} should not affect mountpoint selection"
            );
        }
        Ok(())
    }

    #[test]
    fn mountinfo_rejects_malformed_records_and_escapes() {
        for mountinfo in [
            b"".as_slice(),
            b"not a mountinfo record\n",
            b"36 25 0:32 /bad\\04x /target/var rw - tmpfs tmpfs rw\n",
            b"36 25 0:32 / /target/var\\04x rw - tmpfs tmpfs rw\n",
            b"36 25 0:32 / /target/var\\400 rw - tmpfs tmpfs rw\n",
            b"36 25 0:32 / /target/var\\777 rw - tmpfs tmpfs rw\n",
            b"36 25 0:32 / /target/var\\041 rw - tmpfs tmpfs rw\n",
            b"36 25 0:32 / relative rw - tmpfs tmpfs rw\n",
            b"36 25 0:32 / /target/var/../outside rw - tmpfs tmpfs rw\n",
            b"36 25 0:32 / /target/var rw - tmpfs tmpfs rw extra\n",
        ] {
            assert!(
                parse_mountinfo(mountinfo).is_err(),
                "accepted {mountinfo:?}"
            );
        }
    }

    #[test]
    fn nested_mountpoint_detection_is_component_safe() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let src_var = temp.path().join("target/var");
        fs::create_dir_all(&src_var)?;
        let alias = temp.path().join("var-alias");
        symlink(&src_var, &alias)?;
        let paths = [
            src_var.clone(),
            src_var.join("lib/data"),
            temp.path().join("target/var-old/other"),
            PathBuf::from("/elsewhere/var/mount"),
        ];
        assert_eq!(
            nested_mountpoints(&alias, paths)?,
            BTreeSet::from([PathBuf::from("lib/data")])
        );
        assert!(nested_mountpoints(&temp.path().join("missing"), []).is_err());
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
                OsStr::new("tree")
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
            b"#!/bin/sh\nreflink=no\nwhile [ \"$1\" != -- ]; do\n  [ \"$1\" = --reflink=always ] && reflink=yes\n  shift\ndone\nshift\nsource=$1\nshift\nwhile [ \"$#\" -gt 1 ]; do shift; done\ndestination=$1\nif [ \"$reflink\" = yes ]; then\n  /bin/cp --reflink=always -a -- \"$source\" \"$destination\"\nelse\n  /bin/cp -a -- \"$source\" \"$destination\"\nfi\nexit 1\n",
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
    fn empty_mountpoint_placeholders_are_retry_safe_and_type_checked() -> Result<()> {
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

            fs::write(dst_path.join("directory-mount/sentinel"), b"keep")?;
            let error = if reflink {
                preserve_var_reflink_mounts(&src, &dst, &[], &mounts)
            } else {
                preserve_var_copy_mounts(&src, &dst, &[], &mounts)
            };
            assert!(error.is_err());
            assert_eq!(
                fs::read(dst_path.join("directory-mount/sentinel"))?,
                b"keep"
            );
            fs::remove_file(dst_path.join("directory-mount/sentinel"))?;
            fs::write(dst_path.join("file-mount"), b"keep file")?;
            let error = if reflink {
                preserve_var_reflink_mounts(&src, &dst, &[], &mounts)
            } else {
                preserve_var_copy_mounts(&src, &dst, &[], &mounts)
            };
            assert!(error.is_err());
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
