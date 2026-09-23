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
//!   performs an instantaneous copy-on-write clone.  No extra disk space is used
//!   until data diverges.
//!
//! - **Strategy D — plain copy** (ext4 and other non-reflink filesystems):
//!   `cp -a` copies each non-ephemeral subdirectory of `/var` into the new
//!   deployment's stateroot `var/`.  This is correct but slow for large `/var`
//!   trees, and **unsafe for live databases** (see the known-limitation comment
//!   on `preserve_var_copy`).
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
use std::process::Stdio;

use anyhow::{Context, Result};
use cap_std_ext::cap_std::ambient_authority;
use cap_std_ext::cap_std::fs::Dir as CapStdDir;
use composefs_ctl::composefs::generic_tree::{FileSystem, Stat};
use etc_merge::{compute_diff, merge, traverse_etc};
use fn_error_context::context;

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
    std::fs::create_dir_all(new_var).with_context(|| format!("Creating {}", new_var.display()))?;

    let mut effective_exclusions = ["tmp", "cache", "log/journal", "lib/containers"]
        .into_iter()
        .map(String::from)
        .collect::<Vec<_>>();
    effective_exclusions.extend(exclusions.iter().cloned());

    if reflinks_supported(src_var, new_var) {
        println!("  Filesystem supports reflinks — using copy-on-write clone (Strategy C)");
        preserve_var_reflink(src_var, new_var, &effective_exclusions)
    } else {
        println!("  Filesystem does not support reflinks — falling back to full copy (Strategy D)");
        preserve_var_copy(src_var, new_var, &effective_exclusions)
    }
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

/// Returns true if the filesystem hosting `new_var` supports reflinks.
///
/// Probes by attempting a zero-byte reflink from `src_var` into `new_var`.
fn reflinks_supported(src_var: &Path, new_var: &Path) -> bool {
    let probe_src = src_var.join(".bootc-reflink-probe-src");
    let probe_dst = new_var.join(".bootc-reflink-probe");

    let _ = std::fs::write(&probe_src, b"probe");
    let result = std::process::Command::new("cp")
        .args(["--reflink=always", "-a"])
        .arg(&probe_src)
        .arg(&probe_dst)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let _ = std::fs::remove_file(&probe_src);
    let _ = std::fs::remove_file(&probe_dst);
    result
}

/// Strategy C: reflink-copy each top-level entry under `src_var` into `new_var`.
///
/// Skips well-known ephemeral subdirectories.
#[context("Reflink-copying /var into new deployment (Strategy C)")]
fn preserve_var_reflink(src_var: &Path, new_var: &Path, exclusions: &[String]) -> Result<()> {
    let entries =
        std::fs::read_dir(src_var).with_context(|| format!("Reading {}", src_var.display()))?;

    for entry in entries {
        let entry = entry.with_context(|| format!("Reading entry in {}", src_var.display()))?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if exclusions.iter().any(|s| s == name_str.as_ref()) {
            println!(
                "    Skipping {} (ephemeral)",
                src_var.join(name_str.as_ref()).display()
            );
            continue;
        }

        let src_entry = src_var.join(name_str.as_ref());
        let dst_entry = new_var.join(name_str.as_ref());

        if let Some(skip) = exclusions.iter().find_map(|path| {
            path.strip_prefix(&format!("{name_str}/"))
                .filter(|rest| !rest.contains('/'))
        }) {
            copy_dir_skip_subdir(&src_entry, &dst_entry, skip, true)?;
            continue;
        }

        println!(
            "    Reflink-copying {} → {}",
            src_entry.display(),
            dst_entry.display()
        );
        let status = std::process::Command::new("cp")
            .args(["--reflink=always", "-a", "--no-clobber"])
            .arg(&src_entry)
            .arg(new_var)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .with_context(|| format!("cp --reflink=always {}", src_entry.display()))?;

        anyhow::ensure!(
            status.success(),
            "cp --reflink=always failed for {}",
            src_entry.display()
        );
    }

    println!("  /var reflink copy complete.");
    Ok(())
}

/// Copy a directory recursively, skipping one named subdirectory.
///
/// Used by both Strategy C and Strategy D to copy `var/log/` while excluding
/// `var/log/journal/`.  `reflink` selects whether `cp --reflink=always` or
/// plain `cp -a` is used.
fn copy_dir_skip_subdir(src: &Path, dst: &Path, skip_name: &str, reflink: bool) -> Result<()> {
    std::fs::create_dir_all(dst).with_context(|| format!("Creating {}", dst.display()))?;

    let entries = std::fs::read_dir(src).with_context(|| format!("Reading {}", src.display()))?;

    for entry in entries {
        let entry = entry.with_context(|| format!("Reading entry in {}", src.display()))?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if name_str == skip_name {
            println!("    Skipping {}/{} (ephemeral)", src.display(), name_str);
            continue;
        }

        let src_entry = src.join(name_str.as_ref());
        let mut cmd = std::process::Command::new("cp");
        if reflink {
            cmd.args(["--reflink=always", "-a", "--no-clobber"]);
        } else {
            cmd.args(["-a", "--no-clobber"]);
        }
        let status = cmd
            .arg(&src_entry)
            .arg(dst)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .with_context(|| format!("cp -a {}", src_entry.display()))?;

        anyhow::ensure!(status.success(), "cp failed for {}", src_entry.display());
    }

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
/// btrfs or XFS (which support reflinks, Strategy C) so that the copy is
/// instantaneous and atomic from the kernel's perspective.
///
/// A future improvement would be to accept a user-supplied exclusion list so
/// that specific high-risk directories (e.g. `/var/lib/pgsql`) can be skipped
/// and migrated manually.  For now, operators are responsible for stopping
/// affected services before running `bootc install to-existing-root --preserve-var`
/// on ext4 (or other non-reflink) filesystems.
///
/// See: <https://github.com/bootc-dev/bootc/issues/2220>
#[context("Copying /var into new deployment (Strategy D)")]
fn preserve_var_copy(src_var: &Path, new_var: &Path, exclusions: &[String]) -> Result<()> {
    let entries =
        std::fs::read_dir(src_var).with_context(|| format!("Reading {}", src_var.display()))?;

    for entry in entries {
        let entry = entry.with_context(|| format!("Reading entry in {}", src_var.display()))?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if exclusions.iter().any(|s| s == name_str.as_ref()) {
            println!(
                "    Skipping {} (ephemeral)",
                src_var.join(name_str.as_ref()).display()
            );
            continue;
        }

        let src_entry = src_var.join(name_str.as_ref());
        let dst_entry = new_var.join(name_str.as_ref());

        if let Some(skip) = exclusions.iter().find_map(|path| {
            path.strip_prefix(&format!("{name_str}/"))
                .filter(|rest| !rest.contains('/'))
        }) {
            copy_dir_skip_subdir(&src_entry, &dst_entry, skip, false)?;
            continue;
        }

        println!(
            "    Copying {} → {}",
            src_entry.display(),
            dst_entry.display()
        );
        let status = std::process::Command::new("cp")
            .args(["-a", "--no-clobber"])
            .arg(&src_entry)
            .arg(new_var)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .with_context(|| format!("cp -a {}", src_entry.display()))?;

        anyhow::ensure!(status.success(), "cp -a failed for {}", src_entry.display());
    }

    println!("  /var copy complete.");
    Ok(())
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

    let diff =
        compute_diff(&pristine_tree, &current_tree, &new_tree).context("Computing /etc diff")?;

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
}
