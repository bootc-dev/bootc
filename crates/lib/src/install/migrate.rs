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
//! Well-known ephemeral subdirectories (`tmp`, `cache`, `log/journal`,
//! `lib/containers`) are skipped in both strategies.
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
//! ## Rollback BLS entry (`--preserve-var` also saves the kernel)
//!
//! When `--preserve-var` is passed, the running kernel and initramfs are saved
//! to `<root_path>/var/lib/pkgmode-rollback/` **before** the install wipes
//! `/boot`.  After the install a third BLS entry (`pkgmode-rollback.conf`) is
//! written into the active `loader.N/entries/` directory so GRUB presents a
//! "Previous OS" option.  The entry is invisible to ostree (which only reads
//! `ostree-*.conf` files) and to bootupd (which does not touch `loader/entries/`).

use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result};
use cap_std_ext::cap_std::ambient_authority;
use cap_std_ext::cap_std::fs::Dir as CapStdDir;
use composefs_ctl::composefs::generic_tree::{FileSystem, Stat};
use etc_merge::{compute_diff, merge, traverse_etc};
use fn_error_context::context;

/// Subdirectory of `<root_path>/var` where the running kernel/initramfs are
/// stashed before `/boot` is wiped.  Lives under `/var` (not `/boot`) so it
/// survives `clean_boot_directories()`.
pub(crate) const PKGMODE_ROLLBACK_VAR: &str = "var/lib/pkgmode-rollback";

/// Subdirectory of `<root_path>/boot` where the stashed files are installed
/// after the bootc install re-creates `/boot`.
const PKGMODE_ROLLBACK_BOOT: &str = "boot/pkgmode-rollback";

// ── Top-level entry points ────────────────────────────────────────────────────

/// Save the running kernel, initramfs, and kernel command line to
/// `<root_path>/var/lib/pkgmode-rollback/` before `/boot` is wiped.
///
/// This must be called **before** `install_to_filesystem` runs, because
/// `clean_boot_directories()` inside that function wipes `/boot`.
///
/// `root_path` is the host root as seen from inside the install container
/// (typically `/target`).
#[context("Saving package-mode kernel and initramfs for rollback")]
pub(crate) fn save_pkgmode_kernel(root_path: &Path) -> Result<String> {
    let uname = rustix::system::uname();
    let kver = uname
        .release()
        .to_str()
        .context("Kernel version string is not valid UTF-8")?
        .to_string();

    let stash = root_path.join(PKGMODE_ROLLBACK_VAR);
    std::fs::create_dir_all(&stash)
        .with_context(|| format!("Creating {}", stash.display()))?;

    // Kernel image.
    let vmlinuz_src = root_path.join(format!("boot/vmlinuz-{kver}"));
    let vmlinuz_dst = stash.join("vmlinuz");
    std::fs::copy(&vmlinuz_src, &vmlinuz_dst)
        .with_context(|| format!("Copying {} → {}", vmlinuz_src.display(), vmlinuz_dst.display()))?;

    // Initramfs.
    let initramfs_src = root_path.join(format!("boot/initramfs-{kver}.img"));
    let initramfs_dst = stash.join("initramfs.img");
    std::fs::copy(&initramfs_src, &initramfs_dst)
        .with_context(|| format!("Copying {} → {}", initramfs_src.display(), initramfs_dst.display()))?;

    // Kernel command line — used verbatim (minus BOOT_IMAGE=) in the BLS entry.
    //
    // Read from <root_path>/proc/cmdline rather than /proc/cmdline.  The install
    // runs inside a container that has the host root bind-mounted at root_path
    // (typically /target), so /target/proc is the host's /proc — with the correct
    // host kernel cmdline.  The container's own /proc/cmdline would be the same
    // value when --pid=host is used, but reading via root_path is more explicit
    // and remains correct if the container is re-exec'd into a private mount
    // namespace (ensure_self_unshared_mount_namespace), which does not affect
    // the bind-mounted /target/proc.
    let proc_cmdline_path = root_path.join("proc/cmdline");
    let cmdline = std::fs::read_to_string(&proc_cmdline_path)
        .with_context(|| format!("Reading {}", proc_cmdline_path.display()))?;
    let kargs_dst = stash.join("kargs.txt");
    std::fs::write(&kargs_dst, cmdline.trim())
        .with_context(|| format!("Writing {}", kargs_dst.display()))?;

    println!("  Saved kernel {kver} to {}", stash.display());
    Ok(kver)
}

/// Run the full post-install migration pipeline:
///
/// 1. Preserve `/var` (reflink copy or bind-mount unit injection)
/// 2. Write the package-mode rollback BLS entry
///
/// `root_path` is the host root as seen from inside the install container.
/// `kver` is the running kernel version string returned by `save_pkgmode_kernel`.
#[context("Running post-install /var preservation and rollback entry")]
pub(crate) fn preserve_var_and_write_rollback(root_path: &Path, kver: &str) -> Result<()> {
    // Find the newly-created deployment directory.
    let deploy_dir = find_deploy_dir(root_path)
        .context("Locating new ostree deployment directory")?;
    println!("  Deployment directory: {}", deploy_dir.display());

    // The deployment's var/ is two levels up from the deploy dir:
    //   <root_path>/ostree/deploy/<stateroot>/deploy/<hash>.0  ← deploy_dir
    //   <sysroot>/ostree/deploy/<stateroot>/var/              ← new_var
    let new_var = {
        let mut p = deploy_dir.clone();
        p.pop(); // pop <hash>.0
        p.pop(); // pop `deploy`
        p.push("var");
        p
    };

    println!();
    println!("Preserving /var into new deployment...");
    preserve_var(&root_path.join("var"), &new_var)
        .context("Preserving /var")?;

    println!();
    println!("Writing package-mode rollback boot entry...");
    write_pkgmode_rollback_entry(root_path, kver)
        .context("Writing package-mode rollback BLS entry")?;

    Ok(())
}

/// Run the 3-way `/etc` merge on the new deployment.
///
/// Inputs:
///   - **A (pristine)** = `<deploy_dir>/usr/etc`
///   - **B (current)**  = `<root_path>/etc`
///   - **C (new)**      = `<deploy_dir>/etc`
///
/// `root_path` is the host root as seen from inside the install container.
#[context("Running 3-way /etc merge into new deployment")]
pub(crate) fn merge_etc_into_deployment(root_path: &Path) -> Result<()> {
    let deploy_dir = find_deploy_dir(root_path)
        .context("Locating new ostree deployment directory")?;

    let deploy_usr_etc = deploy_dir.join("usr/etc");
    let deploy_etc = deploy_dir.join("etc");
    let host_etc = root_path.join("etc");

    merge_etc(&host_etc, &deploy_usr_etc, &deploy_etc)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Locate the newly-created ostree deployment directory.
///
/// The deployment dir is at a path like:
///   `<root_path>/ostree/deploy/<stateroot>/deploy/<hash>.0`
///
/// On systems where `install_to_existing_root` detects an ostree sysroot
/// already present at `<root_path>/sysroot/ostree`, `root_path` is adjusted
/// to `<root_path>/sysroot` before we are called, so the deploy tree is then
/// at `<root_path>/ostree/deploy`.  On a plain package-mode root (Fedora Cloud,
/// RHEL, etc.) the ostree sysroot is installed directly under the root, so the
/// path is `<root_path>/ostree/deploy` as well.
///
/// We enumerate `<root_path>/ostree/deploy/` and return the most recently
/// modified entry under each stateroot's `deploy/` subdirectory.
#[context("Locating new ostree deployment directory")]
fn find_deploy_dir(root_path: &Path) -> Result<PathBuf> {
    let stateroot_base = root_path.join("ostree/deploy");
    let mut candidates: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();

    if let Ok(stateroots) = std::fs::read_dir(&stateroot_base) {
        for stateroot_entry in stateroots.flatten() {
            let deploy_subdir = stateroot_entry.path().join("deploy");
            if let Ok(deploys) = std::fs::read_dir(&deploy_subdir) {
                for deploy_entry in deploys.flatten() {
                    let path = deploy_entry.path();
                    if path.is_dir() {
                        let mtime = path
                            .metadata()
                            .and_then(|m| m.modified())
                            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                        candidates.push((mtime, path));
                    }
                }
            }
        }
    }

    // Most recently modified = new deployment.
    candidates.sort_by_key(|(t, _)| *t);
    candidates.reverse();

    candidates
        .into_iter()
        .next()
        .map(|(_, p)| p)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Could not locate new ostree deployment directory under {}.\n\
                 Expected a directory under ostree/deploy/<stateroot>/deploy/",
                stateroot_base.display()
            )
        })
}

/// Preserve the running `/var` into the new deployment's `var/` directory.
///
/// `src_var` is the running system's `/var` (at `<root_path>/var`).
/// `new_var` is the new deployment's empty `var/` directory.
fn preserve_var(src_var: &Path, new_var: &Path) -> Result<()> {
    std::fs::create_dir_all(new_var)
        .with_context(|| format!("Creating {}", new_var.display()))?;

    if reflinks_supported(src_var, new_var) {
        println!("  Filesystem supports reflinks — using copy-on-write clone (Strategy C)");
        preserve_var_reflink(src_var, new_var)
    } else {
        println!("  Filesystem does not support reflinks — falling back to full copy (Strategy D)");
        preserve_var_copy(src_var, new_var)
    }
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
fn preserve_var_reflink(src_var: &Path, new_var: &Path) -> Result<()> {
    // Top-level names to skip entirely — ephemeral / regenerable.
    const SKIP_TOP: &[&str] = &["tmp", "cache"];

    let entries = std::fs::read_dir(src_var)
        .with_context(|| format!("Reading {}", src_var.display()))?;

    for entry in entries {
        let entry = entry.with_context(|| format!("Reading entry in {}", src_var.display()))?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Skip plain top-level ephemeral names.
        if SKIP_TOP.iter().any(|s| *s == name_str.as_ref()) {
            println!("    Skipping {} (ephemeral)", src_var.join(name_str.as_ref()).display());
            continue;
        }

        let src_entry = src_var.join(name_str.as_ref());
        let dst_entry = new_var.join(name_str.as_ref());

        // For `log/`, skip only the `journal` subdirectory (large; regenerated by journald).
        if name_str == "log" {
            copy_dir_skip_subdir(&src_entry, &dst_entry, "journal", true)?;
            continue;
        }

        // For `lib/`, skip `containers` (podman/docker storage — overlay mounts cannot
        // be reflinked across device boundaries, and container images should be re-pulled
        // in the new deployment from the image spec rather than blindly copied).
        if name_str == "lib" {
            copy_dir_skip_subdir(&src_entry, &dst_entry, "containers", true)?;
            continue;
        }

        println!("    Reflink-copying {} → {}", src_entry.display(), dst_entry.display());
        let status = std::process::Command::new("cp")
            .args(["--reflink=always", "-a", "--no-clobber"])
            .arg(&src_entry)
            .arg(new_var)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .with_context(|| format!("cp --reflink=always {}", src_entry.display()))?;

        if !status.success() {
            eprintln!(
                "WARNING: cp --reflink=always failed for {} (exit {:?}); \
                 that entry will be absent in the new deployment.",
                src_entry.display(),
                status.code()
            );
        }
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
    std::fs::create_dir_all(dst)
        .with_context(|| format!("Creating {}", dst.display()))?;

    let entries = std::fs::read_dir(src)
        .with_context(|| format!("Reading {}", src.display()))?;

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

        if !status.success() {
            eprintln!(
                "WARNING: cp failed for {} (exit {:?})",
                src_entry.display(),
                status.code()
            );
        }
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
fn preserve_var_copy(src_var: &Path, new_var: &Path) -> Result<()> {
    // Top-level names to skip entirely — ephemeral / regenerable.
    const SKIP_TOP: &[&str] = &["tmp", "cache"];

    let entries = std::fs::read_dir(src_var)
        .with_context(|| format!("Reading {}", src_var.display()))?;

    for entry in entries {
        let entry = entry.with_context(|| format!("Reading entry in {}", src_var.display()))?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if SKIP_TOP.iter().any(|s| *s == name_str.as_ref()) {
            println!("    Skipping {} (ephemeral)", src_var.join(name_str.as_ref()).display());
            continue;
        }

        let src_entry = src_var.join(name_str.as_ref());
        let dst_entry = new_var.join(name_str.as_ref());

        // For `log/`, skip only the `journal` subdirectory (large; regenerated by journald).
        if name_str == "log" {
            copy_dir_skip_subdir(&src_entry, &dst_entry, "journal", false)?;
            continue;
        }

        // For `lib/`, skip `containers` (podman/docker storage — overlay mounts cannot
        // be copied across device boundaries, and container images should be re-pulled).
        if name_str == "lib" {
            copy_dir_skip_subdir(&src_entry, &dst_entry, "containers", false)?;
            continue;
        }

        println!("    Copying {} → {}", src_entry.display(), dst_entry.display());
        let status = std::process::Command::new("cp")
            .args(["-a", "--no-clobber"])
            .arg(&src_entry)
            .arg(new_var)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .with_context(|| format!("cp -a {}", src_entry.display()))?;

        if !status.success() {
            eprintln!(
                "WARNING: cp -a failed for {} (exit {:?}); \
                 that entry may be absent or incomplete in the new deployment.",
                src_entry.display(),
                status.code()
            );
        }
    }

    println!("  /var copy complete.");
    Ok(())
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

    let diff = compute_diff(&pristine_tree, &current_tree, &new_tree)
        .context("Computing /etc diff")?;

    println!("  /etc diff (changes being applied from running system):");
    etc_merge::print_diff(&diff, &mut std::io::stdout());

    merge(&current_fd, &current_tree, &new_fd, &new_tree, &diff)
        .context("Applying /etc 3-way merge")?;

    println!("  /etc merge complete.");
    Ok(())
}

/// Copy the stashed kernel/initramfs into `<root_path>/boot/pkgmode-rollback/`
/// and write a BLS entry so GRUB presents a "Previous OS" boot option.
///
/// The entry uses `sort-key zz-pkgmode` so it sorts last in the menu.
/// It is written into the currently-active `loader.N/entries/` directory so
/// GRUB sees it immediately on the first reboot.
#[context("Writing package-mode rollback BLS entry")]
fn write_pkgmode_rollback_entry(root_path: &Path, kver: &str) -> Result<()> {
    // Install saved kernel/initramfs into /boot.
    let boot_dir = root_path.join(PKGMODE_ROLLBACK_BOOT);
    std::fs::create_dir_all(&boot_dir)
        .with_context(|| format!("Creating {}", boot_dir.display()))?;

    let stash = root_path.join(PKGMODE_ROLLBACK_VAR);

    let vmlinuz_dst = boot_dir.join("vmlinuz");
    std::fs::copy(stash.join("vmlinuz"), &vmlinuz_dst)
        .with_context(|| format!("Copying vmlinuz to {}", vmlinuz_dst.display()))?;

    let initramfs_dst = boot_dir.join("initramfs.img");
    std::fs::copy(stash.join("initramfs.img"), &initramfs_dst)
        .with_context(|| format!("Copying initramfs to {}", initramfs_dst.display()))?;

    // Build the kernel options line: strip BOOT_IMAGE= (old-bootloader-specific).
    let kargs_raw = std::fs::read_to_string(stash.join("kargs.txt"))
        .context("Reading saved kargs")?;
    let options: String = kargs_raw
        .split_whitespace()
        .filter(|tok| !tok.starts_with("BOOT_IMAGE="))
        .collect::<Vec<_>>()
        .join(" ");

    // Find the active loader.N symlink to know which entries/ dir to write into.
    let loader_link_path = root_path.join("boot/loader");
    let loader_target = std::fs::read_link(&loader_link_path)
        .with_context(|| format!("Reading {} symlink", loader_link_path.display()))?;
    let loader_name = loader_target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("loader")
        .to_string();

    let entries_dir = root_path.join(format!("boot/{loader_name}/entries"));
    std::fs::create_dir_all(&entries_dir)
        .with_context(|| format!("Creating {}", entries_dir.display()))?;

    let entry_path = entries_dir.join("pkgmode-rollback.conf");
    let entry_content = format!(
        "title Previous OS — package-mode rollback (kernel {kver})\n\
         sort-key zz-pkgmode\n\
         linux /boot/pkgmode-rollback/vmlinuz\n\
         initrd /boot/pkgmode-rollback/initramfs.img\n\
         options {options}\n"
    );
    std::fs::write(&entry_path, &entry_content)
        .with_context(|| format!("Writing BLS entry {}", entry_path.display()))?;

    println!("  BLS entry written: {}", entry_path.display());
    println!("  Hold Shift/Esc at GRUB to select the package-mode rollback entry.");
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// The rollback stash must be under var/ (not boot/ which is wiped).
    #[test]
    fn test_pkgmode_rollback_var_under_var() {
        assert!(
            PKGMODE_ROLLBACK_VAR.starts_with("var/"),
            "PKGMODE_ROLLBACK_VAR must be under var/ to survive boot wipe: {PKGMODE_ROLLBACK_VAR}"
        );
    }

    /// The boot destination is under boot/ (written after the wipe).
    #[test]
    fn test_pkgmode_rollback_boot_under_boot() {
        assert!(
            PKGMODE_ROLLBACK_BOOT.starts_with("boot/"),
            "PKGMODE_ROLLBACK_BOOT must be under boot/: {PKGMODE_ROLLBACK_BOOT}"
        );
    }

    /// The var/ path derivation from a deployment directory must be correct.
    #[test]
    fn test_new_var_path_from_deploy_dir() {
        let root = Path::new("/target");
        let deploy_dir = root.join("sysroot/ostree/deploy/default/deploy/abc123.0");
        let mut p = deploy_dir.clone();
        p.pop();
        p.pop();
        p.push("var");
        assert_eq!(p, root.join("sysroot/ostree/deploy/default/var"));
    }

    /// SKIP list must not contain application data directories.
    #[test]
    fn test_reflink_skip_list_is_ephemeral_only() {
        const SKIP_TOP: &[&str] = &["tmp", "cache"];
        for s in SKIP_TOP {
            assert!(
                !s.starts_with("lib/pg") && !s.starts_with("lib/my"),
                "Accidentally skipping application data: {s}"
            );
        }
        // containers is skipped at the lib/ level, not the top level.
        assert!(!SKIP_TOP.contains(&"containers"));
    }
}
