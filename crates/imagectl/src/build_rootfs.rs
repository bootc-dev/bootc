//! Build container root filesystem using rpm-ostree

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use tempfile::TempDir;

use crate::cli::BuildRootfsOpts;
use crate::constants::MANIFESTDIR;
use crate::lockfile::Lockfile;
use crate::manifest::ManifestOverride;

/// Build a container root filesystem from a manifest
pub fn build_rootfs(opts: &BuildRootfsOpts) -> Result<()> {
    tracing::info!("Building rootfs at: {}", opts.target);

    // Find the manifest
    let manifest_path = crate::manifest::find_manifest(&opts.manifest)?;
    tracing::info!("Using manifest: {}", manifest_path);

    // Workaround for https://issues.redhat.com/browse/RHEL-108989
    tracing::debug!("Running dnf repolist as workaround for RHEL-108989");
    let _ = Command::new("dnf")
        .arg("repolist")
        .output()
        .context("Failed to execute dnf repolist")?;

    // Build manifest override if needed
    let (final_manifest_path, _manifest_tmpfile) =
        build_manifest_override(opts, manifest_path.as_str())?;

    // Build lockfile if needed
    let (_lockfile_tmpfile, lockfile_arg) = build_lockfile(opts)?;

    // Handle ostree overlays if needed
    let (_tmp_ostree_repo, ostree_repo_arg, _overlay_commits) = setup_ostree_overlays(opts)?;

    // Build rpm-ostree command
    let mut argv = vec![
        "rpm-ostree".to_string(),
        "compose".to_string(),
        "rootfs".to_string(),
    ];

    // Add lockfile if present
    if let Some(lockfile_path) = lockfile_arg {
        argv.push(format!("--lockfile={}", lockfile_path));
    }

    // Add cachedir if specified
    if !opts.cachedir.is_empty() {
        argv.push(format!("--cachedir={}", opts.cachedir));
    }

    // Add ostree repo if present
    if let Some(repo_path) = ostree_repo_arg {
        argv.push(format!("--ostree-repo={}", repo_path));
    }

    // Add source root
    let source_root = opts.source_root.as_ref().map(|p| p.as_str()).unwrap_or("/");
    if source_root != "/" {
        argv.push(format!("--source-root-rw={}", source_root));
    } else {
        argv.push("--source-root=/".to_string());
    }

    // Add manifest and target
    argv.push(final_manifest_path);
    argv.push(opts.target.to_string());

    // Execute rpm-ostree
    tracing::info!("Executing: {}", argv.join(" "));
    let status = Command::new(&argv[0])
        .args(&argv[1..])
        .status()
        .context("Failed to execute rpm-ostree")?;

    if !status.success() {
        anyhow::bail!(
            "rpm-ostree command failed with exit code: {}",
            status.code().unwrap_or(-1)
        );
    }

    // Apply permission fix workaround
    fix_rootfs_permissions(&opts.target)?;

    // Run bootc container lint
    run_bootc_lint(&opts.target)?;

    // Handle reinject if requested
    if opts.reinject {
        reinject_build_configs(&opts.target)?;
    }

    tracing::info!("Successfully built rootfs at: {}", opts.target);
    Ok(())
}

/// Build manifest override if any options require it
fn build_manifest_override(
    opts: &BuildRootfsOpts,
    base_manifest: &str,
) -> Result<(String, Option<tempfile::NamedTempFile>)> {
    let mut override_manifest = ManifestOverride::new(base_manifest.to_string());
    let mut needs_override = false;

    // Add packages if specified
    if !opts.install.is_empty() {
        let packages: Vec<String> = opts.install.iter().map(|p| p.to_string()).collect();
        override_manifest.packages = Some(packages);
        needs_override = true;
    }

    // Add ostree overlay layers (will be populated by setup_ostree_overlays)
    if !opts.add_dir.is_empty() {
        let layers: Vec<String> = opts
            .add_dir
            .iter()
            .map(|d| {
                let base = d.file_name().unwrap_or("unknown");
                format!("overlay/{}", base)
            })
            .collect();
        override_manifest.ostree_override_layers = Some(layers);
        needs_override = true;
    }

    // Add documentation setting
    if opts.no_docs {
        override_manifest.documentation = Some(false);
        needs_override = true;
    }

    // Add sysusers setting
    if opts.sysusers {
        override_manifest.sysusers = Some("compose-forced".to_string());
        let passwd_mode = if opts.nobody_99 { "nobody" } else { "none" };
        let mut variables = std::collections::HashMap::new();
        variables.insert("passwd_mode".to_string(), passwd_mode.to_string());
        override_manifest.variables = Some(variables);
        needs_override = true;
    }

    // Add repo overrides
    if !opts.repo.is_empty() {
        override_manifest.repos = Some(opts.repo.clone());
        needs_override = true;
    }

    if needs_override {
        tracing::debug!("Creating manifest override");
        let tmpfile = override_manifest.write_to_tempfile()?;
        let path = tmpfile.path().to_str().unwrap().to_string();
        Ok((path, Some(tmpfile)))
    } else {
        Ok((base_manifest.to_string(), None))
    }
}

/// Build lockfile from NEVRA/NEVR specifications
fn build_lockfile(
    opts: &BuildRootfsOpts,
) -> Result<(Option<tempfile::NamedTempFile>, Option<String>)> {
    if opts.lock.is_empty() {
        return Ok((None, None));
    }

    let mut lockfile = Lockfile::new();
    for nevra in &opts.lock {
        lockfile.add_package(nevra)?;
    }

    tracing::debug!("Creating lockfile with {} packages", opts.lock.len());
    let tmpfile = lockfile.write_to_tempfile()?;
    let path = tmpfile.path().to_str().unwrap().to_string();
    Ok((Some(tmpfile), Some(path)))
}

/// Setup ostree overlays for --add-dir
fn setup_ostree_overlays(
    opts: &BuildRootfsOpts,
) -> Result<(Option<TempDir>, Option<String>, Vec<String>)> {
    if opts.add_dir.is_empty() {
        return Ok((None, None, Vec::new()));
    }

    // Create temporary ostree repo
    let tmp_repo = tempfile::Builder::new()
        .prefix("ostree-repo-")
        .tempdir_in("/var/tmp")
        .context("Failed to create temporary ostree repository")?;

    let repo_path = tmp_repo.path().to_str().unwrap().to_string();
    tracing::info!("Created temporary ostree repo at: {}", repo_path);

    // Initialize the repo
    let status = Command::new("ostree")
        .args(["init", "--repo", &repo_path, "--mode=bare"])
        .status()
        .context("Failed to initialize ostree repository")?;

    if !status.success() {
        anyhow::bail!("ostree init failed");
    }

    // Commit each directory as an overlay
    let mut commits = Vec::new();
    for dir in &opts.add_dir {
        let base = dir.file_name().unwrap_or("unknown");
        let branch = format!("overlay/{}", base);
        let abs_path = dir
            .canonicalize_utf8()
            .with_context(|| format!("Failed to canonicalize path: {}", dir))?;

        tracing::info!("Committing {} as {}", dir, branch);

        let output = Command::new("ostree")
            .args([
                "commit",
                "--repo",
                &repo_path,
                "-b",
                &branch,
                abs_path.as_str(),
                "--owner-uid=0",
                "--owner-gid=0",
                "--no-xattrs",
                "--mode-ro-executables",
            ])
            .output()
            .context("Failed to commit ostree overlay")?;

        if !output.status.success() {
            anyhow::bail!(
                "ostree commit failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        commits.push(branch);
    }

    Ok((Some(tmp_repo), Some(repo_path), commits))
}

/// Fix rootfs permissions (workaround for rpm-ostree issue)
fn fix_rootfs_permissions(target: &Utf8Path) -> Result<()> {
    // Work around https://github.com/coreos/rpm-ostree/pull/5322
    let metadata =
        fs::metadata(target).with_context(|| format!("Failed to get metadata for {}", target))?;

    let mode = metadata.permissions().mode();

    // Check if "other execute" bit is not set
    if (mode & 0o001) == 0 {
        tracing::info!("Updating rootfs mode to add execute permissions");
        let new_mode = mode | 0o555;
        let new_perms = fs::Permissions::from_mode(new_mode);
        fs::set_permissions(target, new_perms)
            .with_context(|| format!("Failed to set permissions on {}", target))?;
    }

    Ok(())
}

/// Run bootc container lint on the generated rootfs
fn run_bootc_lint(target: &Utf8Path) -> Result<()> {
    tracing::info!("Running bootc container lint");

    let status = Command::new("bootc")
        .args(["container", "lint", &format!("--rootfs={}", target)])
        .status()
        .context("Failed to execute bootc container lint")?;

    if !status.success() {
        anyhow::bail!("bootc container lint failed");
    }

    Ok(())
}

/// Reinject build configurations into the target
fn reinject_build_configs(target: &Utf8Path) -> Result<()> {
    tracing::info!("Reinjecting build configurations");

    // Copy manifest directory
    let manifest_src = Utf8Path::new("/").join(MANIFESTDIR);
    let manifest_dst = target.join(MANIFESTDIR);

    if manifest_src.exists() {
        tracing::info!("Copying {} to {}", manifest_src, manifest_dst);
        copy_dir_all(&manifest_src, &manifest_dst)?;
    } else {
        tracing::warn!("Manifest directory not found: {}", manifest_src);
    }

    // Copy the imagectl binary itself
    // In the Python version, this was bootc-base-imagectl
    // In our Rust version, this will be part of bootc binary
    let imagectl_src = Utf8Path::new("/usr/libexec/bootc-base-imagectl");
    if imagectl_src.exists() {
        let imagectl_dst = target.join("usr/libexec/bootc-base-imagectl");
        if let Some(parent) = imagectl_dst.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory: {}", parent))?;
        }
        tracing::info!("Copying {} to {}", imagectl_src, imagectl_dst);
        fs::copy(imagectl_src, imagectl_dst).context("Failed to copy bootc-base-imagectl")?;
    } else {
        tracing::debug!("Legacy bootc-base-imagectl not found, skipping");
    }

    Ok(())
}

/// Recursively copy a directory
fn copy_dir_all(src: &Utf8Path, dst: &Utf8Path) -> Result<()> {
    fs::create_dir_all(dst).with_context(|| format!("Failed to create directory: {}", dst))?;

    for entry in fs::read_dir(src).with_context(|| format!("Failed to read directory: {}", src))? {
        let entry = entry.context("Failed to read directory entry")?;
        let ty = entry.file_type().context("Failed to get file type")?;
        let src_path = Utf8PathBuf::try_from(entry.path()).context("Invalid UTF-8 in path")?;
        let dst_path = dst.join(src_path.file_name().unwrap());

        if ty.is_dir() {
            copy_dir_all(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)
                .with_context(|| format!("Failed to copy {} to {}", src_path, dst_path))?;
        }
    }

    Ok(())
}
