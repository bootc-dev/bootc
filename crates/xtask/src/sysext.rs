//! Development VM management with systemd-sysext overlay
//!
//! This module manages a persistent bcvk development VM where the bootc
//! binary is overlaid onto /usr via systemd-sysext.
//!
//! The `target/sysext/` directory is shared with the VM via virtiofs.
//! Inside it, each build creates a versioned subdirectory (e.g.
//! `bootc-1712345678/`) with a `current` symlink pointing at the latest.
//! Inside the VM, `/run/extensions/bootc` is a symlink into the virtiofs
//! mount that follows `current`.
//!
//! On sync, the host builds a new version, then the VM swaps its symlink
//! and runs `systemd-sysext refresh`.  The old version's inodes stay
//! valid until the overlay is torn down during refresh.
//!
//! The development cycle is:
//!   1. `just bcvk up`   — build sysext, launch VM, set up overlay
//!   2. Edit code
//!   3. `just bcvk sync` — rebuild + refresh overlay (~30s)
//!   4. Repeat from 2

use std::fs;
use std::process::Command;

use anyhow::{Context, Result, bail};
use camino::Utf8Path;
use fn_error_context::context;
use xshell::{Shell, cmd};

const SYSEXT_DIR: &str = "target/sysext";
const DEV_VM_NAME: &str = "bootc-dev";
const DEV_VM_LABEL: &str = "bootc.dev=1";
/// Virtiofs mount point inside the VM.  We avoid /run/extensions to
/// prevent systemd-sysext from auto-merging during early boot.
const VM_SYSEXT_MNT: &str = "/run/virtiofs-bootc-sysext";
/// Symlink in the VM that points to the current sysext version.
const VM_EXTENSION_LINK: &str = "/run/extensions/bootc";

/// Read the current sysext version from the `current` symlink.
fn current_version() -> Result<String> {
    let link = Utf8Path::new(SYSEXT_DIR).join("current");
    let target = fs::read_link(&link)
        .with_context(|| format!("No current sysext version (missing {})", link))?;
    let version = target
        .to_str()
        .context("current symlink target is not UTF-8")?
        .to_string();
    Ok(version)
}

/// Launch or sync development VM
#[context("Managing bcvk VM")]
pub(crate) fn bcvk_vm(sh: &Shell) -> Result<()> {
    check_vm_deps()?;
    // Verify sysext exists
    current_version().context("Run 'just sysext' first")?;

    if vm_exists()? {
        println!("Development VM '{}' exists, syncing...", DEV_VM_NAME);
        bcvk_vm_sync(sh)
    } else {
        println!("Creating development VM '{}'...", DEV_VM_NAME);
        create_vm(sh)
    }
}

/// Rebuild the sysext and refresh the overlay in the VM.
#[context("Syncing to VM")]
pub(crate) fn bcvk_vm_sync(sh: &Shell) -> Result<()> {
    check_vm_deps()?;

    if !vm_is_running()? {
        bail!(
            "Development VM '{}' is not running. Use 'just bcvk vm' to start it.",
            DEV_VM_NAME
        );
    }

    let version = current_version()?;
    let target = format!("{}/{}/bootc", VM_SYSEXT_MNT, version);

    // Swap the extension symlink to the new version, then refresh.
    // The old overlay still references valid inodes (the old versioned
    // directory hasn't been deleted).  systemd-sysext refresh will
    // unmerge (dropping the old overlay) then re-merge (following the
    // new symlink).
    //
    // We use systemd-run --no-block so that the SSH session returns
    // immediately while systemd handles the unmerge→merge cycle
    // asynchronously.
    println!("Switching to sysext version: {}", version);
    cmd!(
        sh,
        "bcvk libvirt ssh {DEV_VM_NAME} -- ln -sfn {target} {VM_EXTENSION_LINK}"
    )
    .run()
    .context("Failed to update extension symlink")?;

    println!("Refreshing sysext overlay...");
    cmd!(
        sh,
        "bcvk libvirt ssh {DEV_VM_NAME} -- systemd-run --no-block systemd-sysext refresh"
    )
    .run()
    .context("Failed to trigger sysext refresh")?;

    // Wait for the overlay merge to complete so the new bootc is in place.
    poll(
        "bootc available after sysext refresh",
        std::time::Duration::from_secs(5),
        || Ok(cmd!(sh, "bcvk libvirt ssh {DEV_VM_NAME} -- bootc --version").run()?),
    )?;

    Ok(())
}

/// Stop and remove development VM
#[context("Stopping development VM")]
pub(crate) fn bcvk_vm_down(sh: &Shell) -> Result<()> {
    check_vm_deps()?;

    if vm_exists()? {
        cmd!(sh, "bcvk libvirt rm --stop --force {DEV_VM_NAME}")
            .run()
            .context("Failed to stop VM")?;
        println!("Development VM '{}' stopped and removed", DEV_VM_NAME);
    } else {
        println!("No development VM '{}' found, nothing to do", DEV_VM_NAME);
    }
    Ok(())
}

/// SSH into development VM.
///
/// Uses `std::process::Command` with inherited stdio so that interactive
/// sessions get a proper TTY.  When args are given after `--`, they are
/// passed as a remote command; otherwise an interactive shell is opened.
#[context("SSH to development VM")]
pub(crate) fn bcvk_vm_ssh(_sh: &Shell, args: &[String]) -> Result<()> {
    check_vm_deps()?;

    let mut cmd = Command::new("bcvk");
    cmd.args(["libvirt", "ssh", DEV_VM_NAME]);
    if !args.is_empty() {
        cmd.arg("--");
        cmd.args(args);
    }
    let status = cmd
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .context("Failed to run bcvk ssh")?;
    if !status.success() {
        bail!("ssh command failed with status {status}");
    }
    Ok(())
}

/// Show VM status
#[context("Getting VM status")]
pub(crate) fn bcvk_vm_status(sh: &Shell) -> Result<()> {
    check_vm_deps()?;

    if vm_exists()? {
        cmd!(sh, "bcvk libvirt list {DEV_VM_NAME}")
            .run()
            .context("Failed to get VM status")?;
    } else {
        println!(
            "No development VM '{}' found. Use 'just bcvk vm' to create one.",
            DEV_VM_NAME
        );
    }

    Ok(())
}

/// Watch VM logs
#[context("Watching VM logs")]
pub(crate) fn bcvk_vm_logs(sh: &Shell) -> Result<()> {
    check_vm_deps()?;

    cmd!(sh, "bcvk libvirt ssh {DEV_VM_NAME} -- journalctl -f")
        .run()
        .context("Failed to watch logs")?;

    Ok(())
}

/// Clean all development resources
#[context("Cleaning development resources")]
pub(crate) fn bcvk_vm_clean(sh: &Shell) -> Result<()> {
    bcvk_vm_down(sh).unwrap_or_else(|e| eprintln!("Warning: {}", e));

    let sysext_dir = Utf8Path::new(SYSEXT_DIR);
    if sysext_dir.exists() {
        sh.remove_path(sysext_dir)?;
    }

    println!("Cleaned up development VM and sysext files");
    Ok(())
}

// Helper functions

#[context("Checking VM dependencies")]
fn check_vm_deps() -> Result<()> {
    if Command::new("bcvk").arg("--version").output().is_err() {
        bail!(
            "bcvk is required for VM operations.\n\
             Install it from: https://github.com/bootc-dev/bcvk"
        );
    }

    Ok(())
}

/// Query bcvk for a VM by name.
fn query_vm() -> Result<Option<serde_json::Value>> {
    let output = Command::new("bcvk")
        .args(["libvirt", "list", DEV_VM_NAME, "--format=json"])
        .output()
        .context("Failed to run bcvk list")?;

    if !output.status.success() {
        return Ok(None);
    }

    let stdout =
        String::from_utf8(output.stdout).context("Failed to parse bcvk output as UTF-8")?;
    let val: serde_json::Value =
        serde_json::from_str(&stdout).context("Failed to parse bcvk JSON output")?;

    match &val {
        serde_json::Value::Object(_) => Ok(Some(val)),
        serde_json::Value::Array(arr) => Ok(arr.first().cloned()),
        _ => Ok(None),
    }
}

#[context("Checking if VM exists")]
fn vm_exists() -> Result<bool> {
    Ok(query_vm()?.is_some())
}

#[context("Checking if VM is running")]
fn vm_is_running() -> Result<bool> {
    Ok(query_vm()?
        .as_ref()
        .and_then(|v| v.get("state"))
        .and_then(|s| s.as_str())
        == Some("running"))
}

#[context("Creating development VM")]
fn create_vm(sh: &Shell) -> Result<()> {
    let sysext_path =
        fs::canonicalize(SYSEXT_DIR).context("Failed to get absolute path for sysext directory")?;
    let sysext_path = sysext_path.to_string_lossy();

    let version = current_version()?;

    let base_img = std::env::var("BOOTC_BASE_IMAGE")
        .or_else(|_| std::env::var("BOOTC_base"))
        .unwrap_or_else(|_| "quay.io/centos-bootc/centos-bootc:stream10".to_string());
    let bind_mount = format!("{}:{}", sysext_path, VM_SYSEXT_MNT);

    let variant = std::env::var("BOOTC_variant").unwrap_or_else(|_| "ostree".to_string());
    let mut bcvk_cmd = cmd!(
        sh,
        "bcvk libvirt run --name={DEV_VM_NAME} --replace --label={DEV_VM_LABEL} --bind={bind_mount}"
    );

    let seal_state = std::env::var("BOOTC_seal_state").unwrap_or_else(|_| "unsealed".to_string());
    if variant == "composefs" && seal_state == "sealed" {
        let secureboot_dir = Utf8Path::new("target/test-secureboot");
        if !secureboot_dir.exists() {
            println!("Generating secure boot keys for sealed variant...");
            cmd!(sh, "./hack/generate-secureboot-keys")
                .run()
                .context("Failed to generate secure boot keys")?;
        }
        bcvk_cmd = bcvk_cmd.arg("--secure-boot-keys=target/test-secureboot");
    }

    bcvk_cmd = bcvk_cmd.args(["--ssh-wait", &base_img]);
    bcvk_cmd.run().context("Failed to create VM")?;

    // Set up the sysext: create a symlink from /run/extensions/bootc
    // into the virtiofs-mounted versioned directory.
    let target = format!("{}/{}/bootc", VM_SYSEXT_MNT, version);
    println!("Setting up sysext overlay (version: {})...", version);
    cmd!(
        sh,
        "bcvk libvirt ssh {DEV_VM_NAME} -- mkdir -p /run/extensions"
    )
    .run()
    .context("Failed to create /run/extensions")?;

    cmd!(
        sh,
        "bcvk libvirt ssh {DEV_VM_NAME} -- ln -sfn {target} {VM_EXTENSION_LINK}"
    )
    .run()
    .context("Failed to create extension symlink")?;

    cmd!(sh, "bcvk libvirt ssh {DEV_VM_NAME} -- systemd-sysext merge")
        .run()
        .context("Failed to merge sysext")?;

    cmd!(
        sh,
        "bcvk libvirt ssh {DEV_VM_NAME} -- systemd-sysext status"
    )
    .run()
    .context("Failed to get sysext status")?;

    println!();
    println!("Development VM is ready! bootc is overlaid on /usr via sysext.");
    println!("  Rebuild+sync: just bcvk sync");
    println!("  SSH:          just bcvk ssh");
    println!("  Test:         just bcvk ssh bootc status");
    println!("  Stop:         just bcvk down");

    Ok(())
}

/// Poll a closure until it succeeds or the timeout elapses.
///
/// Calls `f` repeatedly with a 1-second interval. Returns the first
/// `Ok` value, or the last error if the timeout is reached.
fn poll<T>(
    condition: &str,
    timeout: std::time::Duration,
    mut f: impl FnMut() -> Result<T>,
) -> Result<T> {
    let start = std::time::Instant::now();
    let mut last_err = None;
    while start.elapsed() < timeout {
        match f() {
            Ok(v) => return Ok(v),
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("timed out waiting for: {condition}")))
}
