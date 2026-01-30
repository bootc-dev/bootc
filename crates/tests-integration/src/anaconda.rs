//! Anaconda installer testing via QEMU.
//!
//! This module tests the `bootc container export --format=tar` -> Anaconda
//! `liveimg` installation path.  It:
//!
//! 1. Builds a derived container image with the ostree kernel-install layout
//!    disabled (so standard kernel-install plugins work).
//! 2. Exports it to a tarball via `bootc container export`.
//! 3. Generates a kickstart that mounts the tarball via virtiofs and installs
//!    via `liveimg`.
//! 4. Creates an automated ISO with the kickstart baked in.
//! 5. Boots the ISO in QEMU (managed by bcvk-qemu) and monitors logs.
//!
//! ## Container image requirements
//!
//! The input container image must be a bootc/rpm-ostree image.  Before export,
//! the test builds a thin derived image that disables the ostree kernel-install
//! layout:
//!
//! - `/usr/lib/kernel/install.conf` — `layout=ostree` line removed
//! - `/usr/lib/kernel/install.conf.d/*-bootc-*.conf` — bootc drop-ins removed
//! - `/usr/lib/kernel/install.d/*-rpmostree.install` — rpm-ostree plugin removed

use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::process::Child;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use fn_error_context::context;
use xshell::{Shell, cmd};

/// Stage timeouts for installation monitoring.
const STAGE_TIMEOUT_ANACONDA_START: Duration = Duration::from_secs(180);
const STAGE_TIMEOUT_INSTALL: Duration = Duration::from_secs(900);
const STAGE_TIMEOUT_REBOOT: Duration = Duration::from_secs(60);

/// Patterns that indicate installation progress.
const PATTERN_ANACONDA_STARTED: &str = "anaconda";
const PATTERN_LIVEIMG_DOWNLOAD: &str = "liveimg";
const PATTERN_INSTALL_COMPLETE: &str = "reboot: Restarting system";

/// Patterns that indicate errors.
const ERROR_PATTERNS: &[&str] = &[
    "Traceback (most recent call last)",
    "FATAL:",
    "Installation failed",
    "error: Installation was stopped",
    "kernel panic",
    "Kernel panic",
];

/// Arguments for the anaconda test subcommand.
#[derive(Debug, clap::Args)]
pub(crate) struct AnacondaTestArgs {
    /// Path to the Anaconda boot ISO.
    #[arg(long)]
    pub(crate) iso: Utf8PathBuf,

    /// Container image to install (must be in local container storage).
    pub(crate) image: String,

    /// Output disk image path.
    #[arg(long)]
    pub(crate) disk: Option<Utf8PathBuf>,

    /// Disk size in GB.
    #[arg(long, default_value = "20")]
    pub(crate) disk_size: u32,

    /// VM memory in MB.
    #[arg(long, default_value = "10240")]
    pub(crate) memory: u32,

    /// Number of vCPUs.
    #[arg(long, default_value = "4")]
    pub(crate) vcpus: u32,

    /// SSH port forwarding.
    #[arg(long, default_value = "10022")]
    pub(crate) ssh_port: u16,

    /// Keep VM running after installation (for debugging).
    #[arg(long)]
    pub(crate) keep_running: bool,

    /// Path to custom kickstart file.
    #[arg(long)]
    pub(crate) kickstart: Option<Utf8PathBuf>,

    /// Root password for the installed system.
    #[arg(long, default_value = "testcase")]
    pub(crate) root_password: String,

    /// Skip creating automated ISO (use provided ISO directly).
    #[arg(long)]
    pub(crate) no_iso_modify: bool,

    /// Prepare ISO and kickstart only, don't run QEMU.
    #[arg(long)]
    pub(crate) dry_run: bool,
}

/// The derived image tag used for the anaconda test.
const ANACONDA_TEST_IMAGE: &str = "localhost/bootc-anaconda-test";

/// Container image used to run `mkksiso`.
const MKKSISO_CONTAINER: &str = "quay.io/centos/centos:stream10";

/// Build a derived container image with ostree kernel-install layout disabled.
#[context("Building derived image for anaconda test")]
fn build_derived_image(sh: &Shell, base_image: &str) -> Result<()> {
    let containerfile = format!(
        r#"FROM {base_image}
RUN sed -i '/layout=ostree/d' /usr/lib/kernel/install.conf && \
    rm -vf /usr/lib/kernel/install.conf.d/*-bootc-*.conf \
           /usr/lib/kernel/install.d/*-rpmostree.install
"#
    );

    println!("Building derived image {ANACONDA_TEST_IMAGE}...");
    cmd!(
        sh,
        "podman build --network=none -t {ANACONDA_TEST_IMAGE} -f - ."
    )
    .stdin(containerfile.as_bytes())
    .run()
    .context("Building derived anaconda-test image")?;

    Ok(())
}

/// Export a container image to a tarball using `bootc container export`.
#[context("Exporting container to tarball")]
fn export_container_to_tarball(sh: &Shell, image: &str, output_path: &Utf8Path) -> Result<()> {
    println!("Exporting container image to tarball...");
    println!("  Image: {image}");
    println!("  Output: {output_path}");

    let output_dir = output_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Invalid output path"))?;
    let output_filename = output_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Invalid output filename"))?;

    sh.create_dir(output_dir)
        .context("Creating output directory")?;

    let abs_output_dir = std::fs::canonicalize(output_dir)
        .context("Getting absolute path")?
        .to_string_lossy()
        .to_string();

    let output_in_container = format!("/output/{output_filename}");
    cmd!(
        sh,
        "podman run --rm --privileged --network=none
            -v {abs_output_dir}:/output:Z
            {image}
            bootc container export --format=tar --kernel-in-boot -o {output_in_container} /"
    )
    .run()
    .context("Running bootc container export")?;

    if !output_path.exists() {
        anyhow::bail!("Tarball was not created at {output_path}");
    }

    let metadata = std::fs::metadata(output_path).context("Getting tarball metadata")?;
    println!(
        "  Created tarball: {output_path} ({})",
        indicatif::HumanBytes(metadata.len())
    );

    Ok(())
}

/// Generate kickstart content for bootc liveimg installation.
///
/// The tarball is shared into the guest via virtiofs and mounted at
/// `/mnt/tarball/` in a `%pre` script.
fn generate_kickstart_liveimg(root_password: &str) -> String {
    format!(
        r#"# Automated bootc installation kickstart (liveimg)
# Generated by bootc integration tests

reboot

# Install from tarball shared via virtiofs
liveimg --url=file:///mnt/tarball/rootfs.tar

# Basic configuration
rootpw {root_password}

# Mount the virtiofs share before Anaconda tries to fetch the tarball
%pre --log=/tmp/pre-mount.log
set -eux
mkdir -p /mnt/tarball
mount -t virtiofs tarball /mnt/tarball
ls -la /mnt/tarball/
%end

bootloader --timeout=1
zerombr
clearpart --all --initlabel
# Use ext4 to avoid btrfs subvolume complexity
autopart --nohome --noswap --type=plain --fstype=ext4

lang en_US.UTF-8
keyboard us
timezone America/New_York --utc

# Set up bootloader entries for the installed system.
%post --log=/root/ks-post.log
set -eux

KVER=$(ls /usr/lib/modules | head -1)
echo "Kernel version: $KVER"

# Ensure machine-id exists (needed by kernel-install for BLS filenames)
if [ ! -s /etc/machine-id ]; then
    systemd-machine-id-setup
fi

kernel-install add "$KVER" "/usr/lib/modules/$KVER/vmlinuz"

# Append console=ttyS0 to the generated BLS entry so serial output works
for entry in /boot/loader/entries/*.conf; do
    if ! grep -q 'console=ttyS0' "$entry"; then
        sed -i 's/^options .*/& console=ttyS0/' "$entry"
    fi
done

# Regenerate grub config to pick up BLS entries
grub2-mkconfig -o /boot/grub2/grub.cfg || true
if [ -d /boot/efi/EFI/fedora ]; then
    grub2-mkconfig -o /boot/efi/EFI/fedora/grub.cfg || true
fi

echo "Bootloader setup complete"
cat /boot/loader/entries/*.conf
%end
"#,
        root_password = root_password,
    )
}

/// Create an automated ISO by injecting a kickstart file using `mkksiso`.
///
/// Runs inside a container so the host only needs `podman`.
#[context("Preparing automated ISO")]
fn prepare_automated_iso(
    sh: &Shell,
    input_iso: &Utf8Path,
    output_iso: &Utf8Path,
    kickstart_path: &Utf8Path,
) -> Result<()> {
    if output_iso.exists() {
        std::fs::remove_file(output_iso).context("Removing existing output ISO")?;
    }

    let abs_iso =
        std::fs::canonicalize(input_iso).with_context(|| format!("Resolving {input_iso}"))?;
    let abs_ks = std::fs::canonicalize(kickstart_path)
        .with_context(|| format!("Resolving {kickstart_path}"))?;
    let abs_outdir = std::fs::canonicalize(
        output_iso
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Invalid output ISO path"))?,
    )
    .context("Resolving output directory")?;
    let out_filename = output_iso
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Invalid output ISO filename"))?;

    let abs_iso = abs_iso.to_string_lossy().into_owned();
    let abs_ks = abs_ks.to_string_lossy().into_owned();
    let abs_outdir = abs_outdir.to_string_lossy().into_owned();

    let bash_cmd = format!(
        "dnf install -y lorax xorriso && mkksiso --ks /work/ks.cfg --skip-mkefiboot \
         -c 'console=ttyS0 inst.sshd inst.nomediacheck' /work/input.iso /work/out/{out_filename}"
    );
    cmd!(
        sh,
        "podman run --rm --network=host
            -v {abs_iso}:/work/input.iso:ro
            -v {abs_ks}:/work/ks.cfg:ro
            -v {abs_outdir}:/work/out:Z
            {MKKSISO_CONTAINER}
            bash -c {bash_cmd}"
    )
    .run()
    .context("Running mkksiso in container")?;

    println!("Created automated ISO: {output_iso}");
    Ok(())
}

/// Run the Anaconda installation test.
#[context("Running Anaconda test")]
pub(crate) fn run_anaconda_test(args: &AnacondaTestArgs) -> Result<()> {
    let sh = Shell::new()?;

    cmd!(sh, "which podman")
        .ignore_stdout()
        .run()
        .context("podman is required")?;

    let workdir = Utf8Path::new("target/anaconda-test");
    sh.create_dir(workdir).context("Creating workdir")?;

    let disk_path = args
        .disk
        .clone()
        .unwrap_or_else(|| workdir.join("disk.img"));
    let tarball_path = workdir.join("rootfs.tar");
    let kickstart_path = workdir.join("kickstart.ks");
    let auto_iso_path = workdir.join("anaconda-auto.iso");
    let anaconda_log = workdir.join("anaconda-install.log");
    let program_log = workdir.join("anaconda-program.log");
    let serial_log = workdir.join("serial.log");

    // Verify the base image exists
    let image = &args.image;
    cmd!(sh, "podman image exists {image}")
        .run()
        .with_context(|| format!("Image '{image}' not found in local container storage"))?;
    println!("Verified image exists: {image}");

    build_derived_image(&sh, image)?;
    export_container_to_tarball(&sh, ANACONDA_TEST_IMAGE, &tarball_path)?;

    // Generate kickstart
    let kickstart_content = if let Some(ref ks) = args.kickstart {
        std::fs::read_to_string(ks).with_context(|| format!("Reading kickstart: {ks}"))?
    } else {
        generate_kickstart_liveimg(&args.root_password)
    };
    std::fs::write(&kickstart_path, &kickstart_content).context("Writing kickstart")?;
    println!("Kickstart written to: {kickstart_path}");

    // Prepare the ISO
    let boot_iso = if args.no_iso_modify {
        args.iso.clone()
    } else {
        prepare_automated_iso(&sh, &args.iso, &auto_iso_path, &kickstart_path)?;
        auto_iso_path.clone()
    };

    if args.dry_run {
        println!("\nDry-run complete. Generated files:");
        println!("  Tarball: {tarball_path}");
        println!("  Kickstart: {kickstart_path}");
        if !args.no_iso_modify {
            println!("  Automated ISO: {boot_iso}");
        }
        println!("\nTo run the full test, remove --dry-run");
        return Ok(());
    }

    // Non-dry-run: check for qemu-img
    cmd!(sh, "which qemu-img")
        .ignore_stdout()
        .run()
        .context("qemu-img is required")?;

    // Create disk image
    let disk_size = format!("{}G", args.disk_size);
    cmd!(sh, "qemu-img create -f qcow2 {disk_path} {disk_size}")
        .run()
        .context("Creating disk image")?;
    println!("Created disk: {disk_path} ({disk_size})");

    // Resolve workdir to an absolute path; all log/socket paths are derived from it.
    let abs_workdir =
        Utf8PathBuf::try_from(std::fs::canonicalize(workdir).context("Canonicalizing workdir")?)
            .context("Workdir path is not valid UTF-8")?;

    let abs_disk_path = if let Some(ref custom) = args.disk {
        std::fs::canonicalize(custom)
            .context("Getting absolute disk path")?
            .to_string_lossy()
            .into_owned()
    } else {
        abs_workdir.join("disk.img").into_string()
    };

    // Build the SMBIOS credentials for the program-log streaming unit.
    // This injects a systemd unit into the installer that streams
    // /tmp/program.log to the host via virtio-serial.
    let program_log_unit = r#"[Unit]
Description=Stream Anaconda program.log to host via virtio
DefaultDependencies=no
After=dev-virtio\x2dports-org.fedoraproject.anaconda.program.0.device
ConditionKernelCommandLine=inst.stage2

[Service]
Type=simple
ExecStartPre=/bin/sh -c "for i in {1..300}; do [ -e /tmp/program.log ] && [ -e /dev/virtio-ports/org.fedoraproject.anaconda.program.0 ] && break; sleep 0.1; done"
ExecStart=/bin/sh -c "exec tail -f -n +0 /tmp/program.log > /dev/virtio-ports/org.fedoraproject.anaconda.program.0 2>/dev/null || true"
Restart=always
RestartSec=2"#;

    let program_log_dropin = r#"[Unit]
Wants=anaconda-program-log.service
After=anaconda-program-log.service"#;

    let unit_b64 = data_encoding::BASE64.encode(program_log_unit.as_bytes());
    let dropin_b64 = data_encoding::BASE64.encode(program_log_dropin.as_bytes());

    let smbios_unit = format!(
        "io.systemd.credential.binary:systemd.extra-unit.anaconda-program-log.service={unit_b64}",
    );
    let smbios_dropin = format!(
        "io.systemd.credential.binary:systemd.unit-dropin.sysinit.target~anaconda-program-log={dropin_b64}",
    );

    println!("\nStarting QEMU with Anaconda installation...");
    println!("  Disk: {disk_path}");
    println!("  ISO: {boot_iso}");
    println!("  Anaconda log: {anaconda_log}");
    println!("  Program log: {program_log}");
    println!();
    println!("  SSH access: ssh -p {} root@localhost", args.ssh_port);
    println!("  Password: {}", args.root_password);
    println!();
    println!("  Monitor progress:");
    println!("    tail -f {anaconda_log}");
    println!("    tail -f {program_log}");
    println!();

    let socket_path = abs_workdir.join("virtiofs.sock");
    // Remove stale socket from a previous run
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)
            .with_context(|| format!("Removing stale socket {socket_path}"))?;
    }

    let virtiofs_config = bcvk_qemu::VirtiofsConfig {
        socket_path: socket_path.clone(),
        shared_dir: abs_workdir.clone(),
        debug: false,
        readonly: true,
        log_file: None,
    };

    // Build QemuConfig using bcvk-qemu
    let abs_iso = std::fs::canonicalize(&boot_iso)
        .context("Resolving ISO path")?
        .to_string_lossy()
        .into_owned();

    let mut config = bcvk_qemu::QemuConfig::new_iso_boot(args.memory, args.vcpus, abs_iso);
    config.serial_log = Some(abs_workdir.join("serial.log").into_string());
    config.no_reboot = args.keep_running;

    // Add disk
    config.add_virtio_blk_device(
        abs_disk_path,
        "bootdisk".to_string(),
        bcvk_qemu::DiskFormat::Qcow2,
    );

    // SSH port forwarding
    config.enable_ssh_access(Some(args.ssh_port));

    // Virtio-serial for Anaconda log channels
    config.add_virtio_serial_out(
        "org.fedoraproject.anaconda.log.0",
        abs_workdir.join("anaconda-install.log").into_string(),
        false,
    );
    config.add_virtio_serial_out(
        "org.fedoraproject.anaconda.program.0",
        abs_workdir.join("anaconda-program.log").into_string(),
        false,
    );

    // SMBIOS credentials for the program-log streaming unit
    config.add_smbios_credential(smbios_unit);
    config.add_smbios_credential(smbios_dropin);

    // Virtiofs for sharing the tarball into the guest
    config.add_virtiofs(virtiofs_config, "tarball");

    // Spawn QEMU + virtiofsd via bcvk-qemu
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("Creating tokio runtime")?;

    let mut running = rt.block_on(async {
        bcvk_qemu::RunningQemu::spawn(config)
            .await
            .map_err(|e| anyhow::anyhow!("{e:#}"))
    })?;

    println!("QEMU started (PID: {})", running.qemu_process.id());

    // Give QEMU a moment to start and check for immediate failures.
    // Note: bcvk-qemu inherits stderr so QEMU errors appear on the terminal directly.
    std::thread::sleep(Duration::from_millis(500));
    if let Ok(Some(status)) = running.qemu_process.try_wait() {
        anyhow::bail!("QEMU failed to start (exit {status}); check stderr output above");
    }

    // Monitor logs for progress and errors
    let result = monitor_installation(
        &anaconda_log,
        &program_log,
        &serial_log,
        &mut running.qemu_process,
    );

    // Clean up QEMU if still running
    if let Ok(None) = running.qemu_process.try_wait() {
        println!("Terminating QEMU...");
        let _ = running.qemu_process.kill();
        let _ = running.qemu_process.wait();
    }

    match result {
        Ok(()) => {
            println!("\nAnaconda installation completed successfully!");
            println!("Disk image: {disk_path}");
            Ok(())
        }
        Err(e) => {
            eprintln!("\n=== Installation failed ===");
            eprintln!("Error: {e}");
            eprintln!("\n--- Last 20 lines of anaconda log ---");
            print_last_lines(&anaconda_log, 20);
            eprintln!("\n--- Last 20 lines of program log ---");
            print_last_lines(&program_log, 20);
            eprintln!("\n--- Last 20 lines of serial log ---");
            print_last_lines(&serial_log, 20);
            Err(e)
        }
    }
}

/// Print the last N lines of a file.
fn print_last_lines(path: &Utf8Path, n: usize) {
    if let Ok(content) = std::fs::read_to_string(path) {
        let lines: Vec<&str> = content.lines().collect();
        let start = lines.len().saturating_sub(n);
        for line in &lines[start..] {
            eprintln!("{line}");
        }
    } else {
        eprintln!("(file not found or unreadable)");
    }
}

/// Installation stage for progress tracking.
#[derive(Debug, Clone, Copy, PartialEq)]
enum InstallStage {
    Booting,
    AnacondaStarting,
    Installing,
    Rebooting,
}

impl std::fmt::Display for InstallStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Booting => write!(f, "Booting"),
            Self::AnacondaStarting => write!(f, "Starting Anaconda"),
            Self::Installing => write!(f, "Installing (liveimg)"),
            Self::Rebooting => write!(f, "Rebooting"),
        }
    }
}

/// Monitor installation logs for progress and errors.
fn monitor_installation(
    anaconda_log: &Utf8Path,
    program_log: &Utf8Path,
    serial_log: &Utf8Path,
    qemu: &mut Child,
) -> Result<()> {
    let start_time = Instant::now();
    let mut stage = InstallStage::Booting;
    let mut stage_start = Instant::now();
    let mut last_activity = Instant::now();

    let mut anaconda_pos: u64 = 0;
    let mut program_pos: u64 = 0;
    let mut serial_pos: u64 = 0;

    println!("Monitoring installation progress...");
    println!("  Stage: {stage}");

    loop {
        // Check if QEMU exited
        if let Some(status) = qemu.try_wait().context("Checking QEMU status")? {
            if stage == InstallStage::Rebooting || status.success() {
                return Ok(());
            }
            anyhow::bail!("QEMU exited unexpectedly with status: {status} at stage: {stage}");
        }

        let anaconda_new = read_new_content(anaconda_log, &mut anaconda_pos);
        let program_new = read_new_content(program_log, &mut program_pos);
        let serial_new = read_new_content(serial_log, &mut serial_pos);

        // Check for errors
        for (log_name, content) in [
            ("anaconda", &anaconda_new),
            ("program", &program_new),
            ("serial", &serial_new),
        ] {
            for pattern in ERROR_PATTERNS {
                if content.contains(pattern) {
                    anyhow::bail!(
                        "Error detected in {log_name} log: found '{pattern}'\nContext: {}",
                        extract_context(content, pattern)
                    );
                }
            }
        }

        // Update stage
        let old_stage = stage;
        if stage == InstallStage::Booting
            && (anaconda_new.contains(PATTERN_ANACONDA_STARTED) || serial_new.contains("anaconda"))
        {
            stage = InstallStage::AnacondaStarting;
            stage_start = Instant::now();
        }
        if stage == InstallStage::AnacondaStarting
            && (program_new.contains(PATTERN_LIVEIMG_DOWNLOAD)
                || anaconda_new.to_lowercase().contains("liveimg")
                || anaconda_new.contains("/mnt/tarball"))
        {
            stage = InstallStage::Installing;
            stage_start = Instant::now();
        }
        if stage == InstallStage::Installing
            && (serial_new.contains(PATTERN_INSTALL_COMPLETE)
                || serial_new.contains("reboot: Restarting"))
        {
            stage = InstallStage::Rebooting;
            stage_start = Instant::now();
        }
        if stage == InstallStage::Rebooting {
            println!("  Installation completed, reboot initiated.");
            return Ok(());
        }

        if stage != old_stage {
            let elapsed = start_time.elapsed();
            println!("  Stage: {stage} ({}s elapsed)", elapsed.as_secs());
            last_activity = Instant::now();
        }

        if !anaconda_new.is_empty() || !program_new.is_empty() || !serial_new.is_empty() {
            last_activity = Instant::now();
        }

        let stage_elapsed = stage_start.elapsed();
        let timeout = match stage {
            InstallStage::Booting | InstallStage::AnacondaStarting => STAGE_TIMEOUT_ANACONDA_START,
            InstallStage::Installing => STAGE_TIMEOUT_INSTALL,
            InstallStage::Rebooting => STAGE_TIMEOUT_REBOOT,
        };

        if stage_elapsed > timeout {
            anyhow::bail!(
                "Timeout waiting for stage '{stage}' to complete ({}s elapsed, {}s timeout)",
                stage_elapsed.as_secs(),
                timeout.as_secs()
            );
        }

        if last_activity.elapsed() > Duration::from_secs(120) {
            anyhow::bail!(
                "No activity for 120 seconds at stage '{stage}'. Installation may be stuck."
            );
        }

        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Read new content from a file since last position.
fn read_new_content(path: &Utf8Path, pos: &mut u64) -> String {
    let Ok(mut file) = File::open(path) else {
        return String::new();
    };

    let Ok(metadata) = file.metadata() else {
        return String::new();
    };

    let file_len = metadata.len();
    if file_len <= *pos {
        return String::new();
    }

    if file.seek(SeekFrom::Start(*pos)).is_err() {
        return String::new();
    }

    let mut content = String::new();
    let reader = BufReader::new(&mut file);
    for line in reader.lines().map_while(Result::ok) {
        content.push_str(&line);
        content.push('\n');
    }

    *pos = file_len;
    content
}

/// Extract context around a pattern match for error reporting.
fn extract_context(content: &str, pattern: &str) -> String {
    let Some(idx) = content.find(pattern) else {
        return String::new();
    };
    let mut start = idx.saturating_sub(100);
    while start > 0 && !content.is_char_boundary(start) {
        start -= 1;
    }
    let mut end = (idx + pattern.as_bytes().len() + 200).min(content.as_bytes().len());
    while end < content.as_bytes().len() && !content.is_char_boundary(end) {
        end += 1;
    }
    format!("...{}...", &content[start..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_context_basic() {
        let content = "aaa ERROR bbb";
        let ctx = extract_context(content, "ERROR");
        assert!(ctx.contains("ERROR"));
        assert!(ctx.starts_with("..."));
        assert!(ctx.ends_with("..."));
    }

    #[test]
    fn test_extract_context_not_found() {
        assert_eq!(extract_context("hello world", "MISSING"), "");
    }

    #[test]
    fn test_extract_context_multibyte() {
        let prefix = "é".repeat(60);
        let suffix = "日本語".repeat(80);
        let content = format!("{prefix}PATTERN{suffix}");
        let ctx = extract_context(&content, "PATTERN");
        assert!(ctx.contains("PATTERN"));
    }

    #[test]
    fn test_extract_context_at_boundaries() {
        let ctx = extract_context("PATTERN and more", "PATTERN");
        assert!(ctx.contains("PATTERN"));

        let ctx = extract_context("some text PATTERN", "PATTERN");
        assert!(ctx.contains("PATTERN"));
    }
}
