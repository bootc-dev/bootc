//! Anaconda installer testing support.
//!
//! This module provides automated testing of bootc installation via Anaconda.
//! It launches QEMU with an Anaconda ISO and a kickstart that uses `liveimg`
//! to install from a tarball created by `bootc container export --format=tar`.
//!
//! The normal entry point is `just test-container-export`, which first runs
//! `just build` to produce `localhost/bootc` (incorporating any local code
//! changes), then invokes this test against that image.
//!
//! ## Container image requirements
//!
//! The input container image must be a bootc/rpm-ostree image (i.e. it has
//! `ostree.bootable` / `containers.bootc` labels).  Before export, the test
//! automatically builds a thin derived image that disables the ostree
//! kernel-install layout:
//!
//! - `/usr/lib/kernel/install.conf` — the `layout=ostree` line is removed
//!   via sed (preserving any other settings in the file)
//! - `/usr/lib/kernel/install.conf.d/*-bootc-*.conf` — bootc drop-ins removed
//! - `/usr/lib/kernel/install.d/*-rpmostree.install` — rpm-ostree plugin removed
//!
//! Without this step, `kernel-install add` delegates to rpm-ostree (which
//! doesn't work outside an ostree deployment) and the standard BLS, dracut,
//! and grub plugins are skipped.
//!
//! If you are adapting this for production use, either derive your own image
//! the same way or ensure that the ostree kernel-install configuration is
//! absent from the image before calling `bootc container export`.

use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose};
use camino::{Utf8Path, Utf8PathBuf};
use fn_error_context::context;
use xshell::{Shell, cmd};

/// Stage timeouts for installation monitoring
const STAGE_TIMEOUT_ANACONDA_START: Duration = Duration::from_secs(180); // 3 min to start anaconda
const STAGE_TIMEOUT_INSTALL: Duration = Duration::from_secs(900); // 15 min for liveimg install
const STAGE_TIMEOUT_REBOOT: Duration = Duration::from_secs(60); // 1 min for reboot

/// Patterns that indicate installation progress
const PATTERN_ANACONDA_STARTED: &str = "anaconda";
const PATTERN_LIVEIMG_DOWNLOAD: &str = "liveimg";
const PATTERN_INSTALL_COMPLETE: &str = "reboot: Restarting system";

/// Patterns that indicate errors
const ERROR_PATTERNS: &[&str] = &[
    "Traceback (most recent call last)",
    "FATAL:",
    "Installation failed",
    "error: Installation was stopped",
    "kernel panic",
    "Kernel panic",
];

/// Arguments for the anaconda test command
#[derive(Debug, clap::Args)]
pub(crate) struct AnacondaTestArgs {
    /// Path to the Anaconda boot ISO (e.g., Fedora-Everything-netinst-*.iso)
    #[arg(long)]
    pub(crate) iso: Utf8PathBuf,

    /// Container image to install (e.g., "localhost/bootc")
    /// Must be available in local container storage.
    pub(crate) image: String,

    /// Output disk image path (defaults to target/anaconda-test.img)
    #[arg(long)]
    pub(crate) disk: Option<Utf8PathBuf>,

    /// Disk size in GB (default: 20)
    #[arg(long, default_value = "20")]
    pub(crate) disk_size: u32,

    /// VM memory in MB (default: 10240)
    #[arg(long, default_value = "10240")]
    pub(crate) memory: u32,

    /// Number of vCPUs (default: 4)
    #[arg(long, default_value = "4")]
    pub(crate) vcpus: u32,

    /// SSH port forwarding (default: 10022)
    #[arg(long, default_value = "10022")]
    pub(crate) ssh_port: u16,

    /// Keep VM running after installation (for debugging)
    #[arg(long)]
    pub(crate) keep_running: bool,

    /// Path to custom kickstart file (optional; will use built-in template if not provided)
    #[arg(long)]
    pub(crate) kickstart: Option<Utf8PathBuf>,

    /// Root password for the installed system (default: testcase)
    #[arg(long, default_value = "testcase")]
    pub(crate) root_password: String,

    /// Skip creating automated ISO (use provided ISO directly with inst.ks kernel arg)
    #[arg(long)]
    pub(crate) no_iso_modify: bool,

    /// Prepare ISO and kickstart only, don't run QEMU (for testing)
    #[arg(long)]
    pub(crate) dry_run: bool,
}

/// The derived image tag used for the anaconda test.
const ANACONDA_TEST_IMAGE: &str = "localhost/bootc-anaconda-test";

/// Build a derived container image with ostree kernel-install layout disabled.
///
/// See the module-level documentation for why this is necessary.
#[context("Building derived image for anaconda test")]
fn build_derived_image(sh: &Shell, base_image: &str) -> Result<()> {
    // Use sed to remove layout=ostree from install.conf (preserving other settings),
    // then remove the bootc drop-in and rpm-ostree plugin entirely.
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

/// Export a container image to a tarball using the bootc binary inside the image.
#[context("Exporting container to tarball")]
fn export_container_to_tarball(sh: &Shell, image: &str, output_path: &Utf8Path) -> Result<()> {
    println!("Exporting container image to tarball...");
    println!("  Image: {}", image);
    println!("  Output: {}", output_path);

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

    let output_in_container = format!("/output/{}", output_filename);
    cmd!(
        sh,
        "podman run --rm --privileged --network=none
            -v {abs_output_dir}:/output:Z
            {image}
            bootc container export --format=tar --kernel-in-boot -o {output_in_container} /"
    )
    .run()
    .context("Running bootc container export")?;

    // Verify the tarball was created
    if !output_path.exists() {
        anyhow::bail!("Tarball was not created at {}", output_path);
    }

    let metadata = std::fs::metadata(output_path).context("Getting tarball metadata")?;
    println!(
        "  Created tarball: {} ({})",
        output_path,
        indicatif::HumanBytes(metadata.len())
    );

    Ok(())
}

/// Managed virtiofsd process for sharing the tarball directory via virtiofs.
struct VirtiofsProcess {
    child: Child,
}

impl Drop for VirtiofsProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        println!("virtiofsd stopped");
    }
}

/// Generate the kickstart content for bootc installation using liveimg.
/// The tarball is shared into the guest via virtiofs and mounted
/// at `/mnt/tarball/` in a `%pre` script so Anaconda can access it as a
/// local file.
fn generate_kickstart_liveimg(root_password: &str) -> String {
    format!(
        r#"# Automated bootc installation kickstart (liveimg)
# Generated by bootc xtask anaconda
# Uses bootc container export --format=tar with Anaconda liveimg

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
# The derived container image has the ostree kernel-install layout files
# removed, so the standard kernel-install plugins (dracut, loaderentry,
# grub) work normally here.
%post --log=/root/ks-post.log
set -eux

KVER=$(ls /usr/lib/modules | head -1)
echo "Kernel version: $KVER"

# Ensure machine-id exists (needed by kernel-install for BLS filenames)
if [ ! -s /etc/machine-id ]; then
    systemd-machine-id-setup
fi

# kernel-install creates the BLS entry, copies vmlinuz, and generates
# initramfs via the standard plugin chain (50-dracut, 90-loaderentry, etc.)
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

/// The container image used to run `mkksiso` when it is not installed locally.
const MKKSISO_CONTAINER: &str = "quay.io/centos/centos:stream10";

/// Create an automated ISO by injecting a kickstart file and extra kernel args
/// using `mkksiso` (from the `lorax` package).
///
/// `mkksiso` is always run inside a CentOS container so the host only needs
/// `podman` — no lorax/xorriso installation required.
#[context("Preparing automated ISO")]
fn prepare_automated_iso(
    sh: &Shell,
    input_iso: &Utf8Path,
    output_iso: &Utf8Path,
    kickstart_path: &Utf8Path,
) -> Result<()> {
    // Remove existing output ISO if it exists
    if output_iso.exists() {
        std::fs::remove_file(output_iso).context("Removing existing output ISO")?;
    }

    // Resolve to absolute paths for container bind-mounts
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

    // Run mkksiso inside a CentOS container with the ISO, kickstart, and
    // output directory bind-mounted.
    //   --skip-mkefiboot  avoids the mkefiboot step which requires root and
    //                     loopback devices (unavailable in containers). Fine
    //                     because the test VM boots via BIOS, not EFI.
    //   -c                appends extra kernel command-line arguments.
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

    println!("Created automated ISO: {}", output_iso);
    Ok(())
}

/// Find the QEMU binary (qemu-system-x86_64 or qemu-kvm)
fn find_qemu_binary(sh: &Shell) -> Result<String> {
    for binary in ["qemu-system-x86_64", "qemu-kvm"] {
        if cmd!(sh, "which {binary}")
            .ignore_stdout()
            .ignore_stderr()
            .run()
            .is_ok()
        {
            return Ok(binary.to_string());
        }
    }
    anyhow::bail!("Neither qemu-system-x86_64 nor qemu-kvm found in PATH")
}

/// Run the Anaconda installation test
#[context("Running Anaconda test")]
pub(crate) fn run_anaconda_test(sh: &Shell, args: &AnacondaTestArgs) -> Result<()> {
    // Check for required tools (skip QEMU tools in dry-run mode)
    let qemu_binary = if args.dry_run {
        None
    } else {
        Some(find_qemu_binary(sh)?)
    };

    let virtiofsd = "/usr/libexec/virtiofsd";
    if !args.dry_run && !Utf8Path::new(virtiofsd).exists() {
        anyhow::bail!(
            "virtiofsd not found at {}. Install the virtiofsd package.",
            virtiofsd
        );
    }

    for tool in ["qemu-img", "podman"] {
        if args.dry_run && tool == "qemu-img" {
            continue;
        }
        cmd!(sh, "which {tool}")
            .ignore_stdout()
            .run()
            .with_context(|| format!("{} is required", tool))?;
    }

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

    // Verify the base image exists in container storage
    let image = &args.image;
    cmd!(sh, "podman image exists {image}")
        .run()
        .with_context(|| format!("Image '{}' not found in local container storage", image))?;
    println!("Verified image exists: {}", image);

    // Build a derived image with ostree kernel-install plugins removed so
    // that the standard kernel-install works in the kickstart %post.
    build_derived_image(sh, image)?;

    // Export the derived container to tarball
    export_container_to_tarball(sh, ANACONDA_TEST_IMAGE, &tarball_path)?;

    // Generate kickstart (tarball is shared into the guest via virtiofs)
    let kickstart_content = if let Some(ref ks) = args.kickstart {
        std::fs::read_to_string(ks).with_context(|| format!("Reading kickstart: {}", ks))?
    } else {
        generate_kickstart_liveimg(&args.root_password)
    };
    std::fs::write(&kickstart_path, &kickstart_content).context("Writing kickstart")?;
    println!("Kickstart written to: {}", kickstart_path);

    // Prepare the ISO (must be done after kickstart is generated)
    let boot_iso = if args.no_iso_modify {
        args.iso.clone()
    } else {
        prepare_automated_iso(sh, &args.iso, &auto_iso_path, &kickstart_path)?;
        auto_iso_path.clone()
    };

    // In dry-run mode, stop here after preparing kickstart and ISO
    if args.dry_run {
        println!("\nDry-run complete. Generated files:");
        println!("  Tarball: {}", tarball_path);
        println!("  Kickstart: {}", kickstart_path);
        if !args.no_iso_modify {
            println!("  Automated ISO: {}", boot_iso);
        }
        println!("\nTo run the full test, remove --dry-run");
        return Ok(());
    }

    // Create disk image
    let disk_size = format!("{}G", args.disk_size);
    cmd!(sh, "qemu-img create -f qcow2 {disk_path} {disk_size}")
        .run()
        .context("Creating disk image")?;
    println!("Created disk: {} ({})", disk_path, disk_size);

    // Resolve the tarball directory to an absolute path for the virtiofs share
    let tarball_dir = std::fs::canonicalize(
        tarball_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Invalid tarball path"))?,
    )
    .context("Getting absolute tarball directory path")?;
    let tarball_dir =
        Utf8PathBuf::try_from(tarball_dir).context("Tarball directory path is not valid UTF-8")?;

    // Start virtiofsd to share the tarball directory via virtiofs
    let socket_path = workdir.join("virtiofs.sock");
    // Remove stale socket from a previous run
    if socket_path.exists() {
        std::fs::remove_file(&socket_path).ok();
    }

    let virtiofsd_child = Command::new(virtiofsd)
        .args([
            &format!("--socket-path={}", socket_path),
            &format!("--shared-dir={}", tarball_dir),
            "--sandbox=none",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("Spawning virtiofsd")?;

    let _virtiofsd = VirtiofsProcess {
        child: virtiofsd_child,
    };

    // Wait for virtiofsd socket to appear
    let socket_path_std = std::path::Path::new(socket_path.as_str());
    for _ in 0..50 {
        if socket_path_std.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if !socket_path_std.exists() {
        anyhow::bail!("virtiofsd socket did not appear at {}", socket_path);
    }
    println!("virtiofsd started (socket: {})", socket_path);

    // Create systemd unit for streaming /tmp/program.log
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

    let program_log_unit_b64 = base64_encode(program_log_unit.as_bytes());

    let program_log_dropin = r#"[Unit]
Wants=anaconda-program-log.service
After=anaconda-program-log.service"#;
    let program_log_dropin_b64 = base64_encode(program_log_dropin.as_bytes());

    // Build QEMU command
    let memory = format!("{}M", args.memory);
    let ssh_port = args.ssh_port;
    let ssh_forward = format!("hostfwd=tcp::{}-:22", ssh_port);

    println!("\nStarting QEMU with Anaconda installation...");
    println!("  Disk: {}", disk_path);
    println!("  ISO: {}", boot_iso);
    println!("  Anaconda log: {}", anaconda_log);
    println!("  Program log: {}", program_log);
    println!();
    println!("  SSH access: ssh -p {} root@localhost", ssh_port);
    println!("  Password: {}", args.root_password);
    println!();
    println!("  Monitor progress:");
    println!("    tail -f {}", anaconda_log);
    println!("    tail -f {}", program_log);
    println!();
    println!("  Once SSH'd in:");
    println!("    journalctl -f                  # Watch system logs");
    println!("    tail -f /tmp/program.log       # Watch installation progress");
    println!("    journalctl -u bootc-install    # Debug bootc service");
    println!();

    // Construct SMBIOS args for systemd credential injection
    let smbios_unit = format!(
        "io.systemd.credential.binary:systemd.extra-unit.anaconda-program-log.service={}",
        program_log_unit_b64
    );
    let smbios_dropin = format!(
        "io.systemd.credential.binary:systemd.unit-dropin.sysinit.target~anaconda-program-log={}",
        program_log_dropin_b64
    );

    // Run QEMU - serial to file for background monitoring
    let serial_log = workdir.join("serial.log");
    let vcpus = args.vcpus.to_string();
    let mut qemu_args = vec![
        "-machine".to_string(),
        "q35".to_string(),
        "-accel".to_string(),
        "kvm".to_string(),
        "-m".to_string(),
        memory.clone(),
        "-cpu".to_string(),
        "host".to_string(),
        "-smp".to_string(),
        vcpus,
        "-display".to_string(),
        "none".to_string(),
        "-serial".to_string(),
        format!("file:{}", serial_log),
        "-nic".to_string(),
        format!("user,{}", ssh_forward),
        "-drive".to_string(),
        format!("format=qcow2,file={}", disk_path),
        "-cdrom".to_string(),
        boot_iso.to_string(),
        // Virtio serial for logs
        "-device".to_string(),
        "virtio-serial".to_string(),
        "-chardev".to_string(),
        format!("file,id=anaconda_log,path={}", anaconda_log),
        "-device".to_string(),
        "virtserialport,chardev=anaconda_log,name=org.fedoraproject.anaconda.log.0".to_string(),
        "-chardev".to_string(),
        format!("file,id=program_log,path={}", program_log),
        "-device".to_string(),
        "virtserialport,chardev=program_log,name=org.fedoraproject.anaconda.program.0".to_string(),
        // SMBIOS for systemd credential injection
        "-smbios".to_string(),
        format!("type=11,value={}", smbios_unit),
        "-smbios".to_string(),
        format!("type=11,value={}", smbios_dropin),
        // virtiofs requires a shared memory backend
        "-object".to_string(),
        format!("memory-backend-memfd,id=mem,size={},share=on", memory),
        "-numa".to_string(),
        "node,memdev=mem".to_string(),
        // virtiofs device for sharing the tarball directory
        "-chardev".to_string(),
        format!("socket,id=vfschar0,path={}", socket_path),
        "-device".to_string(),
        "vhost-user-fs-pci,chardev=vfschar0,tag=tarball".to_string(),
    ];

    // If keep_running is set, prevent automatic reboot after installation
    if args.keep_running {
        qemu_args.push("-no-reboot".to_string());
        println!("Note: VM will halt instead of rebooting (--keep-running)");
    }

    // Use the detected QEMU binary (qemu-system-x86_64 or qemu-kvm)
    let qemu_binary = qemu_binary
        .as_ref()
        .expect("QEMU binary should be set in non-dry-run mode");

    // Spawn QEMU in background
    let mut qemu_child = Command::new(qemu_binary)
        .args(&qemu_args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("Spawning QEMU")?;

    println!("QEMU started (PID: {})", qemu_child.id());

    // Give QEMU a moment to start and check for immediate failures
    std::thread::sleep(Duration::from_millis(500));
    if let Ok(Some(status)) = qemu_child.try_wait() {
        // QEMU exited immediately - read stderr for error message
        let mut stderr_output = String::new();
        if let Some(mut stderr) = qemu_child.stderr.take() {
            use std::io::Read;
            let _ = stderr.read_to_string(&mut stderr_output);
        }
        anyhow::bail!(
            "QEMU failed to start (exit {}): {}",
            status,
            stderr_output.trim()
        );
    }

    // Monitor logs for progress and errors
    let result = monitor_installation(&anaconda_log, &program_log, &serial_log, &mut qemu_child);

    // Clean up QEMU if still running
    if let Ok(None) = qemu_child.try_wait() {
        println!("Terminating QEMU...");
        let _ = qemu_child.kill();
        let _ = qemu_child.wait();
    }

    match result {
        Ok(()) => {
            println!("\nAnaconda installation completed successfully!");
            println!("Disk image: {}", disk_path);
            Ok(())
        }
        Err(e) => {
            // Print last lines of logs for debugging
            eprintln!("\n=== Installation failed ===");
            eprintln!("Error: {}", e);
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

/// Print the last N lines of a file
fn print_last_lines(path: &Utf8Path, n: usize) {
    if let Ok(content) = std::fs::read_to_string(path) {
        let lines: Vec<&str> = content.lines().collect();
        let start = lines.len().saturating_sub(n);
        for line in &lines[start..] {
            eprintln!("{}", line);
        }
    } else {
        eprintln!("(file not found or unreadable)");
    }
}

/// Installation stage for progress tracking
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
            InstallStage::Booting => write!(f, "Booting"),
            InstallStage::AnacondaStarting => write!(f, "Starting Anaconda"),
            InstallStage::Installing => write!(f, "Installing (liveimg)"),
            InstallStage::Rebooting => write!(f, "Rebooting"),
        }
    }
}

/// Monitor the installation logs for progress and errors
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

    // Track file positions for incremental reading
    let mut anaconda_pos: u64 = 0;
    let mut program_pos: u64 = 0;
    let mut serial_pos: u64 = 0;

    println!("Monitoring installation progress...");
    println!("  Stage: {}", stage);

    loop {
        // Check if QEMU exited
        if let Some(status) = qemu.try_wait().context("Checking QEMU status")? {
            if stage == InstallStage::Rebooting {
                // Expected exit after reboot
                return Ok(());
            }
            if status.success() {
                // QEMU exited cleanly - might be a reboot
                return Ok(());
            }
            anyhow::bail!(
                "QEMU exited unexpectedly with status: {} at stage: {}",
                status,
                stage
            );
        }

        // Read new log content
        let anaconda_new = read_new_content(anaconda_log, &mut anaconda_pos);
        let program_new = read_new_content(program_log, &mut program_pos);
        let serial_new = read_new_content(serial_log, &mut serial_pos);

        // Check for errors in all logs
        for (log_name, content) in [
            ("anaconda", &anaconda_new),
            ("program", &program_new),
            ("serial", &serial_new),
        ] {
            for pattern in ERROR_PATTERNS {
                if content.contains(pattern) {
                    anyhow::bail!(
                        "Error detected in {} log: found '{}'\nContext: {}",
                        log_name,
                        pattern,
                        extract_context(content, pattern)
                    );
                }
            }
        }

        // Update stage based on log content
        let old_stage = stage;
        if stage == InstallStage::Booting
            && (anaconda_new.contains(PATTERN_ANACONDA_STARTED) || serial_new.contains("anaconda"))
        {
            stage = InstallStage::AnacondaStarting;
            stage_start = Instant::now();
        }
        if stage == InstallStage::AnacondaStarting {
            // For liveimg, look for the download starting
            if program_new.contains(PATTERN_LIVEIMG_DOWNLOAD)
                || anaconda_new.to_lowercase().contains("liveimg")
                || anaconda_new.contains("/mnt/tarball")
            {
                stage = InstallStage::Installing;
                stage_start = Instant::now();
            }
        }
        if stage == InstallStage::Installing
            && (serial_new.contains(PATTERN_INSTALL_COMPLETE)
                || serial_new.contains("reboot: Restarting"))
        {
            stage = InstallStage::Rebooting;
            stage_start = Instant::now();
        }
        if stage == InstallStage::Rebooting {
            // Installation completed, reboot initiated.
            // For liveimg installs, the bootloader may not be properly configured,
            // so we consider reaching this point a success and terminate.
            println!("  Installation completed, reboot initiated.");
            return Ok(());
        }

        // Print stage transitions
        if stage != old_stage {
            let elapsed = start_time.elapsed();
            println!("  Stage: {} ({}s elapsed)", stage, elapsed.as_secs());
            last_activity = Instant::now();
        }

        // Check for activity (any new content)
        if !anaconda_new.is_empty() || !program_new.is_empty() || !serial_new.is_empty() {
            last_activity = Instant::now();
        }

        // Check stage timeouts
        let stage_elapsed = stage_start.elapsed();
        let timeout = match stage {
            InstallStage::Booting => STAGE_TIMEOUT_ANACONDA_START,
            InstallStage::AnacondaStarting => STAGE_TIMEOUT_ANACONDA_START,
            InstallStage::Installing => STAGE_TIMEOUT_INSTALL,
            // Rebooting should return quickly, but we won't actually hit this
            // because we return Ok(()) when entering Rebooting stage
            InstallStage::Rebooting => STAGE_TIMEOUT_REBOOT,
        };

        if stage_elapsed > timeout {
            anyhow::bail!(
                "Timeout waiting for stage '{}' to complete ({}s elapsed, {}s timeout)",
                stage,
                stage_elapsed.as_secs(),
                timeout.as_secs()
            );
        }

        // Also check for general inactivity (no log output for too long)
        if last_activity.elapsed() > Duration::from_secs(120) {
            anyhow::bail!(
                "No activity for 120 seconds at stage '{}'. Installation may be stuck.",
                stage
            );
        }

        // Sleep before next iteration
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Read new content from a file since last position.
// TODO: Replace the poll-based monitor_installation loop with tokio —
// async reads on the log files + async wait on the child process would
// eliminate the sleep-poll pattern entirely.
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

/// Extract context around a pattern match.
///
/// Returns up to 100 bytes before and 200 bytes after the first occurrence of
/// `pattern` in `content`, snapped to character boundaries.
fn extract_context(content: &str, pattern: &str) -> String {
    let Some(idx) = content.find(pattern) else {
        return String::new();
    };
    // Snap start backwards to a char boundary
    let mut start = idx.saturating_sub(100);
    while start > 0 && !content.is_char_boundary(start) {
        start -= 1;
    }
    // Snap end forwards to a char boundary
    let mut end = (idx + pattern.len() + 200).min(content.len());
    while end < content.len() && !content.is_char_boundary(end) {
        end += 1;
    }
    format!("...{}...", &content[start..end])
}

/// Base64 encoding with standard padding.
fn base64_encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

// The end-to-end test for this module is `just test-container-export`.

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
        // Build content with multi-byte chars near the window boundary so
        // naive byte slicing would panic on a codepoint interior.
        let prefix = "é".repeat(60); // 2 bytes each → 120 bytes
        let suffix = "日本語".repeat(80); // 3 bytes each → 720 bytes
        let content = format!("{prefix}PATTERN{suffix}");
        let ctx = extract_context(&content, "PATTERN");
        assert!(ctx.contains("PATTERN"));
    }

    #[test]
    fn test_extract_context_at_boundaries() {
        // Pattern at the very start
        let ctx = extract_context("PATTERN and more", "PATTERN");
        assert!(ctx.contains("PATTERN"));

        // Pattern at the very end
        let ctx = extract_context("some text PATTERN", "PATTERN");
        assert!(ctx.contains("PATTERN"));
    }
}
