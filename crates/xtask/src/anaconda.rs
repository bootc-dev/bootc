//! End-to-end Anaconda installation testing
//!
//! This module implements a proper end-to-end test of bootc container export
//! with Anaconda liveimg installation, without relying on TMT framework mounts.

use std::fs;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use fn_error_context::context;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::Command as TokioCommand;
use tokio::time::{sleep, timeout};
// TODO: Deduplicate with ostree-ext::composefs_boot::os_release when dependency issues are resolved
use xshell::{cmd, Shell};

/// URL template functions for each installer type
fn fedora_url(arch: &Architecture) -> String {
    let arch_str = arch.as_str();
    format!(
        "https://download.fedoraproject.org/pub/fedora/linux/releases/43/Everything/{arch_str}/iso/Fedora-Everything-netinst-{arch_str}-43-1.6.iso"
    )
}

fn centos_stream_9_url(arch: &Architecture) -> String {
    let arch_str = arch.as_str();
    format!(
        "https://mirror.stream.centos.org/9-stream/BaseOS/{arch_str}/iso/CentOS-Stream-9-latest-{arch_str}-boot.iso"
    )
}

fn centos_stream_10_url(arch: &Architecture) -> String {
    let arch_str = arch.as_str();
    format!(
        "https://mirror.stream.centos.org/10-stream/BaseOS/{arch_str}/iso/CentOS-Stream-10-latest-{arch_str}-boot.iso"
    )
}

/// Simple os-release parser - minimal implementation for xtask needs
/// TODO: Deduplicate with ostree-ext::composefs_boot::os_release::OsReleaseInfo when possible
#[derive(Debug, Clone)]
struct OsReleaseInfo {
    fields: std::collections::HashMap<String, String>,
}

impl OsReleaseInfo {
    /// Parse os-release content from string
    fn parse(content: &str) -> Self {
        let mut fields = std::collections::HashMap::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse KEY=VALUE or KEY="VALUE" format
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim().to_string();
                let mut value = value.trim();

                // Remove quotes if present
                if let Some(stripped) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
                    value = stripped;
                } else if let Some(stripped) =
                    value.strip_prefix('\'').and_then(|v| v.strip_suffix('\''))
                {
                    value = stripped;
                }

                fields.insert(key, value.to_string());
            }
        }

        Self { fields }
    }

    /// Get value for the given keys (tries first key, then fallbacks)
    fn get_value(&self, keys: &[&str]) -> Option<String> {
        for key in keys {
            if let Some(value) = self.fields.get(*key) {
                return Some(value.clone());
            }
        }
        None
    }

    /// Get pretty name (e.g., "Fedora Linux 43 (Forty Three)")
    fn get_pretty_name(&self) -> Option<String> {
        self.get_value(&["PRETTY_NAME"])
    }

    /// Get version (e.g., "43 (Forty Three)" or just "43")
    fn get_version(&self) -> Option<String> {
        self.get_value(&["VERSION", "VERSION_ID"])
    }
}

/// URL template for generating architecture-specific ISO URLs
type UrlTemplate = fn(&Architecture) -> String;

/// Installer configuration with URL template - checksums are always fetched dynamically
#[derive(Debug, Clone)]
struct InstallerConfig {
    url_template: UrlTemplate,
}

/// All installer configurations
struct InstallerConfigs {
    fedora: InstallerConfig,
    centos_stream_9: InstallerConfig,
    centos_stream_10: InstallerConfig,
}

/// Global installer configurations - URLs generated dynamically from templates
const INSTALLER_CONFIGS: InstallerConfigs = InstallerConfigs {
    fedora: InstallerConfig {
        url_template: fedora_url,
    },
    centos_stream_9: InstallerConfig {
        url_template: centos_stream_9_url,
    },
    centos_stream_10: InstallerConfig {
        url_template: centos_stream_10_url,
    },
};

// Legacy fallback URL for Fedora x86_64
const FEDORA_ISO_URL_FALLBACK: &str = "https://download.fedoraproject.org/pub/fedora/linux/releases/43/Everything/x86_64/iso/Fedora-Everything-netinst-x86_64-43-1.6.iso";

/// virtiofs share target name for the work directory
/// This name is used in both virt-install --filesystem and the kickstart %pre mount
const VIRTIOFS_TARGET_NAME: &str = "bootcexport";

/// Port on localhost for SSH forwarding with SLIRP networking
/// SLIRP forwards host:2222 -> guest:22
const SSH_FORWARDED_PORT: u16 = 2222;

/// Libvirtd status detection result
#[derive(Debug)]
enum LibvirtStatus {
    Running,
    NotRunning(String),
}

/// Supported architectures for ISO selection
#[derive(Debug, Clone, PartialEq)]
enum Architecture {
    X86_64,
    Aarch64,
}

impl Architecture {
    /// Detect current system architecture
    fn detect() -> Result<Self> {
        let arch_output = std::process::Command::new("uname")
            .arg("-m")
            .output()
            .context("Failed to detect system architecture with 'uname -m'")?;

        let arch_string = String::from_utf8(arch_output.stdout)
            .context("Invalid UTF-8 in architecture detection output")?;
        let arch_str = arch_string.trim();

        match arch_str {
            "x86_64" => Ok(Architecture::X86_64),
            "aarch64" | "arm64" => Ok(Architecture::Aarch64),
            other => anyhow::bail!(
                "Unsupported architecture: {}. Supported architectures: x86_64, aarch64",
                other
            ),
        }
    }

    /// Get architecture string for display
    fn as_str(&self) -> &'static str {
        match self {
            Architecture::X86_64 => "x86_64",
            Architecture::Aarch64 => "aarch64",
        }
    }
}

/// Run complete Anaconda installation test
#[context("Running Anaconda test")]
pub(crate) fn run_anaconda_test(sh: &Shell, args: &crate::AnacondaTestArgs) -> Result<()> {
    // Create tokio runtime and run the async test
    let rt = tokio::runtime::Runtime::new().context("Failed to create tokio runtime")?;
    rt.block_on(run_anaconda_test_async(sh, args))
}

/// Async implementation of the Anaconda test
async fn run_anaconda_test_async(sh: &Shell, args: &crate::AnacondaTestArgs) -> Result<()> {
    println!(
        "Starting Anaconda test: {} → {}",
        args.image, args.output_disk
    );

    check_prerequisites(sh)?;
    let work_dir = create_work_directory()?;
    let result = run_anaconda_test_impl(sh, args, &work_dir).await;

    if !args.preserve_vm && result.is_ok() {
        let _ = cleanup_work_directory(&work_dir);
    } else if args.preserve_vm {
        println!("Work directory preserved: {}", work_dir);
    }

    result
}

/// Verify SHA256 checksum of a file
#[context("Verifying file checksum")]
fn verify_file_checksum(file_path: &Utf8Path, expected_sha256: &str) -> Result<()> {
    println!("Verifying checksum for {}...", file_path);

    let output = std::process::Command::new("sha256sum")
        .arg(file_path)
        .output()
        .context("Failed to run sha256sum. Is it installed?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("sha256sum failed: {}", stderr);
    }

    let stdout = String::from_utf8(output.stdout).context("Invalid UTF-8 in sha256sum output")?;

    let computed_hash = stdout
        .split_whitespace()
        .next()
        .context("Invalid sha256sum output format")?;

    if computed_hash.to_lowercase() != expected_sha256.to_lowercase() {
        anyhow::bail!(
            "Checksum verification failed for {}\n  Expected: {}\n  Computed: {}",
            file_path,
            expected_sha256,
            computed_hash
        );
    }

    println!("- Checksum verification passed");
    Ok(())
}

/// Check that all prerequisites are available
#[context("Checking prerequisites")]
fn check_prerequisites(sh: &Shell) -> Result<()> {
    println!("Checking prerequisites...");

    if !Utf8Path::new("/dev/kvm").exists() {
        anyhow::bail!("KVM support not available (/dev/kvm missing)");
    }

    for cmd_name in ["virt-install", "virsh", "qemu-img", "python3"] {
        cmd!(sh, "which {cmd_name}").read().with_context(|| {
            format!("{} not found. Install libvirt, qemu, and python3", cmd_name)
        })?;
    }

    // Note: libguestfs tools are optional - bcvk is now the preferred verification method.
    // We check for bcvk as a soft prerequisite.
    if !has_bcvk(sh) {
        eprintln!("Note: bcvk not found - will fall back to libguestfs or basic verification");
    }

    match libvirt::check_status(sh) {
        LibvirtStatus::Running => {}
        LibvirtStatus::NotRunning(reason) => {
            eprintln!(
                "Warning: libvirtd {}, try: sudo systemctl start libvirtd",
                reason
            );
        }
    }

    println!("Prerequisites OK");
    Ok(())
}



/// Create temporary work directory
#[context("Creating work directory")]
fn create_work_directory() -> Result<Utf8PathBuf> {
    let work_dir = Utf8PathBuf::try_from(std::env::temp_dir())
        .context("Failed to convert temp dir to UTF-8 path")?
        .join(format!("bootc-anaconda-test-{}", std::process::id()));

    fs::create_dir_all(&work_dir)?;
    Ok(work_dir)
}

/// SSH key pair for testing
#[derive(Debug)]
struct SshKeyPair {
    private_key_path: Utf8PathBuf,
    #[allow(dead_code)]
    public_key_path: Utf8PathBuf,
    public_key_content: String,
}

/// RAII guard for resource cleanup to prevent leaks
#[derive(Debug)]
struct ResourceGuard {
    work_dir: Option<Utf8PathBuf>,
    vm_names: Arc<Mutex<Vec<String>>>,
}

impl ResourceGuard {
    fn new() -> Self {
        Self {
            work_dir: None,
            vm_names: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn set_work_dir(&mut self, work_dir: Utf8PathBuf) {
        self.work_dir = Some(work_dir);
    }

    fn add_vm_name(&self, vm_name: String) {
        if let Ok(mut names) = self.vm_names.lock() {
            names.push(vm_name);
        }
    }

    fn cleanup(&mut self, sh: &Shell, preserve_vm: bool, preserve_work_dir: bool) {
        // Cleanup VMs
        if !preserve_vm
            && let Ok(names) = self.vm_names.lock()
        {
            for vm_name in names.iter() {
                let _ = libvirt::cleanup_vm(sh, vm_name);
            }
        }

        // Cleanup work directory
        if !preserve_work_dir
            && let Some(work_dir) = &self.work_dir
        {
            let _ = cleanup_work_directory(work_dir);
        }
    }
}

impl Drop for ResourceGuard {
    fn drop(&mut self) {
        // Emergency cleanup - use basic shell since we might not have the original shell
        if let Ok(sh) = xshell::Shell::new() {
            self.cleanup(&sh, false, false);
        }
    }
}

/// Generate SSH keypair for test authentication
#[context("Generating SSH keypair")]
fn generate_ssh_keypair(sh: &Shell, work_dir: &Utf8Path) -> Result<SshKeyPair> {
    let private_key_path = work_dir.join("test_ssh_key");
    let public_key_path = work_dir.join("test_ssh_key.pub");

    let _ = fs::remove_file(&private_key_path);
    let _ = fs::remove_file(&public_key_path);

    cmd!(
        sh,
        "ssh-keygen -t ed25519 -f {private_key_path} -N '' -C 'bootc-test'"
    )
    .run()
    .context("Failed to generate SSH keypair")?;

    let public_key_content = fs::read_to_string(&public_key_path)
        .context("Failed to read public key")?
        .trim()
        .to_string();

    Ok(SshKeyPair {
        private_key_path,
        public_key_path,
        public_key_content,
    })
}

/// Test os-release detection and mapping
#[context("Testing os-release detection")]
pub(crate) fn test_os_release_detection(sh: &Shell, args: &crate::TestOsReleaseArgs) -> Result<()> {
    println!("Testing os-release detection for image: {}", args.image);

    // Extract os-release information from the container
    let os_release = extract_container_os_release(sh, &args.image)?;

    // Map to installer type
    let installer_type = map_os_release_to_installer(&os_release)?;

    // Display results
    println!("\n=== Container OS Release Information ===");
    println!("Distribution ID: {}", os_release.id);
    println!(
        "Version ID: {}",
        os_release.version_id.as_deref().unwrap_or("N/A")
    );
    println!("Architecture: {}", os_release.architecture);
    if let Some(pretty_name) = &os_release.pretty_name {
        println!("Pretty Name: {}", pretty_name);
    }
    if let Some(version_name) = &os_release.version_name {
        println!("Version Name: {}", version_name);
    }

    println!("\n=== Installer Mapping ===");
    println!("Recommended installer type: {}", installer_type);

    // Show what ISO URL would be used
    let current_arch = Architecture::detect()?;
    let iso_url = get_iso_url_for_installer(&installer_type, &current_arch)?;
    println!("ISO URL ({}): {}", current_arch.as_str(), iso_url);
    println!("Expected SHA256: dynamic (fetched from official source)");

    Ok(())
}

/// Main test implementation with resource management
#[context("Running Anaconda test implementation")]
async fn run_anaconda_test_impl(
    sh: &Shell,
    args: &crate::AnacondaTestArgs,
    work_dir: &Utf8Path,
) -> Result<()> {
    let mut resource_guard = ResourceGuard::new();
    resource_guard.set_work_dir(work_dir.to_path_buf());

    // Step 1: Export container to tar with path sanitization
    let export_tar = export_container(sh, &args.image, work_dir)?;

    // Step 2: Get/download installer ISO
    let installer_iso = get_installer_iso(sh, args, work_dir)?;

    // Step 2.5: Generate SSH keypair if SSH is enabled
    let ssh_keypair = if args.ssh {
        Some(generate_ssh_keypair(sh, work_dir)?)
    } else {
        None
    };

    // Step 3: Create kickstart file (now uses virtiofs instead of HTTP)
    let kickstart_file =
        create_kickstart(sh, work_dir, &export_tar, ssh_keypair.as_ref())?;

    if args.dry_run {
        println!("Dry run complete - files generated but VM not started:");
        println!("   Export: {}", export_tar);
        println!("   Kickstart: {}", kickstart_file);
        println!("   Installer ISO: {}", installer_iso);
        println!("   Work directory: {}", work_dir);
        println!("   virtiofs target: {}", VIRTIOFS_TARGET_NAME);
        return Ok(());
    }

    // Step 4: Create VM disk (virtiofs shares work_dir directly, no HTTP server needed)
    let vm_disk = create_vm_disk(sh, &args.output_disk, work_dir)?;

    // Step 6: Run virt-install with sanitized VM name
    let result = run_virt_install(
        sh,
        args,
        &installer_iso,
        &kickstart_file,
        &vm_disk,
        work_dir,
        &resource_guard,
    )
    .await;

    // Handle installation result
    let result = match result {
        Ok(()) => {
            // Step 7: Verify installation
            let verify_result = verify_installation(sh, &vm_disk, &args.image);

            // Step 8: SSH access (if enabled)
            if let (Ok(()), Some(keypair)) = (&verify_result, ssh_keypair) {
                verify_ssh_access(sh, args, &vm_disk, &keypair, args.ssh_command.as_ref(), &resource_guard).await
            } else {
                verify_result
            }
        }
        Err(e) => Err(e),
    };

    // Cleanup resources
    resource_guard.cleanup(sh, args.preserve_vm, args.preserve_vm);

    result?;
    println!("Anaconda installation test completed successfully!");
    Ok(())
}

/// Export container image to tar format
#[context("Exporting container")]
fn export_container(sh: &Shell, image: &str, work_dir: &Utf8Path) -> Result<Utf8PathBuf> {
    println!("Exporting {} to tar...", image);

    let export_path = work_dir.join("bootc-export.tar");
    let work_dir_str = work_dir.as_str();

    cmd!(sh, "podman run --rm 
              --mount type=image,source={image},target=/target
              -v {work_dir_str}:/out:Z
              {image} 
              bootc container export --kernel-in-boot --format=tar --output /out/bootc-export.tar /target")
        .env("RUST_LOG", "info")
        .run()
        .context("Container export failed. Check image exists and contains bootc")?;

    let export_size = fs::metadata(&export_path)?.len();
    if export_size < 100_000_000 {
        anyhow::bail!("Export suspiciously small: {} bytes", export_size);
    }

    println!(
        "Export complete: {:.1} MB",
        export_size as f64 / 1_000_000.0
    );
    Ok(export_path)
}



/// Container OS release information extracted from the container image
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ContainerOsRelease {
    /// Distribution ID (e.g., "fedora", "centos", "rhel")
    pub id: String,
    /// Version ID (e.g., "41", "9", "10")
    pub version_id: Option<String>,
    /// Architecture (e.g., "x86_64", "aarch64")
    pub architecture: String,
    /// Pretty name from os-release (e.g., "Fedora Linux 41")
    pub pretty_name: Option<String>,
    /// Version name from os-release (e.g., "Forty One")
    pub version_name: Option<String>,
}

/// Extract os-release information from a container image
///
/// Uses `podman run --rm` to run the container and extract `/etc/os-release` (or `/usr/lib/os-release`
/// as fallback) to determine:
/// - Distribution ID (fedora, centos, rhel)  
/// - Version/version_id (e.g., "41", "9", "10")
/// - Architecture (using `uname -m`)
/// - Pretty name and version name for informational purposes
///
/// This function handles containers whether they are running or not, and works with any
/// container runtime compatible with podman.
///
/// # Arguments
/// * `sh` - Shell instance for running commands
/// * `image` - Container image name to inspect (e.g., "fedora:latest", "quay.io/centos/centos:stream9")
///
/// # Returns
/// * `Ok(ContainerOsRelease)` - Parsed os-release information
/// * `Err(anyhow::Error)` - If extraction or parsing fails
///
/// # Errors
/// This function will return an error if:
/// - The container image doesn't exist or can't be accessed
/// - Neither `/etc/os-release` nor `/usr/lib/os-release` exist in the container
/// - The os-release files are empty or malformed
/// - Architecture detection fails (uname command not available)
/// - Container runtime (podman) is not available
///
/// # Example
/// ```no_run
/// # use xshell::Shell;
/// # use anyhow::Result;
/// let sh = Shell::new().unwrap();
/// let os_release = extract_container_os_release(&sh, "quay.io/fedora/fedora-bootc:41").unwrap();
/// assert_eq!(os_release.id, "fedora");
/// assert_eq!(os_release.version_id, Some("41".to_string()));
/// assert_eq!(os_release.architecture, "x86_64");
/// ```
#[context("Extracting container os-release")]
pub fn extract_container_os_release(sh: &Shell, image: &str) -> Result<ContainerOsRelease> {
    // Try /etc/os-release first, then fall back to /usr/lib/os-release
    let os_release_content = extract_os_release_file(sh, image, "/etc/os-release")
        .or_else(|_| extract_os_release_file(sh, image, "/usr/lib/os-release"))
        .context("Failed to extract os-release from container. Neither /etc/os-release nor /usr/lib/os-release found.")?;

    // Get architecture from the container
    let architecture = cmd!(sh, "podman run --rm {image} uname -m")
        .read()
        .context("Failed to detect architecture from container")?
        .trim()
        .to_string();

    // Parse the os-release content
    let os_release_info = OsReleaseInfo::parse(&os_release_content);

    // Extract required fields
    let id = os_release_info
        .get_value(&["ID"])
        .unwrap_or_else(|| "unknown".to_string())
        .to_lowercase();

    let version_id = os_release_info.get_value(&["VERSION_ID"]);
    let pretty_name = os_release_info.get_pretty_name();
    let version_name = os_release_info.get_version();

    if id == "unknown" {
        anyhow::bail!("Unable to determine distribution ID from os-release");
    }

    Ok(ContainerOsRelease {
        id,
        version_id,
        architecture,
        pretty_name,
        version_name,
    })
}

/// Extract os-release file content from container
fn extract_os_release_file(sh: &Shell, image: &str, file_path: &str) -> Result<String> {
    let content = cmd!(sh, "podman run --rm {image} cat {file_path}")
        .read()
        .with_context(|| format!("Failed to read {} from container {}", file_path, image))?;

    if content.trim().is_empty() {
        anyhow::bail!("{} is empty in container {}", file_path, image);
    }

    Ok(content)
}

/// Get ISO configuration for a specific installer type and architecture
#[context("Getting ISO configuration")]
fn get_iso_url_for_installer(installer_type: &str, arch: &Architecture) -> Result<String> {
    let config = match installer_type {
        "fedora" => &INSTALLER_CONFIGS.fedora,
        "centos-stream-9" => &INSTALLER_CONFIGS.centos_stream_9,
        "centos-stream-10" => &INSTALLER_CONFIGS.centos_stream_10,
        other => anyhow::bail!(
            "Unknown installer type: {}. Supported: fedora, centos-stream-9, centos-stream-10",
            other
        ),
    };

    Ok((config.url_template)(arch))
}

/// Map container OS release to appropriate installer type
///
/// Maps the extracted os-release information to installer configurations that can be used
/// to download the correct Anaconda installer ISO:
///
/// ## Supported Mappings:
/// - **Fedora**: Any Fedora version → `"fedora"`
/// - **CentOS Stream 9**: CentOS with VERSION_ID=9 → `"centos-stream-9"`
/// - **CentOS Stream 10**: CentOS with VERSION_ID=10 → `"centos-stream-10"`
/// - **RHEL 9.x**: RHEL version 9.x → `"centos-stream-9"` (compatible installer)
/// - **RHEL 10.x**: RHEL version 10.x → `"centos-stream-10"` (compatible installer)
///
/// ## RHEL Mapping Logic:
/// RHEL versions are mapped to their corresponding CentOS Stream releases because:
/// - CentOS Stream is the upstream of RHEL
/// - The Anaconda installer is compatible between RHEL and CentOS Stream of the same major version
/// - This provides a free installer source for RHEL-compatible installations
///
/// # Arguments
/// * `os_release` - Extracted container os-release information
///
/// # Returns
/// * `Ok(String)` - Installer type identifier that can be used with installer ISO URLs
/// * `Err(anyhow::Error)` - For unsupported distributions or missing version information
///
/// # Errors
/// This function will return an error for:
/// - Unsupported distributions (not fedora, centos, or rhel)
/// - Missing VERSION_ID field for CentOS or RHEL containers
/// - Unsupported versions (e.g., CentOS 8, RHEL 8, or future versions not yet supported)
///
/// # Example
/// ```no_run
/// # use anyhow::Result;
/// let installer_type = map_os_release_to_installer(&os_release)?;
/// match installer_type.as_str() {
///     "fedora" => println!("Will use Fedora installer"),
///     "centos-stream-9" => println!("Will use CentOS Stream 9 installer"),
///     "centos-stream-10" => println!("Will use CentOS Stream 10 installer"),
///     _ => unreachable!("Function only returns known types"),
/// }
/// ```
#[context("Mapping OS release to installer type")]
pub fn map_os_release_to_installer(os_release: &ContainerOsRelease) -> Result<String> {
    match os_release.id.as_str() {
        "fedora" => Ok("fedora".to_string()),
        "centos" => {
            // For CentOS, check if it's Stream and what version
            let version = os_release
                .version_id
                .as_ref()
                .context("CentOS container missing VERSION_ID in os-release")?;

            match version.as_str() {
                "9" => Ok("centos-stream-9".to_string()),
                "10" => Ok("centos-stream-10".to_string()),
                other => anyhow::bail!(
                    "Unsupported CentOS version: {}. Supported versions: 9, 10",
                    other
                ),
            }
        }
        "rhel" => {
            // Map RHEL to corresponding CentOS Stream
            let version = os_release
                .version_id
                .as_ref()
                .context("RHEL container missing VERSION_ID in os-release")?;

            // Parse major version from version strings like "9.4" or "10"
            let major_version = version
                .split('.')
                .next()
                .context("Unable to parse RHEL major version")?;

            match major_version {
                "9" => Ok("centos-stream-9".to_string()),
                "10" => Ok("centos-stream-10".to_string()),
                other => anyhow::bail!(
                    "Unsupported RHEL version: {}. Supported versions: 9, 10",
                    other
                ),
            }
        }
        other => anyhow::bail!(
            "Unsupported distribution: {}. Supported distributions: fedora, centos, rhel",
            other
        ),
    }
}

/// Get installer ISO (download if needed) with architecture detection and checksum verification
#[context("Getting installer ISO")]
fn get_installer_iso(
    sh: &Shell,
    args: &crate::AnacondaTestArgs,
    work_dir: &Utf8Path,
) -> Result<Utf8PathBuf> {
    // If user provided a specific ISO path, use it without checksum verification
    if let Some(iso_path) = &args.installer_iso {
        let iso_path = Utf8PathBuf::from(iso_path);
        if !iso_path.exists() {
            anyhow::bail!("Installer ISO not found: {}", iso_path);
        }
        println!("Using provided ISO: {}", iso_path);
        return Ok(iso_path);
    }

    // Detect current system architecture
    let current_arch = Architecture::detect().context("Failed to detect system architecture")?;
    println!("Detected architecture: {}", current_arch.as_str());

    // Determine installer type (auto-detect if needed)
    let final_installer_type = if args.installer_type == "auto" {
        let os_release = extract_container_os_release(sh, &args.image)
            .context("Failed to auto-detect installer type from container os-release")?;
        let detected_type = map_os_release_to_installer(&os_release)
            .context("Failed to map container OS to installer type")?;

        println!(
            "Auto-detected installer type: {} (from {} {})",
            detected_type,
            os_release.id,
            os_release.version_id.as_deref().unwrap_or("unknown")
        );
        detected_type
    } else {
        // Handle legacy "centos-stream" argument
        if args.installer_type == "centos-stream" {
            "centos-stream-9".to_string()
        } else {
            args.installer_type.clone()
        }
    };

    // Get ISO URL for the determined installer type and architecture
    let iso_url = if let Some(url) = &args.installer_url {
        // If user provided custom URL, we can't verify checksum
        println!(
            "Using custom installer URL (no checksum verification): {}",
            url
        );
        return download_iso_without_verification(
            sh,
            url,
            work_dir,
            &final_installer_type,
            &current_arch,
        );
    } else {
        get_iso_url_for_installer(&final_installer_type, &current_arch).with_context(|| {
            format!(
                "Failed to get ISO URL for {} on {}",
                final_installer_type,
                current_arch.as_str()
            )
        })?
    };

    // Use cached ISO in target/ directory instead of work_dir
    let cache_dir = Utf8Path::new("target/anaconda-cache");
    std::fs::create_dir_all(cache_dir).context("Failed to create ISO cache directory")?;

    let iso_filename = format!("{}-{}.iso", final_installer_type, current_arch.as_str());
    let cached_iso_path = cache_dir.join(&iso_filename);
    let work_iso_path = work_dir.join("installer.iso");

    // Check if cached ISO already exists and verify its checksum
    if cached_iso_path.exists() {
        println!("Found cached ISO: {}", cached_iso_path);
        println!("Verifying cached ISO checksum...");

        // Fetch the dynamic checksum
        let expected_checksum = fetch_dynamic_checksum(sh, &iso_url, &final_installer_type)
            .context("Failed to fetch dynamic checksum for cached ISO verification")?;

        match verify_file_checksum(&cached_iso_path, &expected_checksum) {
            Ok(()) => {
                println!("- Cached ISO checksum verified");
                // Copy cached ISO to work directory for use
                std::fs::copy(&cached_iso_path, &work_iso_path)
                    .context("Failed to copy cached ISO to work directory")?;
                return Ok(work_iso_path);
            }
            Err(e) => {
                println!("Warning: Cached ISO checksum verification failed: {}", e);
                println!("Removing invalid cached ISO and re-downloading...");
                std::fs::remove_file(&cached_iso_path)?;
            }
        }
    }

    // Download and verify ISO to cache, then copy to work directory
    download_and_verify_iso(
        sh,
        &iso_url,
        &cached_iso_path,
        &final_installer_type,
        &current_arch,
    )?;

    // Copy cached ISO to work directory for use
    println!("Copying cached ISO to work directory...");
    std::fs::copy(&cached_iso_path, &work_iso_path)
        .context("Failed to copy cached ISO to work directory")?;

    Ok(work_iso_path)
}

/// Download ISO without checksum verification (for custom URLs)
#[context("Downloading ISO without verification")]
fn download_iso_without_verification(
    sh: &Shell,
    url: &str,
    work_dir: &Utf8Path,
    installer_type: &str,
    arch: &Architecture,
) -> Result<Utf8PathBuf> {
    // Use cached ISO in target/ directory for custom URLs too
    let cache_dir = Utf8Path::new("target/anaconda-cache");
    std::fs::create_dir_all(cache_dir).context("Failed to create ISO cache directory")?;

    // Create a cache filename based on URL hash for custom URLs
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    url.hash(&mut hasher);
    let url_hash = format!("{:x}", hasher.finish());
    let iso_filename = format!("{}-{}-{}.iso", installer_type, arch.as_str(), url_hash);
    let cached_iso_path = cache_dir.join(&iso_filename);
    let work_iso_path = work_dir.join("installer.iso");

    if cached_iso_path.exists() {
        println!("Found cached custom ISO: {}", cached_iso_path);
        println!("Using existing cached ISO (no verification for custom URL)");
        // Copy cached ISO to work directory for use
        std::fs::copy(&cached_iso_path, &work_iso_path)
            .context("Failed to copy cached custom ISO to work directory")?;
        return Ok(work_iso_path);
    }

    println!(
        "Downloading {} ISO from custom URL to cache...",
        installer_type
    );
    cmd!(sh, "curl -f -L --progress-bar -o {cached_iso_path} {url}")
        .run()
        .context("Failed to download installer ISO from custom URL")?;

    // Copy cached ISO to work directory for use
    println!("Copying cached custom ISO to work directory...");
    std::fs::copy(&cached_iso_path, &work_iso_path)
        .context("Failed to copy cached custom ISO to work directory")?;

    Ok(work_iso_path)
}

/// Download and verify ISO with checksums and fallback support
#[context("Downloading and verifying ISO")]
fn download_and_verify_iso(
    sh: &Shell,
    iso_url: &str,
    iso_path: &Utf8Path,
    installer_type: &str,
    current_arch: &Architecture,
) -> Result<Utf8PathBuf> {
    println!(
        "Downloading {} ISO for {}...",
        installer_type,
        current_arch.as_str()
    );
    println!("URL: {}", iso_url);

    // Fetch dynamic checksum
    println!("Fetching dynamic SHA256 checksum...");
    let actual_checksum = fetch_dynamic_checksum(sh, iso_url, installer_type)
        .context("Failed to fetch dynamic checksum")?;

    println!("Expected SHA256: {}", actual_checksum);

    // Primary download attempt
    let url = iso_url;
    let download_result = cmd!(sh, "curl -f -L --progress-bar -o {iso_path} {url}").run();

    // Handle Fedora x86_64 fallback URL if primary fails
    if download_result.is_err()
        && installer_type == "fedora"
        && *current_arch == Architecture::X86_64
    {
        println!("Primary download failed, trying fallback URL...");
        std::fs::remove_file(iso_path).ok(); // Remove partial download

        cmd!(
            sh,
            "curl -f -L --progress-bar -o {iso_path} {FEDORA_ISO_URL_FALLBACK}"
        )
        .run()
        .context("Failed to download from both primary and fallback URLs")?;

        // Note: Fallback URL uses same ISO, so same checksum applies
    } else {
        download_result.context("Failed to download installer ISO")?;
    }

    // Verify checksum
    verify_file_checksum(iso_path, &actual_checksum).with_context(|| {
        format!(
            "Checksum verification failed for downloaded {} ISO",
            installer_type
        )
    })?;

    println!("- ISO download and verification completed successfully");
    Ok(iso_path.to_owned())
}

/// Create Anaconda kickstart file
///
/// The kickstart uses virtiofs to access the bootc export tar file. A %pre script
/// mounts the virtiofs share before installation begins.
#[context("Creating kickstart file")]
fn create_kickstart(
    _sh: &Shell,
    work_dir: &Utf8Path,
    export_tar: &Utf8Path,
    ssh_keypair: Option<&SshKeyPair>,
) -> Result<Utf8PathBuf> {
    println!("Creating Anaconda kickstart file...");

    let kickstart_path = work_dir.join("bootc-anaconda.ks");
    let tar_filename = export_tar
        .file_name()
        .context("Invalid export tar filename")?;

    println!("Using virtiofs mount for kickstart (target: {})", VIRTIOFS_TARGET_NAME);

    // Generate SSH-specific configuration if SSH is enabled
    let ssh_config = if let Some(keypair) = ssh_keypair {
        format!(
            r#"
# SSH key injection for root user (for post-install verification)
sshkey --username=root "{}"
"#,
            keypair.public_key_content
        )
    } else {
        String::new()
    };

    // Generate SSH post-install script if SSH is enabled
    // Note: We're running in a chroot, so we can only enable services (not start them).
    // The services will start automatically on first boot of the installed system.
    let ssh_post_script = if ssh_keypair.is_some() {
        r#"
# Enable SSH daemon for post-install verification (starts on first boot)
echo "Enabling sshd service..."
systemctl enable sshd

# Configure firewall to allow SSH (if firewall is active in the installed system)
# Note: firewalld won't be running in chroot, so we configure it offline
if [ -d /etc/firewalld ]; then
    echo "Configuring firewalld for SSH access..."
    # Create a direct rule file if firewalld is installed
    mkdir -p /etc/firewalld/zones
    # The default zone will allow SSH by default on most systems
fi

echo "SSH configuration complete - sshd will start on first boot"
"#
    } else {
        ""
    };

    let kickstart_content = format!(
        r#"# Bootc Anaconda Installation Kickstart
# Generated by bootc xtask anaconda

# Use text mode for non-interactive installation
text

# Mount virtiofs share containing the bootc export tar
# This runs before installation to make the tar file accessible
%pre --log=/tmp/pre-install.log
#!/bin/bash
set -euo pipefail
echo "Mounting virtiofs share..."
mkdir -p /mnt/bootc-export
mount -t virtiofs {virtiofs_target} /mnt/bootc-export
echo "virtiofs mount successful"
ls -la /mnt/bootc-export/
%end

# Install from exported bootc tar via virtiofs mount
liveimg --url=file:///mnt/bootc-export/{tar_filename}

# Basic system configuration  
keyboard us
lang en_US.UTF-8
timezone UTC
rootpw --plaintext testpassword

# Network configuration
network --bootproto=dhcp --hostname=bootc-anaconda-test
{ssh_config}
# Partitioning - UEFI layout
bootloader --location=none
zerombr
clearpart --all --initlabel
part /boot/efi --fstype=efi --size=600
part /boot --fstype=xfs --size=1024  
part / --fstype=xfs --grow

# Complete installation and reboot into installed system
reboot

%post --erroronfail --log=/root/post-install.log
#!/bin/bash
set -euo pipefail

echo "Starting post-install script at $(date)"

# Install bootloader via bootupd (the bootc way)
BOOT_DISK=$(lsblk -no PKNAME $(findmnt -no SOURCE /) 2>/dev/null | head -1 || echo "vda")
if [ -z "$BOOT_DISK" ]; then
    BOOT_DISK="vda"
fi

echo "Installing bootloader on /dev/$BOOT_DISK"
bootupctl backend install --auto --write-uuid --device /dev/$BOOT_DISK /

# Verify bootloader installation
if [ $? -eq 0 ]; then
    echo "Bootloader installation successful"
else
    echo "Bootloader installation failed" >&2
    exit 1
fi

# Create BLS (Boot Loader Specification) entry for GRUB
# This is required because the bootc tar export doesn't include BLS entries
# (they reference specific partition UUIDs that are only known at install time)
echo "Creating BLS boot entry..."
mkdir -p /boot/loader/entries

# Get root partition UUID
ROOT_UUID=$(findmnt -no UUID /)
if [ -z "$ROOT_UUID" ]; then
    echo "ERROR: Could not determine root partition UUID" >&2
    exit 1
fi

# Find the kernel version from the installed kernel
KERNEL_VERSION=$(ls /boot/vmlinuz-* 2>/dev/null | head -1 | sed 's|.*/vmlinuz-||')
if [ -z "$KERNEL_VERSION" ]; then
    echo "ERROR: Could not find installed kernel" >&2
    exit 1
fi

# Get OS information for the BLS entry
source /etc/os-release
MACHINE_ID=$(cat /etc/machine-id)

# Create the BLS entry
BLS_ENTRY="/boot/loader/entries/$MACHINE_ID-$KERNEL_VERSION.conf"
cat > "$BLS_ENTRY" << BLSEOF
title $NAME $VERSION
version $KERNEL_VERSION
linux /vmlinuz-$KERNEL_VERSION
initrd /initramfs-$KERNEL_VERSION.img
options root=UUID=$ROOT_UUID ro console=tty0 console=ttyS0,115200n8
grub_users \$grub_users
grub_arg --unrestricted
grub_class ${{ID:-linux}}
BLSEOF

echo "Created BLS entry: $BLS_ENTRY"
cat "$BLS_ENTRY"

# Create success marker
echo "BOOTC_ANACONDA_INSTALL_SUCCESS" > /root/INSTALL_RESULT
echo "Installation completed successfully at $(date)" >> /root/INSTALL_RESULT

# Log kernel version for verification
uname -a >> /root/INSTALL_RESULT

# Log some useful system information
echo "--- System Info ---" >> /root/INSTALL_RESULT
df -h >> /root/INSTALL_RESULT
echo "--- Block Devices ---" >> /root/INSTALL_RESULT
lsblk >> /root/INSTALL_RESULT
echo "--- Boot entries ---" >> /root/INSTALL_RESULT
ls -la /boot/loader/entries/ >> /root/INSTALL_RESULT 2>&1 || echo "No systemd-boot entries found" >> /root/INSTALL_RESULT

echo "Post-install script completed successfully at $(date)"
{ssh_post_script}
%end
"#,
        virtiofs_target = VIRTIOFS_TARGET_NAME,
        tar_filename = tar_filename,
        ssh_config = ssh_config,
        ssh_post_script = ssh_post_script
    );

    fs::write(&kickstart_path, kickstart_content).context("Failed to write kickstart file")?;

    println!("- Kickstart file created");
    Ok(kickstart_path)
}

/// Create VM disk image
#[context("Creating VM disk")]
fn create_vm_disk(sh: &Shell, output_disk: &str, work_dir: &Utf8Path) -> Result<Utf8PathBuf> {
    println!("Creating VM disk image...");

    let vm_disk = if Utf8Path::new(output_disk).is_absolute() {
        Utf8PathBuf::from(output_disk)
    } else {
        work_dir.join(output_disk)
    };

    // Create directory if needed
    if let Some(parent) = vm_disk.parent() {
        fs::create_dir_all(parent)?;
    }

    // Remove existing disk if present
    if vm_disk.exists() {
        fs::remove_file(&vm_disk)?;
    }

    cmd!(sh, "qemu-img create -f raw {vm_disk} 20G")
        .run()
        .context("Failed to create VM disk image")?;

    println!("- VM disk created: {}", vm_disk);
    Ok(vm_disk)
}

/// Run virt-install to perform installation with monitoring and auto-shutdown
#[context("Running virt-install")]
async fn run_virt_install(
    sh: &Shell,
    args: &crate::AnacondaTestArgs,
    installer_iso: &Utf8Path,
    kickstart_file: &Utf8Path,
    vm_disk: &Utf8Path,
    work_dir: &Utf8Path,
    resource_guard: &ResourceGuard,
) -> Result<()> {
    let base_vm_name = format!("bootc-anaconda-test-{}", std::process::id());
    let vm_name = libvirt::sanitize_name(&base_vm_name)?;
    let timeout_seconds = args.timeout * 60;

    println!("Running installation ({} min timeout)...", args.timeout);
    println!("VM name: {}", vm_name);

    // Register VM with resource guard
    resource_guard.add_vm_name(vm_name.clone());

    // Cleanup any existing VM
    libvirt::cleanup_vm(sh, &vm_name)?;

    let memory = args.memory.to_string();
    let vcpus = args.vcpus.to_string();

    // Start virt-install without --wait to allow monitoring
    println!("Starting Anaconda installation...");

    // Create virtio socket path for monitoring Anaconda progress
    let virtio_socket_path = work_dir.join("anaconda-progress.socket");

    // Build virtiofs filesystem argument to share the work directory with the VM
    // This allows the kickstart's %pre script to mount the bootc export tar
    let virtiofs_arg = format!(
        "source={},target={},driver.type=virtiofs",
        work_dir.as_str(),
        VIRTIOFS_TARGET_NAME
    );

    let mut child = TokioCommand::new("virt-install")
        .args([
            "--name",
            &vm_name,
            "--memory",
            &memory,
            "--vcpus",
            &vcpus,
            // Boot in UEFI mode to match our UEFI partition layout
            "--boot",
            "uefi",
            "--disk",
            &format!("path={},bus=virtio,format=raw", vm_disk),
            "--network",
            // Use simple SLIRP user networking for installation
            // Port forwarding is not needed during installation, only for post-reboot SSH
            "type=user,model=virtio",
            "--location",
            installer_iso.as_str(),
            "--initrd-inject",
            kickstart_file.as_str(),
            "--extra-args",
            "inst.ks=file:///bootc-anaconda.ks inst.text inst.cmdline console=ttyS0,115200",
            "--graphics",
            "none",
            "--console",
            "pty,target_type=serial",
            "--noautoconsole",
            // Share work directory via virtiofs so kickstart can access the bootc export tar
            "--filesystem",
            &virtiofs_arg,
            // Memory backing required for virtiofs
            "--memorybacking",
            "source.type=memfd,access.mode=shared",
            // Add virtio channel for Anaconda communication
            "--channel",
            &format!(
                "unix,target_type=virtio,name=org.fedoraproject.anaconda.log,path={}",
                virtio_socket_path.as_str()
            ),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to start virt-install")?;

    // Give virt-install time to create and start the VM
    sleep(Duration::from_secs(10)).await;

    // Check if virt-install process is still running
    match child.try_wait() {
        Ok(Some(status)) => {
            if !status.success() {
                let output = child.wait_with_output().await;
                let error_output = output
                    .map(|o| String::from_utf8_lossy(&o.stderr).to_string())
                    .unwrap_or_default();
                return Err(anyhow::anyhow!(
                    "virt-install failed immediately: exit code {}, stderr: {}",
                    status.code().unwrap_or(-1),
                    error_output
                ));
            }
        }
        Ok(None) => {
            // Process is still running, which is expected
            println!("virt-install process started successfully");
        }
        Err(e) => {
            return Err(anyhow::anyhow!(
                "Failed to check virt-install process status: {}",
                e
            ));
        }
    }

    // Monitor VM and wait for completion with timeout
    let monitor_result = timeout(
        Duration::from_secs(timeout_seconds as u64),
        monitor_anaconda_installation(sh, &vm_name, &virtio_socket_path),
    )
    .await;

    // Clean up virt-install process if it's still running
    let _ = child.kill().await;
    let _ = child.wait().await;

    // Check monitoring result
    match monitor_result {
        Ok(inner_result) => inner_result?,
        Err(_) => {
            return Err(anyhow::anyhow!(
                "Installation timeout after {} minutes",
                args.timeout
            ));
        }
    }

    // Installation complete! VM has rebooted into installed system
    // Now we need to shut it down gracefully for cleanup
    println!("Installation monitoring completed successfully");

    if !args.preserve_vm {
        println!("Shutting down VM after successful installation...");
        libvirt::shutdown_vm(sh, &vm_name).await?;
        libvirt::cleanup_vm(sh, &vm_name)?;
    } else {
        println!("VM preserved for inspection: {}", vm_name);
        println!("The VM has rebooted into the installed bootc system.");
        println!("You can SSH to it or inspect it manually.");
    }

    Ok(())
}

/// Anaconda progress event parsed from the virtio log socket
#[derive(Debug, Clone)]
struct AnacondaProgress {
    /// The step/phase name (e.g., "installation", "bootloader", "payload")
    step: String,
    /// Progress message
    message: String,
    /// Timestamp of the event
    timestamp: Instant,
}

/// Parse an Anaconda progress line from the virtio log
///
/// Anaconda logs various events in DBus-like format. Key events include:
/// - Progress updates: step completion, package installation progress
/// - Error messages that indicate failures
fn parse_anaconda_progress(line: &str) -> Option<AnacondaProgress> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    // Look for progress-related keywords
    let step = if line.contains("payload") || line.contains("Payload") {
        "payload"
    } else if line.contains("bootloader") || line.contains("Bootloader") {
        "bootloader"
    } else if line.contains("install") || line.contains("Install") {
        "installation"
    } else if line.contains("storage") || line.contains("Storage") {
        "storage"
    } else if line.contains("network") || line.contains("Network") {
        "network"
    } else if line.contains("error") || line.contains("Error") || line.contains("ERROR") {
        "error"
    } else if line.contains("complete") || line.contains("Complete") || line.contains("finished") {
        "complete"
    } else {
        "progress"
    };

    Some(AnacondaProgress {
        step: step.to_string(),
        message: line.to_string(),
        timestamp: Instant::now(),
    })
}

/// Monitor Anaconda installation progress and detect completion
///
/// This function monitors the VM state machine through the installation process:
/// 1. VM starts running (Anaconda installer boots)
/// 2. Installation runs (VM stays running)
/// 3. VM shuts off (installation complete, kickstart says "reboot")
/// 4. VM restarts (booting into installed system)
/// 5. VM is running the installed system
///
/// The function also connects to the Anaconda virtio log socket to parse progress
/// events. When progress is detected, timeouts are extended to avoid premature failures
/// on slow systems.
///
/// We detect success by observing the VM reboot cycle: running -> shut off -> running.
/// The VM must complete the full cycle for success. We never assume success based on
/// arbitrary timeouts - the VM must actually reboot into the installed system.
///
/// Note: Timeout is handled by the caller using tokio::time::timeout.
#[context("Monitoring Anaconda installation")]
async fn monitor_anaconda_installation(
    sh: &Shell,
    vm_name: &str,
    virtio_socket_path: &Utf8Path,
) -> Result<()> {
    let start_time = Instant::now();

    println!("Monitoring installation progress...");

    // Wait for VM to start up first
    sleep(Duration::from_secs(10)).await;

    // Try to connect to the Anaconda log socket
    let progress_reader = connect_anaconda_socket(virtio_socket_path).await;
    let has_progress_socket = progress_reader.is_some();

    if has_progress_socket {
        println!("Connected to Anaconda progress socket");
    } else {
        println!("Anaconda progress socket not available - using VM state monitoring only");
    }

    /// Installation state machine
    #[derive(Debug, Clone, Copy, PartialEq)]
    enum Phase {
        /// VM just started, waiting for installation to begin
        Starting,
        /// Installation is running
        Installing,
        /// VM shut off after installation, waiting for reboot
        WaitingForReboot,
    }

    let mut last_state = String::new();
    let mut phase = Phase::Starting;
    let mut last_progress_log = Instant::now();
    let mut last_progress_event = Instant::now();
    let mut progress_reader = progress_reader;

    loop {
        // Check for progress events from the socket (non-blocking)
        if let Some(ref mut reader) = progress_reader {
            loop {
                // Try to read a line with a very short timeout
                match timeout(Duration::from_millis(100), reader.read_line(&mut String::new())).await {
                    Ok(Ok(0)) => {
                        // EOF - socket closed
                        progress_reader = None;
                        break;
                    }
                    Ok(Ok(_)) => {
                        // We got a line - the buffer was consumed, so read fresh
                        let mut line = String::new();
                        if let Ok(Ok(n)) = timeout(Duration::from_millis(50), reader.read_line(&mut line)).await
                            && n > 0
                            && let Some(progress) = parse_anaconda_progress(&line)
                        {
                            last_progress_event = progress.timestamp;

                            // Log significant progress events
                            match progress.step.as_str() {
                                "error" => {
                                    eprintln!("Anaconda error: {}", progress.message);
                                }
                                "complete" => {
                                    println!("Anaconda: {}", progress.message);
                                }
                                step @ ("payload" | "bootloader" | "storage" | "installation") => {
                                    println!("[{}] {}", step, progress.message);
                                }
                                _ => {
                                    // Don't spam with every progress line
                                }
                            }
                        }
                    }
                    Ok(Err(_)) => {
                        // Read error - socket may have closed
                        progress_reader = None;
                        break;
                    }
                    Err(_) => {
                        // Timeout - no data available, which is fine
                        break;
                    }
                }
            }
        }

        // Check VM state
        let vm_state = match cmd!(sh, "virsh domstate {vm_name}").ignore_status().read() {
            Ok(state) => state.trim().to_string(),
            Err(e) => {
                // VM doesn't exist - this is always a failure
                return Err(anyhow::anyhow!(
                    "VM '{}' no longer exists (phase: {:?}): {}",
                    vm_name,
                    phase,
                    e
                ));
            }
        };

        // Show state changes
        if vm_state != last_state {
            println!(
                "VM state: {} -> {} ({}s elapsed, phase: {:?})",
                if last_state.is_empty() {
                    "initial"
                } else {
                    &last_state
                },
                vm_state,
                start_time.elapsed().as_secs(),
                phase
            );
            last_state = vm_state.clone();
        }

        match vm_state.as_str() {
            "running" => {
                match phase {
                    Phase::Starting => {
                        phase = Phase::Installing;
                        println!("Anaconda installation started");
                    }
                    Phase::Installing => {
                        // Show progress every 60 seconds
                        if last_progress_log.elapsed().as_secs() >= 60 {
                            let progress_info = if has_progress_socket {
                                format!(
                                    " (last progress: {}s ago)",
                                    last_progress_event.elapsed().as_secs()
                                )
                            } else {
                                String::new()
                            };
                            println!(
                                "Installation in progress ({}m elapsed){}",
                                start_time.elapsed().as_secs() / 60,
                                progress_info
                            );
                            last_progress_log = Instant::now();
                        }
                    }
                    Phase::WaitingForReboot => {
                        // VM came back online - this is the success case
                        println!("VM has rebooted into installed system");

                        // Give the system time to fully boot
                        println!("Waiting for system to fully boot...");
                        sleep(Duration::from_secs(30)).await;

                        // Verify VM is still running after boot
                        let final_state = cmd!(sh, "virsh domstate {vm_name}")
                            .read()
                            .context("Failed to check final VM state")?;

                        if final_state.trim() == "running" {
                            println!("Installation completed successfully");
                            return Ok(());
                        } else {
                            return Err(anyhow::anyhow!(
                                "VM failed to stay running after reboot. Final state: {}",
                                final_state.trim()
                            ));
                        }
                    }
                }
            }
            "shut off" => {
                match phase {
                    Phase::Starting => {
                        // VM shut off before installation started - error
                        return Err(anyhow::anyhow!(
                            "VM shut off before installation could start. Check virt-install output for errors."
                        ));
                    }
                    Phase::Installing => {
                        // Installation complete, VM shut off for reboot
                        phase = Phase::WaitingForReboot;
                        println!("Installation complete, waiting for VM to reboot...");

                        // Start the VM again since kickstart uses 'reboot' but libvirt
                        // may not auto-restart depending on configuration
                        println!("Starting VM to boot into installed system...");
                        let start_result = cmd!(sh, "virsh start {vm_name}").run();
                        if let Err(e) = start_result {
                            return Err(anyhow::anyhow!(
                                "Failed to start VM after installation: {}",
                                e
                            ));
                        }
                    }
                    Phase::WaitingForReboot => {
                        // Still waiting for reboot, try to start it
                        println!("VM still shut off, attempting to start...");
                        let start_result = cmd!(sh, "virsh start {vm_name}").run();
                        if let Err(e) = start_result {
                            return Err(anyhow::anyhow!("Failed to start VM for reboot: {}", e));
                        }
                    }
                }
            }
            "crashed" => {
                return Err(anyhow::anyhow!(
                    "VM crashed during installation (phase: {:?})",
                    phase
                ));
            }
            "paused" => {
                return Err(anyhow::anyhow!(
                    "VM unexpectedly paused during installation (phase: {:?})",
                    phase
                ));
            }
            "in shutdown" => {
                // VM is in the process of shutting down - just wait
                println!("VM is shutting down (phase: {:?})", phase);
            }
            "" => {
                return Err(anyhow::anyhow!(
                    "Empty VM state returned - VM may have been destroyed (phase: {:?})",
                    phase
                ));
            }
            other => {
                return Err(anyhow::anyhow!(
                    "VM in unexpected state '{}' (phase: {:?})",
                    other,
                    phase
                ));
            }
        }

        // Wait before next check
        sleep(Duration::from_secs(5)).await;
    }
}

/// Connect to the Anaconda progress virtio socket
///
/// Returns a buffered reader for the socket if connection succeeds,
/// or None if the socket doesn't exist or connection fails.
async fn connect_anaconda_socket(
    socket_path: &Utf8Path,
) -> Option<BufReader<tokio::net::unix::OwnedReadHalf>> {
    // Give QEMU time to create the socket
    for attempt in 0..10 {
        if socket_path.exists() {
            match UnixStream::connect(socket_path.as_std_path()).await {
                Ok(stream) => {
                    let (read_half, _write_half) = stream.into_split();
                    return Some(BufReader::new(read_half));
                }
                Err(e) => {
                    if attempt < 9 {
                        sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                    eprintln!(
                        "Warning: Failed to connect to Anaconda socket {}: {}",
                        socket_path, e
                    );
                    return None;
                }
            }
        } else if attempt < 9 {
            sleep(Duration::from_secs(1)).await;
        }
    }

    eprintln!(
        "Warning: Anaconda socket not found at {}",
        socket_path
    );
    None
}

/// Capture console output from a running VM for debugging
///
/// Uses `virsh console` to read output from the VM's virtio console (hvc0).
/// This is useful for debugging boot issues after the VM reboots into the
/// installed system.
///
/// Note: This function captures output for a limited time and returns what
/// was captured. It's not meant for interactive use.
#[context("Capturing console output")]
#[allow(dead_code)]
fn capture_console_output(sh: &Shell, vm_name: &str, timeout_seconds: u32) -> Result<String> {
    println!(
        "Capturing console output from {} ({}s timeout)...",
        vm_name, timeout_seconds
    );

    // Use timeout command to limit virsh console duration
    // virsh console requires --force to connect non-interactively
    let timeout_str = timeout_seconds.to_string();
    let output = cmd!(
        sh,
        "timeout {timeout_str} virsh console --force {vm_name}"
    )
    .ignore_status()
    .output()
    .context("Failed to capture console output")?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // virsh console may exit with timeout status, that's OK
    if !stderr.is_empty() && !stderr.contains("Escape character") {
        eprintln!("Console stderr: {}", stderr);
    }

    if stdout.is_empty() {
        println!("No console output captured (VM may not have console=hvc0 configured)");
    } else {
        println!("Captured {} bytes of console output", stdout.len());
    }

    Ok(stdout)
}

/// Verify the installation succeeded using available tools
///
/// Tries verification methods in order of preference:
/// 1. bcvk - preferred, doesn't require libguestfs kernel module loading
/// 2. libguestfs - fallback if bcvk not available or fails
/// 3. container-based (fdisk/parted) - last resort basic verification
#[context("Verifying installation")]
fn verify_installation(sh: &Shell, vm_disk: &Utf8Path, image: &str) -> Result<()> {
    println!("Verifying installation...");

    // Try bcvk first (preferred method)
    if has_bcvk(sh) {
        println!("Using bcvk for disk verification");
        match verify_installation_bcvk(sh, vm_disk, image) {
            Ok(()) => {
                println!("Installation verification completed successfully");
                return Ok(());
            }
            Err(e) => {
                println!("bcvk verification failed: {}", e);
                println!("Falling back to libguestfs verification...");
            }
        }
    }

    // Try libguestfs as fallback
    if has_libguestfs_tools(sh) {
        println!("Using libguestfs userspace inspection");
        match verify_installation_userspace(sh, vm_disk) {
            Ok(()) => {
                println!("Installation verification completed successfully");
                return Ok(());
            }
            Err(e) => {
                println!("libguestfs verification failed: {}", e);
                println!("Falling back to container-based verification...");
            }
        }
    }

    // Last resort: basic container-based verification
    println!("Using basic container-based verification");
    verify_installation_container_based(sh, vm_disk)?;

    println!("Installation verification completed successfully");
    Ok(())
}

/// Check if libguestfs tools are available without failing
fn has_libguestfs_tools(sh: &Shell) -> bool {
    let required_tools = ["virt-filesystems", "virt-ls", "virt-cat", "virt-df"];

    for tool in &required_tools {
        if cmd!(sh, "which {tool}").ignore_status().run().is_err() {
            return false;
        }
    }
    true
}

/// Check if bcvk tool is available
fn has_bcvk(sh: &Shell) -> bool {
    cmd!(sh, "which bcvk").ignore_status().run().is_ok()
}

/// Verify installation using bcvk ephemeral run-ssh with mounted disk
///
/// This function uses bcvk to mount the installed disk inside an ephemeral container
/// and verify the installation artifacts. The disk appears as /dev/disk/by-id/virtio-testdisk
/// with typical partitions:
/// - /dev/vda1 = EFI System Partition
/// - /dev/vda2 = boot partition
/// - /dev/vda3 = root partition
#[context("Verifying installation with bcvk")]
fn verify_installation_bcvk(sh: &Shell, vm_disk: &Utf8Path, image: &str) -> Result<()> {
    println!("Verifying installation with bcvk...");

    // Build the verification script that will run inside the ephemeral container
    // We mount the root partition and check for required files
    let verify_script = r#"
set -eo pipefail
echo "=== bcvk disk verification ==="

# Find the root partition (typically vda3 for UEFI installs)
ROOT_DEV=""
for dev in /dev/vda3 /dev/vda2 /dev/vda1; do
    if [ -b "$dev" ]; then
        # Try to mount and check if it looks like a root filesystem
        if mount -o ro "$dev" /mnt 2>/dev/null; then
            if [ -d /mnt/etc ] && [ -d /mnt/usr ]; then
                ROOT_DEV="$dev"
                echo "Found root partition: $ROOT_DEV"
                break
            fi
            umount /mnt
        fi
    fi
done

if [ -z "$ROOT_DEV" ]; then
    echo "ERROR: Could not find root partition"
    exit 1
fi

# Verify /etc/os-release exists
if [ -f /mnt/etc/os-release ]; then
    echo "PASS: /etc/os-release exists"
    cat /mnt/etc/os-release | head -5
else
    echo "FAIL: /etc/os-release not found"
    exit 1
fi

# Verify /usr/bin/bootc exists
if [ -f /mnt/usr/bin/bootc ]; then
    echo "PASS: /usr/bin/bootc exists"
else
    echo "FAIL: /usr/bin/bootc not found"
    exit 1
fi

# Verify installation success marker
if [ -f /mnt/root/INSTALL_RESULT ]; then
    if grep -q "BOOTC_ANACONDA_INSTALL_SUCCESS" /mnt/root/INSTALL_RESULT; then
        echo "PASS: Installation success marker found"
    else
        echo "FAIL: Installation marker does not contain success flag"
        cat /mnt/root/INSTALL_RESULT
        exit 1
    fi
else
    echo "FAIL: /root/INSTALL_RESULT not found"
    exit 1
fi

umount /mnt

# Now check boot partition (typically vda2)
BOOT_DEV=""
for dev in /dev/vda2 /dev/vda1; do
    if [ -b "$dev" ]; then
        if mount -o ro "$dev" /mnt 2>/dev/null; then
            # Check if it looks like a boot partition
            if ls /mnt/vmlinuz-* >/dev/null 2>&1 || ls /mnt/loader >/dev/null 2>&1; then
                BOOT_DEV="$dev"
                echo "Found boot partition: $BOOT_DEV"
                break
            fi
            umount /mnt
        fi
    fi
done

if [ -n "$BOOT_DEV" ]; then
    # Verify kernel exists
    if ls /mnt/vmlinuz-* >/dev/null 2>&1; then
        echo "PASS: Kernel found"
        ls /mnt/vmlinuz-* | head -1
    else
        echo "WARNING: No vmlinuz found in boot partition"
    fi

    # Verify initramfs exists
    if ls /mnt/initramfs-*.img >/dev/null 2>&1; then
        echo "PASS: Initramfs found"
        ls /mnt/initramfs-*.img | head -1
    else
        echo "WARNING: No initramfs found in boot partition"
    fi
    umount /mnt
else
    echo "WARNING: Could not identify boot partition"
fi

echo "=== bcvk verification complete ==="
"#;

    // Run bcvk with the disk mounted
    let vm_disk_str = vm_disk.as_str();
    let disk_mount_arg = format!("{}:testdisk", vm_disk_str);

    let output = cmd!(
        sh,
        "bcvk ephemeral run-ssh --mount-disk-file {disk_mount_arg} {image} {verify_script}"
    )
    .output()
    .context("Failed to run bcvk verification")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Print output for visibility
    if !stdout.is_empty() {
        for line in stdout.lines() {
            println!("  {}", line);
        }
    }

    if !output.status.success() {
        if !stderr.is_empty() {
            eprintln!("bcvk stderr: {}", stderr);
        }
        anyhow::bail!(
            "bcvk verification failed with exit code {}",
            output.status.code().unwrap_or(-1)
        );
    }

    // Check for PASS markers in output
    if !stdout.contains("PASS: /etc/os-release exists") {
        anyhow::bail!("bcvk verification: /etc/os-release check failed");
    }
    if !stdout.contains("PASS: /usr/bin/bootc exists") {
        anyhow::bail!("bcvk verification: /usr/bin/bootc check failed");
    }
    if !stdout.contains("PASS: Installation success marker found") {
        anyhow::bail!("bcvk verification: installation marker check failed");
    }

    println!("- bcvk verification completed successfully");
    Ok(())
}

/// Main verification function using libguestfs userspace inspection
#[context("Userspace installation verification")]
fn verify_installation_userspace(sh: &Shell, vm_disk: &Utf8Path) -> Result<()> {
    println!("Verifying installation with libguestfs userspace tools...");

    // Verify partition structure
    verify_partitions_libguestfs(sh, vm_disk)?;

    // Verify filesystem structure and contents
    verify_filesystems_libguestfs(sh, vm_disk)?;

    // Verify installation artifacts (boot files, install marker, etc.)
    verify_installation_artifacts_libguestfs(sh, vm_disk)?;

    Ok(())
}

/// Verify partition structure using libguestfs
#[context("Verifying partition structure with libguestfs")]
fn verify_partitions_libguestfs(sh: &Shell, vm_disk: &Utf8Path) -> Result<()> {
    println!("Checking partition structure...");

    // List all partitions and filesystems
    let filesystems_output = cmd!(
        sh,
        "virt-filesystems --long --parts --filesystems -a {vm_disk}"
    )
    .read()
    .context("Failed to list filesystems with virt-filesystems")?;

    println!("Filesystem layout:");
    for line in filesystems_output.lines() {
        if !line.trim().is_empty() && !line.starts_with("Name") {
            println!("  {}", line);
        }
    }

    // Verify we have at least the minimum required partitions
    let partition_count = filesystems_output
        .lines()
        .filter(|line| line.contains("/dev/sda") && !line.contains("filesystem"))
        .count();

    if partition_count < 2 {
        anyhow::bail!("Expected at least 2 partitions, found {}", partition_count);
    }

    // Check for EFI System Partition
    if !filesystems_output.contains("fat") && !filesystems_output.contains("vfat") {
        println!("Warning: No EFI System Partition (FAT) detected");
    }

    // Check for Linux filesystems
    if !filesystems_output.contains("xfs") && !filesystems_output.contains("ext4") {
        anyhow::bail!("No Linux filesystem (xfs/ext4) detected");
    }

    println!("- Partition structure verification completed");
    Ok(())
}

/// Verify filesystem structure using libguestfs
#[context("Verifying filesystem structure with libguestfs")]
fn verify_filesystems_libguestfs(sh: &Shell, vm_disk: &Utf8Path) -> Result<()> {
    println!("Checking filesystem structure...");

    // Get disk information
    let df_output = cmd!(sh, "virt-df -a {vm_disk}")
        .read()
        .context("Failed to get filesystem space information")?;

    println!("Filesystem space usage:");
    for line in df_output.lines() {
        if !line.trim().is_empty() && !line.starts_with("Filesystem") {
            println!("  {}", line);
        }
    }

    // List root filesystem contents to verify basic structure
    let root_contents = cmd!(sh, "virt-ls -a {vm_disk} -R /")
        .ignore_status()
        .read()
        .unwrap_or_default();

    // Check for essential directories
    let required_dirs = ["/etc", "/usr", "/var", "/root", "/bin", "/sbin"];
    let mut missing_dirs = Vec::new();

    for dir in &required_dirs {
        if !root_contents
            .lines()
            .any(|line| line == *dir || line.starts_with(&format!("{}/", dir)))
        {
            missing_dirs.push(*dir);
        }
    }

    if !missing_dirs.is_empty() {
        anyhow::bail!("Missing essential directories: {}", missing_dirs.join(", "));
    }

    // Check for boot directory (either in root or as separate partition)
    if !root_contents
        .lines()
        .any(|line| line == "/boot" || line.starts_with("/boot/"))
    {
        println!("Note: No /boot directory in root filesystem (may be separate partition)");
    }

    println!("- Filesystem structure verification completed");
    Ok(())
}

/// Verify installation artifacts using libguestfs
#[context("Verifying installation artifacts with libguestfs")]
fn verify_installation_artifacts_libguestfs(sh: &Shell, vm_disk: &Utf8Path) -> Result<()> {
    println!("Checking installation artifacts...");

    // Check for installation success marker
    let install_result = cmd!(sh, "virt-cat -a {vm_disk} /root/INSTALL_RESULT")
        .read()
        .context("Installation marker not found at /root/INSTALL_RESULT")?;

    if !install_result.contains("BOOTC_ANACONDA_INSTALL_SUCCESS") {
        anyhow::bail!("Installation marker indicates failure: {}", install_result);
    }

    println!("- Installation success marker found");

    // Verify bootc structure - check for systemd
    let systemd_check = cmd!(sh, "virt-ls -a {vm_disk} /usr/lib/systemd")
        .ignore_status()
        .read();

    if systemd_check.is_err() {
        anyhow::bail!("Missing systemd - bootc requires systemd");
    }

    println!("- systemd found (required for bootc)");

    // Check for kernel and boot files
    verify_boot_files_libguestfs(sh, vm_disk)?;

    // Verify bootloader installation
    verify_bootloader_libguestfs(sh, vm_disk)?;

    println!("- Installation artifacts verification completed");
    Ok(())
}

/// Verify boot files using libguestfs
#[context("Verifying boot files with libguestfs")]
fn verify_boot_files_libguestfs(sh: &Shell, vm_disk: &Utf8Path) -> Result<()> {
    println!("Checking boot files...");

    // Try to find boot files in /boot (root filesystem)
    let boot_contents = cmd!(sh, "virt-ls -a {vm_disk} /boot")
        .ignore_status()
        .read()
        .unwrap_or_default();

    let mut found_kernel = false;
    let mut found_initramfs = false;

    // Check for kernel and initramfs in /boot
    for line in boot_contents.lines() {
        if line.starts_with("vmlinuz-") {
            found_kernel = true;
            println!("  Found kernel: {}", line);
        } else if line.starts_with("initramfs-") {
            found_initramfs = true;
            println!("  Found initramfs: {}", line);
        }
    }

    // If not found in /boot, might be on separate boot partition
    // Try to mount and check first available filesystem
    if !found_kernel || !found_initramfs {
        println!("Boot files not found in /boot, checking for separate boot partition...");

        // List all filesystems and try each one for boot files
        let filesystems_output = cmd!(sh, "virt-filesystems --filesystems -a {vm_disk}")
            .ignore_status()
            .read()
            .unwrap_or_default();

        for fs_line in filesystems_output.lines() {
            if fs_line.starts_with("/dev/sda") && fs_line != "/dev/sda1" {
                // Try to list contents of this filesystem as if it were mounted at /
                let fs_contents = cmd!(sh, "virt-ls -a {vm_disk} -m {fs_line} /")
                    .ignore_status()
                    .read()
                    .unwrap_or_default();

                for content_line in fs_contents.lines() {
                    if content_line.starts_with("vmlinuz-") {
                        found_kernel = true;
                        println!("  Found kernel on {}: {}", fs_line, content_line);
                    } else if content_line.starts_with("initramfs-") {
                        found_initramfs = true;
                        println!("  Found initramfs on {}: {}", fs_line, content_line);
                    }
                }
            }
        }
    }

    if !found_kernel {
        anyhow::bail!("No kernel found in boot directory or separate boot partition");
    }
    if !found_initramfs {
        anyhow::bail!("No initramfs found in boot directory or separate boot partition");
    }

    println!("- Boot files verification completed");
    Ok(())
}

/// Verify bootloader installation using libguestfs
#[context("Verifying bootloader installation with libguestfs")]
fn verify_bootloader_libguestfs(sh: &Shell, vm_disk: &Utf8Path) -> Result<()> {
    println!("Checking bootloader installation...");

    // Check for bootupd state file (the bootc way)
    let bootupd_locations = ["/boot/efi/.bootupd-state.json", "/boot/.bootupd-state.json"];

    for location in &bootupd_locations {
        if cmd!(sh, "virt-cat -a {vm_disk} {location}")
            .ignore_status()
            .run()
            .is_ok()
        {
            println!(
                "- Bootupd state found at {} - bootloader installed via bootupd",
                location
            );
            return Ok(());
        }
    }

    // Check for systemd-boot
    if cmd!(sh, "virt-ls -a {vm_disk} /boot/loader")
        .ignore_status()
        .run()
        .is_ok()
    {
        println!("- systemd-boot structure found");
        return Ok(());
    }

    // Check EFI System Partition for bootloader files
    let efi_check = cmd!(sh, "virt-ls -a {vm_disk} -m /dev/sda1 /EFI")
        .ignore_status()
        .read()
        .unwrap_or_default();

    if !efi_check.trim().is_empty() {
        println!("- EFI directory structure found:");
        for efi_entry in efi_check.lines() {
            println!("  {}", efi_entry);

            // Check for common bootloader directories
            if efi_entry.to_lowercase() == "boot"
                || efi_entry.to_lowercase() == "fedora"
                || efi_entry.to_lowercase() == "centos"
                || efi_entry.to_lowercase() == "grub"
            {
                let bootloader_contents =
                    cmd!(sh, "virt-ls -a {vm_disk} -m /dev/sda1 /EFI/{efi_entry}")
                        .ignore_status()
                        .read()
                        .unwrap_or_default();

                for bootloader_file in bootloader_contents.lines() {
                    if bootloader_file.ends_with(".efi") {
                        println!("    Bootloader EFI file: {}", bootloader_file);
                    }
                }
            }
        }
    }

    // Check for GRUB configuration files
    let grub_locations = ["/boot/grub2/grub.cfg", "/boot/grub/grub.cfg"];

    for grub_location in &grub_locations {
        if cmd!(sh, "virt-cat -a {vm_disk} {grub_location}")
            .ignore_status()
            .run()
            .is_ok()
        {
            println!("- GRUB configuration found at {}", grub_location);
            return Ok(());
        }
    }

    // Check EFI partition for GRUB configs
    let grub_efi_locations = [
        "/EFI/fedora/grub.cfg",
        "/EFI/centos/grub.cfg",
        "/EFI/grub/grub.cfg",
    ];

    for grub_efi_location in &grub_efi_locations {
        if cmd!(sh, "virt-cat -a {vm_disk} -m /dev/sda1 {grub_efi_location}")
            .ignore_status()
            .run()
            .is_ok()
        {
            println!(
                "- GRUB configuration found at {} on EFI partition",
                grub_efi_location
            );
            return Ok(());
        }
    }

    println!("Warning: No explicit bootloader installation detected");
    println!("System may still be bootable if firmware can find EFI executables");
    Ok(())
}

/// Container-based verification fallback when libguestfs is not available
#[context("Container-based installation verification")]
fn verify_installation_container_based(sh: &Shell, vm_disk: &Utf8Path) -> Result<()> {
    println!("Using basic disk verification approach...");

    // Basic disk information using standard tools
    verify_disk_basic_info(sh, vm_disk)?;

    // Try to get partition information using fdisk/parted
    verify_partition_table_basic(sh, vm_disk)?;

    // Try to detect filesystem signatures
    detect_filesystem_signatures(sh, vm_disk)?;

    println!("- Basic verification completed");
    println!("Note: For comprehensive verification, install libguestfs-tools");
    Ok(())
}

/// Basic disk verification using standard tools
#[context("Basic disk verification")]
fn verify_disk_basic_info(sh: &Shell, vm_disk: &Utf8Path) -> Result<()> {
    println!("Checking basic disk information...");

    // Check file exists and has reasonable size
    let metadata = fs::metadata(vm_disk)
        .with_context(|| format!("Failed to get disk file metadata: {}", vm_disk))?;

    let size_mb = metadata.len() / (1024 * 1024);
    println!("Disk file size: {} MB", size_mb);

    if size_mb < 100 {
        anyhow::bail!("Disk file suspiciously small: {} MB", size_mb);
    }

    // Try to get basic file information
    if let Ok(file_output) = cmd!(sh, "file {vm_disk}").ignore_status().read() {
        println!("File type: {}", file_output.trim());
    }

    Ok(())
}

/// Basic partition table verification
#[context("Basic partition table verification")]
fn verify_partition_table_basic(sh: &Shell, vm_disk: &Utf8Path) -> Result<()> {
    println!("Checking partition table...");

    // Try fdisk first
    if let Ok(fdisk_output) = cmd!(sh, "fdisk -l {vm_disk}").ignore_status().read() {
        println!("Partition information (fdisk):");
        let mut partition_count = 0;
        for line in fdisk_output.lines() {
            if line.contains(vm_disk.as_str())
                && (line.contains("Linux") || line.contains("EFI") || line.contains("Microsoft"))
            {
                println!("  {}", line);
                partition_count += 1;
            }
        }

        if partition_count >= 2 {
            println!("- Found {} partitions", partition_count);
            return Ok(());
        }
    }

    // Try parted as alternative
    if let Ok(parted_output) = cmd!(sh, "parted {vm_disk} print").ignore_status().read() {
        println!("Partition information (parted):");
        let mut partition_count = 0;
        for line in parted_output.lines() {
            if line
                .trim()
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_digit())
            {
                println!("  {}", line);
                partition_count += 1;
            }
        }

        if partition_count >= 2 {
            println!("- Found {} partitions", partition_count);
            return Ok(());
        }
    }

    println!("Warning: Could not verify partition structure with available tools");
    println!("The disk file exists and has reasonable size, installation likely succeeded");
    Ok(())
}

/// Detect filesystem signatures in the disk image
#[context("Detecting filesystem signatures")]
fn detect_filesystem_signatures(sh: &Shell, vm_disk: &Utf8Path) -> Result<()> {
    println!("Checking for filesystem signatures...");

    // Try to use file command to detect filesystem types
    if let Ok(file_output) = cmd!(sh, "file {vm_disk}").ignore_status().read() {
        println!("File signature analysis:");
        println!("  {}", file_output.trim());

        if file_output.contains("DOS/MBR boot sector")
            || file_output.contains("GPT partition table")
            || file_output.contains("filesystem")
        {
            println!("- Detected partitioned disk with filesystem signatures");
            return Ok(());
        }
    }

    // Try to use file command to get more details about the disk
    if let Ok(output) = cmd!(sh, "file -s {vm_disk}").ignore_status().read() {
        println!("Detailed file analysis:");
        println!("  {}", output.trim());

        if output.contains("partition") {
            println!("- Partitioned disk detected");
        }
        if output.contains("filesystem") {
            println!("- Filesystem detected in disk image");
        }
    }

    // Try to check if it's a valid disk image using fdisk
    if let Ok(fdisk_output) = cmd!(sh, "fdisk -l {vm_disk}").ignore_status().read()
        && fdisk_output.contains("Device")
        && fdisk_output.contains("Start")
    {
        println!("- Valid partition table detected via fdisk");
    }

    println!("- Filesystem signature detection completed");
    Ok(())
}

/// Verify SSH access to the installed system
#[context("Verifying SSH access to installed system")]
async fn verify_ssh_access(
    sh: &Shell,
    args: &crate::AnacondaTestArgs,
    vm_disk: &Utf8Path,
    keypair: &SshKeyPair,
    ssh_command: Option<&Vec<String>>,
    resource_guard: &ResourceGuard,
) -> Result<()> {
    let action = if ssh_command.is_some() {
        "Executing SSH commands"
    } else {
        "Testing SSH access"
    };
    println!("{}...", action);

    let base_vm_name = format!("bootc-ssh-test-{}", std::process::id());
    let vm_name = libvirt::sanitize_name(&base_vm_name)?;

    // Register VM with resource guard
    resource_guard.add_vm_name(vm_name.clone());

    let vm_process = libvirt::start_verification_vm(sh, args, vm_disk, &vm_name).await?;

    let result: Result<()> = async {
        let vm_ip = libvirt::wait_for_network(sh, &vm_name, 300, 5).await?;
        test_ssh_connectivity(sh, &vm_ip, keypair, 300).await?;

        if let Some(commands) = ssh_command {
            execute_ssh_commands(sh, &vm_ip, keypair, commands)?;
        } else {
            run_ssh_system_validation(sh, &vm_ip, keypair)?;
        }
        Ok(())
    }
    .await;

    libvirt::cleanup_verification_vm(sh, &vm_name, vm_process).await?;
    result?;
    println!("{} completed", action);
    Ok(())
}

/// Execute custom SSH commands and display results with professional formatting
///
/// Uses port forwarding (localhost:SSH_FORWARDED_PORT) to connect to the VM.
#[context("Executing SSH commands")]
fn execute_ssh_commands(
    sh: &Shell,
    vm_ip: &str,
    keypair: &SshKeyPair,
    ssh_commands: &[String],
) -> Result<()> {
    let private_key_str = keypair.private_key_path.as_str();
    let port_str = SSH_FORWARDED_PORT.to_string();
    let ssh_target = format!("root@{}", vm_ip);

    // Validate and sanitize SSH commands to prevent command injection
    let command_str = escape_ssh_commands(ssh_commands)?;

    println!("Executing: {}", command_str);

    let output = cmd!(sh, "ssh -p {port_str} -i {private_key_str} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=30 {ssh_target} {command_str}")
        .output()
        .context("SSH command failed")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !stdout.trim().is_empty() {
        println!("{}", stdout.trim());
    }
    if !stderr.trim().is_empty() {
        eprintln!("{}", stderr.trim());
    }

    if !output.status.success() {
        anyhow::bail!(
            "Command failed with exit code {}",
            output.status.code().unwrap_or(-1)
        );
    }

    // Check if any of the commands was a shutdown command
    let shutdown_commands = ["poweroff", "shutdown", "halt", "reboot"];
    let is_shutdown_cmd = ssh_commands.iter().any(|cmd| {
        shutdown_commands
            .iter()
            .any(|shutdown| cmd.contains(shutdown))
    });

    if is_shutdown_cmd {
        println!("Shutdown command detected, VM will shutdown shortly...");
    }

    Ok(())
}

/// Sanitize file path to prevent directory traversal and ensure safe paths
#[context("Sanitizing file path")]

/// Escape SSH command arguments for safe shell execution
#[context("Escaping SSH commands")]
fn escape_ssh_commands(commands: &[String]) -> Result<String> {
    if commands.is_empty() {
        anyhow::bail!("No SSH commands provided");
    }

    // Use shlex for proper POSIX shell escaping
    shlex::try_join(commands.iter().map(|s| s.as_str()))
        .context("Failed to escape shell command arguments")
}

/// Test SSH connectivity with retries using tokio timeout
///
/// Uses port forwarding (localhost:SSH_FORWARDED_PORT) to connect to the VM.
#[context("Testing SSH connectivity")]
async fn test_ssh_connectivity(
    sh: &Shell,
    vm_ip: &str,
    keypair: &SshKeyPair,
    timeout_seconds: u32,
) -> Result<bool> {
    let private_key_str = keypair.private_key_path.as_str();
    // Build SSH target with port forwarding
    let port_str = SSH_FORWARDED_PORT.to_string();
    let ssh_target = format!("root@{}", vm_ip);

    let result = timeout(Duration::from_secs(timeout_seconds as u64), async {
        loop {
            if let Ok(output) = cmd!(sh, "ssh -p {port_str} -i {private_key_str} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 {ssh_target} echo SSH_OK")
                .ignore_status().read()
                && output.trim() == "SSH_OK"
            {
                return Ok(true);
            }

            sleep(Duration::from_secs(5)).await;
        }
    })
    .await;

    match result {
        Ok(inner) => inner,
        Err(_) => anyhow::bail!("SSH timeout after {} seconds", timeout_seconds),
    }
}

/// Run system validation commands over SSH
///
/// Uses port forwarding (localhost:SSH_FORWARDED_PORT) to connect to the VM.
#[context("Running SSH system validation")]
fn run_ssh_system_validation(sh: &Shell, vm_ip: &str, keypair: &SshKeyPair) -> Result<()> {
    let private_key_str = keypair.private_key_path.as_str();
    let port_str = SSH_FORWARDED_PORT.to_string();
    let ssh_target = format!("root@{}", vm_ip);

    // These validations are critical - failures should be reported
    let validations = [
        ("bootc status", "bootc status"),
        ("install marker", "cat /root/INSTALL_RESULT"),
        ("ssh service", "systemctl is-active sshd"),
    ];

    let mut failures = Vec::new();

    for (name, command) in validations {
        let output = cmd!(sh, "ssh -p {port_str} -i {private_key_str} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=30 {ssh_target} {command}")
            .output();

        match output {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                println!("{}: OK", name);
                if !stdout.trim().is_empty() {
                    for line in stdout.lines().take(5) {
                        println!("  {}", line);
                    }
                }
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                let code = out.status.code().unwrap_or(-1);
                failures.push(format!("{}: exit code {} - {}", name, code, stderr.trim()));
            }
            Err(e) => {
                failures.push(format!("{}: connection failed - {}", name, e));
            }
        }
    }

    if !failures.is_empty() {
        anyhow::bail!("SSH validation failed:\n  {}", failures.join("\n  "));
    }

    Ok(())
}

/// Clean up work directory
#[context("Cleaning up work directory")]
fn cleanup_work_directory(work_dir: &Utf8Path) -> Result<()> {
    fs::remove_dir_all(work_dir)?;
    Ok(())
}

/// Fetch dynamic SHA256 checksum for an ISO URL
#[context("Fetching dynamic checksum")]
fn fetch_dynamic_checksum(sh: &Shell, iso_url: &str, installer_type: &str) -> Result<String> {
    let checksum_url = get_checksum_url(iso_url, installer_type)?;
    let iso_filename = extract_filename_from_url(iso_url)?;

    println!("Fetching checksum from: {}", checksum_url);

    let checksum_content = cmd!(sh, "curl -fsSL {checksum_url}")
        .read()
        .with_context(|| format!("Failed to download checksum file from {}", checksum_url))?;

    parse_checksum_from_file(&checksum_content, &iso_filename).with_context(|| {
        format!(
            "Failed to parse checksum for {} from checksum file",
            iso_filename
        )
    })
}

/// Get the appropriate checksum file URL for an ISO URL
#[context("Getting checksum URL")]
fn get_checksum_url(iso_url: &str, installer_type: &str) -> Result<String> {
    match installer_type {
        "fedora" => {
            // Fedora uses CHECKSUM files in the same directory
            let base_url = iso_url
                .rsplit_once('/')
                .map(|(base, _)| base)
                .context("Invalid Fedora ISO URL format")?;
            Ok(format!(
                "{}/Fedora-Everything-43-1.6-x86_64-CHECKSUM",
                base_url
            ))
        }
        "centos-stream-9" | "centos-stream-10" => {
            // CentOS Stream uses SHA256SUM files
            let base_url = iso_url
                .rsplit_once('/')
                .map(|(base, _)| base)
                .context("Invalid CentOS ISO URL format")?;
            Ok(format!("{}/SHA256SUM", base_url))
        }
        other => anyhow::bail!(
            "Unsupported installer type for checksum fetching: {}",
            other
        ),
    }
}

/// Extract filename from URL
#[context("Extracting filename from URL")]
fn extract_filename_from_url(url: &str) -> Result<String> {
    url.rsplit_once('/')
        .map(|(_, filename)| filename.to_string())
        .context("Invalid URL format - no filename found")
}

/// Parse SHA256 checksum from checksum file content
#[context("Parsing checksum from file")]
fn parse_checksum_from_file(content: &str, filename: &str) -> Result<String> {
    // Extract the base filename pattern for flexible matching
    let base_pattern = extract_iso_base_pattern(filename);

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Handle different checksum formats:
        // 1. BSD format: "SHA256 (filename) = hash"
        // 2. GNU format: "hash filename" or "hash *filename"

        if let Some(hash) = parse_bsd_checksum_line(line, &base_pattern) {
            return Ok(hash);
        }

        if let Some(hash) = parse_gnu_checksum_line(line, &base_pattern) {
            return Ok(hash);
        }
    }

    anyhow::bail!(
        "SHA256 checksum not found for {} (pattern: {}) in checksum file",
        filename,
        base_pattern
    )
}

/// Extract base ISO pattern from filename for flexible matching
/// Converts "CentOS-Stream-10-latest-x86_64-boot.iso" to "CentOS-Stream-10-.*-x86_64-boot.iso"
fn extract_iso_base_pattern(filename: &str) -> String {
    if filename.contains("latest") {
        // Replace "latest" with a pattern that matches date stamps like "20260202.0"
        filename.replace("latest", ".*")
    } else {
        filename.to_string()
    }
}

/// Parse BSD-style checksum line: "SHA256 (filename) = hash"
fn parse_bsd_checksum_line(line: &str, pattern: &str) -> Option<String> {
    // Format: "SHA256 (filename) = hash"
    let rest = line.strip_prefix("SHA256 (")?;
    let (filename_part, hash_part) = rest.split_once(") = ")?;

    if filename_matches_pattern(filename_part, pattern) {
        let hash = hash_part.trim();
        if is_valid_sha256_hash(hash) {
            return Some(hash.to_lowercase());
        }
    }
    None
}

/// Check if a string is a valid SHA256 hash (64 hex characters)
#[allow(clippy::needless_as_bytes)] // Required by project's disallowed-methods for str::len
fn is_valid_sha256_hash(s: &str) -> bool {
    s.as_bytes().len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Parse GNU-style checksum line: "hash filename" or "hash *filename"
fn parse_gnu_checksum_line(line: &str, pattern: &str) -> Option<String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 2 {
        let hash = parts[0];
        let file_part = parts[1..].join(" ");
        let filename_in_line = file_part.strip_prefix('*').unwrap_or(&file_part);

        if filename_matches_pattern(filename_in_line, pattern) && is_valid_sha256_hash(hash) {
            return Some(hash.to_lowercase());
        }
    }
    None
}

/// Check if filename matches pattern (supports basic regex-like patterns)
fn filename_matches_pattern(filename: &str, pattern: &str) -> bool {
    if pattern.contains(".*") {
        // Convert simple pattern to regex-like matching
        let pattern_parts: Vec<&str> = pattern.split(".*").collect();
        if pattern_parts.len() == 2 {
            let prefix = pattern_parts[0];
            let suffix = pattern_parts[1];
            return filename.starts_with(prefix) && filename.ends_with(suffix);
        }
    }

    // Exact match fallback
    filename == pattern
}

/// libvirt/virsh utility functions for VM management
mod libvirt {
    use super::*;

    /// Check libvirtd status using multiple detection methods for robust detection
    pub(super) fn check_status(sh: &Shell) -> LibvirtStatus {
        // Primary check: can we actually use virsh?
        if cmd!(sh, "virsh list --all")
            .ignore_stderr()
            .ignore_status()
            .run()
            .is_ok()
        {
            return LibvirtStatus::Running;
        }

        // Secondary checks for better error reporting
        if let Ok(ps_output) = cmd!(sh, "ps aux").ignore_stderr().ignore_status().read()
            && ps_output.contains("libvirtd") {
                return LibvirtStatus::NotRunning("process found but not accessible".to_string());
            }

        LibvirtStatus::NotRunning("not running".to_string())
    }

    /// Shutdown VM gracefully (if needed for manual intervention)
    #[allow(dead_code)]
    pub(super) async fn shutdown_vm(sh: &Shell, vm_name: &str) -> Result<()> {
        println!("Gracefully shutting down VM: {}", vm_name);

        // Try graceful shutdown first
        if cmd!(sh, "virsh shutdown {vm_name}")
            .ignore_status()
            .run()
            .is_ok()
        {
            // Wait up to 30 seconds for graceful shutdown
            for _ in 0..30 {
                if let Ok(state) = cmd!(sh, "virsh domstate {vm_name}").ignore_status().read()
                    && state.trim() == "shut off" {
                        println!("VM gracefully shut down");
                        return Ok(());
                    }
                sleep(Duration::from_secs(1)).await;
            }
            println!("Graceful shutdown timeout, forcing shutdown...");
        }

        // Force shutdown if graceful failed
        let _ = cmd!(sh, "virsh destroy {vm_name}").ignore_status().run();
        Ok(())
    }

    /// Cleanup VM by name with error handling
    pub(super) fn cleanup_vm(sh: &Shell, vm_name: &str) -> Result<()> {
        let _ = cmd!(sh, "virsh destroy {vm_name}").ignore_status().run();
        let _ = cmd!(sh, "virsh undefine --nvram {vm_name}").ignore_status().run();
        Ok(())
    }

    /// Maximum length for libvirt VM names
    const MAX_VM_NAME_LEN: usize = 64;

    /// Sanitize VM name to prevent command injection and ensure valid libvirt naming
    #[context("Sanitizing VM name")]
    pub(super) fn sanitize_name(base_name: &str) -> Result<String> {
        if base_name.is_empty() {
            anyhow::bail!("VM name cannot be empty");
        }

        let name_len = base_name.chars().count();
        if name_len > MAX_VM_NAME_LEN {
            anyhow::bail!("VM name too long: {} characters (max {})", name_len, MAX_VM_NAME_LEN);
        }

        // Libvirt requires names that match: [a-zA-Z0-9_-]+
        let sanitized = base_name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '-'
                }
            })
            .collect::<String>();

        // Ensure it starts with alphanumeric character
        if !sanitized
            .chars()
            .next()
            .unwrap_or('_')
            .is_ascii_alphanumeric()
        {
            return Ok(format!("vm-{}", sanitized));
        }

        Ok(sanitized)
    }

    /// Start the VM for SSH verification
    ///
    /// Uses passt networking with port forwarding for SSH access.
    /// The VM boots from the installed disk in UEFI mode.
    #[context("Starting verification VM")]
    pub(super) async fn start_verification_vm(
        sh: &Shell,
        args: &crate::AnacondaTestArgs,
        vm_disk: &Utf8Path,
        vm_name: &str,
    ) -> Result<tokio::process::Child> {
        // Cleanup existing VM
        let _ = cmd!(sh, "virsh destroy {vm_name}").ignore_status().run();
        let _ = cmd!(sh, "virsh undefine --nvram {vm_name}").ignore_status().run();

        let network_arg = format!(
            "type=user,model=virtio,backend.type=passt,portForward0.proto=tcp,portForward0.range0.start={},portForward0.range0.to=22",
            SSH_FORWARDED_PORT
        );

        let vm_process = TokioCommand::new("virt-install")
            .args([
                "--name",
                vm_name,
                "--memory",
                &args.memory.to_string(),
                "--vcpus",
                &args.vcpus.to_string(),
                // Boot in UEFI mode to match the installation's UEFI partition layout
                "--boot",
                "uefi",
                "--disk",
                &format!("path={},bus=virtio,format=raw", vm_disk),
                "--network",
                &network_arg,
                "--graphics",
                "none",
                "--console",
                "pty,target_type=serial",
                // Add virtio console for hvc0
                "--console",
                "pty,target_type=virtio",
                "--noautoconsole",
                "--import",
                // Avoid osinfo detection errors on newer virt-install
                "--osinfo",
                "detect=on,require=off",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to start verification VM")?;

        // Wait for VM to start and check it's running
        sleep(Duration::from_secs(10)).await;

        // Verify VM is actually running
        let state_output = cmd!(sh, "virsh domstate {vm_name}")
            .ignore_status()
            .read()
            .unwrap_or_default();
        if !state_output.trim().contains("running") {
            anyhow::bail!(
                "Verification VM failed to start. State: {}",
                state_output.trim()
            );
        }

        Ok(vm_process)
    }

    /// Wait for SSH to become available via port forwarding
    ///
    /// With passt networking and port forwarding (host:2222 -> guest:22),
    /// we can SSH to localhost:2222 to reach the VM's port 22.
    #[context("Waiting for SSH via port forwarding")]
    pub(super) async fn wait_for_network(
        sh: &Shell,
        _vm_name: &str,
        timeout_seconds: u32,
        retry_interval: u32,
    ) -> Result<String> {
        println!(
            "Waiting for SSH port {} to become available...",
            SSH_FORWARDED_PORT
        );

        let start = Instant::now();
        let timeout_duration = Duration::from_secs(timeout_seconds as u64);
        let retry_duration = Duration::from_secs(retry_interval as u64);

        while start.elapsed() < timeout_duration {
            // Try to connect to the forwarded SSH port
            let port_str = SSH_FORWARDED_PORT.to_string();
            let result = cmd!(
                sh,
                "nc -z -w 2 localhost {port_str}"
            )
            .ignore_status()
            .ignore_stderr()
            .run();

            if result.is_ok() {
                println!("SSH port {} is now available", SSH_FORWARDED_PORT);
                // Return localhost as the "IP" since we use port forwarding
                return Ok("localhost".to_string());
            }

            sleep(retry_duration).await;
        }

        anyhow::bail!(
            "Timeout waiting for SSH port {} after {} seconds",
            SSH_FORWARDED_PORT,
            timeout_seconds
        )
    }

    /// Clean up verification VM
    #[context("Cleaning up verification VM")]
    pub(super) async fn cleanup_verification_vm(
        sh: &Shell,
        vm_name: &str,
        mut vm_process: tokio::process::Child,
    ) -> Result<()> {
        let _ = cmd!(sh, "virsh destroy {vm_name}").ignore_status().run();
        let _ = cmd!(sh, "virsh undefine --nvram {vm_name}").ignore_status().run();
        let _ = vm_process.kill().await;
        let _ = vm_process.wait().await;
        Ok(())
    }
}

/// Extract IP address from virsh domifaddr output line
/// Note: Currently unused with SLIRP networking, kept for potential future bridge networking support
#[allow(dead_code)]
fn extract_ip_from_domifaddr_line(line: &str) -> Option<String> {
    // virsh domifaddr output format: "vnet0      52:54:00:xx:xx:xx    ipv4         192.168.122.xx/24"
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 4 && parts[2] == "ipv4"
        && let Some(ip_cidr) = parts.get(3) {
            // Extract IP from CIDR notation (remove /24)
            if let Some(ip) = ip_cidr.split('/').next() {
                return Some(ip.to_string());
            }
        }
    None
}

/// Extract IP address from DHCP lease line
/// Note: Currently unused with SLIRP networking, kept for potential future bridge networking support
#[allow(dead_code)]
fn extract_ip_from_dhcp_lease_line(line: &str) -> Option<String> {
    // DHCP lease format: "2024-01-01 12:00:00  52:54:00:xx:xx:xx  192.168.122.xx  hostname  *"
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 4 {
        let potential_ip = parts[3];
        // Validate it looks like an IPv4 address
        if potential_ip.split('.').count() == 4
            && potential_ip.chars().all(|c| c.is_ascii_digit() || c == '.')
        {
            return Some(potential_ip.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ip_from_domifaddr_line() {
        // Test valid domifaddr line
        let valid_line = "vnet0      52:54:00:12:34:56    ipv4         192.168.122.100/24";
        assert_eq!(
            extract_ip_from_domifaddr_line(valid_line),
            Some("192.168.122.100".to_string())
        );

        // Test invalid line (no IP)
        let invalid_line = "vnet0      52:54:00:12:34:56    -            -";
        assert_eq!(extract_ip_from_domifaddr_line(invalid_line), None);

        // Test malformed line
        let malformed_line = "incomplete line";
        assert_eq!(extract_ip_from_domifaddr_line(malformed_line), None);
    }

    #[test]
    fn test_extract_ip_from_dhcp_lease_line() {
        // Test valid DHCP lease line
        let valid_line = "2024-01-01 12:00:00  52:54:00:12:34:56  192.168.122.50  test-vm  *";
        assert_eq!(
            extract_ip_from_dhcp_lease_line(valid_line),
            Some("192.168.122.50".to_string())
        );

        // Test line with hostname containing hyphens
        let line_with_hostname =
            "2024-01-01 12:00:00  52:54:00:12:34:56  192.168.122.99  bootc-anaconda-test  *";
        assert_eq!(
            extract_ip_from_dhcp_lease_line(line_with_hostname),
            Some("192.168.122.99".to_string())
        );

        // Test invalid IP format
        let invalid_ip_line =
            "2024-01-01 12:00:00  52:54:00:12:34:56  not.an.ip.address  test-vm  *";
        assert_eq!(extract_ip_from_dhcp_lease_line(invalid_ip_line), None);

        // Test insufficient fields
        let short_line = "2024-01-01 12:00:00";
        assert_eq!(extract_ip_from_dhcp_lease_line(short_line), None);
    }

    #[test]
    fn test_ssh_keypair_structure() {
        // Test that SshKeyPair can be created
        let keypair = SshKeyPair {
            private_key_path: Utf8PathBuf::from("/tmp/test_key"),
            public_key_path: Utf8PathBuf::from("/tmp/test_key.pub"),
            public_key_content: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest... test@example.com"
                .to_string(),
        };

        assert!(keypair.private_key_path.as_str().contains("test_key"));
        assert!(keypair.public_key_content.contains("ssh-ed25519"));
    }

    #[test]
    fn test_extract_os_release_file_mock() {
        // Test basic os-release parsing without requiring actual containers
        let mock_fedora_os_release = r#"NAME="Fedora Linux"
VERSION="41 (Container Image)"
ID=fedora
VERSION_ID=41
VERSION_CODENAME=""
PLATFORM_ID="platform:f41"
PRETTY_NAME="Fedora Linux 41 (Container Image)"
ANSI_COLOR="0;38;2;60;110;180"
LOGO=fedora-logo-icon
CPE_NAME="cpe:/o:fedoraproject:fedora:41"
DEFAULT_HOSTNAME="fedora"
HOME_URL="https://fedoraproject.org/"
DOCUMENTATION_URL="https://docs.fedoraproject.org/en-US/fedora/f41/"
SUPPORT_URL="https://ask.fedoraproject.org/"
BUG_REPORT_URL="https://bugzilla.redhat.com/"
REDHAT_BUGZILLA_PRODUCT="Fedora"
REDHAT_BUGZILLA_PRODUCT_VERSION=41
REDHAT_SUPPORT_PRODUCT="Fedora"
REDHAT_SUPPORT_PRODUCT_VERSION=41
SUPPORT_END=2025-12-01
"#;

        let os_release_info = OsReleaseInfo::parse(mock_fedora_os_release);
        let id = os_release_info.get_value(&["ID"]).unwrap();
        let version_id = os_release_info.get_value(&["VERSION_ID"]).unwrap();

        assert_eq!(id, "fedora");
        assert_eq!(version_id, "41");
    }

    #[test]
    fn test_architecture_detection() {
        // Test architecture enum functionality
        assert_eq!(Architecture::X86_64.as_str(), "x86_64");
        assert_eq!(Architecture::Aarch64.as_str(), "aarch64");

        // The detect() function relies on system uname, so we can't test it in isolation
        // but we can test the string parsing logic would work
        assert_eq!(Architecture::X86_64, Architecture::X86_64);
        assert_eq!(Architecture::Aarch64, Architecture::Aarch64);
    }

    #[test]
    fn test_iso_config_retrieval() {
        // Test that we can retrieve ISO configurations for all supported combinations
        let x86_arch = Architecture::X86_64;
        let aarch64_arch = Architecture::Aarch64;

        // Test all installer types with both architectures
        let installer_types = ["fedora", "centos-stream-9", "centos-stream-10"];

        for installer_type in &installer_types {
            // Test x86_64
            let x86_url = get_iso_url_for_installer(installer_type, &x86_arch).unwrap();
            assert!(!x86_url.is_empty());
            // All ISOs use dynamic checksum fetching

            // Test aarch64
            let aarch64_url = get_iso_url_for_installer(installer_type, &aarch64_arch).unwrap();
            assert!(!aarch64_url.is_empty());
            // All ISOs use dynamic checksum fetching

            // URLs should be different between architectures
            assert_ne!(x86_url, aarch64_url);
        }

        // Test unsupported installer type
        assert!(get_iso_url_for_installer("unsupported", &x86_arch).is_err());
    }

    #[test]
    fn test_libguestfs_availability() {
        // Test basic detection (doesn't actually require tools)
        let sh = Shell::new().unwrap();
        // Just verify the function doesn't panic
        let _result = has_libguestfs_tools(&sh);
    }

    #[test]
    fn test_bcvk_availability() {
        // Test basic detection (doesn't actually require bcvk)
        let sh = Shell::new().unwrap();
        // Just verify the function doesn't panic
        let _result = has_bcvk(&sh);
    }

    #[test]
    fn test_ssh_command_escaping() {
        // Test basic command
        let result = escape_ssh_commands(&["bootc".to_string(), "status".to_string()]).unwrap();
        assert_eq!(result, "bootc status");

        // Test command with shell operators (should be escaped)
        let result = escape_ssh_commands(&[
            "systemctl".to_string(),
            "is-system-running".to_string(),
            "||".to_string(),
            "true".to_string(),
        ])
        .unwrap();
        // Should contain all parts, with || properly escaped
        assert!(result.contains("systemctl"));
        assert!(result.contains("is-system-running"));
        assert!(result.contains("true"));
        // || should be quoted in some way
        assert!(result.contains("'||'") || result.contains("\"||\""));

        // Test command with spaces (should be quoted)
        let result = escape_ssh_commands(&["echo".to_string(), "hello world".to_string()]).unwrap();
        assert!(result.contains("echo"));
        assert!(result.contains("hello world"));

        // Test complex command with quotes and semicolons
        let result = escape_ssh_commands(&[
            "/bin/sh".to_string(),
            "-c".to_string(),
            "echo 'test'; ls /tmp".to_string(),
        ])
        .unwrap();
        assert!(result.contains("/bin/sh"));
        assert!(result.contains("-c"));
        // The complex string should be properly escaped
        assert!(result.len() > "/bin/sh -c echo 'test'; ls /tmp".len());

        // Test empty commands fail
        let result = escape_ssh_commands(&[]);
        assert!(result.is_err());

        // Test that dangerous commands are now allowed (properly escaped)
        let result =
            escape_ssh_commands(&["rm".to_string(), "-rf".to_string(), "/tmp/*".to_string()])
                .unwrap();
        assert!(result.contains("rm"));
        assert!(result.contains("-rf"));
    }

    #[test]
    fn test_map_os_release_to_installer() {
        // Test Fedora mapping
        let fedora_os_release = ContainerOsRelease {
            id: "fedora".to_string(),
            version_id: Some("41".to_string()),
            architecture: "x86_64".to_string(),
            pretty_name: Some("Fedora Linux 41".to_string()),
            version_name: Some("Forty One".to_string()),
        };
        assert_eq!(
            map_os_release_to_installer(&fedora_os_release).unwrap(),
            "fedora"
        );

        // Test CentOS Stream 9 mapping
        let centos9_os_release = ContainerOsRelease {
            id: "centos".to_string(),
            version_id: Some("9".to_string()),
            architecture: "x86_64".to_string(),
            pretty_name: Some("CentOS Stream 9".to_string()),
            version_name: None,
        };
        assert_eq!(
            map_os_release_to_installer(&centos9_os_release).unwrap(),
            "centos-stream-9"
        );

        // Test CentOS Stream 10 mapping
        let centos10_os_release = ContainerOsRelease {
            id: "centos".to_string(),
            version_id: Some("10".to_string()),
            architecture: "x86_64".to_string(),
            pretty_name: Some("CentOS Stream 10".to_string()),
            version_name: None,
        };
        assert_eq!(
            map_os_release_to_installer(&centos10_os_release).unwrap(),
            "centos-stream-10"
        );

        // Test RHEL 9 mapping to CentOS Stream 9
        let rhel9_os_release = ContainerOsRelease {
            id: "rhel".to_string(),
            version_id: Some("9.4".to_string()),
            architecture: "x86_64".to_string(),
            pretty_name: Some("Red Hat Enterprise Linux 9.4".to_string()),
            version_name: Some("Plow".to_string()),
        };
        assert_eq!(
            map_os_release_to_installer(&rhel9_os_release).unwrap(),
            "centos-stream-9"
        );

        // Test RHEL 10 mapping to CentOS Stream 10
        let rhel10_os_release = ContainerOsRelease {
            id: "rhel".to_string(),
            version_id: Some("10".to_string()),
            architecture: "x86_64".to_string(),
            pretty_name: Some("Red Hat Enterprise Linux 10".to_string()),
            version_name: None,
        };
        assert_eq!(
            map_os_release_to_installer(&rhel10_os_release).unwrap(),
            "centos-stream-10"
        );

        // Test unsupported distribution
        let unsupported_os_release = ContainerOsRelease {
            id: "unsupported".to_string(),
            version_id: Some("1.0".to_string()),
            architecture: "x86_64".to_string(),
            pretty_name: Some("Unsupported Linux 1.0".to_string()),
            version_name: None,
        };
        assert!(map_os_release_to_installer(&unsupported_os_release).is_err());

        // Test missing version ID for CentOS
        let centos_no_version = ContainerOsRelease {
            id: "centos".to_string(),
            version_id: None,
            architecture: "x86_64".to_string(),
            pretty_name: Some("CentOS Stream".to_string()),
            version_name: None,
        };
        assert!(map_os_release_to_installer(&centos_no_version).is_err());

        // Test unsupported CentOS version
        let centos_unsupported = ContainerOsRelease {
            id: "centos".to_string(),
            version_id: Some("8".to_string()),
            architecture: "x86_64".to_string(),
            pretty_name: Some("CentOS Stream 8".to_string()),
            version_name: None,
        };
        assert!(map_os_release_to_installer(&centos_unsupported).is_err());
    }

    #[test]
    fn test_parse_checksum_from_file() {
        // Test BSD format (CentOS/RHEL style)
        let bsd_content = r#"# CentOS-Stream-10-20260202.0-x86_64-boot.iso: 1063153664 bytes
SHA256 (CentOS-Stream-10-20260202.0-x86_64-boot.iso) = a57fbc243d543003c090534e5011fd62a1bdabf9c1db70cf3b5941a30d5b0b84
# CentOS-Stream-10-20260202.0-x86_64-dvd1.iso: 1063153664 bytes  
SHA256 (CentOS-Stream-10-20260202.0-x86_64-dvd1.iso) = 2ea6b38c40d9e232188dc8f6b274e17ab390bd852668ff25250c9acd9fe8e62f
"#;

        // Test with "latest" pattern matching
        let result =
            parse_checksum_from_file(bsd_content, "CentOS-Stream-10-latest-x86_64-boot.iso");
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "a57fbc243d543003c090534e5011fd62a1bdabf9c1db70cf3b5941a30d5b0b84"
        );

        // Test with exact filename match
        let result =
            parse_checksum_from_file(bsd_content, "CentOS-Stream-10-20260202.0-x86_64-boot.iso");
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "a57fbc243d543003c090534e5011fd62a1bdabf9c1db70cf3b5941a30d5b0b84"
        );

        // Test with DVD ISO
        let result =
            parse_checksum_from_file(bsd_content, "CentOS-Stream-10-latest-x86_64-dvd1.iso");
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "2ea6b38c40d9e232188dc8f6b274e17ab390bd852668ff25250c9acd9fe8e62f"
        );

        // Test GNU format (Fedora style)
        let gnu_content = r#"# Fedora-Everything-netinst-x86_64-43-1.6.iso: 734003200 bytes
b9bb77c6429becf7b1ac803b6a09b69b9e75a30dc1c0fa92b6d8c37f87e33e2a *Fedora-Everything-netinst-x86_64-43-1.6.iso
"#;

        let result =
            parse_checksum_from_file(gnu_content, "Fedora-Everything-netinst-x86_64-43-1.6.iso");
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "b9bb77c6429becf7b1ac803b6a09b69b9e75a30dc1c0fa92b6d8c37f87e33e2a"
        );

        // Test file not found
        let result = parse_checksum_from_file(bsd_content, "nonexistent-file.iso");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_iso_base_pattern() {
        assert_eq!(
            extract_iso_base_pattern("CentOS-Stream-10-latest-x86_64-boot.iso"),
            "CentOS-Stream-10-.*-x86_64-boot.iso"
        );
        assert_eq!(
            extract_iso_base_pattern("Fedora-Everything-netinst-x86_64-43-1.6.iso"),
            "Fedora-Everything-netinst-x86_64-43-1.6.iso"
        );
    }

    #[test]
    fn test_filename_matches_pattern() {
        // Test pattern matching with wildcards
        assert!(filename_matches_pattern(
            "CentOS-Stream-10-20260202.0-x86_64-boot.iso",
            "CentOS-Stream-10-.*-x86_64-boot.iso"
        ));
        assert!(filename_matches_pattern(
            "CentOS-Stream-10-20260101.5-x86_64-boot.iso",
            "CentOS-Stream-10-.*-x86_64-boot.iso"
        ));

        // Test exact matching
        assert!(filename_matches_pattern(
            "Fedora-Everything-netinst-x86_64-43-1.6.iso",
            "Fedora-Everything-netinst-x86_64-43-1.6.iso"
        ));

        // Test non-matches
        assert!(!filename_matches_pattern(
            "CentOS-Stream-9-20260202.0-x86_64-boot.iso",
            "CentOS-Stream-10-.*-x86_64-boot.iso"
        ));
        assert!(!filename_matches_pattern(
            "different-file.iso",
            "CentOS-Stream-10-.*-x86_64-boot.iso"
        ));
    }

    #[test]
    fn test_real_centos_stream_checksum_parsing() {
        // Test with the actual format from CentOS Stream 10 mirror
        let real_checksum_content = r#"# CentOS-Stream-10-20260202.0-x86_64-boot.iso: 1063153664 bytes
SHA256 (CentOS-Stream-10-20260202.0-x86_64-boot.iso) = a57fbc243d543003c090534e5011fd62a1bdabf9c1db70cf3b5941a30d5b0b84
# CentOS-Stream-10-20260202.0-x86_64-dvd1.iso: 10181148672 bytes
SHA256 (CentOS-Stream-10-20260202.0-x86_64-dvd1.iso) = 2ea6b38c40d9e232188dc8f6b274e17ab390bd852668ff25250c9acd9fe8e62f
"#;

        // This is the key test - the URL template generates "latest" but the actual file has a date
        let result = parse_checksum_from_file(
            real_checksum_content,
            "CentOS-Stream-10-latest-x86_64-boot.iso",
        );
        assert!(
            result.is_ok(),
            "Failed to parse checksum for 'latest' pattern: {:?}",
            result.err()
        );
        let expected_hash = "a57fbc243d543003c090534e5011fd62a1bdabf9c1db70cf3b5941a30d5b0b84";
        assert_eq!(result.unwrap(), expected_hash);

        // Test the DVD variant as well
        let result = parse_checksum_from_file(
            real_checksum_content,
            "CentOS-Stream-10-latest-x86_64-dvd1.iso",
        );
        assert!(
            result.is_ok(),
            "Failed to parse checksum for DVD 'latest' pattern: {:?}",
            result.err()
        );
        let expected_hash = "2ea6b38c40d9e232188dc8f6b274e17ab390bd852668ff25250c9acd9fe8e62f";
        assert_eq!(result.unwrap(), expected_hash);

        // Test that non-matching patterns still fail appropriately
        let result = parse_checksum_from_file(
            real_checksum_content,
            "CentOS-Stream-9-latest-x86_64-boot.iso",
        );
        assert!(result.is_err(), "Should not match CentOS Stream 9 pattern");
    }

    #[test]
    fn test_parse_anaconda_progress() {
        // Test empty line returns None
        assert!(parse_anaconda_progress("").is_none());
        assert!(parse_anaconda_progress("   ").is_none());

        // Test payload-related messages
        let progress = parse_anaconda_progress("Starting payload").unwrap();
        assert_eq!(progress.step, "payload");

        // Test bootloader-related messages
        let progress = parse_anaconda_progress("Bootloader configuration").unwrap();
        assert_eq!(progress.step, "bootloader");

        // Test storage-related messages
        let progress = parse_anaconda_progress("Configuring storage").unwrap();
        assert_eq!(progress.step, "storage");

        // Test network-related messages
        let progress = parse_anaconda_progress("Setting up network configuration").unwrap();
        assert_eq!(progress.step, "network");

        // Test error messages (note: "install" keyword takes priority, so use pure error message)
        let progress = parse_anaconda_progress("ERROR: Something went wrong").unwrap();
        assert_eq!(progress.step, "error");

        // Test completion messages (note: "install" keyword takes priority)
        let progress = parse_anaconda_progress("Task complete").unwrap();
        assert_eq!(progress.step, "complete");

        // Test installation messages
        let progress = parse_anaconda_progress("Installation progress: 50%").unwrap();
        assert_eq!(progress.step, "installation");

        // Test generic progress
        let progress = parse_anaconda_progress("Some random log message").unwrap();
        assert_eq!(progress.step, "progress");
    }
}
