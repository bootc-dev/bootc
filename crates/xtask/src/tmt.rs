use std::sync::mpsc;
use std::time::Duration;
use std::usize;

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use fn_error_context::context;
use rand::RngExt;
use xshell::{Shell, cmd};

// Generation markers for integration.fmf
const PLAN_MARKER_BEGIN: &str = "# BEGIN GENERATED PLANS\n";
const PLAN_MARKER_END: &str = "# END GENERATED PLANS\n";

// VM and SSH connectivity timeouts for bcvk integration
// Cloud-init can take 2-3 minutes to start SSH
const VM_READY_TIMEOUT_SECS: u64 = 60;
const SSH_CONNECTIVITY_MAX_ATTEMPTS: u32 = 60;
const SSH_CONNECTIVITY_RETRY_DELAY_SECS: u64 = 3;

// Base args - firmware type will be added dynamically based on secure boot key availability
const COMMON_INST_ARGS: &[&str] = &["--label=bootc.test=1"];

// Metadata field names
const FIELD_TRY_BIND_STORAGE: &str = "try_bind_storage";
const FIELD_SUMMARY: &str = "summary";
const FIELD_ADJUST: &str = "adjust";

const FIELD_FIXME_SKIP_IF_COMPOSEFS: &str = "fixme_skip_if_composefs";
const FIELD_FIXME_SKIP_IF_UKI: &str = "fixme_skip_if_uki";

/// For tests that should only run for composefs systems
/// Ex. composefs-gc
const FIELD_SKIP_IF_OSTREE: &str = "skip_if_ostree";

// bcvk options
const BCVK_OPT_BIND_STORAGE_RO: &str = "--bind-storage-ro";
const ENV_BOOTC_UPGRADE_IMAGE: &str = "BOOTC_upgrade_image";

// Distro identifiers
const DISTRO_CENTOS_9: &str = "centos-9";

// Tests sorted by time taken (descending)
const TESTS_SORTED_BY_TIME: [&str; 23] = [
    // 10+ mins
    "multi-device-esp",
    "composefs-gc-uki",
    "composefs-gc",
    // 5+ mins
    "loader-entries-source",
    "download-only-upgrade",
    "bib-build",
    "rollback",
    "logically-bound-switch",
    "soft-reboot",
    "switch-to-unified",
    "image-pushpull-upgrade",
    "install-no-boot-dir",
    "upgrade-tag",
    "custom-selinux-policy",
    "factory-reset",
    // 3+ mins
    "upgrade-check-status",
    "soft-reboot-selinux-policy",
    "install-bootloader-none",
    "install-outside-container",
    "install-unified-flag",
    "usroverlay",
    "image-upgrade-reboot",
    "install-karg-delete",
];

// Import the argument types from xtask.rs
use crate::bcvk::BcvkInstallOpts;
use crate::{RunTmtArgs, SealState, TmtProvisionArgs, out_of_sync_error};

/// Generate a random alphanumeric suffix for VM names
fn generate_random_suffix() -> String {
    let mut rng = rand::rng();
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    (0..8)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Sanitize a plan name for use in a VM name
/// Replaces non-alphanumeric characters (except - and _) with dashes
/// Returns "plan" if the result would be empty
fn sanitize_plan_name(plan: &str) -> String {
    let sanitized = plan
        .replace('/', "-")
        .replace(|c: char| !c.is_alphanumeric() && c != '-' && c != '_', "-")
        .trim_matches('-')
        .to_string();

    if sanitized.is_empty() {
        "plan".to_string()
    } else {
        sanitized
    }
}

/// Check that required dependencies are available
#[context("Checking dependencies")]
fn check_dependencies(sh: &Shell) -> Result<()> {
    for tool in ["bcvk", "tmt", "rsync", "podman"] {
        cmd!(sh, "which {tool}")
            .ignore_stdout()
            .run()
            .with_context(|| format!("{} is not available in PATH", tool))?;
    }
    Ok(())
}

/// Detect distro from container image by reading os-release
/// Returns distro string like "centos-9" or "fedora-42"
#[context("Detecting distro from image")]
fn detect_distro_from_image(sh: &Shell, image: &str) -> Result<String> {
    let distro = cmd!(
        sh,
        "podman run --rm {image} bash -c '. /usr/lib/os-release && echo $ID-$VERSION_ID'"
    )
    .read()
    .context("Failed to run image as container to detect distro")?;

    let distro = distro.trim();
    if distro.is_empty() {
        anyhow::bail!("Failed to extract distro from os-release");
    }

    Ok(distro.to_string())
}

/// Detect if image is a sealed image by checking for /boot/EFI
/// Sealed images have EFI boot components, non-sealed images don't
/// TODO: Have `bootc container status` expose this in a nice way instead of running podman
#[context("Detecting if image is sealed")]
fn is_sealed_image(sh: &Shell, image: &str) -> Result<bool> {
    let result = cmd!(sh, "podman run --rm {image} ls /boot").read()?;
    Ok(!result.is_empty())
}

/// Detect VARIANT_ID from container image by reading os-release
/// Returns string like "coreos" or empty
#[context("Detecting distro from image")]
fn detect_variantid_from_image(sh: &Shell, image: &str) -> Result<Option<String>> {
    let variant_id = cmd!(
        sh,
        "podman run --net=none --rm {image} bash -c '. /usr/lib/os-release && echo $VARIANT_ID'"
    )
    .read()
    .context("Failed to run image as container to detect distro")?;

    let variant_id = variant_id.trim();
    if variant_id.is_empty() {
        return Ok(None);
    }

    Ok(Some(variant_id.to_string()))
}

/// Check if a distro supports --bind-storage-ro
/// CentOS 9 lacks systemd.extra-unit.* support required for bind-storage-ro
fn distro_supports_bind_storage_ro(distro: &str) -> bool {
    !distro.starts_with(DISTRO_CENTOS_9)
}

/// Wait for a bcvk VM to be ready and return SSH connection info
#[context("Waiting for VM to be ready")]
fn wait_for_vm_ready(sh: &Shell, vm_name: &str) -> Result<(u16, String)> {
    use std::thread;
    use std::time::Duration;

    for attempt in 1..=VM_READY_TIMEOUT_SECS {
        if let Ok(json_output) = cmd!(sh, "bcvk libvirt inspect {vm_name} --format=json")
            .ignore_stderr()
            .read()
        {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&json_output) {
                if let (Some(ssh_port), Some(ssh_key)) = (
                    json.get("ssh_port").and_then(|v| v.as_u64()),
                    json.get("ssh_private_key").and_then(|v| v.as_str()),
                ) {
                    let ssh_port = ssh_port as u16;
                    return Ok((ssh_port, ssh_key.to_string()));
                }
            }
        }

        if attempt < VM_READY_TIMEOUT_SECS {
            thread::sleep(Duration::from_secs(1));
        }
    }

    anyhow::bail!(
        "VM {} did not become ready within {} seconds",
        vm_name,
        VM_READY_TIMEOUT_SECS
    )
}

/// Verify SSH connectivity to the VM
/// Uses a more complex command similar to what TMT runs to ensure full readiness
#[context("Verifying SSH connectivity")]
fn verify_ssh_connectivity(sh: &Shell, port: u16, key_path: &Utf8Path) -> Result<()> {
    use std::thread;
    use std::time::Duration;

    let port_str = port.to_string();
    for attempt in 1..=SSH_CONNECTIVITY_MAX_ATTEMPTS {
        // Test with a complex command like TMT uses (exports + whoami)
        // Use IdentitiesOnly=yes to prevent ssh-agent from offering other keys
        let result = cmd!(
            sh,
            "ssh -i {key_path} -p {port_str} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o IdentitiesOnly=yes root@localhost 'export TEST=value; whoami'"
        )
        .ignore_stderr()
        .read();

        match &result {
            Ok(output) if output.trim() == "root" => {
                return Ok(());
            }
            _ => {}
        }

        if attempt % 10 == 0 {
            println!(
                "Waiting for SSH... attempt {}/{}",
                attempt, SSH_CONNECTIVITY_MAX_ATTEMPTS
            );
        }

        if attempt < SSH_CONNECTIVITY_MAX_ATTEMPTS {
            thread::sleep(Duration::from_secs(SSH_CONNECTIVITY_RETRY_DELAY_SECS));
        }
    }

    anyhow::bail!(
        "SSH connectivity check failed after {} attempts",
        SSH_CONNECTIVITY_MAX_ATTEMPTS
    )
}

#[derive(Debug, Default)]
struct PlanMetadata {
    try_bind_storage: bool,
    skip_if_composefs: bool,
    skip_if_ostree: bool,
    skip_if_uki: bool,
}

/// Parse integration.fmf to extract extra-try_bind_storage for all plans
#[context("Parsing integration.fmf")]
fn parse_plan_metadata(
    plans_file: &Utf8Path,
) -> Result<std::collections::HashMap<String, PlanMetadata>> {
    let content = std::fs::read_to_string(plans_file)?;
    let yaml = serde_yaml::from_str::<serde_yaml::Value>(&content)
        .context("Failed to parse integration.fmf YAML")?;

    let Some(mapping) = yaml.as_mapping() else {
        anyhow::bail!("Expected YAML mapping in integration.fmf");
    };

    let mut plan_metadata: std::collections::HashMap<String, PlanMetadata> =
        std::collections::HashMap::new();

    for (key, value) in mapping {
        let Some(plan_name) = key.as_str() else {
            continue;
        };
        if !plan_name.starts_with("/plan-") {
            continue;
        }

        let Some(plan_data) = value.as_mapping() else {
            continue;
        };

        if let Some(try_bind) = plan_data.get(&serde_yaml::Value::String(format!(
            "extra-{}",
            FIELD_TRY_BIND_STORAGE
        ))) {
            if let Some(b) = try_bind.as_bool() {
                plan_metadata
                    .entry(plan_name.to_string())
                    .and_modify(|m| m.try_bind_storage = b)
                    .or_insert(PlanMetadata {
                        try_bind_storage: b,
                        ..Default::default()
                    });
            }
        }

        if let Some(works_for_composefs) = plan_data.get(&serde_yaml::Value::String(format!(
            "extra-{}",
            FIELD_FIXME_SKIP_IF_COMPOSEFS
        ))) {
            if let Some(b) = works_for_composefs.as_bool() {
                plan_metadata
                    .entry(plan_name.to_string())
                    .and_modify(|m| m.skip_if_composefs = b)
                    .or_insert(PlanMetadata {
                        skip_if_composefs: b,
                        ..Default::default()
                    });
            }
        }

        if let Some(skip_if_uki) = plan_data.get(&serde_yaml::Value::String(format!(
            "extra-{}",
            FIELD_FIXME_SKIP_IF_UKI
        ))) {
            if let Some(b) = skip_if_uki.as_bool() {
                plan_metadata
                    .entry(plan_name.to_string())
                    .and_modify(|m| m.skip_if_uki = b)
                    .or_insert(PlanMetadata {
                        skip_if_uki: b,
                        ..Default::default()
                    });
            }
        }

        if let Some(skip_if_ostree) = plan_data.get(&serde_yaml::Value::String(format!(
            "extra-{}",
            FIELD_SKIP_IF_OSTREE
        ))) {
            if let Some(b) = skip_if_ostree.as_bool() {
                plan_metadata
                    .entry(plan_name.to_string())
                    .and_modify(|m| m.skip_if_ostree = b)
                    .or_insert(PlanMetadata {
                        skip_if_ostree: b,
                        ..Default::default()
                    });
            }
        }
    }

    Ok(plan_metadata)
}

struct RunPlanResult {
    plan_name: String,
    passed: bool,
    time_taken: Option<Duration>,
    run_id: Option<String>,
}

impl RunPlanResult {
    fn new(
        plan_name: String,
        passed: bool,
        time_taken: Option<Duration>,
        run_id: Option<String>,
    ) -> Self {
        Self {
            plan_name,
            passed,
            time_taken,
            run_id,
        }
    }
}

fn run_plan(
    plan: String,
    vm_name: String,
    image: String,
    plan_bcvk_opts: Vec<String>,
    firmware_args: Vec<String>,
    context: Vec<String>,
    tmt_env_vars: Vec<String>,
    arg_env: Vec<String>,
    preserve_vm: bool,
    vm_cpu: String,
    vm_mem_mb: String,
    base_log_dir: Utf8PathBuf,
    bcvk_has_log_dir: bool,
) -> RunPlanResult {
    let sh = match Shell::new() {
        Ok(sh) => sh,
        Err(err) => {
            eprintln!("Failed to create new shell instance: {err:?}");
            return RunPlanResult::new(plan, false, None, None);
        }
    };

    // Set up per-VM log directory for journal + console capture (if bcvk supports it)
    let vm_log_dir = base_log_dir.join(&vm_name);
    let log_dir_args: Vec<String> = if bcvk_has_log_dir {
        if let Err(e) = std::fs::create_dir_all(&vm_log_dir) {
            eprintln!("Creating VM log directory {}: {e:?}", vm_log_dir);
            return RunPlanResult::new(plan, false, None, None);
        }

        println!("VM logs will be written to: {}", vm_log_dir);
        vec![format!("--log-dir=journal,console={}", vm_log_dir)]
    } else {
        vec![]
    };

    // Launch VM with bcvk
    let firmware_args_slice = firmware_args.as_slice();
    let launch_result = cmd!(
            sh,
            "bcvk libvirt run --name {vm_name} --memory {vm_mem_mb} --cpus {vm_cpu} --detach {firmware_args_slice...} {COMMON_INST_ARGS...} {plan_bcvk_opts...} {log_dir_args...} {image}"
        )
        .run()
        .context("Launching VM with bcvk");

    if let Err(e) = launch_result {
        eprintln!("Failed to launch VM for plan {}: {:#}", plan, e);
        return RunPlanResult::new(plan, false, None, None);
    }

    // Ensure VM cleanup happens even on error (unless --preserve-vm is set)
    let cleanup_vm = || {
        if preserve_vm {
            return;
        }
        if let Err(e) = cmd!(sh, "bcvk libvirt rm --stop --force {vm_name}")
            .ignore_stderr()
            .ignore_status()
            .run()
        {
            eprintln!("Warning: Failed to cleanup VM {}: {}", vm_name, e);
        }
    };

    // Wait for VM to be ready and get SSH info
    let vm_info = wait_for_vm_ready(&sh, &vm_name);
    let (ssh_port, ssh_key) = match vm_info {
        Ok((port, key)) => (port, key),
        Err(e) => {
            eprintln!("Failed to get VM info for plan {}: {:#}", plan, e);
            cleanup_vm();
            return RunPlanResult::new(plan, false, None, None);
        }
    };

    println!("VM ready, SSH port: {}", ssh_port);

    // Save SSH private key to a temporary file
    let key_file = tempfile::NamedTempFile::new().context("Creating temporary SSH key file");

    let key_file = match key_file {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to create SSH key file for plan {}: {:#}", plan, e);
            cleanup_vm();
            return RunPlanResult::new(plan, false, None, None);
        }
    };

    let key_path = Utf8PathBuf::try_from(key_file.path().to_path_buf())
        .context("Converting key path to UTF-8");

    let key_path = match key_path {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to convert key path for plan {}: {:#}", plan, e);
            cleanup_vm();
            return RunPlanResult::new(plan, false, None, None);
        }
    };

    if let Err(e) = std::fs::write(&key_path, ssh_key) {
        eprintln!("Failed to write SSH key for plan {}: {:#}", plan, e);
        cleanup_vm();
        return RunPlanResult::new(plan, false, None, None);
    }

    // Set proper permissions on the key file (SSH requires 0600)
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        if let Err(e) = std::fs::set_permissions(&key_path, perms) {
            eprintln!("Failed to set key permissions for plan {}: {:#}", plan, e);
            cleanup_vm();
            return RunPlanResult::new(plan, false, None, None);
        }
    }

    // Verify SSH connectivity
    println!("Verifying SSH connectivity...");
    if let Err(e) = verify_ssh_connectivity(&sh, ssh_port, &key_path) {
        eprintln!("SSH verification failed for plan {}: {:#}", plan, e);
        if bcvk_has_log_dir {
            eprintln!(
                "VM logs (journal + console) may be available at: {}",
                vm_log_dir
            );
        }
        cleanup_vm();
        return RunPlanResult::new(plan, false, None, None);
    }

    println!("SSH connectivity verified");

    let ssh_port_str = ssh_port.to_string();

    let time_start = std::time::Instant::now();

    // Run tmt for this specific plan using connect provisioner
    println!("Running tmt tests for plan {}...", plan);

    // Generate a unique run ID for this test
    // Use the VM name which already contains a random suffix for uniqueness
    let run_id = vm_name.clone();

    // Run tmt for this specific plan
    // Note: provision must come before plan for connect to work properly
    let how = ["--how=connect", "--guest=localhost", "--user=root"];
    let env = ["TMT_SCRIPTS_DIR=/var/lib/tmt/scripts", "BCVK_EXPORT=1"]
        .into_iter()
        .chain(arg_env.iter().map(|v| v.as_str()))
        .chain(tmt_env_vars.iter().map(|v| v.as_str()))
        .flat_map(|v| ["--environment", v]);
    let test_result = cmd!(
            sh,
            "tmt {context...} run --id {run_id} --all {env...} provision {how...} --port {ssh_port_str} --key {key_path} plan --name {plan}"
        )
        .run();

    let elapsed = time_start.elapsed();

    // Log disk usage after each test run to help diagnose "no space left on device" failures
    println!("Disk usage after plan {}:", plan);
    let _ = cmd!(sh, "df -h").run();

    // Clean up VM regardless of test result (unless --preserve-vm is set)
    cleanup_vm();

    let plan_result = match test_result {
        Ok(_) => {
            println!("Plan {} completed successfully", plan);
            RunPlanResult::new(plan, true, Some(elapsed), Some(run_id))
        }
        Err(e) => {
            eprintln!("Plan {} failed: {:#}", plan, e);
            RunPlanResult::new(plan, false, Some(elapsed), Some(run_id))
        }
    };

    // Print VM connection details if preserving
    if preserve_vm {
        // Copy SSH key to a persistent location
        let persistent_key_path = Utf8Path::new("target").join(format!("{}.ssh-key", vm_name));
        if let Err(e) = std::fs::copy(&key_path, &persistent_key_path) {
            eprintln!("Warning: Failed to save persistent SSH key: {}", e);
        } else {
            println!("\n========================================");
            println!("VM preserved for debugging:");
            println!("========================================");
            println!("VM name: {}", vm_name);
            println!("SSH port: {}", ssh_port_str);
            println!("SSH key: {}", persistent_key_path);
            println!("\nTo connect via SSH:");
            println!(
                "  ssh -i {} -p {} -o IdentitiesOnly=yes root@localhost",
                persistent_key_path, ssh_port_str
            );
            println!("\nTo cleanup:");
            println!("  bcvk libvirt rm --stop --force {}", vm_name);
            println!("========================================\n");
        }
    }

    plan_result
}

/// Run TMT tests using bcvk for VM management
/// This spawns a separate VM per test plan to avoid state leakage between tests.
#[context("Running TMT tests")]
pub(crate) fn run_tmt(sh: &Shell, args: &RunTmtArgs) -> Result<()> {
    // Check dependencies first
    check_dependencies(sh)?;

    let image = &args.image;
    let filter_args = &args.filters;

    // Detect distro from the image
    let distro = detect_distro_from_image(sh, image)?;
    // Detect VARIANT_ID from the image
    // As this can not be empty value in context, use "unknown" instead
    let variant_id = detect_variantid_from_image(sh, image)?.unwrap_or("unknown".to_string());

    let context = args
        .context
        .iter()
        .map(|v| format!("--context={}", v))
        .chain(std::iter::once(format!("--context=running_env=image_mode")))
        .chain(std::iter::once(format!("--context=distro={}", distro)))
        .chain(std::iter::once(format!(
            "--context=VARIANT_ID={variant_id}"
        )))
        .collect::<Vec<_>>();
    let preserve_vm = args.preserve_vm;

    println!("Using bcvk image: {}", image);
    println!("Detected distro: {}", distro);
    println!("Detected VARIANT_ID: {variant_id}");

    let bcvk_opts = BcvkInstallOpts {
        composefs_backend: args.composefs_backend,
        bootloader: args.bootloader.clone(),
        filesystem: args.filesystem.clone(),
        seal_state: args.seal_state.clone(),
        kargs: args.karg.clone(),
    };
    let firmware_args = bcvk_opts.firmware_args()?;

    // Create tmt-workdir and copy tmt bits to it
    // This works around https://github.com/teemtee/tmt/issues/4062
    let workdir = Utf8Path::new("target/tmt-workdir");
    sh.create_dir(workdir)
        .with_context(|| format!("Creating {}", workdir))?;

    // rsync .fmf and tmt directories to workdir
    cmd!(sh, "rsync -a --delete --force .fmf tmt {workdir}/")
        .run()
        .with_context(|| format!("Copying tmt files to {}", workdir))?;

    // Workaround for https://github.com/bootc-dev/bcvk/issues/174
    // Save the container image to tar, this will be synced to tested OS
    if variant_id == "coreos" {
        cmd!(
            sh,
            "podman save -q -o {workdir}/tmt/tests/bootc.tar localhost/bootc-coreos:latest"
        )
        .run()
        .with_context(|| format!("Saving container image to tar"))?;
    }

    // Change to workdir for running tmt commands
    let _dir = sh.push_dir(workdir);

    // Parse plan metadata from integration.fmf
    let plans_file = Utf8Path::new("tmt/plans/integration.fmf");
    let plan_metadata = parse_plan_metadata(plans_file)?;

    // Get the list of plans
    println!("Discovering test plans...");
    let plans_output = cmd!(sh, "tmt plan ls")
        .read()
        .context("Getting list of test plans")?;

    let mut plans: Vec<&str> = plans_output
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && line.starts_with("/"))
        .collect();

    let original_plans_count = plans.len();

    // Filter plans based on user arguments
    if !filter_args.is_empty() {
        plans.retain(|plan| filter_args.iter().any(|arg| plan.contains(arg.as_str())));
    }

    if args.composefs_backend {
        plans.retain(|plan| {
            !plan_metadata
                .iter()
                .find(|(key, _)| plan.ends_with(key.as_str()))
                .map(|(_, v)| v.skip_if_composefs)
                .unwrap_or(false)
        });
    } else {
        plans.retain(|plan| {
            !plan_metadata
                .iter()
                .find(|(key, _)| plan.ends_with(key.as_str()))
                .map(|(_, v)| v.skip_if_ostree)
                .unwrap_or(false)
        });
    }

    if matches!(args.boot_type, crate::BootType::Uki) {
        plans.retain(|plan| {
            !plan_metadata
                .iter()
                .find(|(key, _)| plan.ends_with(key.as_str()))
                .map(|(_, v)| v.skip_if_uki)
                .unwrap_or(false)
        });
    }

    if plans.len() < original_plans_count {
        println!(
            "Filtered from {} to {} plan(s) based on arguments: {:?}",
            original_plans_count,
            plans.len(),
            filter_args
        );
    }

    if plans.is_empty() {
        println!("No test plans found");
        return Ok(());
    }

    plans.sort_by_key(|full_plan_name| {
        TESTS_SORTED_BY_TIME
            .iter()
            .position(|test_time| full_plan_name.contains(test_time))
            .unwrap_or(usize::MAX)
    });

    println!("Found {} test plan(s): {:?}", plans.len(), plans);

    // Determine base log directory: CLI flag > TMT_LOG_DIR env var > default.
    // Filter out empty TMT_LOG_DIR (e.g. TMT_LOG_DIR="") to avoid creating
    // log subdirectories in the current working directory.
    let base_log_dir: Utf8PathBuf = if let Some(ref d) = args.log_dir {
        d.clone()
    } else if let Some(env_dir) = std::env::var("TMT_LOG_DIR").ok().filter(|s| !s.is_empty()) {
        Utf8PathBuf::from(env_dir)
    } else {
        Utf8PathBuf::from("/var/tmp/tmt")
    };

    // Probe whether this bcvk supports --log-dir (added in bcvk 0.17).
    // Older installs silently lack it; we skip the flag rather than hard-failing.
    let bcvk_has_log_dir = cmd!(sh, "bcvk libvirt run --help")
        .ignore_stderr()
        .read()
        .map(|help| help.contains("--log-dir"))
        .unwrap_or(false);

    let mut install_opts = Vec::new();

    // Add --filesystem=xfs by default on fedora-coreos
    if variant_id == "coreos" {
        if distro.starts_with("fedora") {
            install_opts.push("--filesystem=xfs".to_string());
        }
    }

    if args.composefs_backend {
        let filesystem = args.filesystem.as_deref().unwrap_or("ext4");
        install_opts.push(format!("--filesystem={}", filesystem));
        install_opts.push("--composefs-backend".into());

        if let Some(b) = &args.bootloader {
            install_opts.push(format!("--bootloader={b}"));
        }
    }

    for k in &args.karg {
        install_opts.push(format!("--karg={k}"));
    }

    let start = std::time::Instant::now();

    println!("Creating base disk...");
    let opts = install_opts.clone();
    cmd!(sh, "bcvk libvirt to-base-disk {opts...} localhost/bootc").run()?;

    println!("Creating base disk took: {:#?}", start.elapsed());

    // Generate a random suffix for VM names
    let random_suffix = generate_random_suffix();

    // Track overall success/failure
    let mut all_passed = true;
    let mut test_results: Vec<RunPlanResult> = Vec::new();

    // Environment variables to pass to tmt (in addition to args.env)
    let mut tmt_env_vars = Vec::new();

    let mut active_threads = 0;

    let num_cpu = std::thread::available_parallelism()
        .map(|c| c.get())
        .unwrap_or(1);

    println!("num_cpu: {num_cpu}");

    let (vm_cpu, vm_mem) = (1, 2048);

    // Leave 1 cpu for the host
    // If there's only 1 cpu (unlikely), then we only run 1 VM
    let avail_cpu = (num_cpu - 1).max(1);

    // More than this and we bottleneck on IO
    let parallel_vms = (avail_cpu / vm_cpu).min(6);

    println!("parallel_vms: {parallel_vms}");

    let (tx, rx) = mpsc::channel::<RunPlanResult>();

    // Run each plan in its own VM
    for plan in plans {
        let plan_name = sanitize_plan_name(plan);
        let vm_name = format!("bootc-tmt-{}-{}", random_suffix, plan_name);

        println!("\n========================================");
        println!("Running plan: {}", plan);
        println!("VM name: {}", vm_name);
        println!("========================================\n");

        // Reset plan-specific environment variables
        tmt_env_vars.clear();

        // Get bcvk-opts based on plan metadata and distro support
        let plan_bcvk_opts = {
            let supports_bind_storage_ro = distro_supports_bind_storage_ro(&distro);

            // Plan names from tmt are like /tmt/plans/integration/plan-01-readonly
            // but metadata keys are like /plan-01-readonly, so match on suffix
            let try_bind_storage = plan_metadata
                .iter()
                .find(|(key, _)| plan.ends_with(key.as_str()))
                .map(|(_, v)| v.try_bind_storage)
                .unwrap_or(false);

            let mut opts = Vec::new();

            // If test wants bind storage and distro supports it, add --bind-storage-ro
            if try_bind_storage && supports_bind_storage_ro {
                opts.push(BCVK_OPT_BIND_STORAGE_RO.to_string());

                // If upgrade image is provided, set it as an environment variable for tmt
                // (not bcvk, as bcvk doesn't support --env)
                if let Some(ref upgrade_img) = args.upgrade_image {
                    tmt_env_vars.push(format!("{}={}", ENV_BOOTC_UPGRADE_IMAGE, upgrade_img));
                }
            } else if try_bind_storage && !supports_bind_storage_ro {
                println!(
                    "Note: Test wants bind storage but skipping on {} (missing systemd.extra-unit.* support)",
                    distro
                );
            }

            opts.extend(bcvk_opts.install_args());

            opts
        };

        let firmware_args = firmware_args.clone();
        let context = context.clone();
        let tmt_env_vars = tmt_env_vars.clone();
        let env = args.env.clone();
        let cloned_plan = plan.to_string();
        let cloned_vm_name = vm_name.to_string();
        let image = image.to_string();
        let vm_mem = vm_mem.to_string();
        let vm_cpu = vm_cpu.to_string();
        let base_log_dir = base_log_dir.clone();

        let tx_clone = tx.clone();
        std::thread::spawn(move || {
            let result = run_plan(
                cloned_plan,
                cloned_vm_name,
                image,
                plan_bcvk_opts,
                firmware_args,
                context,
                tmt_env_vars,
                env,
                preserve_vm,
                vm_cpu,
                vm_mem,
                base_log_dir,
                bcvk_has_log_dir,
            );

            if let Err(e) = tx_clone.send(result) {
                eprintln!("Failed to send result through channel: {}", e);
            }
        });

        active_threads += 1;

        // wait for a thread to complete if we've reached the parallel limit
        if active_threads >= parallel_vms {
            match rx.recv() {
                Ok(plan_result) => {
                    test_results.push(plan_result);
                    active_threads -= 1;
                }
                Err(e) => {
                    eprintln!("Failed to receive result from channel: {}", e);
                    // still decrement to avoid infinite loop
                    // in theory this shouldn't happen as we loop over plans, but
                    // for sanity
                    active_threads -= 1;
                }
            }
        }
    }

    // drop the sender to signal no more messages
    drop(tx);

    // remaining results from channel
    for _ in 0..active_threads {
        match rx.recv() {
            Ok(plan_result) => {
                test_results.push(plan_result);
            }
            Err(e) => {
                eprintln!("Failed to receive remaining result from channel: {}", e);
            }
        }
    }

    // Print summary
    println!("\n========================================");
    println!("Test Summary");
    println!("========================================");

    test_results.sort_by(|a, b| b.time_taken.cmp(&a.time_taken));

    for RunPlanResult {
        plan_name: plan,
        passed,
        time_taken,
        ..
    } in &test_results
    {
        let status = if *passed {
            "PASSED"
        } else {
            all_passed = false;
            "FAILED"
        };
        println!(
            "{}: {} ({:?})",
            plan,
            status,
            time_taken.unwrap_or(Duration::from_secs(0))
        );
    }
    println!("========================================\n");

    // Print detailed error reports for failed tests
    let failed_tests: Vec<_> = test_results
        .iter()
        .filter(|plan_res| !plan_res.passed)
        .collect();

    if !failed_tests.is_empty() {
        println!("\n========================================");
        println!("Detailed Error Reports");
        println!("========================================\n");

        for RunPlanResult {
            plan_name: plan,
            run_id,
            ..
        } in failed_tests
        {
            println!("----------------------------------------");
            println!("Plan: {}", plan);
            println!("----------------------------------------");

            if let Some(id) = run_id {
                println!("Run ID: {}\n", id);

                // Run tmt with the specific run ID and generate verbose report
                let report_result = cmd!(sh, "tmt run -i {id} report -vvv")
                    .ignore_status()
                    .run();

                match report_result {
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!(
                            "Warning: Failed to generate detailed report for {}: {:#}",
                            plan, e
                        );
                    }
                }
            } else {
                println!("Run ID not available - cannot generate detailed report");
            }

            println!("\n");
        }

        println!("========================================\n");
    }

    if !all_passed {
        anyhow::bail!("Some test plans failed");
    }

    Ok(())
}

/// Provision a VM for manual tmt testing
/// Wraps bcvk libvirt run and waits for SSH connectivity
///
/// Prints SSH connection details for use with tmt provision --how connect
#[context("Provisioning VM for TMT")]
pub(crate) fn tmt_provision(sh: &Shell, args: &TmtProvisionArgs) -> Result<()> {
    // Check for bcvk
    if cmd!(sh, "which bcvk").ignore_status().read().is_err() {
        anyhow::bail!("bcvk is not available in PATH");
    }

    let image = &args.image;
    let vm_name = args
        .vm_name
        .clone()
        .unwrap_or_else(|| format!("bootc-tmt-manual-{}", generate_random_suffix()));

    println!("Provisioning VM...");
    println!("  Image: {}", image);
    println!("  VM name: {}\n", vm_name);

    // TODO: Send bootloader param here
    let provision_opts = BcvkInstallOpts {
        seal_state: if is_sealed_image(sh, image)? {
            Some(SealState::Sealed)
        } else {
            None
        },
        ..Default::default()
    };
    let firmware_args = provision_opts.firmware_args()?;

    // Launch VM with bcvk
    // Use ds=iid-datasource-none to disable cloud-init for faster boot
    let firmware_args_slice = firmware_args.as_slice();
    cmd!(
        sh,
        "bcvk libvirt run --name {vm_name} --detach {firmware_args_slice...} {COMMON_INST_ARGS...} {image}"
    )
    .run()
    .context("Launching VM with bcvk")?;

    println!("VM launched, waiting for SSH...");

    // Wait for VM to be ready and get SSH info
    let (ssh_port, ssh_key) = wait_for_vm_ready(sh, &vm_name)?;

    // Save SSH private key to target directory
    let key_dir = Utf8Path::new("target");
    sh.create_dir(key_dir)
        .context("Creating target directory")?;
    let key_path = key_dir.join(format!("{}.ssh-key", vm_name));

    std::fs::write(&key_path, ssh_key).context("Writing SSH key file")?;

    // Set proper permissions on key file (0600)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .context("Setting SSH key file permissions")?;
    }

    println!("SSH key saved to: {}", key_path);

    // Verify SSH connectivity
    verify_ssh_connectivity(sh, ssh_port, &key_path)?;

    println!("\n========================================");
    println!("VM provisioned successfully!");
    println!("========================================");
    println!("VM name: {}", vm_name);
    println!("SSH port: {}", ssh_port);
    println!("SSH key: {}", key_path);
    println!("\nTo use with tmt:");
    println!("  tmt run --all provision --how connect \\");
    println!("    --guest localhost --port {} \\", ssh_port);
    println!("    --user root --key {} \\", key_path);
    println!("    plan --name <PLAN_NAME>");
    println!("\nTo connect via SSH:");
    println!(
        "  ssh -i {} -p {} -o IdentitiesOnly=yes root@localhost",
        key_path, ssh_port
    );
    println!("\nTo cleanup:");
    println!("  bcvk libvirt rm --stop --force {}", vm_name);
    println!("========================================\n");

    Ok(())
}

/// Parse tmt metadata from a test file
/// Looks for:
/// # number: N
/// # extra:
/// #   try_bind_storage: true
/// # tmt:
/// #   (yaml content)
fn parse_tmt_metadata(content: &str) -> Result<Option<TmtMetadata>> {
    let mut number = None;
    let mut in_extra_block = false;
    let mut in_tmt_block = false;
    let mut extra_yaml_lines = Vec::new();
    let mut tmt_yaml_lines = Vec::new();

    for line in content.lines().take(50) {
        let trimmed = line.trim();

        // Look for "# number: N" line
        if let Some(rest) = trimmed.strip_prefix("# number:") {
            number = Some(
                rest.trim()
                    .parse::<u32>()
                    .context("Failed to parse number field")?,
            );
            continue;
        }

        if trimmed == "# extra:" {
            in_extra_block = true;
            in_tmt_block = false;
            continue;
        } else if trimmed == "# tmt:" {
            in_tmt_block = true;
            in_extra_block = false;
            continue;
        } else if in_extra_block || in_tmt_block {
            // Stop if we hit a line that doesn't start with #, or is just "#"
            if !trimmed.starts_with('#') || trimmed == "#" {
                in_extra_block = false;
                in_tmt_block = false;
                continue;
            }
            // Remove the leading # and preserve indentation
            if let Some(yaml_line) = line.strip_prefix('#') {
                if in_extra_block {
                    extra_yaml_lines.push(yaml_line);
                } else {
                    tmt_yaml_lines.push(yaml_line);
                }
            }
        }
    }

    let Some(number) = number else {
        return Ok(None);
    };

    // Parse extra metadata
    let extra_yaml = extra_yaml_lines.join("\n");
    let extra: serde_yaml::Value = if extra_yaml.trim().is_empty() {
        serde_yaml::Value::Mapping(serde_yaml::Mapping::new())
    } else {
        serde_yaml::from_str(&extra_yaml)
            .with_context(|| format!("Failed to parse extra metadata YAML:\n{}", extra_yaml))?
    };

    // Parse tmt metadata
    let tmt_yaml = tmt_yaml_lines.join("\n");
    let tmt: serde_yaml::Value = if tmt_yaml.trim().is_empty() {
        serde_yaml::Value::Mapping(serde_yaml::Mapping::new())
    } else {
        serde_yaml::from_str(&tmt_yaml)
            .with_context(|| format!("Failed to parse tmt metadata YAML:\n{}", tmt_yaml))?
    };

    Ok(Some(TmtMetadata { number, extra, tmt }))
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
struct TmtMetadata {
    /// Test number for ordering and naming
    number: u32,
    /// Extra metadata (try_bind_storage, etc.)
    extra: serde_yaml::Value,
    /// TMT metadata (summary, duration, adjust, require, etc.)
    tmt: serde_yaml::Value,
}

#[derive(Debug, Eq, PartialEq)]
struct TestDef {
    number: u32,
    name: String,
    test_command: String,
    /// Whether this test wants to try bind storage (if distro supports it)
    try_bind_storage: bool,
    /// Whether to skip this test for composefs backend
    skip_if_composefs: bool,
    /// Whether to skip this test for ostree backend
    skip_if_ostree: bool,
    /// Whether to skip this test for images with UKI
    skip_if_uki: bool,
    /// TMT fmf attributes to pass through (summary, duration, adjust, etc.)
    tmt: serde_yaml::Value,
}

impl Ord for TestDef {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.number
            .cmp(&other.number)
            .then_with(|| self.name.cmp(&other.name))
    }
}

impl PartialOrd for TestDef {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Check that tmt generated files are up to date.
/// Fails with an error if any file would change, similar to `cargo fmt --check`.
#[context("Checking TMT generated files")]
pub(crate) fn check_integration() -> Result<()> {
    let tests_fmf_path = Utf8Path::new("tmt/tests/tests.fmf");
    let integration_fmf_path = Utf8Path::new("tmt/plans/integration.fmf");

    let (tests_generated, integration_generated) = generate_integration()?;

    let tests_on_disk = std::fs::read_to_string(tests_fmf_path)
        .with_context(|| format!("Reading {}", tests_fmf_path))?;
    let integration_on_disk = std::fs::read_to_string(integration_fmf_path)
        .with_context(|| format!("Reading {}", integration_fmf_path))?;

    if tests_generated != tests_on_disk {
        return out_of_sync_error(&format!("{tests_fmf_path} is out of date"));
    }
    if integration_generated != integration_on_disk {
        return out_of_sync_error(&format!("{integration_fmf_path} is out of date"));
    }

    Ok(())
}

/// Generate tmt/plans/integration.fmf from test definitions
#[context("Updating TMT integration.fmf")]
pub(crate) fn update_integration() -> Result<()> {
    let tests_fmf_path = Utf8Path::new("tmt/tests/tests.fmf");
    let integration_fmf_path = Utf8Path::new("tmt/plans/integration.fmf");

    let (tests_content, integration_content) = generate_integration()?;

    let needs_update_tests = match std::fs::read_to_string(tests_fmf_path) {
        Ok(existing) => existing != tests_content,
        Err(_) => true,
    };
    if needs_update_tests {
        std::fs::write(tests_fmf_path, &tests_content).context("Writing tests.fmf")?;
        println!("Generated {}", tests_fmf_path);
    } else {
        println!("Unchanged: {}", tests_fmf_path);
    }

    let needs_update_integration = match std::fs::read_to_string(integration_fmf_path) {
        Ok(existing) => existing != integration_content,
        Err(_) => true,
    };
    if needs_update_integration {
        std::fs::write(integration_fmf_path, &integration_content)
            .context("Writing integration.fmf")?;
        println!("Generated {}", integration_fmf_path);
    } else {
        println!("Unchanged: {}", integration_fmf_path);
    }

    Ok(())
}

/// Pure function: compute the content of tests.fmf and integration.fmf from
/// the test file metadata in tmt/tests/booted/, without writing to disk.
/// Returns (tests_fmf_content, integration_fmf_content).
#[context("Generating TMT integration content")]
fn generate_integration() -> Result<(String, String)> {
    // Define tests in order
    let mut tests = vec![];

    // Scan for test-*.nu, test-*.sh, and test-*.py files in tmt/tests/booted/
    let booted_dir = Utf8Path::new("tmt/tests/booted");

    for entry in std::fs::read_dir(booted_dir)
        .with_context(|| format!("Reading directory {}", booted_dir))?
    {
        let entry = entry?;
        let path = entry.path();
        let Some(filename) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        // Extract stem (filename without "test-" prefix and extension)
        let Some(stem) = filename.strip_prefix("test-").and_then(|s| {
            s.strip_suffix(".nu")
                .or_else(|| s.strip_suffix(".sh"))
                .or_else(|| s.strip_suffix(".py"))
        }) else {
            continue;
        };

        let content =
            std::fs::read_to_string(&path).with_context(|| format!("Reading {}", filename))?;

        let metadata = parse_tmt_metadata(&content)
            .with_context(|| format!("Parsing tmt metadata from {}", filename))?
            .with_context(|| format!("Missing tmt metadata in {}", filename))?;

        // Remove number prefix if present (e.g., "01-readonly" -> "readonly", "26-examples-build" -> "examples-build")
        let display_name = stem
            .split_once('-')
            .and_then(|(prefix, suffix)| {
                if prefix.chars().all(|c| c.is_ascii_digit()) {
                    Some(suffix.to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| stem.to_string());

        // Derive relative path from booted_dir
        let relative_path = path
            .strip_prefix("tmt/tests/")
            .with_context(|| format!("Failed to get relative path for {}", filename))?;

        // Determine test command based on file extension
        let test_command = if filename.ends_with(".nu") {
            format!("nu {}", relative_path.display())
        } else if filename.ends_with(".sh") {
            format!("bash {}", relative_path.display())
        } else if filename.ends_with(".py") {
            format!("python3 {}", relative_path.display())
        } else {
            anyhow::bail!("Unsupported test file extension: {}", filename);
        };

        // Check if test wants bind storage
        let try_bind_storage = metadata
            .extra
            .as_mapping()
            .and_then(|m| {
                m.get(&serde_yaml::Value::String(
                    FIELD_TRY_BIND_STORAGE.to_string(),
                ))
            })
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let skip_if_composefs = metadata
            .extra
            .as_mapping()
            .and_then(|m| {
                m.get(&serde_yaml::Value::String(
                    FIELD_FIXME_SKIP_IF_COMPOSEFS.to_string(),
                ))
            })
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let skip_if_ostree = metadata
            .extra
            .as_mapping()
            .and_then(|m| m.get(&serde_yaml::Value::String(FIELD_SKIP_IF_OSTREE.to_string())))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let skip_if_uki = metadata
            .extra
            .as_mapping()
            .and_then(|m| {
                m.get(&serde_yaml::Value::String(
                    FIELD_FIXME_SKIP_IF_UKI.to_string(),
                ))
            })
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        tests.push(TestDef {
            number: metadata.number,
            name: display_name,
            test_command,
            try_bind_storage,
            skip_if_composefs,
            skip_if_ostree,
            skip_if_uki,
            tmt: metadata.tmt,
        });
    }

    tests.sort();

    // Generate single tests.fmf file using structured YAML

    // Build YAML structure
    let mut tests_mapping = serde_yaml::Mapping::new();
    for test in &tests {
        let test_key = format!("/test-{:02}-{}", test.number, test.name);

        // Start with the tmt metadata (summary, duration, adjust, etc.)
        let mut test_value = if let serde_yaml::Value::Mapping(map) = &test.tmt {
            map.clone()
        } else {
            serde_yaml::Mapping::new()
        };

        // Add the test command (derived from file type, not in metadata)
        test_value.insert(
            serde_yaml::Value::String("test".to_string()),
            serde_yaml::Value::String(test.test_command.clone()),
        );

        tests_mapping.insert(
            serde_yaml::Value::String(test_key),
            serde_yaml::Value::Mapping(test_value),
        );
    }

    // Serialize to YAML
    let tests_yaml = serde_yaml::to_string(&serde_yaml::Value::Mapping(tests_mapping))
        .context("Serializing tests to YAML")?;

    // Post-process YAML to add blank lines between tests for readability
    let mut tests_yaml_formatted = String::new();
    for line in tests_yaml.lines() {
        if line.starts_with("/test-") && !tests_yaml_formatted.is_empty() {
            tests_yaml_formatted.push('\n');
        }
        tests_yaml_formatted.push_str(line);
        tests_yaml_formatted.push('\n');
    }

    // Build final content with header
    let mut tests_content = String::new();
    tests_content.push_str("# THIS IS GENERATED CODE - DO NOT EDIT\n");
    tests_content.push_str("# Generated by: cargo xtask tmt\n");
    tests_content.push_str("\n");
    // bootc probes for SELinux mac_admin capability by attempting chcon with
    // an intentionally invalid label, which generates expected AVC denials.
    // Report as informational only in OSCI gating test
    tests_content
        .push_str("# bootc probes for SELinux mac_admin capability by attempting chcon with\n");
    tests_content
        .push_str("# an intentionally invalid label, which generates expected AVC denials.\n");
    tests_content.push_str("# Report as informational only in OSCI gating test\n");
    tests_content.push_str("check:\n");
    tests_content.push_str("  - how: avc\n");
    tests_content.push_str("    result: info\n");
    tests_content.push_str("\n");
    tests_content.push_str(&tests_yaml_formatted);

    // Generate plans section using structured YAML
    let mut plans_mapping = serde_yaml::Mapping::new();
    for test in &tests {
        let plan_key = format!("/plan-{:02}-{}", test.number, test.name);
        let mut plan_value = serde_yaml::Mapping::new();

        // Extract summary from tmt metadata
        if let serde_yaml::Value::Mapping(map) = &test.tmt {
            if let Some(summary) = map.get(&serde_yaml::Value::String(FIELD_SUMMARY.to_string())) {
                plan_value.insert(
                    serde_yaml::Value::String(FIELD_SUMMARY.to_string()),
                    summary.clone(),
                );
            }
        }

        // Build discover section
        let mut discover = serde_yaml::Mapping::new();
        discover.insert(
            serde_yaml::Value::String("how".to_string()),
            serde_yaml::Value::String("fmf".to_string()),
        );
        let test_path = format!("/tmt/tests/tests/test-{:02}-{}", test.number, test.name);
        discover.insert(
            serde_yaml::Value::String("test".to_string()),
            serde_yaml::Value::Sequence(vec![serde_yaml::Value::String(test_path)]),
        );
        plan_value.insert(
            serde_yaml::Value::String("discover".to_string()),
            serde_yaml::Value::Mapping(discover),
        );

        // Extract and add adjust section if present
        if let serde_yaml::Value::Mapping(map) = &test.tmt {
            if let Some(adjust) = map.get(&serde_yaml::Value::String(FIELD_ADJUST.to_string())) {
                plan_value.insert(
                    serde_yaml::Value::String(FIELD_ADJUST.to_string()),
                    adjust.clone(),
                );
            }
        }

        // Add extra-try_bind_storage if test wants it
        if test.try_bind_storage {
            plan_value.insert(
                serde_yaml::Value::String(format!("extra-{}", FIELD_TRY_BIND_STORAGE)),
                serde_yaml::Value::Bool(true),
            );
        }

        if test.skip_if_composefs {
            plan_value.insert(
                serde_yaml::Value::String(format!("extra-{}", FIELD_FIXME_SKIP_IF_COMPOSEFS)),
                serde_yaml::Value::Bool(true),
            );
        }

        if test.skip_if_ostree {
            plan_value.insert(
                serde_yaml::Value::String(format!("extra-{}", FIELD_SKIP_IF_OSTREE)),
                serde_yaml::Value::Bool(true),
            );
        }

        if test.skip_if_uki {
            plan_value.insert(
                serde_yaml::Value::String(format!("extra-{}", FIELD_FIXME_SKIP_IF_UKI)),
                serde_yaml::Value::Bool(true),
            );
        }

        plans_mapping.insert(
            serde_yaml::Value::String(plan_key),
            serde_yaml::Value::Mapping(plan_value),
        );
    }

    // Serialize plans to YAML
    let plans_yaml = serde_yaml::to_string(&serde_yaml::Value::Mapping(plans_mapping))
        .context("Serializing plans to YAML")?;

    // Post-process YAML to add blank lines between plans for readability
    // and fix indentation for test list items
    let mut plans_section = String::new();
    for line in plans_yaml.lines() {
        if line.starts_with("/plan-") && !plans_section.is_empty() {
            plans_section.push('\n');
        }
        // Fix indentation: YAML serializer uses 2-space indent for list items,
        // but we want them at 6 spaces (4 for discover + 2 for test)
        if line.starts_with("    - /tmt/tests/") {
            plans_section.push_str("      ");
            plans_section.push_str(line.trim_start());
        } else {
            plans_section.push_str(line);
        }
        plans_section.push('\n');
    }

    // Build integration.fmf content by splicing the generated plans section
    // between the existing marker lines, preserving hand-written content outside them.
    let integration_fmf_path = Utf8Path::new("tmt/plans/integration.fmf");
    let existing_content =
        std::fs::read_to_string(integration_fmf_path).context("Reading integration.fmf")?;

    let (before_plans, rest) = existing_content
        .split_once(PLAN_MARKER_BEGIN)
        .context("Missing # BEGIN GENERATED PLANS marker in integration.fmf")?;
    let (_old_plans, after_plans) = rest
        .split_once(PLAN_MARKER_END)
        .context("Missing # END GENERATED PLANS marker in integration.fmf")?;

    let integration_content = format!(
        "{}{}{}{}{}",
        before_plans, PLAN_MARKER_BEGIN, plans_section, PLAN_MARKER_END, after_plans
    );

    Ok((tests_content, integration_content))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tmt_metadata_basic() {
        let content = r#"# number: 1
# tmt:
#   summary: Execute booted readonly/nondestructive tests
#   duration: 30m
#
# Run all readonly tests in sequence
use tap.nu
"#;

        let metadata = parse_tmt_metadata(content).unwrap().unwrap();
        assert_eq!(metadata.number, 1);

        // Verify tmt fields are captured
        let tmt = metadata.tmt.as_mapping().unwrap();
        assert_eq!(
            tmt.get(&serde_yaml::Value::String("summary".to_string())),
            Some(&serde_yaml::Value::String(
                "Execute booted readonly/nondestructive tests".to_string()
            ))
        );
        assert_eq!(
            tmt.get(&serde_yaml::Value::String("duration".to_string())),
            Some(&serde_yaml::Value::String("30m".to_string()))
        );
    }

    #[test]
    fn test_parse_tmt_metadata_with_adjust() {
        let content = r#"# number: 27
# tmt:
#   summary: Execute custom selinux policy test
#   duration: 30m
#   adjust:
#     - when: running_env != image_mode
#       enabled: false
#       because: these tests require features only available in image mode
#
use std assert
"#;

        let metadata = parse_tmt_metadata(content).unwrap().unwrap();
        assert_eq!(metadata.number, 27);

        // Verify adjust section is in tmt
        let tmt = metadata.tmt.as_mapping().unwrap();
        assert!(tmt.contains_key(&serde_yaml::Value::String("adjust".to_string())));
    }

    #[test]
    fn test_parse_tmt_metadata_no_metadata() {
        let content = r#"# Just a comment
use std assert
"#;

        let result = parse_tmt_metadata(content).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_tmt_metadata_shell_script() {
        let content = r#"# number: 26
# tmt:
#   summary: Test bootc examples build scripts
#   duration: 45m
#   adjust:
#     - when: running_env != image_mode
#       enabled: false
#
#!/bin/bash
set -eux
"#;

        let metadata = parse_tmt_metadata(content).unwrap().unwrap();
        assert_eq!(metadata.number, 26);

        let tmt = metadata.tmt.as_mapping().unwrap();
        assert_eq!(
            tmt.get(&serde_yaml::Value::String("duration".to_string())),
            Some(&serde_yaml::Value::String("45m".to_string()))
        );
        assert!(tmt.contains_key(&serde_yaml::Value::String("adjust".to_string())));
    }

    #[test]
    fn test_parse_tmt_metadata_with_try_bind_storage() {
        let content = r#"# number: 24
# extra:
#   try_bind_storage: true
# tmt:
#   summary: Execute local upgrade tests
#   duration: 30m
#
use std assert
"#;

        let metadata = parse_tmt_metadata(content).unwrap().unwrap();
        assert_eq!(metadata.number, 24);

        let extra = metadata.extra.as_mapping().unwrap();
        assert_eq!(
            extra.get(&serde_yaml::Value::String("try_bind_storage".to_string())),
            Some(&serde_yaml::Value::Bool(true))
        );

        let tmt = metadata.tmt.as_mapping().unwrap();
        assert_eq!(
            tmt.get(&serde_yaml::Value::String("summary".to_string())),
            Some(&serde_yaml::Value::String(
                "Execute local upgrade tests".to_string()
            ))
        );
    }
}
