//! See https://github.com/matklad/cargo-xtask
//! This project now has a Justfile and a Makefile.
//! Commands here are not always intended to be run directly
//! by the user - add commands here which otherwise might
//! end up as a lot of nontrivial bash code.

use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::process::Command;

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use clap::{Args, Parser, Subcommand};
use fn_error_context::context;
use rand::Rng;
use serde::Deserialize;
use xshell::{cmd, Shell};

mod man;

const NAME: &str = "bootc";
const TAR_REPRODUCIBLE_OPTS: &[&str] = &[
    "--sort=name",
    "--owner=0",
    "--group=0",
    "--numeric-owner",
    "--pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime",
];

// VM and SSH connectivity timeouts for bcvk integration
// Cloud-init can take 2-3 minutes to start SSH
const VM_READY_TIMEOUT_SECS: u64 = 60;
const SSH_CONNECTIVITY_MAX_ATTEMPTS: u32 = 60;
const SSH_CONNECTIVITY_RETRY_DELAY_SECS: u64 = 3;

/// Build tasks for bootc
#[derive(Debug, Parser)]
#[command(name = "xtask")]
#[command(about = "Build tasks for bootc", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Generate man pages
    Manpages,
    /// Update generated files (man pages, JSON schemas)
    UpdateGenerated,
    /// Package the source code
    Package,
    /// Package source RPM
    PackageSrpm,
    /// Generate spec file
    Spec,
    /// Run TMT tests using bcvk
    RunTmt(RunTmtArgs),
    /// Provision a VM for manual TMT testing
    TmtProvision(TmtProvisionArgs),
}

/// Arguments for run-tmt command
#[derive(Debug, Args)]
struct RunTmtArgs {
    /// Image name (e.g., "localhost/bootc-integration")
    image: String,

    /// Test plan filters (e.g., "readonly")
    #[arg(value_name = "FILTER")]
    filters: Vec<String>,

    /// Include additional context values
    #[clap(long)]
    context: Vec<String>,

    /// Set environment variables in the test
    #[clap(long)]
    env: Vec<String>,

    /// Preserve VMs after test completion (useful for debugging)
    #[arg(long)]
    preserve_vm: bool,
}

/// Arguments for tmt-provision command
#[derive(Debug, Args)]
struct TmtProvisionArgs {
    /// Image name (e.g., "localhost/bootc-integration")
    image: String,

    /// VM name (defaults to "bootc-tmt-manual-<timestamp>")
    #[arg(value_name = "VM_NAME")]
    vm_name: Option<String>,
}

fn main() {
    use std::io::Write as _;

    use owo_colors::OwoColorize;
    if let Err(e) = try_main() {
        let mut stderr = anstream::stderr();
        // Don't panic if writing fails.
        let _ = writeln!(stderr, "{}{:#}", "error: ".red(), e);
        std::process::exit(1);
    }
}

fn try_main() -> Result<()> {
    // Ensure our working directory is the toplevel (if we're in a git repo)
    {
        if let Ok(toplevel_path) = Command::new("git")
            .args(["rev-parse", "--show-toplevel"])
            .output()
        {
            if toplevel_path.status.success() {
                let path = String::from_utf8(toplevel_path.stdout)?;
                std::env::set_current_dir(path.trim()).context("Changing to toplevel")?;
            }
        }
        // Otherwise verify we're in the toplevel
        if !Utf8Path::new("ADOPTERS.md")
            .try_exists()
            .context("Checking for toplevel")?
        {
            anyhow::bail!("Not in toplevel")
        }
    }

    let cli = Cli::parse();
    let sh = xshell::Shell::new()?;

    match cli.command {
        Commands::Manpages => man::generate_man_pages(&sh),
        Commands::UpdateGenerated => update_generated(&sh),
        Commands::Package => package(&sh),
        Commands::PackageSrpm => package_srpm(&sh),
        Commands::Spec => spec(&sh),
        Commands::RunTmt(args) => run_tmt(&sh, &args),
        Commands::TmtProvision(args) => tmt_provision(&sh, &args),
    }
}

fn gitrev_to_version(v: &str) -> String {
    let v = v.trim().trim_start_matches('v');
    v.replace('-', ".")
}

#[context("Finding gitrev")]
fn gitrev(sh: &Shell) -> Result<String> {
    if let Ok(rev) = cmd!(sh, "git describe --tags --exact-match")
        .ignore_stderr()
        .read()
    {
        Ok(gitrev_to_version(&rev))
    } else {
        // Grab the abbreviated commit
        let abbrev_commit = cmd!(sh, "git rev-parse HEAD")
            .read()?
            .chars()
            .take(10)
            .collect::<String>();
        let timestamp = git_timestamp(sh)?;
        // We always inject the timestamp first to ensure that newer is better.
        Ok(format!("{timestamp}.g{abbrev_commit}"))
    }
}

/// Return a string formatted version of the git commit timestamp, up to the minute
/// but not second because, well, we're not going to build more than once a second.
#[context("Finding git timestamp")]
fn git_timestamp(sh: &Shell) -> Result<String> {
    let ts = cmd!(sh, "git show -s --format=%ct").read()?;
    let ts = ts.trim().parse::<i64>()?;
    let ts = chrono::DateTime::from_timestamp(ts, 0)
        .ok_or_else(|| anyhow::anyhow!("Failed to parse timestamp"))?;
    Ok(ts.format("%Y%m%d%H%M").to_string())
}

struct Package {
    version: String,
    srcpath: Utf8PathBuf,
    vendorpath: Utf8PathBuf,
}

/// Return the timestamp of the latest git commit in seconds since the Unix epoch.
fn git_source_date_epoch(dir: &Utf8Path) -> Result<u64> {
    let o = Command::new("git")
        .args(["log", "-1", "--pretty=%ct"])
        .current_dir(dir)
        .output()?;
    if !o.status.success() {
        anyhow::bail!("git exited with an error: {:?}", o);
    }
    let buf = String::from_utf8(o.stdout).context("Failed to parse git log output")?;
    let r = buf.trim().parse()?;
    Ok(r)
}

/// When using cargo-vendor-filterer --format=tar, the config generated has a bogus source
/// directory. This edits it to refer to vendor/ as a stable relative reference.
#[context("Editing vendor config")]
fn edit_vendor_config(config: &str) -> Result<String> {
    let mut config: toml::Value = toml::from_str(config)?;
    let config = config.as_table_mut().unwrap();
    let source_table = config.get_mut("source").unwrap();
    let source_table = source_table.as_table_mut().unwrap();
    let vendored_sources = source_table.get_mut("vendored-sources").unwrap();
    let vendored_sources = vendored_sources.as_table_mut().unwrap();
    let previous =
        vendored_sources.insert("directory".into(), toml::Value::String("vendor".into()));
    assert!(previous.is_some());

    Ok(config.to_string())
}

#[context("Packaging")]
fn impl_package(sh: &Shell) -> Result<Package> {
    let source_date_epoch = git_source_date_epoch(".".into())?;
    let v = gitrev(sh)?;

    let namev = format!("{NAME}-{v}");
    let p = Utf8Path::new("target").join(format!("{namev}.tar"));
    let prefix = format!("{namev}/");
    cmd!(sh, "git archive --format=tar --prefix={prefix} -o {p} HEAD").run()?;
    // Generate the vendor directory now, as we want to embed the generated config to use
    // it in our source.
    let vendorpath = Utf8Path::new("target").join(format!("{namev}-vendor.tar.zstd"));
    let vendor_config = cmd!(
        sh,
        "cargo vendor-filterer --prefix=vendor --format=tar.zstd {vendorpath}"
    )
    .read()?;
    let vendor_config = edit_vendor_config(&vendor_config)?;
    // Append .cargo/vendor-config.toml (a made up filename) into the tar archive.
    {
        let tmpdir = tempfile::tempdir_in("target")?;
        let tmpdir_path = tmpdir.path();
        let path = tmpdir_path.join("vendor-config.toml");
        std::fs::write(&path, vendor_config)?;
        let source_date_epoch = format!("{source_date_epoch}");
        cmd!(
            sh,
            "tar -r -C {tmpdir_path} {TAR_REPRODUCIBLE_OPTS...} --mtime=@{source_date_epoch} --transform=s,^,{prefix}.cargo/, -f {p} vendor-config.toml"
        )
        .run()?;
    }
    // Compress with zstd
    let srcpath: Utf8PathBuf = format!("{p}.zstd").into();
    cmd!(sh, "zstd --rm -f {p} -o {srcpath}").run()?;

    Ok(Package {
        version: v,
        srcpath,
        vendorpath,
    })
}

fn package(sh: &Shell) -> Result<()> {
    let p = impl_package(sh)?.srcpath;
    println!("Generated: {p}");
    Ok(())
}

fn update_spec(sh: &Shell) -> Result<Utf8PathBuf> {
    let p = Utf8Path::new("target");
    let pkg = impl_package(sh)?;
    let srcpath = pkg.srcpath.file_name().unwrap();
    let v = pkg.version;
    let src_vendorpath = pkg.vendorpath.file_name().unwrap();
    {
        let specin = File::open(format!("contrib/packaging/{NAME}.spec"))
            .map(BufReader::new)
            .context("Opening spec")?;
        let mut o = File::create(p.join(format!("{NAME}.spec"))).map(BufWriter::new)?;
        for line in specin.lines() {
            let line = line?;
            if line.starts_with("Version:") {
                writeln!(o, "# Replaced by cargo xtask spec")?;
                writeln!(o, "Version: {v}")?;
            } else if line.starts_with("Source0") {
                writeln!(o, "Source0: {srcpath}")?;
            } else if line.starts_with("Source1") {
                writeln!(o, "Source1: {src_vendorpath}")?;
            } else {
                writeln!(o, "{line}")?;
            }
        }
    }
    let spec_path = p.join(format!("{NAME}.spec"));
    Ok(spec_path)
}

fn spec(sh: &Shell) -> Result<()> {
    let s = update_spec(sh)?;
    println!("Generated: {s}");
    Ok(())
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
#[serde(rename_all = "PascalCase")]
struct ImageInspect {
    pub id: String,
    pub digest: String,
}

fn impl_srpm(sh: &Shell) -> Result<Utf8PathBuf> {
    {
        let _g = sh.push_dir("target");
        for name in sh.read_dir(".")? {
            if let Some(name) = name.to_str() {
                if name.ends_with(".src.rpm") {
                    sh.remove_path(name)?;
                }
            }
        }
    }
    let pkg = impl_package(sh)?;
    let td = tempfile::tempdir_in("target").context("Allocating tmpdir")?;
    let td = td.keep();
    let td: &Utf8Path = td.as_path().try_into().unwrap();
    let srcpath = &pkg.srcpath;
    cmd!(sh, "mv {srcpath} {td}").run()?;
    let v = pkg.version;
    let src_vendorpath = &pkg.vendorpath;
    cmd!(sh, "mv {src_vendorpath} {td}").run()?;
    {
        let specin = File::open(format!("contrib/packaging/{NAME}.spec"))
            .map(BufReader::new)
            .context("Opening spec")?;
        let mut o = File::create(td.join(format!("{NAME}.spec"))).map(BufWriter::new)?;
        for line in specin.lines() {
            let line = line?;
            if line.starts_with("Version:") {
                writeln!(o, "# Replaced by cargo xtask package-srpm")?;
                writeln!(o, "Version: {v}")?;
            } else {
                writeln!(o, "{line}")?;
            }
        }
    }
    let d = sh.push_dir(td);
    let mut cmd = cmd!(sh, "rpmbuild");
    for k in [
        "_sourcedir",
        "_specdir",
        "_builddir",
        "_srcrpmdir",
        "_rpmdir",
    ] {
        cmd = cmd.arg("--define");
        cmd = cmd.arg(format!("{k} {td}"));
    }
    cmd.arg("--define")
        .arg(format!("_buildrootdir {td}/.build"))
        .args(["-bs", "bootc.spec"])
        .run()?;
    drop(d);
    let mut srpm = None;
    for e in std::fs::read_dir(td)? {
        let e = e?;
        let n = e.file_name();
        let Some(n) = n.to_str() else {
            continue;
        };
        if n.ends_with(".src.rpm") {
            srpm = Some(td.join(n));
            break;
        }
    }
    let srpm = srpm.ok_or_else(|| anyhow::anyhow!("Failed to find generated .src.rpm"))?;
    let dest = Utf8Path::new("target").join(srpm.file_name().unwrap());
    std::fs::rename(&srpm, &dest)?;
    Ok(dest)
}

fn package_srpm(sh: &Shell) -> Result<()> {
    let srpm = impl_srpm(sh)?;
    println!("Generated: {srpm}");
    Ok(())
}

/// Update JSON schema files
#[context("Updating JSON schemas")]
fn update_json_schemas(sh: &Shell) -> Result<()> {
    for (of, target) in [
        ("host", "docs/src/host-v1.schema.json"),
        ("progress", "docs/src/progress-v0.schema.json"),
    ] {
        let schema = cmd!(sh, "cargo run -q -- internals print-json-schema --of={of}").read()?;
        std::fs::write(target, &schema)?;
        println!("Updated {target}");
    }
    Ok(())
}

/// Update all generated files
/// This is the main command developers should use to update generated content.
/// It handles:
/// - Creating new man page templates for new commands
/// - Syncing CLI options to existing man pages
/// - Updating JSON schema files
#[context("Updating generated files")]
fn update_generated(sh: &Shell) -> Result<()> {
    // Update man pages (create new templates + sync options)
    man::update_manpages(sh)?;

    // Update JSON schemas
    update_json_schemas(sh)?;

    Ok(())
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

/// Generate a random alphanumeric suffix for VM names
fn generate_random_suffix() -> String {
    let mut rng = rand::thread_rng();
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    (0..8)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
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
    for tool in ["bcvk", "tmt", "rsync"] {
        cmd!(sh, "which {tool}")
            .ignore_stdout()
            .run()
            .with_context(|| format!("{} is not available in PATH", tool))?;
    }
    Ok(())
}

const COMMON_INST_ARGS: &[&str] = &[
    // We don't use cloud-init with bcvk right now, but it needs to be there for
    // testing-farm+tmt
    "--karg=ds=iid-datasource-none",
    // TODO: Pass down the Secure Boot keys for tests if present
    "--firmware=uefi-insecure",
    "--label=bootc.test=1",
];

/// Run TMT tests using bcvk for VM management
/// This spawns a separate VM per test plan to avoid state leakage between tests.
#[context("Running TMT tests")]
fn run_tmt(sh: &Shell, args: &RunTmtArgs) -> Result<()> {
    // Check dependencies first
    check_dependencies(sh)?;

    let image = &args.image;
    let filter_args = &args.filters;
    let context = args
        .context
        .iter()
        .map(|v| v.as_str())
        .chain(std::iter::once("running_env=image_mode"))
        .map(|v| format!("--context={v}"))
        .collect::<Vec<_>>();
    let preserve_vm = args.preserve_vm;

    println!("Using bcvk image: {}", image);

    // Create tmt-workdir and copy tmt bits to it
    // This works around https://github.com/teemtee/tmt/issues/4062
    let workdir = Utf8Path::new("target/tmt-workdir");
    sh.create_dir(workdir)
        .with_context(|| format!("Creating {}", workdir))?;

    // rsync .fmf and tmt directories to workdir
    cmd!(sh, "rsync -a --delete --force .fmf tmt {workdir}/")
        .run()
        .with_context(|| format!("Copying tmt files to {}", workdir))?;

    // Change to workdir for running tmt commands
    let _dir = sh.push_dir(workdir);

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

    // Filter plans based on user arguments
    if !filter_args.is_empty() {
        let original_count = plans.len();
        plans.retain(|plan| filter_args.iter().any(|arg| plan.contains(arg.as_str())));
        if plans.len() < original_count {
            println!(
                "Filtered from {} to {} plan(s) based on arguments: {:?}",
                original_count,
                plans.len(),
                filter_args
            );
        }
    }

    if plans.is_empty() {
        println!("No test plans found");
        return Ok(());
    }

    println!("Found {} test plan(s): {:?}", plans.len(), plans);

    // Generate a random suffix for VM names
    let random_suffix = generate_random_suffix();

    // Track overall success/failure
    let mut all_passed = true;
    let mut test_results = Vec::new();

    // Run each plan in its own VM
    for plan in plans {
        let plan_name = sanitize_plan_name(plan);
        let vm_name = format!("bootc-tmt-{}-{}", random_suffix, plan_name);

        println!("\n========================================");
        println!("Running plan: {}", plan);
        println!("VM name: {}", vm_name);
        println!("========================================\n");

        // Launch VM with bcvk

        let launch_result = cmd!(
            sh,
            "bcvk libvirt run --name {vm_name} --detach {COMMON_INST_ARGS...} {image}"
        )
        .run()
        .context("Launching VM with bcvk");

        if let Err(e) = launch_result {
            eprintln!("Failed to launch VM for plan {}: {:#}", plan, e);
            all_passed = false;
            test_results.push((plan.to_string(), false));
            continue;
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
        let vm_info = wait_for_vm_ready(sh, &vm_name);
        let (ssh_port, ssh_key) = match vm_info {
            Ok((port, key)) => (port, key),
            Err(e) => {
                eprintln!("Failed to get VM info for plan {}: {:#}", plan, e);
                cleanup_vm();
                all_passed = false;
                test_results.push((plan.to_string(), false));
                continue;
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
                all_passed = false;
                test_results.push((plan.to_string(), false));
                continue;
            }
        };

        let key_path = Utf8PathBuf::try_from(key_file.path().to_path_buf())
            .context("Converting key path to UTF-8");

        let key_path = match key_path {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Failed to convert key path for plan {}: {:#}", plan, e);
                cleanup_vm();
                all_passed = false;
                test_results.push((plan.to_string(), false));
                continue;
            }
        };

        if let Err(e) = std::fs::write(&key_path, ssh_key) {
            eprintln!("Failed to write SSH key for plan {}: {:#}", plan, e);
            cleanup_vm();
            all_passed = false;
            test_results.push((plan.to_string(), false));
            continue;
        }

        // Set proper permissions on the key file (SSH requires 0600)
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            if let Err(e) = std::fs::set_permissions(&key_path, perms) {
                eprintln!("Failed to set key permissions for plan {}: {:#}", plan, e);
                cleanup_vm();
                all_passed = false;
                test_results.push((plan.to_string(), false));
                continue;
            }
        }

        // Verify SSH connectivity
        println!("Verifying SSH connectivity...");
        if let Err(e) = verify_ssh_connectivity(sh, ssh_port, &key_path) {
            eprintln!("SSH verification failed for plan {}: {:#}", plan, e);
            cleanup_vm();
            all_passed = false;
            test_results.push((plan.to_string(), false));
            continue;
        }

        println!("SSH connectivity verified");

        let ssh_port_str = ssh_port.to_string();

        // Run tmt for this specific plan using connect provisioner
        println!("Running tmt tests for plan {}...", plan);

        // Run tmt for this specific plan
        // Note: provision must come before plan for connect to work properly
        let context = context.clone();
        let how = ["--how=connect", "--guest=localhost", "--user=root"];
        let test_result = cmd!(
            sh,
            "tmt {context...} run --all -e TMT_SCRIPTS_DIR=/var/lib/tmt/scripts provision {how...} --port {ssh_port_str} --key {key_path} plan --name {plan}"
        )
        .run();

        // Clean up VM regardless of test result (unless --preserve-vm is set)
        cleanup_vm();

        match test_result {
            Ok(_) => {
                println!("Plan {} completed successfully", plan);
                test_results.push((plan.to_string(), true));
            }
            Err(e) => {
                eprintln!("Plan {} failed: {:#}", plan, e);
                all_passed = false;
                test_results.push((plan.to_string(), false));
            }
        }

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
    }

    // Print summary
    println!("\n========================================");
    println!("Test Summary");
    println!("========================================");
    for (plan, passed) in &test_results {
        let status = if *passed { "PASSED" } else { "FAILED" };
        println!("{}: {}", plan, status);
    }
    println!("========================================\n");

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
fn tmt_provision(sh: &Shell, args: &TmtProvisionArgs) -> Result<()> {
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

    // Launch VM with bcvk
    // Use ds=iid-datasource-none to disable cloud-init for faster boot
    cmd!(
        sh,
        "bcvk libvirt run --name {vm_name} --detach {COMMON_INST_ARGS...} {image}"
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
