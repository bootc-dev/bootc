//! See https://github.com/matklad/cargo-xtask
//! This project now has a Justfile and a Makefile.
//! Commands here are not always intended to be run directly
//! by the user - add commands here which otherwise might
//! end up as a lot of nontrivial bash code.

use std::borrow::Cow;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::process::Command;

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use clap::{Args, Parser, Subcommand};
use fn_error_context::context;
use xshell::{Shell, cmd};

mod anaconda;
mod buildsys;
mod man;
mod tmt;

const NAME: &str = "bootc";
const TAR_REPRODUCIBLE_OPTS: &[&str] = &[
    "--sort=name",
    "--owner=0",
    "--group=0",
    "--numeric-owner",
    "--pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime",
];

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
    /// Check build system properties (e.g., reproducible builds)
    CheckBuildsys,
    /// Validate composefs digests match between build-time and install-time views
    ValidateComposefsDigest(ValidateComposefsDigestArgs),
    /// Print podman bind mount arguments for local path dependencies
    LocalRustDeps(LocalRustDepsArgs),
    /// Run end-to-end Anaconda installation test
    Anaconda(AnacondaTestArgs),
    /// Test container os-release detection and installer mapping
    TestOsRelease(TestOsReleaseArgs),
}

/// Arguments for validate-composefs-digest command
#[derive(Debug, Args)]
pub(crate) struct ValidateComposefsDigestArgs {
    /// Container image to validate (e.g., "localhost/bootc" or "quay.io/centos-bootc/centos-bootc:stream10")
    pub(crate) image: String,
}

/// Arguments for local-rust-deps command
#[derive(Debug, Args)]
pub(crate) struct LocalRustDepsArgs {
    /// Output format: "podman" for -v arguments, "json" for structured data
    #[arg(long, default_value = "podman")]
    pub(crate) format: String,
}

/// Arguments for run-tmt command
#[derive(Debug, Args)]
pub(crate) struct RunTmtArgs {
    /// Image name (e.g., "localhost/bootc")
    pub(crate) image: String,

    /// Test plan filters (e.g., "readonly")
    #[arg(value_name = "FILTER")]
    pub(crate) filters: Vec<String>,

    /// Include additional context values
    #[clap(long)]
    pub(crate) context: Vec<String>,

    /// Set environment variables in the test
    #[clap(long)]
    pub(crate) env: Vec<String>,

    /// Upgrade image to use when bind-storage-ro is available (e.g., localhost/bootc-upgrade)
    #[clap(long)]
    pub(crate) upgrade_image: Option<String>,

    /// Preserve VMs after test completion (useful for debugging)
    #[arg(long)]
    pub(crate) preserve_vm: bool,
}

/// Arguments for tmt-provision command
#[derive(Debug, Args)]
pub(crate) struct TmtProvisionArgs {
    /// Image name (e.g., "localhost/bootc")
    pub(crate) image: String,

    /// VM name (defaults to "bootc-tmt-manual-<timestamp>")
    #[arg(value_name = "VM_NAME")]
    pub(crate) vm_name: Option<String>,
}

/// Arguments for test-os-release command
#[derive(Debug, Args)]
pub(crate) struct TestOsReleaseArgs {
    /// Container image to test os-release detection on
    pub(crate) image: String,
}

/// Arguments for anaconda command
#[derive(Debug, Args)]
pub(crate) struct AnacondaTestArgs {
    /// Container image to test (e.g., "quay.io/fedora/fedora-bootc:41")
    pub(crate) image: String,
    /// Output disk image path (e.g., "/tmp/test-disk.raw")
    pub(crate) output_disk: String,
    /// VM memory in MB
    #[arg(long, default_value = "4096")]
    pub(crate) memory: u32,
    /// Number of virtual CPUs
    #[arg(long, default_value = "2")]
    pub(crate) vcpus: u32,
    /// Installation timeout in minutes
    #[arg(long, default_value = "25")]
    pub(crate) timeout: u32,
    /// Path to installer ISO (auto-download if not provided)
    #[arg(long)]
    pub(crate) installer_iso: Option<String>,
    /// Installer type: fedora, centos-stream-9, centos-stream-10, auto
    #[arg(long, default_value = "auto")]
    pub(crate) installer_type: String,
    /// Custom installer ISO URL
    #[arg(long)]
    pub(crate) installer_url: Option<String>,
    /// Preserve VM for debugging (don't auto-cleanup)
    #[arg(long)]
    pub(crate) preserve_vm: bool,
    /// Dry run mode - validate setup without running VM
    #[arg(long)]
    pub(crate) dry_run: bool,
    /// Enable SSH access to the installed VM and optionally run custom commands
    ///
    /// When used alone, performs default SSH verification including system health checks.
    /// When followed by -- and command arguments, executes the specified command via SSH instead.
    ///
    /// Examples:
    ///   --ssh                              (default verification)
    ///   --ssh -- bootc status             (run single command)  
    ///   --ssh -- "bootc status && uname -a"  (run shell command string)
    #[arg(
        long,
        help = "Enable SSH access with optional custom commands (use -- to specify commands)"
    )]
    pub(crate) ssh: bool,
    /// Custom SSH command to execute (captured after -- separator)
    #[arg(skip)]
    pub(crate) ssh_command: Option<Vec<String>>,
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

/// Parse command line arguments, separating main CLI args from SSH command
///
/// This function splits the original command line arguments at the -- separator,
/// returning the main CLI arguments (for clap parsing) and any SSH command
/// specified after the separator.
fn parse_args_with_ssh_command() -> Result<(Vec<String>, Option<Vec<String>>)> {
    let cmd_args: Vec<String> = std::env::args().collect();

    // Find the position of the -- separator
    if let Some(separator_pos) = cmd_args.iter().position(|arg| arg == "--") {
        // Split arguments at the separator
        let cli_args: Vec<String> = cmd_args.iter().take(separator_pos).cloned().collect();

        let ssh_command: Vec<String> = cmd_args.into_iter().skip(separator_pos + 1).collect();

        let ssh_command = if ssh_command.is_empty() {
            None
        } else {
            Some(ssh_command)
        };

        Ok((cli_args, ssh_command))
    } else {
        // No separator found, return all arguments as CLI args
        Ok((cmd_args, None))
    }
}

fn try_main() -> Result<()> {
    // Ensure our working directory is the toplevel (if we're in a git repo)
    {
        if let Ok(toplevel_path) = Command::new("git")
            .args(["rev-parse", "--show-toplevel"])
            .output()
            && toplevel_path.status.success() {
                let path = String::from_utf8(toplevel_path.stdout)?;
                std::env::set_current_dir(path.trim()).context("Changing to toplevel")?;
            }
        // Otherwise verify we're in the toplevel
        if !Utf8Path::new("ADOPTERS.md")
            .try_exists()
            .context("Checking for toplevel")?
        {
            anyhow::bail!("Not in toplevel")
        }
    }

    // Parse arguments manually to handle SSH command after -- separator
    let (cli_args, ssh_command) = parse_args_with_ssh_command()?;

    // Parse CLI with the filtered arguments
    let mut cli = Cli::parse_from(cli_args);

    // Handle SSH command injection for Anaconda command
    if let Commands::Anaconda(ref mut args) = cli.command
        && args.ssh && ssh_command.is_some() {
            args.ssh_command = ssh_command;
        }

    let sh = xshell::Shell::new()?;

    match cli.command {
        Commands::Manpages => man::generate_man_pages(&sh),
        Commands::UpdateGenerated => update_generated(&sh),
        Commands::Package => package(&sh),
        Commands::PackageSrpm => package_srpm(&sh),
        Commands::Spec => spec(&sh),
        Commands::RunTmt(args) => tmt::run_tmt(&sh, &args),
        Commands::TmtProvision(args) => tmt::tmt_provision(&sh, &args),
        Commands::CheckBuildsys => buildsys::check_buildsys(&sh, "Dockerfile".into()),
        Commands::ValidateComposefsDigest(args) => validate_composefs_digest(&sh, &args),
        Commands::LocalRustDeps(args) => local_rust_deps(&sh, &args),
        Commands::TestOsRelease(args) => anaconda::test_os_release_detection(&sh, &args),
        Commands::Anaconda(args) => anaconda::run_anaconda_test(&sh, &args),
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
fn impl_srpm(sh: &Shell) -> Result<Utf8PathBuf> {
    {
        let _g = sh.push_dir("target");
        for name in sh.read_dir(".")? {
            if let Some(name) = name.to_str()
                && name.ends_with(".src.rpm") {
                    sh.remove_path(name)?;
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

    // Update TMT integration.fmf
    tmt::update_integration()?;

    Ok(())
}

/// Find local path dependencies outside the workspace and output podman bind mount arguments.
///
/// This uses `cargo metadata` to find all packages with no source (i.e., local path deps).
/// For packages outside the workspace root, it computes the minimal set of directories
/// to bind mount into the container.
#[context("Finding local Rust dependencies")]
fn local_rust_deps(_sh: &Shell, args: &LocalRustDepsArgs) -> Result<()> {
    let metadata = cargo_metadata::MetadataCommand::new()
        .exec()
        .context("Running cargo metadata")?;

    let workspace_root = &metadata.workspace_root;

    let mut external_roots: std::collections::BTreeSet<Utf8PathBuf> =
        std::collections::BTreeSet::new();

    for pkg in &metadata.packages {
        // Packages with source are from registries/git, skip them
        if pkg.source.is_some() {
            continue;
        }

        // Get the package directory (parent of Cargo.toml)
        let pkg_dir = pkg
            .manifest_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("No parent for manifest_path"))?;

        // Skip packages inside the workspace
        if pkg_dir.starts_with(workspace_root) {
            continue;
        }

        // Find the workspace root for this external package by running cargo metadata
        // in the package directory
        let external_metadata = cargo_metadata::MetadataCommand::new()
            .current_dir(pkg_dir)
            .exec()
            .with_context(|| format!("Running cargo metadata in {pkg_dir}"))?;

        external_roots.insert(external_metadata.workspace_root.clone());
    }

    match args.format.as_str() {
        "podman" => {
            // Output podman -v arguments
            let mut args_out = Vec::new();
            for root in &external_roots {
                // Map /home/... -> /var/home/... for the container destination.
                // bootc images have /home as a symlink to /var/home, but /var/home
                // may not exist in the base image. Mounting to /var/home/... creates
                // the directory, and cargo can then access it via /home/... symlink.
                let dest: Cow<'_, str> = if let Some(suffix) = root.as_str().strip_prefix("/home/")
                {
                    format!("/var/home/{suffix}").into()
                } else {
                    root.as_str().into()
                };
                // Mount read-only with SELinux disabled (for cross-context access)
                args_out.push("-v".to_string());
                args_out.push(format!("{}:{}:ro", root, dest));
                args_out.push("--security-opt=label=disable".to_string());
            }
            if !args_out.is_empty() {
                println!("{}", args_out.join(" "));
            }
        }
        "json" => {
            let roots: Vec<&str> = external_roots.iter().map(|p| p.as_str()).collect();
            println!("{}", serde_json::to_string_pretty(&roots)?);
        }
        other => {
            anyhow::bail!("Unknown format: {other}. Use 'podman' or 'json'.");
        }
    }

    Ok(())
}

/// Validate that composefs digests match between build-time and install-time views.
///
/// Compares dumpfiles generated from:
/// 1. The mounted filesystem (what seal-uki sees at build time via --mount=type=image)
/// 2. The OCI tar layers in containers-storage (what bootc upgrade sees)
///
/// This helps debug mtime and metadata discrepancies that cause sealed boot failures.
#[context("Validating composefs digest")]
fn validate_composefs_digest(sh: &Shell, args: &ValidateComposefsDigestArgs) -> Result<()> {
    let image = &args.image;

    // Generate dumpfile from mounted filesystem (build-time view)
    let build_dumpfile = cmd!(
        sh,
        "podman run --rm --mount=type=image,source={image},target=/target {image} bootc container compute-composefs-digest /target"
    )
    .read()?;

    // Generate dumpfile from containers-storage (install-time view)
    let format_arg = "{{.Store.GraphRoot}}";
    let graphroot = cmd!(sh, "podman system info -f {format_arg}").read()?;
    let graphroot = graphroot.trim();
    let storage_vol = format!("{graphroot}:/run/host-container-storage:ro");
    let storage_dumpfile = cmd!(
        sh,
        "podman run --rm --privileged --security-opt=label=disable
            -v {storage_vol}
            -v /sys:/sys:ro
            --tmpfs=/var
            {image}
            bootc container compute-composefs-digest-from-storage"
    )
    .read()?;

    // Compare dumpfiles
    if build_dumpfile == storage_dumpfile {
        println!("OK: Dumpfiles match");
        Ok(())
    } else {
        println!("MISMATCH: Dumpfiles differ:");
        // Use diff via process substitution by writing to temp files
        let tmpdir = tempfile::tempdir()?;
        let build_path = tmpdir.path().join("build.dumpfile");
        let storage_path = tmpdir.path().join("storage.dumpfile");
        std::fs::write(&build_path, &build_dumpfile)?;
        std::fs::write(&storage_path, &storage_dumpfile)?;
        cmd!(sh, "diff -u {build_path} {storage_path}")
            .ignore_status()
            .run()?;
        anyhow::bail!("Composefs digest mismatch");
    }
}
