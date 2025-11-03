//! The main entrypoint for the bootc system reinstallation CLI

use anyhow::{ensure, Context, Result};
use bootc_utils::CommandRunExt;
use clap::Parser;
use fn_error_context::context;
use rustix::process::getuid;

mod btrfs;
mod config;
mod lvm;
mod podman;
mod prompt;
pub(crate) mod users;

const ROOT_KEY_MOUNT_POINT: &str = "/bootc_authorized_ssh_keys/root";

/// Reinstall the system using the provided bootc container.
///
/// This will interactively replace the system with the content of the targeted
/// container image.
///
/// If the environment variable BOOTC_REINSTALL_CONFIG is set, it must be a YAML
/// file with a single member `bootc_image` that specifies the image to install.
/// This will take precedence over the CLI.
#[derive(clap::Parser)]
pub(crate) struct ReinstallOpts {
    /// The bootc image to install
    pub(crate) image: String,
    // Note if we ever add any other options here,
    #[arg(long)]
    pub(crate) composefs_backend: bool,
}

#[context("run")]
fn run() -> Result<()> {
    // We historically supported an environment variable providing a config to override the image, so
    // keep supporting that. I'm considering deprecating that though.
    let opts = if let Some(config) = config::ReinstallConfig::load().context("loading config")? {
        ReinstallOpts {
            image: config.bootc_image,
            composefs_backend: config.composefs_backend,
        }
    } else {
        // Otherwise an image is required.
        ReinstallOpts::parse()
    };

    bootc_utils::initialize_tracing();
    tracing::trace!("starting {}", env!("CARGO_PKG_NAME"));

    // Rootless podman is not supported by bootc
    ensure!(getuid().is_root(), "Must run as the root user");

    podman::ensure_podman_installed()?;

    //pull image early so it can be inspected, e.g. to check for cloud-init
    podman::pull_if_not_present(&opts.image)?;

    println!();

    let ssh_key_file = tempfile::NamedTempFile::new()?;
    let ssh_key_file_path = ssh_key_file
        .path()
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("unable to create authorized_key temp file"))?;

    tracing::trace!("ssh_key_file_path: {}", ssh_key_file_path);

    prompt::get_ssh_keys(ssh_key_file_path)?;

    prompt::mount_warning()?;

    let mut reinstall_podman_command = podman::reinstall_command(&opts, ssh_key_file_path)?;

    println!();
    println!("Going to run command:");
    println!();
    println!("{}", reinstall_podman_command.to_string_pretty());

    println!();
    println!("After reboot, the current root will be available in the /sysroot directory. Existing mounts will not be automatically mounted by the bootc system unless they are defined in the bootc image. Some automatic cleanup of the previous root will be performed.");

    prompt::temporary_developer_protection_prompt()?;

    reinstall_podman_command
        .run_inherited_with_cmd_context()
        .context("running reinstall command")?;

    prompt::reboot()?;

    std::process::Command::new("reboot").run_capture_stderr()?;

    Ok(())
}

fn main() {
    bootc_utils::run_main(run)
}
