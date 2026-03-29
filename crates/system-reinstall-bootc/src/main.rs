//! The main entrypoint for the bootc system reinstallation CLI

use anyhow::{ensure, Context, Result};
use bootc_utils::CommandRunExt;
use clap::Parser;
use fn_error_context::context;
use rustix::process::getuid;
use std::time::Duration;

mod btrfs;
mod config;
mod lvm;
mod os_release;
mod podman;
mod prompt;
pub(crate) mod users;

const ROOT_KEY_MOUNT_POINT: &str = "/bootc_authorized_ssh_keys/root";
const ETC_OS_RELEASE: &str = "/etc/os-release";
const USR_LIB_OS_RELEASE: &str = "/usr/lib/os-release";

/// Reinstall the system using the provided bootc container.
///
/// This will interactively replace the system with the content of the targeted
/// container image.
///
/// If the environment variable BOOTC_REINSTALL_CONFIG is set, it must be a YAML
/// file with a single member `bootc_image` that specifies the image to install.
/// This will take precedence over the CLI.
pub(crate) struct ReinstallOpts {
    /// The bootc image to install
    pub(crate) image: String,
    // Note if we ever add any other options here,
    pub(crate) composefs_backend: bool,
}

#[derive(clap::Parser)]
pub(crate) struct ReinstallOptsArgs {
    /// The bootc image to install
    pub(crate) image: Option<String>,
    // Note if we ever add any other options here,
    #[arg(long)]
    pub(crate) composefs_backend: bool,
}

impl ReinstallOptsArgs {
    pub(crate) fn build(self) -> Result<ReinstallOpts> {
        let image = if let Some(image) = self.image {
            image
        } else {
            os_release::get_bootc_image_from_file(ETC_OS_RELEASE)
                .ok()
                .flatten()
                .or_else(|| {
                    os_release::get_bootc_image_from_file(USR_LIB_OS_RELEASE)
                        .ok()
                        .flatten()
                })
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "No image provided. Specify an image or set BOOTC_IMAGE in os-release."
                    )
                })?
        };

        Ok(ReinstallOpts {
            image,
            composefs_backend: self.composefs_backend,
        })
    }
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
        // Otherwise an image is specified via the CLI or fallback to the os-release
        ReinstallOptsArgs::parse().build()?
    };

    bootc_utils::initialize_tracing();
    tracing::trace!("starting {}", env!("CARGO_PKG_NAME"));

    // Rootless podman is not supported by bootc
    ensure!(getuid().is_root(), "Must run as the root user");

    podman::ensure_podman_installed()?;

    // Pull phase: explicitly pull the image before any other operations that use it.
    // This ensures no implicit pulls happen in later steps (e.g. capability check).
    podman::pull_if_not_present(&opts.image)?;

    println!();

    // Capability check phase: run after the image is guaranteed to be present locally.
    let spinner = indicatif::ProgressBar::new_spinner();
    spinner.set_style(
        indicatif::ProgressStyle::default_spinner()
            .template("{spinner} {msg}")
            .expect("Failed to parse spinner template"),
    );
    spinner.set_message("Checking image capabilities...");
    spinner.enable_steady_tick(Duration::from_millis(150));
    let has_clean = podman::bootc_has_clean(&opts.image)?;
    spinner.finish_and_clear();

    let ssh_key_file = tempfile::NamedTempFile::new()?;
    let ssh_key_file_path = ssh_key_file
        .path()
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("unable to create authorized_key temp file"))?;

    tracing::trace!("ssh_key_file_path: {}", ssh_key_file_path);

    prompt::get_ssh_keys(ssh_key_file_path)?;

    prompt::mount_warning()?;

    let mut reinstall_podman_command =
        podman::reinstall_command(&opts, ssh_key_file_path, has_clean)?;

    println!();
    println!("Going to run command:");
    println!();
    println!("{}", reinstall_podman_command.to_string_pretty());

    println!();
    println!(
        "After reboot, the current root will be available in the /sysroot directory. Existing mounts will not be automatically mounted by the bootc system unless they are defined in the bootc image. Some automatic cleanup of the previous root will be performed."
    );

    prompt::temporary_developer_protection_prompt()?;

    println!("Starting bootc installation. This may take several minutes...");
    println!();

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
