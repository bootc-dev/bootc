//! Build Unified Kernel Images (UKI) using ukify.
//!
//! This module provides functionality to build UKIs by computing the necessary
//! arguments from a container image and invoking the ukify tool. Default V1
//! UKIs also carry the legacy V2 digest for older bootc clients.

use std::ffi::OsString;
use std::process::Command;

use anyhow::{Context, Result};
use bootc_utils::CommandRunExt;
use camino::Utf8Path;
use fn_error_context::context;

use crate::boot_artifact::prepare_boot_artifact;
use crate::cli::ErofsVersionArg;

/// Build a UKI from the given rootfs.
///
/// Finds the kernel, computes the composefs digest, reads kernel arguments from
/// kargs.d, then invokes ukify with any additional pass-through arguments.
#[context("Building UKI")]
pub(crate) async fn build_ukify(
    rootfs: &Utf8Path,
    extra_kargs: &[String],
    args: &[OsString],
    kernel_dir: Option<&Utf8Path>,
    allow_missing_fsverity: bool,
    erofs_version: Option<ErofsVersionArg>,
    write_dumpfile_to: Option<&Utf8Path>,
) -> Result<()> {
    if !extra_kargs.is_empty() {
        tracing::warn!(
            "The --karg flag is temporary and will be removed as soon as possible \
            (https://github.com/bootc-dev/bootc/issues/1826)"
        );
    }

    if !crate::utils::have_executable("ukify")? {
        anyhow::bail!(
            "ukify executable not found in PATH. Please install systemd-ukify or equivalent."
        );
    }

    let inputs = prepare_boot_artifact(
        rootfs,
        kernel_dir,
        extra_kargs,
        allow_missing_fsverity,
        erofs_version,
        write_dumpfile_to,
    )
    .await?;

    let mut cmd = Command::new("ukify");
    cmd.current_dir(rootfs);
    cmd.arg("build")
        .arg("--linux")
        .arg(&inputs.vmlinuz)
        .arg("--initrd")
        .arg(&inputs.initramfs)
        .arg("--uname")
        .arg(&inputs.kernel_version)
        .arg("--cmdline")
        .arg(&inputs.cmdline)
        .arg("--os-release")
        .arg("@usr/lib/os-release");
    cmd.args(args);

    tracing::debug!("Executing ukify: {:?}", cmd);
    cmd.run_inherited().context("Running ukify")?;

    Ok(())
}
