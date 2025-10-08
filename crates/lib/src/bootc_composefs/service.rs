use anyhow::{Context, Result};
use fn_error_context::context;
use std::process::Command;

use crate::composefs_consts::BOOTC_FINALIZE_STAGED_SERVICE;

/// Starts the finaize staged service which will "unstage" the deployment
/// This is called before an upgrade or switch operation, as these create a staged
/// deployment
#[context("Starting finalize staged service")]
pub(crate) fn start_finalize_stated_svc() -> Result<()> {
    let cmd_status = Command::new("systemctl")
        .args(["start", "--quiet", BOOTC_FINALIZE_STAGED_SERVICE])
        .status()
        .context("Starting finalize service")?;

    if !cmd_status.success() {
        anyhow::bail!("systemctl exited with status {cmd_status}")
    }

    Ok(())
}
