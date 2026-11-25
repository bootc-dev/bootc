//! SELinux-related helper APIs.

use anyhow::Result;
use fn_error_context::context;
use std::path::Path;

/// The well-known selinuxfs mount point
const SELINUX_MNT: &str = "/sys/fs/selinux";
/// Hardcoded value for SELinux domain capable of setting unknown contexts.
const INSTALL_T: &str = "install_t";

/// Query for whether or not SELinux is enabled.
pub fn is_selinux_enabled() -> bool {
    Path::new(SELINUX_MNT).join("access").exists()
}

/// Return an error if the current process is not running in the `install_t` domain.
#[context("Verifying self is install_t SELinux domain")]
pub fn verify_install_domain() -> Result<()> {
    // If it doesn't look like SELinux is enabled, then nothing to do.
    if !is_selinux_enabled() {
        return Ok(());
    }

    // If we're not root, there's no need to try to warn because we can only
    // do read-only operations anyways.
    if !rustix::process::getuid().is_root() {
        return Ok(());
    }

    let self_domain = std::fs::read_to_string("/proc/self/attr/current")?;
    let is_install_t = self_domain.split(':').any(|x| x == INSTALL_T);
    if !is_install_t {
        anyhow::bail!(
            "Detected SELinux enabled system, but the executing binary is not labeled install_exec_t"
        );
    }
    Ok(())
}
