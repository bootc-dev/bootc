//! Handling of system restarts/reboot

use std::io::Write;

use fn_error_context::context;

use crate::task::Task;

/// Initiate a system reboot.
/// This function will only return in case of error.
#[context("Initiating reboot")]
pub(crate) fn reboot() -> anyhow::Result<()> {
    // Flush output streams
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    Task::new("Rebooting system", "systemd-run")
        .args([
            "--quiet",
            "--",
            "systemctl",
            "reboot",
            "--message=Initiated by bootc",
        ])
        .run()?;
    tracing::debug!("Initiated reboot, sleeping forever...");
    loop {
        std::thread::park();
    }
}
