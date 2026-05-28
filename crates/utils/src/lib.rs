//! The inevitable catchall "utils" crate. Generally only add
//! things here that only depend on the standard library and
//! "core" crates.
//!
mod chroot;
pub use chroot::*;
mod command;
pub use command::*;
mod iterators;
pub use iterators::*;
mod path;
pub use path::*;
/// Re-execute the current process
pub mod reexec;
mod result_ext;
pub use result_ext::*;
mod timestamp;
pub use timestamp::*;
mod tracing_util;
pub use tracing_util::*;
mod uki;
pub use uki::*;

/// The name of our binary
pub const NAME: &str = "bootc";

/// Return the podman binary path, honouring the `BOOTC_EXP_EXTERNAL_CONTAINER_TOOL`
/// environment variable so callers can substitute an alternative tool (e.g. `dtool`)
/// without hard-linking it as `/usr/bin/podman`. The _EXP prefix indicates this
/// interface is experimental and subject to change.
pub fn podman_bin() -> &'static str {
    static BIN: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    BIN.get_or_init(|| {
        std::env::var("BOOTC_EXP_EXTERNAL_CONTAINER_TOOL").unwrap_or_else(|_| "podman".to_string())
    })
}

/// Return the skopeo binary path, honouring the `BOOTC_EXP_EXTERNAL_CONTAINER_TOOL`
/// environment variable so callers can substitute an alternative tool (e.g. `dtool`)
/// without hard-linking it as `/usr/bin/skopeo`. The _EXP prefix indicates this
/// interface is experimental and subject to change.
pub fn skopeo_bin() -> &'static str {
    static BIN: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    BIN.get_or_init(|| {
        std::env::var("BOOTC_EXP_EXTERNAL_CONTAINER_TOOL").unwrap_or_else(|_| "skopeo".to_string())
    })
}

/// Intended for use in `main`, calls an inner function and
/// handles errors by printing them.
pub fn run_main<F>(f: F)
where
    F: FnOnce() -> anyhow::Result<()>,
{
    use std::io::Write as _;

    use owo_colors::OwoColorize;

    if let Err(e) = f() {
        let mut stderr = anstream::stderr();
        // Don't panic if writing fails.
        let _ = writeln!(stderr, "{}{:#}", "error: ".red(), e);
        std::process::exit(1);
    }
}
