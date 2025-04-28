//! Handling of deployment overlays

use std::{os::unix::process::CommandExt, process::Command};

use anyhow::Result;
use fn_error_context::context;

use crate::spec;

#[context("Setting /usr overlay")]
pub fn set_usr_overlay(state: spec::FilesystemOverlay) -> Result<()> {
    match state {
        spec::FilesystemOverlay::Readonly => {
            tracing::info!("Setting /usr overlay to read-only");
            // There's no clean way to remove the readwrite overlay, so we lazily unmount it.
            crate::mount::unmount(camino::Utf8Path::new("/usr"), true)?;
        }
        spec::FilesystemOverlay::ReadWrite => {
            tracing::info!("Setting /usr overlay to read-write");
            // This is just a pass-through today.  At some point we may make this a libostree API
            // or even oxidize it.
            Err(anyhow::Error::from(
                Command::new("ostree").args(["admin", "unlock"]).exec(),
            ))?;
        }
    }
    return Ok({});
}
