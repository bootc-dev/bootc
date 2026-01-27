//! Builder for running commands inside a container using bubblewrap (bwrap).
//!
//! This provides namespace isolation for running commands in a target
//! root filesystem, handling API filesystem setup (/dev, /proc, /sys)
//! automatically.

use std::ffi::OsStr;
use std::process::Command;

use anyhow::Result;
use fn_error_context::context;

use crate::CommandRunExt;

/// Builder for running commands inside a container using bubblewrap (bwrap).
///
/// # Example
/// ```ignore
/// use bootc_utils::BwrapCmd;
///
/// BwrapCmd::new("/path/to/rootfs")
///     .bind("/host/boot", "/boot")
///     .bind_device("/dev/sda")
///     .run(&["grub2-install", "/dev/sda"])?;
/// ```
#[derive(Debug, Default)]
pub struct BwrapCmd<'a> {
    /// The root directory for the container
    chroot_path: &'a str,
    /// Bind mounts in format (source, target)
    bind_mounts: Vec<(&'a str, &'a str)>,
    /// Device nodes to bind into the container
    devices: Vec<&'a str>,
    /// Environment variables to set
    env_vars: Vec<(&'a str, &'a str)>,
}

impl<'a> BwrapCmd<'a> {
    /// Create a new BwrapCmd builder with the given root directory.
    pub fn new(path: &'a str) -> Self {
        Self {
            chroot_path: path,
            ..Default::default()
        }
    }

    /// Add a bind mount from source to target inside the container.
    pub fn bind(mut self, source: &'a str, target: &'a str) -> Self {
        self.bind_mounts.push((source, target));
        self
    }

    /// Bind a device node into the container.
    pub fn bind_device(mut self, device: &'a str) -> Self {
        self.devices.push(device);
        self
    }

    /// Set an environment variable for the command.
    pub fn setenv(mut self, key: &'a str, value: &'a str) -> Self {
        self.env_vars.push((key, value));
        self
    }

    /// Run the specified command inside the container.
    #[context("Running command in bwrap container")]
    pub fn run<S: AsRef<OsStr>>(self, args: impl IntoIterator<Item = S>) -> Result<()> {
        let mut cmd = Command::new("bwrap");

        // Bind the root filesystem
        cmd.args(["--bind", self.chroot_path, "/"]);

        // Setup API filesystems
        cmd.args(["--proc", "/proc"]);
        cmd.args(["--dev", "/dev"]);
        cmd.args(["--ro-bind", "/sys", "/sys"]);

        // Add bind mounts
        for (source, target) in &self.bind_mounts {
            cmd.args(["--bind", source, target]);
        }

        // Add device bind mounts
        for device in self.devices {
            cmd.args(["--dev-bind", device, device]);
        }

        // Add environment variables
        for (key, value) in &self.env_vars {
            cmd.args(["--setenv", key, value]);
        }

        // Command to run
        cmd.arg("--");
        cmd.args(args);

        cmd.log_debug().run_inherited_with_cmd_context()
    }
}
