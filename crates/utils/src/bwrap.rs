//! Builder for running commands inside a container using bubblewrap (bwrap).
//!
//! This provides clean namespace isolation for running commands in a target
//! root filesystem, handling API filesystem setup (/dev, /proc, /sys) and
//! proper cleanup automatically.

use std::ffi::OsStr;
use std::process::Command;

use anyhow::Result;
use fn_error_context::context;

use crate::CommandRunExt;

/// Builder for running commands inside a container using bubblewrap (bwrap).
///
/// Helps running commands in a target deployment,
/// handling API filesystem setup (/dev, /proc, /sys) and cleanup automatically.
///
/// # Example
/// ```ignore
/// use bootc_utils::BwrapCmd;
///
/// BwrapCmd::new("/path/to/rootfs")
///     .bind("/host/boot", "/boot")
///     .bind_device("/dev/sda")
///     .run(&["bootupctl", "backend", "install", ...])?;
/// ```
#[derive(Debug)]
pub struct BwrapCmd<'a> {
    /// The root directory for the container
    chroot_path: &'a str,
    /// Bind mounts in format (source, target)
    bind_mounts: Vec<(&'a str, &'a str)>,
    /// Read-only bind mounts in format (source, target)
    bind_ro_mounts: Vec<(&'a str, &'a str)>,
    /// Device nodes to bind into the container
    devices: Vec<&'a str>,
    /// Environment variables to set
    env_vars: Vec<(&'a str, &'a str)>,
    /// Whether to suppress output (no-op for bwrap, kept for API compatibility)
    quiet: bool,
}

impl<'a> BwrapCmd<'a> {
    /// Create a new BwrapCmd builder with the given root directory.
    pub fn new(path: &'a str) -> Self {
        Self {
            chroot_path: path,
            bind_mounts: Vec::new(),
            bind_ro_mounts: Vec::new(),
            devices: Vec::new(),
            env_vars: Vec::new(),
            quiet: true,
        }
    }

    /// Add a bind mount from source to target inside the container.
    /// If target is the same as source, you can pass the same value for both.
    pub fn bind(mut self, source: &'a str, target: &'a str) -> Self {
        self.bind_mounts.push((source, target));
        self
    }

    /// Add a read-only bind mount from source to target inside the container.
    #[allow(dead_code)]
    pub fn bind_ro(mut self, source: &'a str, target: &'a str) -> Self {
        self.bind_ro_mounts.push((source, target));
        self
    }

    /// Bind a device node into the container.
    /// This bind-mounts the device node so it's accessible inside.
    pub fn bind_device(mut self, device: &'a str) -> Self {
        self.devices.push(device);
        self
    }

    /// Set an environment variable for the command.
    pub fn setenv(mut self, key: &'a str, value: &'a str) -> Self {
        self.env_vars.push((key, value));
        self
    }

    /// Whether to suppress output (no-op for bwrap, kept for API compatibility).
    #[allow(dead_code)]
    pub fn quiet(mut self, quiet: bool) -> Self {
        self.quiet = quiet;
        self
    }

    /// Build the bwrap Command.
    pub fn command<S: AsRef<OsStr>>(&self, args: impl IntoIterator<Item = S>) -> Command {
        let mut cmd = Command::new("bwrap");

        // Bind the root filesystem
        cmd.args(["--bind", self.chroot_path, "/"]);

        // Setup API filesystems automatically
        // --proc creates a new procfs mount
        cmd.args(["--proc", "/proc"]);
        // --dev creates a minimal /dev with null, zero, full, random, urandom, tty
        cmd.args(["--dev", "/dev"]);
        // Bind /sys read-only for safety
        cmd.args(["--ro-bind", "/sys", "/sys"]);

        // Add bind mounts
        for (source, target) in &self.bind_mounts {
            cmd.args(["--bind", source, target]);
        }

        // Add read-only bind mounts
        for (source, target) in &self.bind_ro_mounts {
            cmd.args(["--ro-bind", source, target]);
        }

        // Add device bind mounts using --dev-bind to preserve device node permissions
        for device in &self.devices {
            cmd.args(["--dev-bind", device, device]);
        }

        // Add environment variables
        for (key, value) in &self.env_vars {
            cmd.args(["--setenv", key, value]);
        }

        // Separator and command to run
        cmd.arg("--");
        cmd.args(args);

        cmd
    }

    /// Run the specified command inside the container.
    #[context("Running command in bwrap container")]
    pub fn run<S: AsRef<OsStr>>(self, args: impl IntoIterator<Item = S>) -> Result<()> {
        self.command(args)
            .log_debug()
            .run_inherited_with_cmd_context()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bwrap_command_basic() {
        let bwrap = BwrapCmd::new("/some/rootfs");
        let cmd = bwrap.command(["echo", "hello"]);

        let args: Vec<_> = cmd.get_args().collect();
        assert!(args.contains(&&std::ffi::OsStr::new("--bind")));
        assert!(args.contains(&&std::ffi::OsStr::new("/some/rootfs")));
        assert!(args.contains(&&std::ffi::OsStr::new("/")));
        assert!(args.contains(&&std::ffi::OsStr::new("--proc")));
        assert!(args.contains(&&std::ffi::OsStr::new("/proc")));
        assert!(args.contains(&&std::ffi::OsStr::new("--dev")));
        assert!(args.contains(&&std::ffi::OsStr::new("/dev")));
        assert!(args.contains(&&std::ffi::OsStr::new("--ro-bind")));
        assert!(args.contains(&&std::ffi::OsStr::new("/sys")));
        assert!(args.contains(&&std::ffi::OsStr::new("--")));
        assert!(args.contains(&&std::ffi::OsStr::new("echo")));
        assert!(args.contains(&&std::ffi::OsStr::new("hello")));
    }

    #[test]
    fn test_bwrap_command_with_binds() {
        let bwrap = BwrapCmd::new("/rootfs")
            .bind("/host/boot", "/boot")
            .bind_ro("/host/etc", "/etc")
            .bind_device("/dev/sda");

        let cmd = bwrap.command(["ls"]);
        let args: Vec<_> = cmd.get_args().collect();

        // Check bind mount - bwrap uses separate args, not colon-separated
        assert!(args.contains(&&std::ffi::OsStr::new("/host/boot")));
        assert!(args.contains(&&std::ffi::OsStr::new("/boot")));
        assert!(args.contains(&&std::ffi::OsStr::new("/host/etc")));
        assert!(args.contains(&&std::ffi::OsStr::new("/etc")));
        // Device binds use --dev-bind
        assert!(args.contains(&&std::ffi::OsStr::new("--dev-bind")));
        assert!(args.contains(&&std::ffi::OsStr::new("/dev/sda")));
    }

    #[test]
    fn test_bwrap_command_same_source_target() {
        let bwrap = BwrapCmd::new("/rootfs").bind("/same/path", "/same/path");

        let cmd = bwrap.command(["ls"]);
        let args: Vec<_> = cmd.get_args().collect();

        // bwrap always uses separate source and target args
        // Count occurrences of /same/path - should appear twice (source and target)
        let count = args
            .iter()
            .filter(|a| *a == &std::ffi::OsStr::new("/same/path"))
            .count();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_bwrap_command_with_env() {
        let bwrap = BwrapCmd::new("/rootfs").setenv("PATH", "/usr/bin:/bin");

        let cmd = bwrap.command(["ls"]);
        let args: Vec<_> = cmd.get_args().collect();

        assert!(args.contains(&&std::ffi::OsStr::new("--setenv")));
        assert!(args.contains(&&std::ffi::OsStr::new("PATH")));
        assert!(args.contains(&&std::ffi::OsStr::new("/usr/bin:/bin")));
    }
}
