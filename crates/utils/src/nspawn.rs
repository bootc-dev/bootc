//! Builder for running commands inside a container using systemd-nspawn.
//!
//! This provides clean namespace isolation for running commands in a target
//! root filesystem, handling API filesystem setup (/dev, /proc, /sys) and
//! proper cleanup automatically.

use std::ffi::OsStr;
use std::process::Command;

use anyhow::Result;
use fn_error_context::context;

use crate::CommandRunExt;

/// Builder for running commands inside a container using systemd-nspawn.
///
/// Helps running commands in a target deployment,
/// handling API filesystem setup (/dev, /proc, /sys) and cleanup automatically.
///
/// # Example
/// ```ignore
/// use bootc_utils::NspawnCmd;
///
/// NspawnCmd::new("/path/to/rootfs")
///     .bind("/host/boot", "/boot")
///     .bind_device("/dev/sda")
///     .run(&["bootupctl", "backend", "install", ...])?;
/// ```
#[derive(Debug)]
pub struct NspawnCmd<'a> {
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
    /// Whether to suppress nspawn's own output
    quiet: bool,
}

impl<'a> NspawnCmd<'a> {
    /// Create a new NspawnCmd builder with the given root directory.
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

    /// Whether to suppress nspawn's own output (default: true).
    #[allow(dead_code)]
    pub fn quiet(mut self, quiet: bool) -> Self {
        self.quiet = quiet;
        self
    }

    /// Build the nspawn Command.
    pub fn command<S: AsRef<OsStr>>(&self, args: impl IntoIterator<Item = S>) -> Command {
        let mut cmd = Command::new("/usr/sbin/systemd-nspawn");

        // Basic options for non-interactive, isolated execution
        cmd.args(["--directory", self.chroot_path]);
        cmd.arg("--pipe"); // Non-interactive, pass stdio through

        if self.quiet {
            cmd.arg("--quiet"); // Suppress nspawn's own output
        }

        // Add bind mounts
        for (source, target) in &self.bind_mounts {
            if source == target {
                cmd.args(["--bind", source]);
            } else {
                cmd.args(["--bind", &format!("{source}:{target}")]);
            }
        }

        // Add read-only bind mounts
        for (source, target) in &self.bind_ro_mounts {
            if source == target {
                cmd.args(["--bind-ro", source]);
            } else {
                cmd.args(["--bind-ro", &format!("{source}:{target}")]);
            }
        }

        // Add device bind mounts - we bind-mount device nodes directly
        for device in &self.devices {
            cmd.args(["--bind", device]);
        }

        // Add environment variables
        for (key, value) in &self.env_vars {
            cmd.args(["--setenv", &format!("{key}={value}")]);
        }

        // don't register the service with machinectl
        // as this is expected to be short-lived
        cmd.arg("--register=no");

        // Separator and command to run
        cmd.arg("--");
        cmd.args(args);

        cmd
    }

    /// Run the specified command inside the container.
    #[context("Running command in nspawn container")]
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
    fn test_nspawn_command_basic() {
        let nspawn = NspawnCmd::new("/some/rootfs");
        let cmd = nspawn.command(["echo", "hello"]);

        let args: Vec<_> = cmd.get_args().collect();
        assert!(args.contains(&&std::ffi::OsStr::new("--directory")));
        assert!(args.contains(&&std::ffi::OsStr::new("/some/rootfs")));
        assert!(args.contains(&&std::ffi::OsStr::new("--pipe")));
        assert!(args.contains(&&std::ffi::OsStr::new("--quiet")));
        assert!(args.contains(&&std::ffi::OsStr::new("--register=no")));
        assert!(args.contains(&&std::ffi::OsStr::new("--")));
        assert!(args.contains(&&std::ffi::OsStr::new("echo")));
        assert!(args.contains(&&std::ffi::OsStr::new("hello")));
    }

    #[test]
    fn test_nspawn_command_with_binds() {
        let nspawn = NspawnCmd::new("/rootfs")
            .bind("/host/boot", "/boot")
            .bind_ro("/host/etc", "/etc")
            .bind_device("/dev/sda");

        let cmd = nspawn.command(["ls"]);
        let args: Vec<_> = cmd.get_args().collect();

        // Check bind mount format
        assert!(args.contains(&&std::ffi::OsStr::new("--bind")));
        assert!(args.contains(&&std::ffi::OsStr::new("/host/boot:/boot")));
        assert!(args.contains(&&std::ffi::OsStr::new("--bind-ro")));
        assert!(args.contains(&&std::ffi::OsStr::new("/host/etc:/etc")));
        assert!(args.contains(&&std::ffi::OsStr::new("/dev/sda")));
    }

    #[test]
    fn test_nspawn_command_same_source_target() {
        let nspawn = NspawnCmd::new("/rootfs").bind("/same/path", "/same/path");

        let cmd = nspawn.command(["ls"]);
        let args: Vec<_> = cmd.get_args().collect();

        // When source == target, should just use source without colon
        assert!(args.contains(&&std::ffi::OsStr::new("/same/path")));
        assert!(!args.iter().any(|a| a.to_str().unwrap().contains(':')));
    }

    #[test]
    fn test_nspawn_command_with_env() {
        let nspawn = NspawnCmd::new("/rootfs").setenv("PATH", "/usr/bin:/bin");

        let cmd = nspawn.command(["ls"]);
        let args: Vec<_> = cmd.get_args().collect();

        assert!(args.contains(&&std::ffi::OsStr::new("--setenv")));
        assert!(args.contains(&&std::ffi::OsStr::new("PATH=/usr/bin:/bin")));
    }
}
