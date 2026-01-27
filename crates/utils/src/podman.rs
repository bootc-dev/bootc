//! Builder for running commands inside a container using podman with --rootfs.
//!
//! This provides clean namespace isolation for running commands in a target
//! root filesystem, handling API filesystem setup (/dev, /proc, /sys) and
//! proper cleanup automatically.

use std::ffi::OsStr;
use std::process::Command;

use anyhow::Result;
use fn_error_context::context;

use crate::CommandRunExt;

/// Builder for running commands inside a container using podman with --rootfs.
///
/// Helps running commands in a target deployment,
/// handling API filesystem setup (/dev, /proc, /sys) and cleanup automatically.
///
/// # Example
/// ```ignore
/// use bootc_utils::PodmanCmd;
///
/// PodmanCmd::new("/path/to/rootfs")
///     .bind("/host/boot", "/boot")
///     .bind_device("/dev/sda")
///     .run(&["bootupctl", "backend", "install", ...])?;
/// ```
#[derive(Debug)]
pub struct PodmanCmd<'a> {
    /// The root directory for the container
    rootfs_path: &'a str,
    /// Bind mounts in format (source, target)
    bind_mounts: Vec<(&'a str, &'a str)>,
    /// Read-only bind mounts in format (source, target)
    bind_ro_mounts: Vec<(&'a str, &'a str)>,
    /// Device nodes to pass into the container
    devices: Vec<&'a str>,
    /// Environment variables to set
    env_vars: Vec<(&'a str, &'a str)>,
    /// Whether to run in privileged mode (default: true for device access)
    privileged: bool,
    /// Whether to remove the container after exit (default: true)
    rm: bool,
}

impl<'a> PodmanCmd<'a> {
    /// Create a new PodmanCmd builder with the given root directory.
    pub fn new(path: &'a str) -> Self {
        Self {
            rootfs_path: path,
            bind_mounts: Vec::new(),
            bind_ro_mounts: Vec::new(),
            devices: Vec::new(),
            env_vars: Vec::new(),
            privileged: true,
            rm: true,
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

    /// Pass a device node into the container.
    pub fn bind_device(mut self, device: &'a str) -> Self {
        self.devices.push(device);
        self
    }

    /// Set an environment variable for the command.
    pub fn setenv(mut self, key: &'a str, value: &'a str) -> Self {
        self.env_vars.push((key, value));
        self
    }

    /// Whether to run in privileged mode (default: true).
    #[allow(dead_code)]
    pub fn privileged(mut self, privileged: bool) -> Self {
        self.privileged = privileged;
        self
    }

    /// Whether to remove the container after exit (default: true).
    #[allow(dead_code)]
    pub fn rm(mut self, rm: bool) -> Self {
        self.rm = rm;
        self
    }

    /// Build the podman Command.
    pub fn command<S: AsRef<OsStr>>(&self, args: impl IntoIterator<Item = S>) -> Command {
        let mut cmd = Command::new("podman");

        cmd.arg("run");

        if self.rm {
            cmd.arg("--rm");
        }

        if self.privileged {
            cmd.arg("--privileged");
        }

        // Add bind mounts as volumes
        for (source, target) in &self.bind_mounts {
            cmd.args(["--volume", &format!("{source}:{target}")]);
        }

        // Add read-only bind mounts
        for (source, target) in &self.bind_ro_mounts {
            cmd.args(["--volume", &format!("{source}:{target}:ro")]);
        }

        // Add device nodes
        for device in &self.devices {
            cmd.args(["--device", device]);
        }

        // Add environment variables
        for (key, value) in &self.env_vars {
            cmd.args(["--env", &format!("{key}={value}")]);
        }

        // Use the rootfs as the container filesystem
        cmd.args(["--rootfs", self.rootfs_path]);

        // Add the command to run
        cmd.args(args);

        cmd
    }

    /// Run the specified command inside the container.
    #[context("Running command in podman container")]
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
    fn test_podman_command_basic() {
        let podman = PodmanCmd::new("/some/rootfs");
        let cmd = podman.command(["echo", "hello"]);

        let args: Vec<_> = cmd.get_args().collect();
        assert!(args.contains(&&std::ffi::OsStr::new("run")));
        assert!(args.contains(&&std::ffi::OsStr::new("--rm")));
        assert!(args.contains(&&std::ffi::OsStr::new("--privileged")));
        assert!(args.contains(&&std::ffi::OsStr::new("--rootfs")));
        assert!(args.contains(&&std::ffi::OsStr::new("/some/rootfs")));
        assert!(args.contains(&&std::ffi::OsStr::new("echo")));
        assert!(args.contains(&&std::ffi::OsStr::new("hello")));
    }

    #[test]
    fn test_podman_command_with_binds() {
        let podman = PodmanCmd::new("/rootfs")
            .bind("/host/boot", "/boot")
            .bind_ro("/host/etc", "/etc")
            .bind_device("/dev/sda");

        let cmd = podman.command(["ls"]);
        let args: Vec<_> = cmd.get_args().collect();

        // Check volume mount format
        assert!(args.contains(&&std::ffi::OsStr::new("--volume")));
        assert!(args.contains(&&std::ffi::OsStr::new("/host/boot:/boot")));
        assert!(args.contains(&&std::ffi::OsStr::new("/host/etc:/etc:ro")));
        assert!(args.contains(&&std::ffi::OsStr::new("--device")));
        assert!(args.contains(&&std::ffi::OsStr::new("/dev/sda")));
    }

    #[test]
    fn test_podman_command_with_env() {
        let podman = PodmanCmd::new("/rootfs").setenv("PATH", "/usr/bin:/bin");

        let cmd = podman.command(["ls"]);
        let args: Vec<_> = cmd.get_args().collect();

        assert!(args.contains(&&std::ffi::OsStr::new("--env")));
        assert!(args.contains(&&std::ffi::OsStr::new("PATH=/usr/bin:/bin")));
    }

    #[test]
    fn test_podman_command_not_privileged() {
        let podman = PodmanCmd::new("/rootfs").privileged(false);

        let cmd = podman.command(["ls"]);
        let args: Vec<_> = cmd.get_args().collect();

        // Should NOT contain --privileged when privileged is false
        assert!(!args.contains(&&std::ffi::OsStr::new("--privileged")));
    }
}
