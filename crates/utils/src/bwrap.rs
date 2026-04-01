/// Builder for running commands inside a target os tree using bubblewrap (bwrap).
use std::borrow::Cow;
use std::ffi::OsStr;
use std::os::fd::AsRawFd;
use std::process::Command;

use anyhow::Result;
use cap_std_ext::camino::{Utf8Path, Utf8PathBuf};
use cap_std_ext::cap_std::fs::Dir;

use crate::CommandRunExt;

/// Builder for running commands inside a target directory using bwrap.
#[derive(Debug)]
pub struct BwrapCmd<'a> {
    /// The target directory to use as root for the container
    chroot_path: Cow<'a, Utf8Path>,
    /// Bind mounts in format (source, target)
    bind_mounts: Vec<(&'a str, &'a str)>,
    /// Environment variables to set
    env_vars: Vec<(&'a str, &'a str)>,
}

impl<'a> BwrapCmd<'a> {
    /// Create a new BwrapCmd builder with a root directory as a File Descriptor.
    #[allow(dead_code)]
    pub fn new_with_dir(path: &'a Dir) -> Self {
        let fd_path: String = format!("/proc/self/fd/{}", path.as_raw_fd());
        Self {
            chroot_path: Cow::Owned(Utf8PathBuf::from(&fd_path)),
            bind_mounts: Vec::new(),
            env_vars: Vec::new(),
        }
    }

    /// Create a new BwrapCmd builder with a root directory
    pub fn new(path: &'a Utf8Path) -> Self {
        Self {
            chroot_path: Cow::Borrowed(path),
            bind_mounts: Vec::new(),
            env_vars: Vec::new(),
        }
    }

    /// Add a bind mount from source to target inside the container.
    pub fn bind(
        mut self,
        source: &'a impl AsRef<Utf8Path>,
        target: &'a impl AsRef<Utf8Path>,
    ) -> Self {
        self.bind_mounts
            .push((source.as_ref().as_str(), target.as_ref().as_str()));
        self
    }

    /// Set an environment variable for the command.
    pub fn setenv(mut self, key: &'a str, value: &'a str) -> Self {
        self.env_vars.push((key, value));
        self
    }

    /// Set $PATH to a reasonable default for finding system binaries.
    ///
    /// The bwrap environment may not have a complete $PATH, causing
    /// tools like bootupctl or sfdisk to not be found. This sets a
    /// default that covers the standard binary directories.
    pub fn set_default_path(self) -> Self {
        self.setenv(
            "PATH",
            "/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin",
        )
    }

    /// Build the bwrap `Command` with all bind mounts, env vars, and args.
    fn build_command<S: AsRef<OsStr>>(&self, args: impl IntoIterator<Item = S>) -> Command {
        let mut cmd = Command::new("bwrap");

        // Bind the root filesystem
        cmd.args(["--bind", self.chroot_path.as_str(), "/"]);

        // Setup API filesystems
        // See https://systemd.io/API_FILE_SYSTEMS/
        cmd.args(["--proc", "/proc"]);
        cmd.args(["--dev-bind", "/dev", "/dev"]);
        cmd.args(["--bind", "/sys", "/sys"]);

        // Bind /run primarily for the udev database so that
        // lsblk/libblkid inside the sandbox can read
        // partition type GUIDs and other device properties.
        cmd.args(["--tmpfs", "/run"]);
        cmd.args(["--bind", "/run", "/run"]);

        // Add bind mounts
        for (source, target) in &self.bind_mounts {
            cmd.args(["--bind", source, target]);
        }

        // Add environment variables
        for (key, value) in &self.env_vars {
            cmd.args(["--setenv", key, value]);
        }

        // Command to run
        cmd.arg("--");
        cmd.args(args);

        cmd
    }

    /// Run the specified command inside the container.
    pub fn run<S: AsRef<OsStr>>(self, args: impl IntoIterator<Item = S>) -> Result<()> {
        self.build_command(args)
            .log_debug()
            .run_inherited_with_cmd_context()
    }

    /// Run the specified command inside the container and capture stdout as a string.
    pub fn run_get_string<S: AsRef<OsStr>>(
        self,
        args: impl IntoIterator<Item = S>,
    ) -> Result<String> {
        self.build_command(args).log_debug().run_get_string()
    }
}
