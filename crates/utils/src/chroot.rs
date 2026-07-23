//! Builder for running commands inside a target os tree using a
//! mount namespace + chroot. Requires `CAP_SYS_ADMIN`.

use std::borrow::Cow;
use std::ffi::{CString, OsStr};
use std::fs::create_dir_all;
use std::os::unix::process::CommandExt;
use std::process::Command;

use anyhow::{Context, Result};
use cap_std_ext::camino::Utf8Path;
use rustix::mount::{
    MountFlags, MountPropagationFlags, mount, mount_bind, mount_bind_recursive, mount_change,
};
use rustix::process::{chdir, chroot};
use rustix::thread::{UnshareFlags, unshare_unsafe};

use crate::CommandRunExt;

/// Whether a [`ChrootCmd::bind`] mount also carries over mounts nested
/// under its source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindMode {
    /// A plain bind mount: only `source` itself is bound. Mounts nested
    /// under `source` on the host (e.g. an ESP mounted under a `/boot`
    /// source) are *not* carried over, leaving the corresponding
    /// mountpoint directories under `target` empty.
    Default,
    /// A recursive bind mount: mounts nested under `source` on the host
    /// are also visible under `target` inside the chroot.
    Recursive,
}

/// Builder for running commands inside a target directory using a
/// mount namespace + chroot.
#[derive(Debug)]
pub struct ChrootCmd<'a> {
    /// The target directory to use as root for the chroot.
    chroot_path: Cow<'a, Utf8Path>,
    /// Bind mounts in format (host source, chroot-relative target, mode).
    bind_mounts: Vec<(&'a str, &'a str, BindMode)>,
    /// Environment variables to set on the spawned command.
    env_vars: Vec<(&'a str, &'a str)>,
}

impl<'a> ChrootCmd<'a> {
    /// Create a new `ChrootCmd` builder with a root directory.
    pub fn new(path: &'a Utf8Path) -> Self {
        Self {
            chroot_path: Cow::Borrowed(path),
            bind_mounts: Vec::new(),
            env_vars: Vec::new(),
        }
    }

    /// Add a bind mount from `source` (on the host) to `target` (a path
    /// inside the chroot, e.g. `/sysroot`). See [`BindMode`] for the
    /// difference between recursive and non-recursive bind mounts.
    pub fn bind(
        mut self,
        source: &'a impl AsRef<Utf8Path>,
        target: &'a impl AsRef<Utf8Path>,
        mode: BindMode,
    ) -> Self {
        self.bind_mounts
            .push((source.as_ref().as_str(), target.as_ref().as_str(), mode));
        self
    }

    /// Set an environment variable for the child. The chrooted
    /// command runs with a cleared environment, isolating it from
    /// the buildroot — callers must set every variable they want
    /// the child to see.
    pub fn setenv(mut self, key: &'a str, value: &'a str) -> Self {
        self.env_vars.push((key, value));
        self
    }

    /// Set `$PATH` to a reasonable default covering the standard
    /// system binary directories.
    pub fn set_default_path(self) -> Self {
        self.setenv(
            "PATH",
            "/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin",
        )
    }

    /// Build the underlying [`Command`] with the mount-namespace
    /// setup and chroot installed as a `pre_exec` hook.
    fn build_command<S: AsRef<OsStr>>(self, args: impl IntoIterator<Item = S>) -> Result<Command> {
        let mut args_iter = args.into_iter();
        let program = args_iter
            .next()
            .context("ChrootCmd requires the program as the first arg")?;

        // mount() requires its target directories to exist.
        let proc_target = self.chroot_path.join("proc");
        let dev_target = self.chroot_path.join("dev");
        let sys_target = self.chroot_path.join("sys");
        let run_target = self.chroot_path.join("run");
        for p in [&proc_target, &dev_target, &sys_target, &run_target] {
            create_dir_all(p).with_context(|| format!("Creating {p}"))?;
        }

        // Convert paths to CStrings up front so the pre_exec closure
        // below stays allocation-free.
        let proc_target = CString::new(proc_target.as_str())?;
        let dev_target = CString::new(dev_target.as_str())?;
        let sys_target = CString::new(sys_target.as_str())?;
        let run_target = CString::new(run_target.as_str())?;

        let user_binds: Vec<(CString, CString, BindMode)> = self
            .bind_mounts
            .iter()
            .map(|(src, tgt, mode)| -> Result<_> {
                let tgt_in_chroot = self.chroot_path.join(tgt.trim_start_matches('/'));
                create_dir_all(&tgt_in_chroot)
                    .with_context(|| format!("Creating bind target {tgt_in_chroot}"))?;
                Ok((
                    CString::new(*src)?,
                    CString::new(tgt_in_chroot.as_str())?,
                    *mode,
                ))
            })
            .collect::<Result<_>>()?;

        let chroot_cstr = CString::new(self.chroot_path.as_str())?;

        let mut cmd = Command::new(program);
        cmd.args(args_iter);
        cmd.env_clear().envs(self.env_vars.iter().copied());

        // SAFETY: All operations below are safe to invoke between
        // fork and exec — only rustix-wrapped syscalls and iteration
        // over CStrings allocated above.
        #[allow(unsafe_code)]
        unsafe {
            cmd.pre_exec(move || {
                unshare_unsafe(UnshareFlags::NEWNS)?;

                // Recursively mark every mount in our new namespace as
                // PRIVATE. This both prevents the mounts we add below
                // from leaking back to the host, and ensures that those
                // mounts inherit PRIVATE propagation from their parent.
                mount_change(
                    c"/",
                    MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
                )?;

                // Bind-mount the chroot target onto itself so that `/`
                // appears as a real mount point after chroot. Without
                // this, tools that inspect mounts (e.g. `findmnt
                // --mountpoint /`, which bootupd uses behind
                // `--filesystem /`) fail because the chroot dir is a
                // plain subdirectory of its parent mount and has no
                // mountinfo entry of its own.
                mount_bind_recursive(chroot_cstr.as_c_str(), chroot_cstr.as_c_str())?;

                // Setup API filesystems
                // See https://systemd.io/API_FILE_SYSTEMS/
                mount(
                    c"proc",
                    proc_target.as_c_str(),
                    c"proc",
                    MountFlags::empty(),
                    None,
                )?;
                mount_bind_recursive(c"/dev", dev_target.as_c_str())?;
                mount_bind_recursive(c"/sys", sys_target.as_c_str())?;
                // /run carries the udev database, which lsblk/libblkid
                // use to resolve partition GUIDs and other device
                // properties.
                mount_bind_recursive(c"/run", run_target.as_c_str())?;

                for (src, tgt, mode) in &user_binds {
                    match mode {
                        BindMode::Recursive => {
                            mount_bind_recursive(src.as_c_str(), tgt.as_c_str())?
                        }
                        BindMode::Default => mount_bind(src.as_c_str(), tgt.as_c_str())?,
                    }
                }

                chroot(chroot_cstr.as_c_str())?;
                chdir(c"/")?;

                Ok(())
            });
        }

        Ok(cmd)
    }

    /// Run the specified command inside the chroot, inheriting stdio.
    /// `args` must include the program as its first element.
    pub fn run<S: AsRef<OsStr>>(self, args: impl IntoIterator<Item = S>) -> Result<()> {
        self.build_command(args)?
            .log_debug()
            .run_inherited_with_cmd_context()
    }

    /// Run the specified command inside the chroot and capture stdout
    /// as a string. `args` must include the program as its first
    /// element.
    pub fn run_get_string<S: AsRef<OsStr>>(
        self,
        args: impl IntoIterator<Item = S>,
    ) -> Result<String> {
        self.build_command(args)?.log_debug().run_get_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std_ext::camino::Utf8PathBuf;

    fn tmp_root() -> (tempfile::TempDir, Utf8PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();
        (dir, path)
    }

    #[test]
    fn builder_accumulates_binds_and_env() {
        let (_keep, root) = tmp_root();
        let src = root.join("src");
        let non_recursive_src = root.join("non-recursive-src");
        let cmd = ChrootCmd::new(&root)
            .bind(&src, &"/boot", BindMode::Recursive)
            .bind(&non_recursive_src, &"/sysroot", BindMode::Default)
            .setenv("FOO", "bar")
            .set_default_path();
        assert_eq!(cmd.bind_mounts.len(), 2);
        assert_eq!(
            cmd.bind_mounts[0],
            (src.as_str(), "/boot", BindMode::Recursive)
        );
        assert_eq!(
            cmd.bind_mounts[1],
            (non_recursive_src.as_str(), "/sysroot", BindMode::Default)
        );
        // setenv + set_default_path
        assert_eq!(cmd.env_vars.len(), 2);
        assert!(cmd.env_vars.iter().any(|(k, _)| *k == "PATH"));
        assert!(cmd.env_vars.iter().any(|(k, v)| *k == "FOO" && *v == "bar"));
    }

    #[test]
    fn build_command_creates_api_mount_dirs() {
        let (_keep, root) = tmp_root();
        // No user binds — just the API mount targets.
        let cmd = ChrootCmd::new(&root).build_command(["/bin/true"]).unwrap();
        for sub in ["proc", "dev", "sys", "run"] {
            assert!(
                root.join(sub).is_dir(),
                "API mount dir {sub} not created in {root}"
            );
        }
        assert_eq!(cmd.get_program(), "/bin/true");
    }

    #[test]
    fn build_command_creates_user_bind_targets() {
        let (_keep, root) = tmp_root();
        let (_keep2, src_root) = tmp_root();
        ChrootCmd::new(&root)
            .bind(&src_root, &"/sysroot", BindMode::Recursive)
            .build_command(["/bin/true"])
            .unwrap();
        assert!(root.join("sysroot").is_dir());
    }

    #[test]
    fn build_command_rejects_empty_args() {
        let (_keep, root) = tmp_root();
        let err = ChrootCmd::new(&root)
            .build_command(std::iter::empty::<&str>())
            .unwrap_err();
        assert!(
            err.to_string().contains("ChrootCmd requires the program"),
            "unexpected error: {err}"
        );
    }
}
