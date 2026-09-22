use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;

use anyhow::Result;

/// Environment variables to set on re-executions of ourself; see [`set_reexec_env`].
static REEXEC_ENV: Mutex<Vec<(OsString, OsString)>> = Mutex::new(Vec::new());

/// Record an environment variable to set on any subsequent re-execution of ourself.
///
/// This carries state computed before a re-exec (e.g. the content of a file that is
/// no longer visible after we change mounts) into the new process without mutating
/// our own environment, which is not thread safe.
pub fn set_reexec_env(k: impl Into<OsString>, v: impl Into<OsString>) {
    let mut env = REEXEC_ENV.lock().unwrap();
    let k = k.into();
    env.retain(|(existing, _)| *existing != k);
    env.push((k, v.into()));
}

/// Set up `cmd` to re-execute ourself: pass along our arguments, `argv[0]`
/// and the environment recorded via [`set_reexec_env`].
pub fn prepare_reexec(cmd: &mut Command) {
    for (k, v) in REEXEC_ENV.lock().unwrap().iter() {
        cmd.env(k, v);
    }
    cmd.args(std::env::args_os().skip(1));
    cmd.arg0(crate::NAME);
}

/// Environment variable holding a reference to our original binary
pub const ORIG: &str = "_BOOTC_ORIG_EXE";

/// Return the path to our own executable. In some cases (SELinux) we may have
/// performed a re-exec with a temporary copy of the binary and
/// this environment variable will hold the path to the original binary.
pub fn executable_path() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os(ORIG) {
        Ok(p.into())
    } else {
        std::env::current_exe().map_err(Into::into)
    }
}

/// Re-execute the current process if the provided environment variable is not set.
pub fn reexec_with_guardenv(k: &str, prefix_args: &[&str]) -> Result<()> {
    if std::env::var_os(k).is_some() {
        tracing::trace!("Skipping re-exec due to env var {k}");
        return Ok(());
    }
    let self_exe = executable_path()?;
    let mut prefix_args = prefix_args.iter();
    let mut cmd = if let Some(p) = prefix_args.next() {
        let mut c = Command::new(p);
        c.args(prefix_args);
        c.arg(self_exe);
        c
    } else {
        Command::new(self_exe)
    };
    cmd.env(k, "1");
    prepare_reexec(&mut cmd);
    tracing::debug!("Re-executing current process for {k}");
    Err(cmd.exec().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reexec_env() {
        set_reexec_env("_BOOTC_TEST_A", "1");
        set_reexec_env("_BOOTC_TEST_A", "2");
        set_reexec_env("_BOOTC_TEST_B", "3");
        let mut cmd = Command::new("true");
        prepare_reexec(&mut cmd);
        let env: Vec<_> = cmd
            .get_envs()
            .filter_map(|(k, v)| Some((k.to_str()?, v?.to_str()?)))
            .filter(|(k, _)| k.starts_with("_BOOTC_TEST_"))
            .collect();
        assert_eq!(env, [("_BOOTC_TEST_A", "2"), ("_BOOTC_TEST_B", "3")]);
    }
}
