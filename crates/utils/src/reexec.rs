use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

use anyhow::Result;

/// Set up `cmd` to re-execute ourself: pass along our arguments and `argv[0]`,
/// and set `extra_env` (state that must survive the re-exec) in the child.
pub fn prepare_reexec(cmd: &mut Command, extra_env: &[(&str, &str)]) {
    cmd.envs(extra_env.iter().copied());
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
pub fn reexec_with_guardenv(
    k: &str,
    prefix_args: &[&str],
    extra_env: &[(&str, &str)],
) -> Result<()> {
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
    prepare_reexec(&mut cmd, extra_env);
    tracing::debug!("Re-executing current process for {k}");
    Err(cmd.exec().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prepare_reexec_env() {
        let mut cmd = Command::new("true");
        prepare_reexec(&mut cmd, &[("_BOOTC_TEST_A", "1"), ("_BOOTC_TEST_B", "2")]);
        let env: Vec<_> = cmd
            .get_envs()
            .filter_map(|(k, v)| Some((k.to_str()?, v?.to_str()?)))
            .collect();
        assert_eq!(env, [("_BOOTC_TEST_A", "1"), ("_BOOTC_TEST_B", "2")]);
    }
}
