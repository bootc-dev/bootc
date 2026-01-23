use std::{
    ffi::OsStr,
    io::{Seek, Write},
    process::{Command, Stdio},
};

use anyhow::{Context, Result};
use cap_std::fs::Dir;
use cap_std_ext::cap_std;
use cap_std_ext::prelude::CapStdExtCommandExt;

/// How much information we output
#[derive(Debug, PartialEq, Eq, Default)]
enum CmdVerbosity {
    /// Nothing is output
    Quiet,
    /// Only the task description is output
    #[default]
    Description,
    /// The task description and the full command line are output
    Verbose,
}

/// Too many things in the install path are conditional
pub(crate) struct Task {
    description: String,
    verbosity: CmdVerbosity,
    quiet_output: bool,
    pub(crate) cmd: Command,
}

#[allow(dead_code)]
impl Task {
    pub(crate) fn new(description: impl AsRef<str>, exe: impl AsRef<str>) -> Self {
        Self::new_cmd(description, Command::new(exe.as_ref()))
    }

    /// This API can be used in place of Command::new() generally and just adds error
    /// checking on top.
    pub(crate) fn new_quiet(exe: impl AsRef<str>) -> Self {
        let exe = exe.as_ref();
        Self::new(exe, exe).quiet()
    }

    /// Set the working directory for this task.
    pub(crate) fn cwd(mut self, dir: &Dir) -> Result<Self> {
        self.cmd.cwd_dir(dir.try_clone()?);
        Ok(self)
    }

    pub(crate) fn new_cmd(description: impl AsRef<str>, mut cmd: Command) -> Self {
        let description = description.as_ref().to_string();
        // Default to noninteractive
        cmd.stdin(Stdio::null());
        Self {
            description,
            verbosity: Default::default(),
            quiet_output: false,
            cmd,
        }
    }

    /// Don't output description by default
    pub(crate) fn quiet(mut self) -> Self {
        self.verbosity = CmdVerbosity::Quiet;
        self
    }

    /// Output description and cmdline
    pub(crate) fn verbose(mut self) -> Self {
        self.verbosity = CmdVerbosity::Verbose;
        self
    }

    // Do not print stdout/stderr, unless the command fails
    pub(crate) fn quiet_output(mut self) -> Self {
        self.quiet_output = true;
        self
    }

    pub(crate) fn args<S: AsRef<OsStr>>(mut self, args: impl IntoIterator<Item = S>) -> Self {
        self.cmd.args(args);
        self
    }

    pub(crate) fn arg<S: AsRef<OsStr>>(mut self, arg: S) -> Self {
        self.cmd.args([arg]);
        self
    }

    /// Run the command, returning an error if the command does not exit successfully.
    pub(crate) fn run(self) -> Result<()> {
        self.run_with_stdin_buf(None)
    }

    fn pre_run_output(&self) {
        match self.verbosity {
            CmdVerbosity::Quiet => {}
            CmdVerbosity::Description => {
                println!("{}", self.description);
            }
            CmdVerbosity::Verbose => {
                // Output the description first
                println!("{}", self.description);

                // Lock stdout so we buffer
                let mut stdout = std::io::stdout().lock();
                let cmd_args = std::iter::once(self.cmd.get_program())
                    .chain(self.cmd.get_args())
                    .map(|arg| arg.to_string_lossy());
                // We unwrap() here to match the default for println!() even though
                // arguably that's wrong
                stdout.write_all(b">").unwrap();
                for s in cmd_args {
                    stdout.write_all(b" ").unwrap();
                    stdout.write_all(s.as_bytes()).unwrap();
                }
                stdout.write_all(b"\n").unwrap();
            }
        }
    }

    /// Run the command with optional stdin buffer, returning an error if the command does not exit successfully.
    pub(crate) fn run_with_stdin_buf(self, stdin: Option<&[u8]>) -> Result<()> {
        self.pre_run_output();
        let description = self.description;
        let mut cmd = self.cmd;
        let mut output = None;
        if self.quiet_output {
            let tmpf = tempfile::tempfile()?;
            cmd.stdout(Stdio::from(tmpf.try_clone()?));
            cmd.stderr(Stdio::from(tmpf.try_clone()?));
            output = Some(tmpf);
        }
        tracing::debug!("exec: {cmd:?}");
        let st = if let Some(stdin_value) = stdin {
            cmd.stdin(Stdio::piped());
            let mut child = cmd.spawn()?;
            // SAFETY: We used piped for stdin
            let mut stdin = child.stdin.take().unwrap();
            // If this was async, we could avoid spawning a thread here
            std::thread::scope(|s| {
                s.spawn(move || stdin.write_all(stdin_value))
                    .join()
                    .map_err(|e| anyhow::anyhow!("Failed to spawn thread: {e:?}"))?
                    .context("Failed to write to cryptsetup stdin")
            })?;
            child.wait()?
        } else {
            cmd.status()?
        };
        tracing::trace!("{st:?}");
        if !st.success() {
            if let Some(mut output) = output {
                output.seek(std::io::SeekFrom::Start(0))?;
                let mut stderr = std::io::stderr().lock();
                std::io::copy(&mut output, &mut stderr)?;
            }
            anyhow::bail!("Task {description} failed: {st:?}");
        }
        Ok(())
    }

    /// Like [`Task::run`], but return stdout.
    pub(crate) fn read(self) -> Result<String> {
        self.pre_run_output();
        let description = self.description;
        let mut cmd = self.cmd;
        tracing::debug!("exec: {cmd:?}");
        cmd.stdout(Stdio::piped());
        let child = cmd
            .spawn()
            .with_context(|| format!("Spawning {description} failed"))?;
        let o = child
            .wait_with_output()
            .with_context(|| format!("Executing {description} failed"))?;
        let st = o.status;
        if !st.success() {
            anyhow::bail!("Task {description} failed: {st:?}");
        }
        Ok(String::from_utf8(o.stdout)?)
    }

    pub(crate) fn new_and_run<'a>(
        description: impl AsRef<str>,
        exe: impl AsRef<str>,
        args: impl IntoIterator<Item = &'a str>,
    ) -> Result<()> {
        let mut t = Self::new(description.as_ref(), exe);
        t.cmd.args(args);
        t.run()
    }
}
