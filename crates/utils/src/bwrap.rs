/// Builder for running commands inside a target os tree using bubblewrap (bwrap).
use std::borrow::Cow;
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::process::{Command, ExitStatus, Stdio};

use anyhow::{Context, Result};
use cap_std_ext::camino::{Utf8Path, Utf8PathBuf};
use cap_std_ext::cap_std::fs::Dir;

use crate::CommandRunExt;

/// Hardcoded English substring `bwrap` prints to stderr when its
/// `clone()` for a new user namespace returns `EINVAL`. The trailing
/// `: <strerror>` text is locale-dependent, so we deliberately match
/// only this prefix from `bubblewrap/bubblewrap.c`. Observed under QEMU
/// user-mode emulation in <https://github.com/bootc-dev/bootc/issues/2111>.
const BWRAP_NAMESPACE_ERROR_MARKER: &str = "Creating new namespace failed";

/// Builder for running commands inside a target directory using bwrap.
#[derive(Debug)]
pub struct BwrapCmd<'a> {
    /// The target directory to use as root for the container
    chroot_path: Cow<'a, Utf8Path>,
    /// Bind mounts in format (source, target)
    bind_mounts: Vec<(&'a str, &'a str)>,
    /// Environment variables to set
    env_vars: Vec<(&'a str, &'a str)>,
    /// Path to the `bwrap` binary. Always `"bwrap"` outside of tests;
    /// tests use `with_bwrap_program` to inject a fake.
    bwrap_program: &'a str,
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
            bwrap_program: "bwrap",
        }
    }

    /// Create a new BwrapCmd builder with a root directory
    pub fn new(path: &'a Utf8Path) -> Self {
        Self {
            chroot_path: Cow::Borrowed(path),
            bind_mounts: Vec::new(),
            env_vars: Vec::new(),
            bwrap_program: "bwrap",
        }
    }

    /// Override the `bwrap` binary path. Test-only hook to point the
    /// builder at a fake bwrap that exercises a specific stderr/exit
    /// pattern.
    #[cfg(test)]
    fn with_bwrap_program(mut self, prog: &'a str) -> Self {
        self.bwrap_program = prog;
        self
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

    /// Promote this bwrap builder to one that can fall back to a
    /// direct invocation of `fallback_program` if bwrap cannot create
    /// a new namespace. The same program is exec'd inside the bwrap
    /// chroot, so the bwrap variant becomes
    /// `bwrap … -- <fallback_program> <args>`. See
    /// [`BwrapCmdWithFallback`].
    pub fn with_fallback(self, fallback_program: &'a str) -> BwrapCmdWithFallback<'a> {
        BwrapCmdWithFallback {
            bwrap: self,
            fallback_program,
            args: Vec::new(),
        }
    }

    /// Build the bwrap `Command` with all bind mounts, env vars, and args.
    fn build_command<S: AsRef<OsStr>>(&self, args: impl IntoIterator<Item = S>) -> Command {
        let mut cmd = Command::new(self.bwrap_program);

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

/// A `BwrapCmd` paired with a program to invoke in two variants:
/// inside the bwrap chroot, and directly (the fallback) if `bwrap`
/// cannot create a new namespace.
///
/// On invocation the bwrap variant is built and tried first as
/// `bwrap … -- <fallback_program> <bwrap-side args>`. If it fails
/// with stderr containing the bwrap namespace-creation error marker
/// the wrapper runs `<fallback_program> <fallback-side args>`
/// instead. Any other failure is propagated unchanged.
///
/// Symmetric args (identical in both invocations) are added via
/// [`Self::args`]; asymmetric args, where the bwrap and fallback
/// forms differ (e.g. chroot-relative `/` ↔ a real rootfs path), go
/// through [`Self::arg_pair`] or [`Self::arg_pairs`]. Keeping the
/// rewrite local to the call site avoids the alternative of two
/// parallel arg lists that can drift out of sync.
///
/// Note: this fallback will naturally stop firing once the upstream
/// bwrap/qemu-user/kernel interaction is fixed. At that point, this
/// wrapper can be removed.
#[derive(Debug)]
pub struct BwrapCmdWithFallback<'a> {
    bwrap: BwrapCmd<'a>,
    fallback_program: &'a str,
    /// `(bwrap_arg, fallback_arg)` pairs. Identical entries (e.g.
    /// `(a, a)`) mean the arg is the same in both invocations.
    args: Vec<(&'a str, &'a str)>,
}

impl<'a> BwrapCmdWithFallback<'a> {
    /// Append args used as-is in both the bwrap and fallback
    /// invocations. Equivalent to passing `(a, a)` pairs to
    /// [`Self::arg_pairs`]; mirrors [`std::process::Command::args`]
    /// for the common symmetric case.
    pub fn args<I>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = &'a str>,
    {
        self.args.extend(args.into_iter().map(|a| (a, a)));
        self
    }

    /// Add a single `(bwrap, fallback)` arg pair. Use this when the
    /// arg must differ between the two invocations (e.g. a
    /// chroot-relative `/` in the bwrap form and a real rootfs path
    /// in the fallback form).
    pub fn arg_pair(mut self, bwrap: &'a str, fallback: &'a str) -> Self {
        self.args.push((bwrap, fallback));
        self
    }

    /// Append multiple `(bwrap, fallback)` arg pairs.
    pub fn arg_pairs<I>(mut self, pairs: I) -> Self
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        self.args.extend(pairs);
        self
    }

    /// Run the bwrap-wrapped command with stdout inherited and stderr
    /// piped through a tee to the parent. On bwrap namespace-creation
    /// failure, run the fallback `Command` instead.
    ///
    /// Stderr is piped (rather than inherited) so we can inspect it
    /// for the bwrap namespace-creation error marker; every chunk
    /// read is forwarded to the real stderr in real time, so the user
    /// still sees output as it happens with no parent-side buffering.
    ///
    /// Caveat: because the child's stderr is a pipe rather than the
    /// parent's terminal, programs that probe `isatty(STDERR)` (most
    /// CLI tools doing colourisation, spinners, or `\r`-based
    /// progress bars) will render the non-TTY variant.
    pub fn run(self) -> Result<()> {
        let mut cmd = self.bwrap.build_command(self.bwrap_argv());
        cmd.log_debug();
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().context("Spawning bwrap")?;
        let mut child_stderr = child.stderr.take().expect("piped stderr");
        let mut stderr = std::io::stderr();
        let stderr_buf =
            tee_to_writer(&mut child_stderr, &mut stderr).context("Reading bwrap stderr")?;
        let status = child.wait().context("Waiting for bwrap")?;
        if is_bwrap_namespace_creation_failure(status, &stderr_buf) {
            self.log_falling_back(&stderr_buf);
            return self.build_fallback().run_inherited_with_cmd_context();
        }
        if !status.success() {
            anyhow::bail!("Failed to run bwrap command {cmd:#?}: {status}");
        }
        Ok(())
    }

    /// Run the bwrap-wrapped command and capture stdout as a string. On
    /// bwrap namespace-creation failure, run the fallback `Command`
    /// instead.
    pub fn run_get_string(self) -> Result<String> {
        let mut cmd = self.bwrap.build_command(self.bwrap_argv());
        cmd.log_debug();
        let output = cmd.output().context("Spawning bwrap")?;
        if is_bwrap_namespace_creation_failure(output.status, &output.stderr) {
            self.log_falling_back(&output.stderr);
            return self.build_fallback().run_get_string();
        }
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "Failed to run bwrap command {cmd:#?}: {}\n{stderr}",
                output.status
            );
        }
        String::from_utf8(output.stdout).context("bwrap stdout was not valid UTF-8")
    }

    /// The argv passed *inside* the bwrap chroot: the fallback
    /// program (which is also what bwrap will exec) followed by the
    /// bwrap-side arg of every pair.
    fn bwrap_argv(&self) -> Vec<&'a str> {
        std::iter::once(self.fallback_program)
            .chain(self.args.iter().map(|&(b, _)| b))
            .collect()
    }

    fn build_fallback(&self) -> Command {
        let mut cmd = Command::new(self.fallback_program);
        cmd.args(self.args.iter().map(|&(_, a)| a));
        cmd.log_debug();
        cmd
    }

    fn log_falling_back(&self, stderr: &[u8]) {
        tracing::debug!(
            "bwrap stderr: {}",
            String::from_utf8_lossy(stderr).trim_end()
        );
        // Bypass tracing: this fallback silently changes sandboxing
        // semantics, so it must surface together with the bwrap error message.
        eprintln!(
            "warning: bwrap could not create a new namespace; falling back to direct invocation of {:?}. \
             See https://github.com/bootc-dev/bootc/issues/2111",
            self.fallback_program,
        );
    }
}

/// Read from `reader` until EOF, copying every chunk to `writer` in
/// real time and accumulating a captured copy of the same bytes.
///
/// Write errors on `writer` are silently dropped: the captured buffer
/// is the contract; the tee'd writer copy is best-effort. When the
/// caller passes `std::io::stderr()` its `Write` impl locks
/// internally per `write_all`, so concurrent writers (e.g. `tracing`)
/// can interleave between chunks.
fn tee_to_writer<R: Read, W: Write>(reader: &mut R, writer: &mut W) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = reader.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        let _ = writer.write_all(&chunk[..n]);
        // Unbounded by design: the only existing caller pipes bwrap's
        // stderr, which is silent on success and a single line on
        // namespace failure. If a future caller pipes something
        // noisier through here this assumption should be revisited.
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(buf)
}

fn is_bwrap_namespace_creation_failure(status: ExitStatus, stderr: &[u8]) -> bool {
    if status.success() {
        return false;
    }
    let marker = BWRAP_NAMESPACE_ERROR_MARKER.as_bytes();
    stderr.windows(marker.len()).any(|w| w == marker)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, MutexGuard};

    /// Serialises tests that `fs::write` then `exec` a script in a
    /// tempdir. With parallel cargo test threads, the multi-threaded
    /// fork+exec race can cause ETXTBSY: another thread mid-`fs::write`
    /// holds an open write fd that gets inherited by a third thread's
    /// fork(), and the kernel sees the would-be-execed file as still
    /// open for writing. The window is tiny but reliably hit; gating
    /// these tests on one mutex eliminates it without affecting the
    /// pure unit tests.
    static FAKE_BIN_LOCK: Mutex<()> = Mutex::new(());

    fn lock_fake_bin() -> MutexGuard<'static, ()> {
        FAKE_BIN_LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn write_executable(path: &Path, contents: &str) {
        fs::write(path, contents).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// A fake bwrap + fallback pair living in a tempdir. Holding the
    /// `TempDir` keeps the scripts alive for the test's duration.
    struct FakeBinaries {
        tmp: tempfile::TempDir,
        bwrap: PathBuf,
        fallback: PathBuf,
    }

    impl FakeBinaries {
        fn new(bwrap_script: &str, fallback_script: &str) -> Self {
            let tmp = tempfile::TempDir::new().unwrap();
            let bwrap = tmp.path().join("bwrap");
            let fallback = tmp.path().join("fallback");
            write_executable(&bwrap, bwrap_script);
            write_executable(&fallback, fallback_script);
            Self {
                tmp,
                bwrap,
                fallback,
            }
        }
        fn dir(&self) -> &Path {
            self.tmp.path()
        }
        fn bwrap_str(&self) -> &str {
            self.bwrap.to_str().unwrap()
        }
        fn fallback_str(&self) -> &str {
            self.fallback.to_str().unwrap()
        }
    }

    /// Fake bwrap that prints the namespace-creation marker to stderr
    /// and exits non-zero — the exact symptom of issue #2111.
    const FAKE_BWRAP_NAMESPACE_FAIL: &str = "\
#!/bin/sh
echo 'bwrap: Creating new namespace failed: Invalid argument' >&2
exit 1
";

    /// Fake bwrap that records its argv (one arg per line) into
    /// `args.log` next to the script and exits 0.
    const FAKE_BWRAP_LOG_ARGS: &str = "\
#!/bin/sh
log=\"$(dirname \"$0\")/bwrap.argv\"
: > \"$log\"
for arg in \"$@\"; do
    printf '%s\\n' \"$arg\" >> \"$log\"
done
";

    /// Fake fallback that records its argv into `fallback.argv` next
    /// to the script and exits 0.
    const FAKE_FALLBACK_LOG_ARGS: &str = "\
#!/bin/sh
log=\"$(dirname \"$0\")/fallback.argv\"
: > \"$log\"
for arg in \"$@\"; do
    printf '%s\\n' \"$arg\" >> \"$log\"
done
";

    fn read_argv_log(path: &Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|s| s.to_string())
            .collect()
    }

    #[test]
    fn tee_to_writer_captures_full_input() {
        // The captured buffer must contain every byte read from the
        // reader: downstream marker detection depends on it being
        // complete.
        let input: &[u8] = b"bwrap: Creating new namespace failed: Invalid argument\nextra line\n";
        let mut reader = std::io::Cursor::new(input);
        let mut sink = std::io::sink();
        let captured = tee_to_writer(&mut reader, &mut sink).unwrap();
        assert_eq!(captured.as_slice(), input);
    }

    #[test]
    fn tee_to_writer_handles_empty_input() {
        let mut reader = std::io::Cursor::new(&[][..]);
        let mut sink = std::io::sink();
        let captured = tee_to_writer(&mut reader, &mut sink).unwrap();
        assert!(captured.is_empty());
    }

    #[test]
    fn tee_to_writer_handles_input_larger_than_chunk() {
        // 4096-byte chunk size; exercise the multi-iteration path.
        let input = vec![b'x'; 4096 * 3 + 17];
        let mut reader = std::io::Cursor::new(&input[..]);
        let mut sink = std::io::sink();
        let captured = tee_to_writer(&mut reader, &mut sink).unwrap();
        assert_eq!(captured, input);
    }

    #[test]
    fn tee_to_writer_forwards_to_writer() {
        // Both destinations should receive every byte.
        let input: &[u8] = b"hello world";
        let mut reader = std::io::Cursor::new(input);
        let mut forwarded = Vec::new();
        let captured = tee_to_writer(&mut reader, &mut forwarded).unwrap();
        assert_eq!(captured.as_slice(), input);
        assert_eq!(forwarded.as_slice(), input);
    }

    #[test]
    fn run_falls_back_on_namespace_marker() {
        let _guard = lock_fake_bin();
        let fake_bins = FakeBinaries::new(
            FAKE_BWRAP_NAMESPACE_FAIL,
            // Fallback exits 0 so a successful Result means it ran.
            "#!/bin/sh\nexit 0\n",
        );
        let chroot = Utf8Path::new("/");
        let result = BwrapCmd::new(chroot)
            .with_bwrap_program(fake_bins.bwrap_str())
            .with_fallback(fake_bins.fallback_str())
            .run();
        assert!(result.is_ok(), "expected fallback success, got {result:?}");
    }

    #[test]
    fn run_does_not_fall_back_on_non_marker_failure() {
        let _guard = lock_fake_bin();
        let fake_bins = FakeBinaries::new(
            "#!/bin/sh\necho 'some other bwrap error' >&2\nexit 1\n",
            // If the fallback runs, it exits 99 — but the assertion below
            // checks for the bwrap-failure message, not the fallback's.
            "#!/bin/sh\nexit 99\n",
        );
        let chroot = Utf8Path::new("/");
        let err = BwrapCmd::new(chroot)
            .with_bwrap_program(fake_bins.bwrap_str())
            .with_fallback(fake_bins.fallback_str())
            .run()
            .expect_err("non-marker failure should error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Failed to run bwrap"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn run_succeeds_without_invoking_fallback() {
        let _guard = lock_fake_bin();
        let fake_bins = FakeBinaries::new(
            "#!/bin/sh\nexit 0\n",
            // If the fallback runs the test fails (exit 99 → Err).
            "#!/bin/sh\nexit 99\n",
        );
        let chroot = Utf8Path::new("/");
        let result = BwrapCmd::new(chroot)
            .with_bwrap_program(fake_bins.bwrap_str())
            .with_fallback(fake_bins.fallback_str())
            .run();
        assert!(result.is_ok(), "expected success, got {result:?}");
    }

    #[test]
    fn run_get_string_falls_back_and_returns_stdout() {
        let _guard = lock_fake_bin();
        let expected = "fallback-ok";
        let fake_bins = FakeBinaries::new(
            FAKE_BWRAP_NAMESPACE_FAIL,
            &format!("#!/bin/sh\nprintf '%s' '{expected}'\n"),
        );
        let chroot = Utf8Path::new("/");
        let out = BwrapCmd::new(chroot)
            .with_bwrap_program(fake_bins.bwrap_str())
            .with_fallback(fake_bins.fallback_str())
            .run_get_string()
            .unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn run_passes_expected_argv_to_bwrap() {
        let _guard = lock_fake_bin();
        // Verify the full bwrap command line that BwrapCmd assembles:
        // root bind, API filesystems, user binds, env vars, `--`,
        // then the fallback program and the bwrap-side of each arg
        // pair, in this order.
        let fake_bins = FakeBinaries::new(
            FAKE_BWRAP_LOG_ARGS,
            // Fallback shouldn't fire on success.
            "#!/bin/sh\nexit 99\n",
        );
        let chroot = Utf8Path::new("/tmp/chroot");
        BwrapCmd::new(chroot)
            .with_bwrap_program(fake_bins.bwrap_str())
            .bind(&"/host/boot", &"/boot")
            .setenv("PATH", "/bin:/usr/bin")
            .with_fallback("bootupctl")
            .args(["backend", "install"])
            .arg_pair("/", "/real")
            .run()
            .unwrap();
        let logged = read_argv_log(&fake_bins.dir().join("bwrap.argv"));
        let expected: Vec<&str> = vec![
            "--bind",
            "/tmp/chroot",
            "/",
            "--proc",
            "/proc",
            "--dev-bind",
            "/dev",
            "/dev",
            "--bind",
            "/sys",
            "/sys",
            "--tmpfs",
            "/run",
            "--bind",
            "/run",
            "/run",
            "--bind",
            "/host/boot",
            "/boot",
            "--setenv",
            "PATH",
            "/bin:/usr/bin",
            "--",
            "bootupctl",
            "backend",
            "install",
            "/",
        ];
        assert_eq!(logged, expected);
    }

    #[test]
    fn fallback_receives_rewritten_argv() {
        let _guard = lock_fake_bin();
        // The fallback must be invoked with the second element of
        // each arg pair. Exercising a `(/ → /real/rootfs)` pair pins
        // down the "rewrite at the call site" pattern end-to-end.
        let fake_bins = FakeBinaries::new(FAKE_BWRAP_NAMESPACE_FAIL, FAKE_FALLBACK_LOG_ARGS);
        let chroot = Utf8Path::new("/");
        BwrapCmd::new(chroot)
            .with_bwrap_program(fake_bins.bwrap_str())
            .with_fallback(fake_bins.fallback_str())
            .args(["backend", "install", "--filesystem"])
            .arg_pair("/", "/real/rootfs")
            .run()
            .unwrap();
        let logged = read_argv_log(&fake_bins.dir().join("fallback.argv"));
        assert_eq!(
            logged,
            vec!["backend", "install", "--filesystem", "/real/rootfs"]
        );
    }
}
