//! Machine-readable result of `bootc install`.
//!
//! An installer wrapping `bootc install` usually needs to know where the new
//! deployment ended up, e.g. to inject configuration into its `/etc` before
//! the first boot.  The `--output-{json,pairs}-{path,fd}` options write an
//! [`InstallResult`] once the installation has succeeded, either as JSON or
//! as shell-quoted `KEY="value"` lines in the style of `lsblk --pairs --shell`.

use std::io::Write;
use std::os::fd::{AsFd, AsRawFd, IntoRawFd};
use std::str::FromStr;

use anyhow::{Context, Result, anyhow};
use bootc_utils::{InheritedFd, write_shell_pairs};
use camino::{Utf8Path, Utf8PathBuf};
use cap_std_ext::cap_std::fs::{Dir, Permissions, PermissionsExt};
use cap_std_ext::dirext::CapStdExtDirExt;
use ostree_ext::container::OstreeImageReference;
use rustix::fs::{Access, AtFlags, Mode, OFlags};
use serde::Serialize;

use crate::spec::{Bootloader, ImageReference};
use crate::store::Backend;

/// Carries the directory of an `--output-*-path` across re-executions of
/// bootc; see [`OutputPath`].
const OUTPUT_DIRFD_ENV: &str = "_BOOTC_INSTALL_OUTPUT_DIRFD";

/// Mode of a file written by `--output-*-path`.
const OUTPUT_FILE_MODE: u32 = 0o644;

/// Options to write the result of the installation in a machine-readable form.
///
/// The destinations are validated as the arguments are parsed, so that a bad
/// one fails before anything is installed.
#[derive(Debug, Clone, Default, clap::Args, PartialEq, Eq)]
#[group(id = "install-output", multiple = false)]
pub(crate) struct InstallOutputOpts {
    /// Write the result of the installation as JSON to this path, replacing it
    /// atomically.
    ///
    /// Nothing is written unless the installation succeeds.  At most one of
    /// the --output-* options may be given.
    #[clap(long, value_name = "PATH", value_parser = parse_output_path)]
    pub(crate) output_json_path: Option<OutputPath>,

    /// Write the result of the installation as JSON to this inherited file
    /// descriptor, which must be open for writing, then close it.
    #[clap(long, value_name = "FD", value_parser = parse_output_fd)]
    pub(crate) output_json_fd: Option<InheritedFd>,

    /// Write the result of the installation as shell-quoted KEY="value" lines,
    /// like `lsblk --pairs --shell`, to this path, replacing it atomically.
    ///
    /// The output is suitable for `eval` or `.` in a shell script.
    #[clap(long, value_name = "PATH", value_parser = parse_output_path)]
    pub(crate) output_pairs_path: Option<OutputPath>,

    /// Write the result of the installation as shell-quoted KEY="value" lines
    /// to this inherited file descriptor, which must be open for writing, then
    /// close it.
    #[clap(long, value_name = "FD", value_parser = parse_output_fd)]
    pub(crate) output_pairs_fd: Option<InheritedFd>,
}

impl InstallOutputOpts {
    /// The requested destination, if any.
    pub(crate) fn into_output(self) -> Option<InstallOutput> {
        let Self {
            output_json_path,
            output_json_fd,
            output_pairs_path,
            output_pairs_fd,
        } = self;
        // clap ensures that at most one of these is set
        [
            (OutputFormat::Json, output_json_path, output_json_fd),
            (OutputFormat::Pairs, output_pairs_path, output_pairs_fd),
        ]
        .into_iter()
        .find_map(|(format, path, fd)| {
            let dest = match (path, fd) {
                (Some(path), _) => Destination::Path(path),
                (None, Some(fd)) => Destination::Fd(fd),
                (None, None) => return None,
            };
            Some(InstallOutput { format, dest })
        })
    }
}

/// Parse an `--output-*-fd`, which must be inherited and open for writing.
fn parse_output_fd(s: &str) -> Result<InheritedFd, String> {
    let parse = || -> Result<InheritedFd> {
        let fd: InheritedFd = s.parse()?;
        let flags = rustix::fs::fcntl_getfl(fd.as_fd())?;
        if !flags.intersects(OFlags::WRONLY | OFlags::RDWR) {
            anyhow::bail!("fd {s} is not open for writing");
        }
        Ok(fd)
    };
    // clap shows only the outermost error otherwise
    parse().map_err(|e| format!("{e:#}"))
}

/// Parse an `--output-*-path`.
fn parse_output_path(s: &str) -> Result<OutputPath, String> {
    s.parse::<OutputPath>().map_err(|e| format!("{e:#}"))
}

/// A validated `--output-*-path`.
///
/// Its directory is opened while parsing the argument, and handed down to
/// re-executed bootc processes (see [`InstallOutput::reexec_env`]): these may
/// run with a tmpfs mounted on `/tmp`, where a path given by the caller would
/// otherwise silently end up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OutputPath {
    /// The directory, kept open across exec.
    dir: InheritedFd,
    name: String,
    path: Utf8PathBuf,
}

impl FromStr for OutputPath {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let path = Utf8Path::new(s);
        let name = path
            .file_name()
            .ok_or_else(|| anyhow!("{path}: Not a file path"))?
            .to_owned();
        let dir = match std::env::var(OUTPUT_DIRFD_ENV) {
            // Set by the process that re-executed us
            Ok(fd) => fd
                .parse()
                .with_context(|| format!("Parsing {OUTPUT_DIRFD_ENV}"))?,
            Err(std::env::VarError::NotPresent) => {
                let parent = path
                    .parent()
                    .filter(|p| !p.as_str().is_empty())
                    .unwrap_or(Utf8Path::new("."));
                // Deliberately without O_CLOEXEC, so it survives a re-exec.
                let dir = rustix::fs::open(
                    parent.as_std_path(),
                    OFlags::DIRECTORY | OFlags::RDONLY,
                    Mode::empty(),
                )
                .with_context(|| format!("Opening directory {parent}"))?;
                InheritedFd::new(dir.into_raw_fd())?
            }
            Err(e) => return Err(e).with_context(|| format!("Reading {OUTPUT_DIRFD_ENV}")),
        };
        let r = Self {
            dir,
            name,
            path: path.to_owned(),
        };
        r.validate().with_context(|| format!("Validating {path}"))?;
        Ok(r)
    }
}

impl OutputPath {
    fn validate(&self) -> Result<()> {
        let dir = self.dir.as_fd();
        rustix::fs::accessat(dir, ".", Access::WRITE_OK, AtFlags::EACCESS)
            .context("Checking that the directory is writable")?;
        match rustix::fs::statat(dir, self.name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) if rustix::fs::FileType::from_raw_mode(st.st_mode).is_dir() => {
                anyhow::bail!("Is a directory")
            }
            Ok(_) | Err(rustix::io::Errno::NOENT) => Ok(()),
            Err(e) => Err(e).context("Querying the existing file"),
        }
    }
}

/// What `bootc install` installed.
///
/// This is a stable interface, documented in bootc-install-to-filesystem(8):
/// keys may be added, but existing ones keep their meaning.  Paths are
/// relative to the root of the target filesystem.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InstallResult {
    /// The storage backend.
    pub(crate) backend: Backend,
    /// The stateroot of the deployment.
    pub(crate) stateroot: String,
    /// The deployment's root directory.
    pub(crate) deployment_path: Utf8PathBuf,
    /// The deployment's persistent `/etc`.
    pub(crate) etc_path: Utf8PathBuf,
    /// The persistent `/var`, shared by the deployments of the stateroot.
    pub(crate) var_path: Utf8PathBuf,
    /// The bootloader that was set up.
    pub(crate) bootloader: Bootloader,
    /// The image the system will update from.
    pub(crate) image: String,
    /// The transport of `image`, e.g. `registry`.
    pub(crate) image_transport: String,
    /// The manifest digest of the installed image.
    pub(crate) image_digest: String,
}

impl InstallResult {
    pub(crate) fn new(
        backend: Backend,
        stateroot: String,
        deployment_path: Utf8PathBuf,
        var_path: Utf8PathBuf,
        bootloader: Bootloader,
        target_imgref: &OstreeImageReference,
        image_digest: String,
    ) -> Self {
        let ImageReference {
            image, transport, ..
        } = ImageReference::from(target_imgref.clone());
        Self {
            backend,
            stateroot,
            etc_path: deployment_path.join("etc"),
            deployment_path,
            var_path,
            bootloader,
            image,
            image_transport: transport,
            image_digest,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Json,
    Pairs,
}

impl OutputFormat {
    fn render(self, result: &InstallResult, mut w: impl Write) -> Result<()> {
        match self {
            OutputFormat::Json => {
                serde_json::to_writer_pretty(&mut w, result)?;
                writeln!(w)?;
            }
            OutputFormat::Pairs => write_shell_pairs(&mut w, result)?,
        }
        w.flush()?;
        Ok(())
    }
}

#[derive(Debug)]
enum Destination {
    Fd(InheritedFd),
    Path(OutputPath),
}

/// A validated output destination and format.
#[derive(Debug)]
pub(crate) struct InstallOutput {
    format: OutputFormat,
    dest: Destination,
}

impl InstallOutput {
    /// Environment for a re-executed bootc to find the destination again.
    pub(crate) fn reexec_env(&self) -> Option<(&'static str, String)> {
        match &self.dest {
            Destination::Path(p) => Some((OUTPUT_DIRFD_ENV, p.dir.as_fd().as_raw_fd().to_string())),
            Destination::Fd(_) => None,
        }
    }

    /// Make the destination close-on-exec, once bootc won't re-execute itself
    /// any more: the processes bootc runs to install must not inherit it,
    /// lest a caller reading a pipe to its end waits for them too.
    pub(crate) fn set_cloexec(&self) -> Result<()> {
        let fd = match &self.dest {
            Destination::Fd(fd) => fd.as_fd(),
            Destination::Path(p) => p.dir.as_fd(),
        };
        rustix::io::fcntl_setfd(fd, rustix::io::FdFlags::CLOEXEC)
            .context("Setting the output fd close-on-exec")?;
        Ok(())
    }

    /// Write the result; an fd is closed afterwards.
    pub(crate) fn write(self, result: &InstallResult) -> Result<()> {
        match self.dest {
            Destination::Fd(fd) => {
                let fdnum = fd.as_fd().as_raw_fd();
                let f = std::fs::File::from(fd.into_owned()?);
                self.format
                    .render(result, f)
                    .with_context(|| format!("Writing install result to fd {fdnum}"))
            }
            Destination::Path(OutputPath { dir, name, path }) => {
                let dir = Dir::from_std_file(std::fs::File::from(dir.into_owned()?));
                dir.atomic_replace_with(&name, |w| -> Result<()> {
                    w.get_mut()
                        .as_file_mut()
                        .set_permissions(Permissions::from_mode(OUTPUT_FILE_MODE))?;
                    self.format.render(result, w)
                })
                .with_context(|| format!("Writing install result to {path}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read as _;

    use cap_std_ext::cap_std;

    use super::*;

    fn sample_result() -> InstallResult {
        InstallResult::new(
            Backend::Ostree,
            "default".into(),
            "ostree/deploy/default/deploy/abc.0".into(),
            "ostree/deploy/default/var".into(),
            Bootloader::Grub,
            &"ostree-unverified-registry:quay.io/example/os:latest"
                .parse()
                .unwrap(),
            "sha256:0123".into(),
        )
    }

    fn render(format: OutputFormat) -> Vec<u8> {
        let mut buf = Vec::new();
        format.render(&sample_result(), &mut buf).unwrap();
        buf
    }

    #[test]
    fn test_render() {
        let json: serde_json::Value = serde_json::from_slice(&render(OutputFormat::Json)).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "backend": "ostree",
                "stateroot": "default",
                "deploymentPath": "ostree/deploy/default/deploy/abc.0",
                "etcPath": "ostree/deploy/default/deploy/abc.0/etc",
                "varPath": "ostree/deploy/default/var",
                "bootloader": "grub",
                "image": "quay.io/example/os:latest",
                "imageTransport": "registry",
                "imageDigest": "sha256:0123",
            })
        );
        let pairs = String::from_utf8(render(OutputFormat::Pairs)).unwrap();
        assert_eq!(
            pairs,
            indoc::indoc! {r#"
                BACKEND="ostree"
                BOOTLOADER="grub"
                DEPLOYMENT_PATH="ostree/deploy/default/deploy/abc.0"
                ETC_PATH="ostree/deploy/default/deploy/abc.0/etc"
                IMAGE="quay.io/example/os:latest"
                IMAGE_DIGEST="sha256:0123"
                IMAGE_TRANSPORT="registry"
                STATEROOT="default"
                VAR_PATH="ostree/deploy/default/var"
            "#}
        );
    }

    /// A pipe whose ends are not close-on-exec, as if inherited.
    fn inherited_pipe() -> Result<(std::fs::File, std::fs::File)> {
        let (r, w) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::empty())?;
        Ok((r.into(), w.into()))
    }

    #[test]
    fn test_fd_destination() -> Result<()> {
        // The read end is not writable
        // (parsing takes ownership of the fd, and closes it on error)
        let (r, _w) = inherited_pipe()?;
        let e = parse_output_fd(&r.into_raw_fd().to_string()).unwrap_err();
        assert!(e.contains("not open for writing"), "{e}");

        let (mut r, w) = inherited_pipe()?;
        let fd = parse_output_fd(&w.into_raw_fd().to_string()).map_err(anyhow::Error::msg)?;
        let output = InstallOutputOpts {
            output_pairs_fd: Some(fd),
            ..Default::default()
        }
        .into_output()
        .unwrap();
        assert_eq!(output.reexec_env(), None);
        output.write(&sample_result())?;
        // The write end is closed now, so this reads to EOF.
        let mut buf = String::new();
        r.read_to_string(&mut buf)?;
        assert!(buf.starts_with("BACKEND=\"ostree\"\n"), "{buf}");
        Ok(())
    }

    #[test]
    fn test_path_destination() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let tdpath = Utf8Path::from_path(tmp.path()).unwrap();
        let td = Dir::open_ambient_dir(tdpath, cap_std::ambient_authority())?;
        td.create_dir("subdir")?;

        for (path, msg) in [
            (tdpath.join("nonexistent/result.json"), "Opening directory"),
            (tdpath.join("subdir"), "Is a directory"),
            (tdpath.join(".."), "Not a file path"),
        ] {
            let e = parse_output_path(path.as_str()).unwrap_err();
            assert!(e.contains(msg), "{path}: {e}");
        }

        td.write("result.json", "old contents")?;
        let output = InstallOutputOpts {
            output_json_path: Some(tdpath.join("result.json").as_str().parse()?),
            ..Default::default()
        }
        .into_output()
        .unwrap();
        let (k, _) = output.reexec_env().unwrap();
        assert_eq!(k, OUTPUT_DIRFD_ENV);
        output.write(&sample_result())?;
        let written: serde_json::Value = serde_json::from_str(&td.read_to_string("result.json")?)?;
        assert_eq!(written, serde_json::to_value(sample_result())?);
        let mode = td.metadata("result.json")?.permissions().mode() & 0o7777;
        assert_eq!(mode, OUTPUT_FILE_MODE);
        Ok(())
    }

    #[test]
    fn test_no_output() {
        assert!(InstallOutputOpts::default().into_output().is_none());
    }
}
