use std::future::Future;
use std::io::Write;
use std::os::fd::BorrowedFd;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};
use bootc_utils::CommandRunExt;
use camino::Utf8Path;
use cap_std_ext::cap_std::fs::Dir;
use cap_std_ext::dirext::CapStdExtDirExt;
use cap_std_ext::prelude::CapStdExtCommandExt;
use fn_error_context::context;
use indicatif::HumanDuration;
use libsystemd::logging::journal_print;
use ostree::glib;
use ostree_ext::container::SignatureSource;
use ostree_ext::ostree;

/// Try to look for keys injected by e.g. rpm-ostree requesting machine-local
/// changes; if any are present, return `true`.
pub(crate) fn origin_has_rpmostree_stuff(kf: &glib::KeyFile) -> bool {
    // These are groups set in https://github.com/coreos/rpm-ostree/blob/27f72dce4f9b5c176ad030911c12354e2498c07d/rust/src/origin.rs#L23
    // TODO: Add some notion of "owner" into origin files
    for group in ["rpmostree", "packages", "overrides", "modules"] {
        if kf.has_group(group) {
            return true;
        }
    }
    false
}

// Access the file descriptor for a sysroot
#[allow(unsafe_code)]
pub(crate) fn sysroot_fd(sysroot: &ostree::Sysroot) -> BorrowedFd<'_> {
    unsafe { BorrowedFd::borrow_raw(sysroot.fd()) }
}

// Return a cap-std `Dir` type for a sysroot
pub(crate) fn sysroot_dir(sysroot: &ostree::Sysroot) -> Result<Dir> {
    Dir::reopen_dir(&sysroot_fd(sysroot)).map_err(Into::into)
}

// Return a cap-std `Dir` type for a deployment.
// TODO: in the future this should perhaps actually mount via composefs
pub(crate) fn deployment_fd(
    sysroot: &ostree::Sysroot,
    deployment: &ostree::Deployment,
) -> Result<Dir> {
    let sysroot_dir = &Dir::reopen_dir(&sysroot_fd(sysroot))?;
    let dirpath = sysroot.deployment_dirpath(deployment);
    sysroot_dir.open_dir(&dirpath).map_err(Into::into)
}

/// Given an mount option string list like foo,bar=baz,something=else,ro parse it and find
/// the first entry like $optname=
/// This will not match a bare `optname` without an equals.
pub(crate) fn find_mount_option<'a>(
    option_string_list: &'a str,
    optname: &'_ str,
) -> Option<&'a str> {
    option_string_list
        .split(',')
        .filter_map(|k| k.split_once('='))
        .filter_map(|(k, v)| (k == optname).then_some(v))
        .next()
}

pub fn have_executable(name: &str) -> Result<bool> {
    let Some(path) = std::env::var_os("PATH") else {
        return Ok(false);
    };
    for mut elt in std::env::split_paths(&path) {
        elt.push(name);
        if elt.try_exists()? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Given a target directory, if it's a read-only mount, then remount it writable
#[context("Opening {target} with writable mount")]
pub(crate) fn open_dir_remount_rw(root: &Dir, target: &Utf8Path) -> Result<Dir> {
    if matches!(root.is_mountpoint(target), Ok(Some(true))) {
        tracing::debug!("Target {target} is a mountpoint, remounting rw");
        let st = Command::new("mount")
            .args(["-o", "remount,rw", target.as_str()])
            .cwd_dir(root.try_clone()?)
            .status()?;

        anyhow::ensure!(st.success(), "Failed to remount: {st:?}");
    }
    root.open_dir(target).map_err(anyhow::Error::new)
}

/// Given a target path, remove its immutability if present
#[context("Removing immutable flag from {target}")]
pub(crate) fn remove_immutability(root: &Dir, target: &Utf8Path) -> Result<()> {
    use anyhow::ensure;

    tracing::debug!("Target {target} is a mountpoint, remounting rw");
    let st = Command::new("chattr")
        .args(["-i", target.as_str()])
        .cwd_dir(root.try_clone()?)
        .status()?;

    ensure!(st.success(), "Failed to remove immutability: {st:?}");

    Ok(())
}

pub(crate) fn spawn_editor(tmpf: &tempfile::NamedTempFile) -> Result<()> {
    let editor_variables = ["EDITOR"];
    // These roughly match https://github.com/systemd/systemd/blob/769ca9ab557b19ee9fb5c5106995506cace4c68f/src/shared/edit-util.c#L275
    let backup_editors = ["nano", "vim", "vi"];
    let editor = editor_variables.into_iter().find_map(std::env::var_os);
    let editor = if let Some(e) = editor.as_ref() {
        e.to_str()
    } else {
        backup_editors
            .into_iter()
            .find(|v| std::path::Path::new("/usr/bin").join(v).exists())
    };
    let editor =
        editor.ok_or_else(|| anyhow::anyhow!("$EDITOR is unset, and no backup editor found"))?;
    let mut editor_args = editor.split_ascii_whitespace();
    let argv0 = editor_args
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid editor: {editor}"))?;
    Command::new(argv0)
        .args(editor_args)
        .arg(tmpf.path())
        .lifecycle_bind()
        .run_inherited()
        .with_context(|| format!("Invoking editor {editor} failed"))
}

/// Convert a combination of values (likely from CLI parsing) into a signature source
pub(crate) fn sigpolicy_from_opt(enforce_container_verification: bool) -> SignatureSource {
    match enforce_container_verification {
        true => SignatureSource::ContainerPolicy,
        false => SignatureSource::ContainerPolicyAllowInsecure,
    }
}

/// Output a warning message that we want to be quite visible.
/// The process (thread) execution will be delayed for a short time.
pub(crate) fn medium_visibility_warning(s: &str) {
    anstream::eprintln!(
        "{}{s}{}",
        anstyle::AnsiColor::Red.render_fg(),
        anstyle::Reset.render()
    );
    // When warning, add a sleep to ensure it's seen
    std::thread::sleep(std::time::Duration::from_secs(1));
}

/// Call an async task function, and write a message to stderr
/// with an automatic spinner to show that we're not blocked.
/// Note that generally the called function should not output
/// anything to stderr as this will interfere with the spinner.
pub(crate) async fn async_task_with_spinner<F, T>(msg: &str, f: F) -> T
where
    F: Future<Output = T>,
{
    let start_time = std::time::Instant::now();
    let pb = indicatif::ProgressBar::new_spinner();
    let style = indicatif::ProgressStyle::default_bar();
    pb.set_style(style.template("{spinner} {msg}").unwrap());
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(Duration::from_millis(150));
    // We need to handle the case where we aren't connected to
    // a tty, so indicatif would show nothing by default.
    if pb.is_hidden() {
        eprint!("{msg}...");
        std::io::stderr().flush().unwrap();
    }
    let r = f.await;
    let elapsed = HumanDuration(start_time.elapsed());
    let _ = journal_print(
        libsystemd::logging::Priority::Info,
        &format!("completed task in {elapsed}: {msg}"),
    );
    if pb.is_hidden() {
        eprintln!("done ({elapsed})");
    } else {
        pb.finish_with_message(format!("{msg}: done ({elapsed})"));
    }
    r
}

/// Given a possibly tagged image like quay.io/foo/bar:latest and a digest 0ab32..., return
/// the digested form quay.io/foo/bar:latest@sha256:0ab32...
/// If the image already has a digest, it will be replaced.
#[allow(dead_code)]
pub(crate) fn digested_pullspec(image: &str, digest: &str) -> String {
    let image = image.rsplit_once('@').map(|v| v.0).unwrap_or(image);
    format!("{image}@{digest}")
}

#[derive(Debug)]
pub enum EfiError {
    SystemNotUEFI,
    MissingVar,
    #[allow(dead_code)]
    InvalidData(&'static str),
    #[allow(dead_code)]
    Io(std::io::Error),
}

impl From<std::io::Error> for EfiError {
    fn from(e: std::io::Error) -> Self {
        EfiError::Io(e)
    }
}

pub fn read_uefi_var(var_name: &str) -> Result<String, EfiError> {
    use crate::install::EFIVARFS;
    use cap_std_ext::cap_std::ambient_authority;

    let efivarfs = match Dir::open_ambient_dir(EFIVARFS, ambient_authority()) {
        Ok(dir) => dir,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(EfiError::SystemNotUEFI),
        Err(e) => Err(e)?,
    };

    match efivarfs.read(var_name) {
        Ok(loader_bytes) => {
            if loader_bytes.len() % 2 != 0 {
                return Err(EfiError::InvalidData(
                    "EFI var length is not valid UTF-16 LE",
                ));
            }

            // EFI vars are UTF-16 LE
            let loader_u16_bytes: Vec<u16> = loader_bytes
                .chunks_exact(2)
                .map(|x| u16::from_le_bytes([x[0], x[1]]))
                .collect();

            let loader = String::from_utf16(&loader_u16_bytes)
                .map_err(|_| EfiError::InvalidData("EFI var is not UTF-16"))?;

            return Ok(loader);
        }

        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(EfiError::MissingVar);
        }

        Err(e) => Err(e)?,
    }
}

/// Computes a relative path from `from` to `to`.
///
/// Both `from` and `to` must be absolute paths.
pub(crate) fn path_relative_to(from: &Path, to: &Path) -> Result<PathBuf> {
    if !from.is_absolute() || !to.is_absolute() {
        anyhow::bail!("Paths must be absolute");
    }

    let from = from.components().collect::<Vec<_>>();
    let to = to.components().collect::<Vec<_>>();

    let common = from.iter().zip(&to).take_while(|(a, b)| a == b).count();

    let up = std::iter::repeat(Component::ParentDir).take(from.len() - common);

    let mut final_path = PathBuf::new();
    final_path.extend(up);
    final_path.extend(&to[common..]);

    return Ok(final_path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digested_pullspec() {
        let digest = "ebe3bdccc041864e5a485f1e755e242535c3b83d110c0357fe57f110b73b143e";
        assert_eq!(
            digested_pullspec("quay.io/example/foo:bar", digest),
            format!("quay.io/example/foo:bar@{digest}")
        );
        assert_eq!(
            digested_pullspec("quay.io/example/foo@sha256:otherdigest", digest),
            format!("quay.io/example/foo@{digest}")
        );
        assert_eq!(
            digested_pullspec("quay.io/example/foo", digest),
            format!("quay.io/example/foo@{digest}")
        );
    }

    #[test]
    fn test_find_mount_option() {
        const V1: &str = "rw,relatime,compress=foo,subvol=blah,fast";
        assert_eq!(find_mount_option(V1, "subvol").unwrap(), "blah");
        assert_eq!(find_mount_option(V1, "rw"), None);
        assert_eq!(find_mount_option(V1, "somethingelse"), None);
    }

    #[test]
    fn test_sigpolicy_from_opts() {
        assert_eq!(sigpolicy_from_opt(true), SignatureSource::ContainerPolicy);
        assert_eq!(
            sigpolicy_from_opt(false),
            SignatureSource::ContainerPolicyAllowInsecure
        );
    }

    #[test]
    fn test_relative_path() {
        let from = Path::new("/sysroot/state/deploy/image_id");
        let to = Path::new("/sysroot/state/os/default/var");

        assert_eq!(
            path_relative_to(from, to).unwrap(),
            PathBuf::from("../../os/default/var")
        );
        assert_eq!(
            path_relative_to(&Path::new("state/deploy"), to)
                .unwrap_err()
                .to_string(),
            "Paths must be absolute"
        );
    }

    #[test]
    fn test_have_executable() {
        assert!(have_executable("true").unwrap());
        assert!(!have_executable("someexethatdoesnotexist").unwrap());
    }
}
