use std::borrow::Cow;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use bootc_utils::CommandRunExt;
use camino::{Utf8Path, Utf8PathBuf};
use cap_std::fs::Dir;
use cap_std::fs::{DirBuilder, OpenOptions};
use cap_std::io_lifetimes::AsFilelike;
use cap_std_ext::cap_std;
use cap_std_ext::cap_std::fs::{Metadata, MetadataExt};
use cap_std_ext::dirext::CapStdExtDirExt;
use fn_error_context::context;
use ostree_ext::gio;
use ostree_ext::ostree;
use rustix::fd::AsFd;

/// The mount path for selinux
const SELINUXFS: &str = "/sys/fs/selinux";
/// The SELinux xattr
const SELINUX_XATTR: &[u8] = b"security.selinux\0";
const SELF_CURRENT: &str = "/proc/self/attr/current";

#[context("Querying selinux availability")]
pub(crate) fn selinux_enabled() -> Result<bool> {
    Path::new("/proc/1/root/sys/fs/selinux/enforce")
        .try_exists()
        .map_err(Into::into)
}

/// Get the current process SELinux security context
fn get_current_security_context() -> Result<String> {
    std::fs::read_to_string(SELF_CURRENT).with_context(|| format!("Reading {SELF_CURRENT}"))
}

/// Check if the current process has the capability to write SELinux security
/// contexts unknown to the current policy. In SELinux terms this capability is
/// gated under `mac_admin` (admin control over SELinux state), and in the Fedora
/// policy at least it's part of `install_t`.
#[context("Testing install_t")]
fn test_install_t() -> Result<bool> {
    let tmpf = tempfile::NamedTempFile::new()?;
    // Our implementation here writes a label which is always unknown to the current policy
    // to verify that we have the capability to do so.
    let st = Command::new("chcon")
        .args(["-t", "invalid_bootcinstall_testlabel_t"])
        .arg(tmpf.path())
        .stderr(std::process::Stdio::null())
        .status()?;
    Ok(st.success())
}

/// Ensure that the current process has the capability to write SELinux security
/// contexts unknown to the current policy.
///
/// See [`test_install_t`] above for how we check for that capability.
///
/// In the general case of both upgrade or install, we may e.g. jump major versions
/// or even operating systems, and we need the ability to write arbitrary labels.
/// If the current process doesn't already have `mac_admin/install_t` then we
/// make a new temporary copy of our binary, and give it the same label as /usr/bin/ostree,
/// which in Fedora derivatives at least was already historically labeled with
/// the correct install_t label.
///
/// However, if you maintain a bootc operating system with SELinux, you should from
/// the start ensure that /usr/bin/bootc has the correct capabilities.
#[context("Ensuring selinux install_t type")]
pub(crate) fn selinux_ensure_install() -> Result<bool> {
    let guardenv = "_bootc_selinuxfs_mounted";
    let current = get_current_security_context()?;
    tracing::debug!("Current security context is {current}");
    if let Some(p) = std::env::var_os(guardenv) {
        let p = Path::new(&p);
        if p.exists() {
            tracing::debug!("Removing temporary file");
            std::fs::remove_file(p).context("Removing {p:?}")?;
        } else {
            tracing::debug!("Assuming we now have a privileged (e.g. install_t) label");
        }
        return test_install_t();
    }
    if test_install_t()? {
        tracing::debug!("We have install_t");
        return Ok(true);
    }
    tracing::debug!("Lacking install_t capabilities; copying self to temporary file for re-exec");
    // OK now, we always copy our binary to a tempfile, set its security context
    // to match that of /usr/bin/ostree, and then re-exec.  This is really a gross
    // hack; we can't always rely on https://github.com/fedora-selinux/selinux-policy/pull/1500/commits/67eb283c46d35a722636d749e5b339615fe5e7f5
    let mut tmpf = tempfile::NamedTempFile::new()?;
    let srcpath = std::env::current_exe()?;
    let mut src = std::fs::File::open(&srcpath)?;
    let meta = src.metadata()?;
    std::io::copy(&mut src, &mut tmpf).context("Copying self to tempfile for selinux re-exec")?;
    tmpf.as_file_mut()
        .set_permissions(meta.permissions())
        .context("Setting permissions of tempfile")?;
    let container_root = Dir::open_ambient_dir("/", cap_std::ambient_authority())?;
    let policy = ostree::SePolicy::new_at(container_root.as_raw_fd(), gio::Cancellable::NONE)?;
    let label = require_label(&policy, "/usr/bin/ostree".into(), libc::S_IFREG | 0o755)?;
    set_security_selinux(tmpf.as_fd(), label.as_bytes())?;
    let tmpf: Utf8PathBuf = tmpf.keep()?.1.try_into().unwrap();
    tracing::debug!("Created {tmpf:?}");

    let mut cmd = Command::new(&tmpf);
    cmd.env(guardenv, tmpf);
    cmd.env(bootc_utils::reexec::ORIG, srcpath);
    cmd.args(std::env::args_os().skip(1));
    cmd.arg0(bootc_utils::NAME);
    cmd.log_debug();
    Err(anyhow::Error::msg(cmd.exec()).context("execve"))
}

/// Query whether SELinux is apparently enabled in the target root
pub(crate) fn have_selinux_policy(root: &Dir) -> Result<bool> {
    // TODO use ostree::SePolicy and query policy name
    root.try_exists("etc/selinux/config").map_err(Into::into)
}

/// A type which will reset SELinux back to enforcing mode when dropped.
/// This is a workaround for the deep difficulties in trying to reliably
/// gain the `mac_admin` permission (install_t).
#[must_use]
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct SetEnforceGuard(Option<()>);

impl SetEnforceGuard {
    pub(crate) fn new() -> Self {
        SetEnforceGuard(Some(()))
    }

    #[allow(dead_code)]
    pub(crate) fn consume(mut self) -> Result<()> {
        // SAFETY: The option cannot have been consumed until now
        self.0.take().unwrap();
        // This returns errors
        selinux_set_permissive(false)
    }
}

impl Drop for SetEnforceGuard {
    fn drop(&mut self) {
        // A best-effort attempt to re-enable enforcement on drop (installation failure)
        if let Some(()) = self.0.take() {
            let _ = selinux_set_permissive(false);
        }
    }
}

/// Try to enter the install_t domain, but if we can't do that, then
/// just setenforce 0.
#[context("Ensuring selinux install_t type")]
pub(crate) fn selinux_ensure_install_or_setenforce() -> Result<Option<SetEnforceGuard>> {
    // If the process already has install_t, exit early
    // Note that this may re-exec the entire process
    if selinux_ensure_install()? {
        return Ok(None);
    }
    let g = if std::env::var_os("BOOTC_SETENFORCE0_FALLBACK").is_some() {
        tracing::warn!("Failed to enter install_t; temporarily setting permissive mode");
        selinux_set_permissive(true)?;
        Some(SetEnforceGuard::new())
    } else {
        let current = get_current_security_context()?;
        anyhow::bail!(
            "Failed to enter install_t (running as {current}) - use BOOTC_SETENFORCE0_FALLBACK=1 to override"
        );
    };
    Ok(g)
}

/// A thin wrapper for loading a SELinux policy that maps "policy nonexistent" to None.
pub(crate) fn new_sepolicy_at(fd: impl AsFd) -> Result<Option<ostree::SePolicy>> {
    let fd = fd.as_fd();
    let cancellable = gio::Cancellable::NONE;
    let sepolicy = ostree::SePolicy::new_at(fd.as_raw_fd(), cancellable)?;
    let r = if sepolicy.csum().is_none() {
        None
    } else {
        Some(sepolicy)
    };
    Ok(r)
}

#[context("Setting SELinux permissive mode")]
#[allow(dead_code)]
pub(crate) fn selinux_set_permissive(permissive: bool) -> Result<()> {
    let enforce_path = &Utf8Path::new(SELINUXFS).join("enforce");
    if !enforce_path.exists() {
        return Ok(());
    }
    let mut f = std::fs::File::options().write(true).open(enforce_path)?;
    f.write_all(if permissive { b"0" } else { b"1" })?;
    tracing::debug!(
        "Set SELinux mode: {}",
        if permissive {
            "permissive"
        } else {
            "enforcing"
        }
    );
    Ok(())
}

/// Check if the ostree-formatted extended attributes include a security.selinux value.
pub(crate) fn xattrs_have_selinux(xattrs: &ostree::glib::Variant) -> bool {
    let n = xattrs.n_children();
    for i in 0..n {
        let child = xattrs.child_value(i);
        let key = child.child_value(0);
        let key = key.data_as_bytes();
        if key == SELINUX_XATTR {
            return true;
        }
    }
    false
}

/// Look up the label for a path in a policy, and error if one is not found.
pub(crate) fn require_label(
    policy: &ostree::SePolicy,
    destname: &Utf8Path,
    mode: u32,
) -> Result<ostree::glib::GString> {
    policy
        .label(destname.as_str(), mode, ostree::gio::Cancellable::NONE)?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No label found in policy '{:?}' for {destname})",
                policy.csum()
            )
        })
}

/// A thin wrapper for invoking fsetxattr(security.selinux)
pub(crate) fn set_security_selinux(fd: std::os::fd::BorrowedFd, label: &[u8]) -> Result<()> {
    rustix::fs::fsetxattr(
        fd,
        "security.selinux",
        label,
        rustix::fs::XattrFlags::empty(),
    )
    .context("fsetxattr(security.selinux)")
}

/// The labeling state; "unsupported" is distinct as we need to handle
/// cases like the ESP which don't support labeling.
pub(crate) enum SELinuxLabelState {
    Unlabeled,
    Unsupported,
    Labeled,
}

/// Query the SELinux labeling for a particular path
pub(crate) fn has_security_selinux(root: &Dir, path: &Utf8Path) -> Result<SELinuxLabelState> {
    // TODO: avoid hardcoding a max size here
    let mut buf = [0u8; 2048];
    let fdpath = format!("/proc/self/fd/{}/{path}", root.as_raw_fd());
    match rustix::fs::lgetxattr(fdpath, "security.selinux", &mut buf) {
        Ok(_) => Ok(SELinuxLabelState::Labeled),
        Err(rustix::io::Errno::OPNOTSUPP) => Ok(SELinuxLabelState::Unsupported),
        Err(rustix::io::Errno::NODATA) => Ok(SELinuxLabelState::Unlabeled),
        Err(e) => Err(e).with_context(|| format!("Failed to look up context for {path:?}")),
    }
}

/// Directly set the `security.selinux` extended attribute on the target
/// path. Symbolic links are not followed for the target.
///
/// Note that this API will work even if SELinux is disabled.
pub(crate) fn set_security_selinux_path(root: &Dir, path: &Utf8Path, label: &[u8]) -> Result<()> {
    let fdpath = format!("/proc/self/fd/{}/", root.as_raw_fd());
    let fdpath = &Path::new(&fdpath).join(path);
    rustix::fs::lsetxattr(
        fdpath,
        "security.selinux",
        label,
        rustix::fs::XattrFlags::empty(),
    )?;
    Ok(())
}

/// Given a policy, ensure the target file path has a security.selinux label.
/// If the path already is labeled, this function is a no-op, even if
/// the policy would default to a different label.
pub(crate) fn ensure_labeled(
    root: &Dir,
    path: &Utf8Path,
    metadata: &Metadata,
    policy: &ostree::SePolicy,
) -> Result<SELinuxLabelState> {
    let r = has_security_selinux(root, path)?;
    if matches!(r, SELinuxLabelState::Unlabeled) {
        relabel(root, metadata, path, None, policy)?;
    }
    Ok(r)
}

/// Given the policy, relabel the target file or directory.
/// Optionally, an override for the path can be provided
/// to set the label as if the target has that filename.
pub(crate) fn relabel(
    root: &Dir,
    metadata: &Metadata,
    path: &Utf8Path,
    as_path: Option<&Utf8Path>,
    policy: &ostree::SePolicy,
) -> Result<()> {
    assert!(!path.starts_with("/"));
    let as_path = as_path
        .map(Cow::Borrowed)
        .unwrap_or_else(|| Utf8Path::new("/").join(path).into());
    let label = require_label(policy, &as_path, metadata.mode())?;
    tracing::trace!("Setting label for {path} to {label}");
    set_security_selinux_path(root, &path, label.as_bytes())
}

pub(crate) fn relabel_recurse_inner(
    root: &Dir,
    path: &mut Utf8PathBuf,
    mut as_path: Option<&mut Utf8PathBuf>,
    policy: &ostree::SePolicy,
) -> Result<()> {
    // Relabel this directory
    let self_meta = root.dir_metadata()?;
    relabel(
        root,
        &self_meta,
        path,
        as_path.as_ref().map(|p| p.as_path()),
        policy,
    )?;

    // Relabel all children
    for ent in root.read_dir(&path)? {
        let ent = ent?;
        let metadata = ent.metadata()?;
        let name = ent.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid non-UTF-8 filename: {name:?}"))?;
        // Extend both copies of the path
        path.push(name);
        if let Some(p) = as_path.as_mut() {
            p.push(name);
        }

        if metadata.is_dir() {
            let as_path = as_path.as_deref_mut();
            relabel_recurse_inner(root, path, as_path, policy)?;
        } else {
            let as_path = as_path.as_ref().map(|p| p.as_path());
            relabel(root, &metadata, &path, as_path, policy)?
        }
        // Trim what we added to the path
        let r = path.pop();
        assert!(r);
        if let Some(p) = as_path.as_mut() {
            let r = p.pop();
            assert!(r);
        }
    }

    Ok(())
}

/// Recursively relabel the target directory.
pub(crate) fn relabel_recurse(
    root: &Dir,
    path: impl AsRef<Utf8Path>,
    as_path: Option<&Utf8Path>,
    policy: &ostree::SePolicy,
) -> Result<()> {
    let mut path = path.as_ref().to_owned();
    // This path must be relative, as we access via cap-std
    assert!(!path.starts_with("/"));
    let mut as_path = as_path.map(|v| v.to_owned());
    // But the as_path must be absolute, if provided
    if let Some(as_path) = as_path.as_deref() {
        assert!(as_path.starts_with("/"));
    }
    relabel_recurse_inner(root, &mut path, as_path.as_mut(), policy)
}

/// A wrapper for creating a directory, also optionally setting a SELinux label.
/// The provided `skip` parameter is a device/inode that we will ignore (and not traverse).
pub(crate) fn ensure_dir_labeled_recurse(
    root: &Dir,
    path: &mut Utf8PathBuf,
    policy: &ostree::SePolicy,
    skip: Option<(libc::dev_t, libc::ino64_t)>,
) -> Result<()> {
    // Juggle the cap-std requirement for relative paths vs the libselinux
    // requirement for absolute paths by special casing the empty string "" as "."
    // just for the initial directory enumeration.
    let path_for_read = if path.as_str().is_empty() {
        Utf8Path::new(".")
    } else {
        &*path
    };

    let mut n = 0u64;

    let metadata = root.symlink_metadata(path_for_read)?;
    match ensure_labeled(root, path, &metadata, policy)? {
        SELinuxLabelState::Unlabeled => {
            n += 1;
        }
        SELinuxLabelState::Unsupported => return Ok(()),
        SELinuxLabelState::Labeled => {}
    }

    for ent in root.read_dir(path_for_read)? {
        let ent = ent?;
        let metadata = ent.metadata()?;
        if let Some((skip_dev, skip_ino)) = skip.as_ref().copied() {
            if (metadata.dev(), metadata.ino()) == (skip_dev, skip_ino) {
                tracing::debug!("Skipping dev={skip_dev} inode={skip_ino}");
                continue;
            }
        }
        let name = ent.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid non-UTF-8 filename: {name:?}"))?;
        path.push(name);

        if metadata.is_dir() {
            ensure_dir_labeled_recurse(root, path, policy, skip)?;
        } else {
            match ensure_labeled(root, path, &metadata, policy)? {
                SELinuxLabelState::Unlabeled => {
                    n += 1;
                }
                SELinuxLabelState::Unsupported => break,
                SELinuxLabelState::Labeled => {}
            }
        }
        path.pop();
    }

    if n > 0 {
        tracing::debug!("Relabeled {n} objects in {path}");
    }
    Ok(())
}

/// A wrapper for creating a directory, also optionally setting a SELinux label.
pub(crate) fn ensure_dir_labeled(
    root: &Dir,
    destname: impl AsRef<Utf8Path>,
    as_path: Option<&Utf8Path>,
    mode: rustix::fs::Mode,
    policy: Option<&ostree::SePolicy>,
) -> Result<()> {
    use std::borrow::Cow;

    let destname = destname.as_ref();
    // Special case the empty string
    let local_destname = if destname.as_str().is_empty() {
        ".".into()
    } else {
        destname
    };
    tracing::debug!("Labeling {local_destname}");
    let label = policy
        .map(|policy| {
            let as_path = as_path
                .map(Cow::Borrowed)
                .unwrap_or_else(|| Utf8Path::new("/").join(destname).into());
            require_label(policy, &as_path, libc::S_IFDIR | mode.as_raw_mode())
        })
        .transpose()
        .with_context(|| format!("Labeling {local_destname}"))?;
    tracing::trace!("Label for {local_destname} is {label:?}");

    root.ensure_dir_with(local_destname, &DirBuilder::new())
        .with_context(|| format!("Opening {local_destname}"))?;
    let dirfd = cap_std_ext::cap_primitives::fs::open(
        &root.as_filelike_view(),
        local_destname.as_std_path(),
        OpenOptions::new().read(true),
    )
    .context("opendir")?;
    let dirfd = dirfd.as_fd();
    rustix::fs::fchmod(dirfd, mode).context("fchmod")?;
    if let Some(label) = label {
        set_security_selinux(dirfd, label.as_bytes())?;
    }

    Ok(())
}

/// A wrapper for atomically writing a file, also optionally setting a SELinux label.
pub(crate) fn atomic_replace_labeled<F>(
    root: &Dir,
    destname: impl AsRef<Utf8Path>,
    mode: rustix::fs::Mode,
    policy: Option<&ostree::SePolicy>,
    f: F,
) -> Result<()>
where
    F: FnOnce(&mut std::io::BufWriter<cap_std_ext::cap_tempfile::TempFile>) -> Result<()>,
{
    let destname = destname.as_ref();
    let label = policy
        .map(|policy| {
            let abs_destname = Utf8Path::new("/").join(destname);
            require_label(policy, &abs_destname, libc::S_IFREG | mode.as_raw_mode())
        })
        .transpose()?;

    root.atomic_replace_with(destname, |w| {
        // Peel through the bufwriter to get the fd
        let fd = w.get_mut();
        let fd = fd.as_file_mut();
        let fd = fd.as_fd();
        // Apply the target mode bits
        rustix::fs::fchmod(fd, mode).context("fchmod")?;
        // If we have a label, apply it
        if let Some(label) = label {
            tracing::debug!("Setting label for {destname} to {label}");
            set_security_selinux(fd, label.as_bytes())?;
        } else {
            tracing::debug!("No label for {destname}");
        }
        // Finally call the underlying writer function
        f(w)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use gio::glib::Variant;

    #[test]
    fn test_selinux_xattr() {
        let notfound: &[&[(&[u8], &[u8])]] = &[&[], &[(b"foo", b"bar")]];
        for case in notfound {
            assert!(!xattrs_have_selinux(&Variant::from(case)));
        }
        let found: &[(&[u8], &[u8])] = &[(b"foo", b"bar"), (SELINUX_XATTR, b"foo_t")];
        assert!(xattrs_have_selinux(&Variant::from(found)));
    }
}
