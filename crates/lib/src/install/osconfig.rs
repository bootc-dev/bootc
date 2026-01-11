use std::borrow::Cow;
use std::io::Write;

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use cap_std::fs::Dir;
use cap_std_ext::{cap_std, dirext::CapStdExtDirExt};
use fn_error_context::context;
use ostree_ext::ostree;

const ETC_TMPFILES: &str = "etc/tmpfiles.d";
const ROOT_SSH_TMPFILE: &str = "bootc-root-ssh.conf";

#[context("Injecting root authorized_keys")]
pub(crate) fn inject_root_ssh_authorized_keys(
    root: &Dir,
    sepolicy: Option<&ostree::SePolicy>,
    contents: &str,
) -> Result<()> {
    // While not documented right now, this one looks like it does not newline wrap
    let b64_encoded = ostree_ext::glib::base64_encode(contents.as_bytes());

    // Eagerly resolve the path of /root in order to avoid tmpfiles.d clashes/problems.
    // If it's local state (i.e. /root -> /var/roothome) then we resolve that symlink now.
    let roothome_meta = root.symlink_metadata_optional("root")?;
    let root_path = if roothome_meta.as_ref().filter(|m| m.is_symlink()).is_some() {
        let path = root.read_link("root")?;
        Utf8PathBuf::try_from(path)
            .context("Reading /root symlink")
            .map(Cow::Owned)?
    } else {
        Cow::Borrowed(Utf8Path::new("root"))
    };

    // See the example in https://systemd.io/CREDENTIALS/
    let tmpfiles_content =
        format!("f~ /{root_path}/.ssh/authorized_keys 600 root root - {b64_encoded}\n");

    crate::lsm::ensure_dir_labeled(root, ETC_TMPFILES, None, 0o755.into(), sepolicy)?;
    let tmpfiles_dir = root.open_dir(ETC_TMPFILES)?;
    crate::lsm::atomic_replace_labeled(
        &tmpfiles_dir,
        ROOT_SSH_TMPFILE,
        0o644.into(),
        sepolicy,
        |w| w.write_all(tmpfiles_content.as_bytes()).map_err(Into::into),
    )?;

    println!("Injected: {ETC_TMPFILES}/{ROOT_SSH_TMPFILE}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inject_root_ssh_symlinked() -> Result<()> {
        let root = &cap_std_ext::cap_tempfile::TempDir::new(cap_std::ambient_authority())?;

        // The code expects this to exist, reasonably so
        root.create_dir("etc")?;
        // Test with a symlink
        root.symlink("var/roothome", "root")?;
        inject_root_ssh_authorized_keys(root, None, "ssh-ed25519 ABCDE example@demo\n").unwrap();

        let content = root.read_to_string(format!("etc/tmpfiles.d/{ROOT_SSH_TMPFILE}"))?;
        assert_eq!(
            content,
            "f~ /var/roothome/.ssh/authorized_keys 600 root root - c3NoLWVkMjU1MTkgQUJDREUgZXhhbXBsZUBkZW1vCg==\n"
        );

        Ok(())
    }

    #[test]
    fn test_inject_root_ssh_dir() -> Result<()> {
        let root = &cap_std_ext::cap_tempfile::TempDir::new(cap_std::ambient_authority())?;

        root.create_dir("etc")?;
        root.create_dir("root")?;
        inject_root_ssh_authorized_keys(root, None, "ssh-ed25519 ABCDE example@demo\n").unwrap();

        let content = root.read_to_string(format!("etc/tmpfiles.d/{ROOT_SSH_TMPFILE}"))?;
        assert_eq!(
            content,
            "f~ /root/.ssh/authorized_keys 600 root root - c3NoLWVkMjU1MTkgQUJDREUgZXhhbXBsZUBkZW1vCg==\n"
        );
        Ok(())
    }
}
