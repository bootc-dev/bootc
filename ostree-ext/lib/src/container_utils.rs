//! Helpers for interacting with containers at runtime.

use crate::keyfileext::KeyFileExt;
use anyhow::Result;
use ostree::glib;
use std::io::Read;
use std::path::Path;

// See https://github.com/coreos/rpm-ostree/pull/3285#issuecomment-999101477
// For compatibility with older ostree, we stick this in /sysroot where
// it will be ignored.
const V0_REPO_CONFIG: &str = "/sysroot/config";
const V1_REPO_CONFIG: &str = "/sysroot/ostree/repo/config";

/// Attempts to detect if the current process is running inside a container.
/// This looks for the `container` environment variable or the presence
/// of Docker or podman's more generic `/run/.containerenv`.
pub fn running_in_container() -> bool {
    if std::env::var_os("container").is_some() {
        return true;
    }
    // https://stackoverflow.com/questions/20010199/how-to-determine-if-a-process-runs-inside-lxc-docker
    for p in ["/run/.containerenv", "/.dockerenv"] {
        if std::path::Path::new(p).exists() {
            return true;
        }
    }
    false
}

// https://docs.rs/openat-ext/0.1.10/openat_ext/trait.OpenatDirExt.html#tymethod.open_file_optional
// https://users.rust-lang.org/t/why-i-use-anyhow-error-even-in-libraries/68592
pub(crate) fn open_optional(path: impl AsRef<Path>) -> std::io::Result<Option<std::fs::File>> {
    match std::fs::File::open(path.as_ref()) {
        Ok(r) => Ok(Some(r)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Returns `true` if the current root filesystem has an ostree repository in `bare-split-xattrs` mode.
/// This will be the case in a running ostree-native container.
pub fn is_bare_split_xattrs() -> Result<bool> {
    if let Some(configf) = open_optional(V1_REPO_CONFIG)
        .transpose()
        .or_else(|| open_optional(V0_REPO_CONFIG).transpose())
    {
        let configf = configf?;
        let mut bufr = std::io::BufReader::new(configf);
        let mut s = String::new();
        bufr.read_to_string(&mut s)?;
        let kf = glib::KeyFile::new();
        kf.load_from_data(&s, glib::KeyFileFlags::NONE)?;
        let r = if let Some(mode) = kf.optional_string("core", "mode")? {
            mode == crate::tar::BARE_SPLIT_XATTRS_MODE
        } else {
            false
        };
        Ok(r)
    } else {
        Ok(false)
    }
}

/// Returns `true` if the current booted filesystem appears to be an ostree-native container.
///
/// This just invokes [`is_bare_split_xattrs`] and [`running_in_container`].
pub fn is_ostree_container() -> Result<bool> {
    Ok(running_in_container() && is_bare_split_xattrs()?)
}

/// Returns an error unless the current filesystem is an ostree-based container
///
/// This just wraps [`is_ostree_container`].
pub fn require_ostree_container() -> Result<()> {
    if !is_ostree_container()? {
        anyhow::bail!("Not in an ostree-based container environment");
    }
    Ok(())
}
