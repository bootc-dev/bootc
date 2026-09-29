//! Detecting which backend a container image's root filesystem is built for.

use anyhow::Result;
use cap_std_ext::cap_std::fs::Dir;
use cap_std_ext::dirext::CapStdExtDirExt as _;

/// The setup-root configuration, relative to the root directory.
pub(crate) fn setup_root_conf_path() -> &'static str {
    bootc_initramfs_setup::SETUP_ROOT_CONF_PATH.trim_start_matches('/')
}

/// Whether the image is intended to be deployed with the composefs
/// backend, which is signaled by the presence of a setup-root configuration
/// file (even if empty).
pub(crate) fn is_composefs_native(root: &Dir) -> Result<bool> {
    Ok(root
        .symlink_metadata_optional(setup_root_conf_path())?
        .is_some())
}
