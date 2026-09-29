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

/// Whether `bootc install` should default to the composefs backend for this
/// root: it is composefs-native, and it has no ostree `prepare-root.conf`
/// (`has_ostree_prepareroot`, which the caller loads anyway), without which
/// it can't be installed with the ostree backend. An image that has both
/// configurations still defaults to ostree.
pub(crate) fn defaults_to_composefs_backend(
    root: &Dir,
    has_ostree_prepareroot: bool,
) -> Result<bool> {
    Ok(!has_ostree_prepareroot && is_composefs_native(root)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use camino::Utf8Path;
    use ostree_ext::ostree_prepareroot;

    const OSTREE_PREPAREROOT: &str = "usr/lib/ostree/prepare-root.conf";
    const OSTREE_PREPAREROOT_ETC: &str = "etc/ostree/prepare-root.conf";

    #[test]
    fn test_defaults_to_composefs_backend() -> Result<()> {
        let setup_root = setup_root_conf_path();
        // (files present in the image) => (composefs-native, defaults to composefs)
        let cases: &[(&[&str], bool, bool)] = &[
            (&[], false, false),
            (&[setup_root], true, true),
            (&[OSTREE_PREPAREROOT], false, false),
            (&[OSTREE_PREPAREROOT_ETC], false, false),
            (&[setup_root, OSTREE_PREPAREROOT], true, false),
            (&[setup_root, OSTREE_PREPAREROOT_ETC], true, false),
        ];
        for &(files, native, composefs) in cases {
            let td = cap_std_ext::cap_tempfile::tempdir(cap_std_ext::cap_std::ambient_authority())?;
            for f in files {
                let f = Utf8Path::new(f);
                td.create_dir_all(f.parent().unwrap())?;
                // Both files are signals even if empty
                td.write(f, "")?;
            }
            assert_eq!(is_composefs_native(&td)?, native, "{files:?}");
            let has_ostree = ostree_prepareroot::load_config_from_root(&td)?.is_some();
            assert_eq!(
                defaults_to_composefs_backend(&td, has_ostree)?,
                composefs,
                "{files:?}"
            );
        }
        Ok(())
    }
}
