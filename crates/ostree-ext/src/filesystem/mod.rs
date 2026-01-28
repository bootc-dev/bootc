//! Filesystem-based filtering and processing
//!
//! This module provides functionality to import filesystem directories directly
//! to OSTree, applying path transformations without creating temporary files
//! on disk.

mod filter;

pub use filter::{FilesystemFilterConfig, import_filesystem_to_ostree};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_from_tar_options() {
        let tar_opts = crate::tar::WriteTarOptions {
            base: None,
            selinux: false,
            allow_nonusr: true,
            retain_var: false,
        };

        let fs_config = FilesystemFilterConfig::from_tar_options(&tar_opts);
        assert!(fs_config.allow_nonusr);
        assert!(fs_config.remap_factory_var); // !retain_var
    }

    #[test]
    fn test_config_from_tar_options_retain_var() {
        let tar_opts = crate::tar::WriteTarOptions {
            base: None,
            selinux: false,
            allow_nonusr: false,
            retain_var: true,
        };

        let fs_config = FilesystemFilterConfig::from_tar_options(&tar_opts);
        assert!(!fs_config.allow_nonusr);
        assert!(!fs_config.remap_factory_var); // !retain_var
    }
}
