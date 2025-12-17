//! Composefs digest computation utilities.

use std::fs::File;
use std::io::BufWriter;
use std::sync::Arc;

use anyhow::{Context, Result};
use camino::Utf8Path;
use cap_std_ext::cap_std;
use cap_std_ext::cap_std::fs::Dir;
use composefs::dumpfile;
use composefs::fsverity::FsVerityHashValue;
use composefs_boot::BootOps as _;
use tempfile::TempDir;

use crate::store::ComposefsRepository;

/// Creates a temporary composefs repository for computing digests.
///
/// Returns the TempDir guard (must be kept alive for the repo to remain valid)
/// and the repository wrapped in Arc.
pub(crate) fn new_temp_composefs_repo() -> Result<(TempDir, Arc<ComposefsRepository>)> {
    let td_guard = tempfile::tempdir_in("/var/tmp")?;
    let td_path = td_guard.path();
    let td_dir = Dir::open_ambient_dir(td_path, cap_std::ambient_authority())?;

    td_dir.create_dir("repo")?;
    let repo_dir = td_dir.open_dir("repo")?;
    let mut repo = ComposefsRepository::open_path(&repo_dir, ".").context("Init cfs repo")?;
    // We don't need to hard require verity on the *host* system, we're just computing a checksum here
    repo.set_insecure(true);
    Ok((td_guard, Arc::new(repo)))
}

/// Computes the bootable composefs digest for a filesystem at the given path.
///
/// This reads the filesystem from the specified path, transforms it for boot,
/// and computes the composefs image ID.
///
/// # Arguments
/// * `path` - Path to the filesystem root to compute digest for
/// * `write_dumpfile_to` - Optional path to write a dumpfile
///
/// # Returns
/// The computed digest as a 128-character hex string (SHA-512).
///
/// # Errors
/// Returns an error if:
/// * The path is "/" (cannot operate on active root filesystem)
/// * The filesystem cannot be read
/// * The transform or digest computation fails
pub(crate) fn compute_composefs_digest(
    path: &Utf8Path,
    write_dumpfile_to: Option<&Utf8Path>,
) -> Result<String> {
    if path.as_str() == "/" {
        anyhow::bail!("Cannot operate on active root filesystem; mount separate target instead");
    }

    let (_td_guard, repo) = new_temp_composefs_repo()?;

    // Read filesystem from path, transform for boot, compute digest
    let mut fs =
        composefs::fs::read_filesystem(rustix::fs::CWD, path.as_std_path(), Some(&repo), false)?;
    fs.transform_for_boot(&repo).context("Preparing for boot")?;
    let id = fs.compute_image_id();
    let digest = id.to_hex();

    if let Some(dumpfile_path) = write_dumpfile_to {
        let mut w = File::create(dumpfile_path)
            .with_context(|| format!("Opening {dumpfile_path}"))
            .map(BufWriter::new)?;
        dumpfile::write_dumpfile(&mut w, &fs).context("Writing dumpfile")?;
    }

    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, Permissions};
    use std::os::unix::fs::PermissionsExt;

    /// Helper to create a minimal test filesystem structure
    fn create_test_filesystem(root: &std::path::Path) -> Result<()> {
        // Create directories required by transform_for_boot
        fs::create_dir_all(root.join("boot"))?;
        fs::create_dir_all(root.join("sysroot"))?;

        // Create usr/bin directory
        let usr_bin = root.join("usr/bin");
        fs::create_dir_all(&usr_bin)?;

        // Create usr/bin/hello with executable permissions
        let hello_path = usr_bin.join("hello");
        fs::write(&hello_path, "test\n")?;
        fs::set_permissions(&hello_path, Permissions::from_mode(0o755))?;

        // Create etc directory
        let etc = root.join("etc");
        fs::create_dir_all(&etc)?;

        // Create etc/config with regular file permissions
        let config_path = etc.join("config");
        fs::write(&config_path, "test\n")?;
        fs::set_permissions(&config_path, Permissions::from_mode(0o644))?;

        Ok(())
    }

    #[test]
    fn test_compute_composefs_digest() {
        // Create temp directory with test filesystem structure
        let td = tempfile::tempdir().unwrap();
        create_test_filesystem(td.path()).unwrap();

        // Compute the digest
        let path = Utf8Path::from_path(td.path()).unwrap();
        let digest = compute_composefs_digest(path, None).unwrap();

        // Verify it's a valid hex string of expected length (SHA-512 = 128 hex chars)
        assert_eq!(
            digest.len(),
            128,
            "Expected 512-bit hex digest, got length {}",
            digest.len()
        );
        assert!(
            digest.chars().all(|c| c.is_ascii_hexdigit()),
            "Digest contains non-hex characters: {digest}"
        );

        // Verify consistency - computing twice on the same filesystem produces the same result
        let digest2 = compute_composefs_digest(path, None).unwrap();
        assert_eq!(
            digest, digest2,
            "Digest should be consistent across multiple computations"
        );
    }

    #[test]
    fn test_compute_composefs_digest_rejects_root() {
        let result = compute_composefs_digest(Utf8Path::new("/"), None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Cannot operate on active root filesystem"),
            "Unexpected error message: {err}"
        );
    }
}
