use anyhow::{Context, Result};
use bootc_initramfs_setup::mount_composefs_image;
use bootc_mount::tempmount::TempMount;
use cap_std_ext::cap_std::{ambient_authority, fs::Dir};
use cap_std_ext::dirext::CapStdExtDirExt;
use fn_error_context::context;

use crate::bootc_composefs::status::ComposefsCmdline;
use crate::lsm::selinux_enabled;
use crate::store::Storage;

const SELINUX_CONFIG_PATH: &str = "etc/selinux/config";
const SELINUX_TYPE: &str = "SELINUXTYPE=";
const POLICY_FILE_PREFIX: &str = "policy.";

/// Find the highest versioned policy file in the given directory
fn find_latest_policy_file(policy_dir: &Dir) -> Result<String> {
    let mut highest_policy_version = -1;
    let mut latest_policy_name = None;

    for entry in policy_dir
        .entries_utf8()
        .context("Getting policy dir entries")?
    {
        let entry = entry?;

        if !entry.file_type()?.is_file() {
            // We don't want symlinks, another directory etc
            continue;
        }

        let filename = entry.file_name()?;

        match filename.strip_prefix(POLICY_FILE_PREFIX) {
            Some(version) => {
                let v_int = version
                    .parse::<i32>()
                    .with_context(|| anyhow::anyhow!("Parsing {version} as int"))?;

                if v_int < highest_policy_version {
                    continue;
                }

                highest_policy_version = v_int;
                latest_policy_name = Some(filename.to_string());
            }

            None => continue,
        };
    }

    latest_policy_name.ok_or_else(|| anyhow::anyhow!("Failed to get latest SELinux policy"))
}

/// Compute SHA256 hash of a policy file
fn compute_policy_file_hash(deployment_root: &Dir, full_path: &str) -> Result<String> {
    let mut file = deployment_root
        .open(full_path)
        .context("Opening policy file")?;
    let mut hasher = openssl::hash::Hasher::new(openssl::hash::MessageDigest::sha256())?;
    std::io::copy(&mut file, &mut hasher)?;

    let hash = hex::encode(hasher.finish().context("Computing hash")?);
    Ok(hash)
}

#[context("Getting SELinux policy for deployment {depl_id}")]
fn get_selinux_policy_for_deployment(
    storage: &Storage,
    booted_cmdline: &ComposefsCmdline,
    depl_id: &str,
) -> Result<Option<String>> {
    let sysroot_fd = storage.physical_root.reopen_as_ownedfd()?;

    // Booted deployment. We want to get the policy from "/etc" as it might have been modified
    let (deployment_root, _mount_guard) = if *booted_cmdline.digest == *depl_id {
        (Dir::open_ambient_dir("/", ambient_authority())?, None)
    } else {
        let composefs_fd = mount_composefs_image(&sysroot_fd, depl_id, false)?;
        let erofs_tmp_mnt = TempMount::mount_fd(&composefs_fd)?;

        (erofs_tmp_mnt.fd.try_clone()?, Some(erofs_tmp_mnt))
    };

    if !deployment_root.exists(SELINUX_CONFIG_PATH) {
        return Ok(None);
    }

    let selinux_config = deployment_root
        .read_to_string(SELINUX_CONFIG_PATH)
        .context("Reading selinux config")?;

    let type_ = selinux_config
        .lines()
        .find(|l| l.starts_with(SELINUX_TYPE))
        .ok_or_else(|| anyhow::anyhow!("Falied to find SELINUXTYPE"))?
        .split("=")
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("Failed to parse SELINUXTYPE"))?
        .trim();

    let policy_dir_path = format!("etc/selinux/{type_}/policy");

    let policy_dir = deployment_root
        .open_dir(&policy_dir_path)
        .context("Opening selinux policy dir")?;

    let policy_name = find_latest_policy_file(&policy_dir)?;

    let full_path = format!("{policy_dir_path}/{policy_name}");

    let hash = compute_policy_file_hash(&deployment_root, &full_path)?;

    Ok(Some(hash))
}

#[context("Checking SELinux policy compatibility")]
pub(crate) fn are_selinux_policies_compatible(
    storage: &Storage,
    booted_cmdline: &ComposefsCmdline,
    depl_id: &str,
) -> Result<bool> {
    if !selinux_enabled()? {
        return Ok(true);
    }

    let booted_policy_hash =
        get_selinux_policy_for_deployment(storage, booted_cmdline, &booted_cmdline.digest)?;

    let depl_policy_hash = get_selinux_policy_for_deployment(storage, booted_cmdline, depl_id)?;

    let sl_policy_match = match (booted_policy_hash, depl_policy_hash) {
        // both have policies, compare them
        (Some(booted_csum), Some(target_csum)) => booted_csum == target_csum,
        // one depl has policy while the other doesn't
        (Some(_), None) | (None, Some(_)) => false,
        // no policy in either
        (None, None) => true,
    };

    if !sl_policy_match {
        tracing::debug!("Soft rebooting not allowed due to differing SELinux policies");
    }

    Ok(sl_policy_match)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std_ext::cap_std::ambient_authority;
    use cap_std_ext::dirext::CapStdExtDirExt;

    #[test]
    fn test_find_latest_policy_file() -> Result<()> {
        let tempdir = cap_std_ext::cap_tempfile::tempdir(ambient_authority())?;

        // Create policy files with different versions
        tempdir.atomic_write("policy.30", "policy content 30")?;
        tempdir.atomic_write("policy.31", "policy content 31")?;
        tempdir.atomic_write("policy.29", "policy content 29")?;
        tempdir.atomic_write("not_policy.32", "not a policy file")?;
        tempdir.atomic_write("other_policy.txt", "invalid policy file")?;

        let result = find_latest_policy_file(&tempdir)?;
        assert_eq!(result, "policy.31");

        Ok(())
    }

    #[test]
    fn test_find_latest_policy_file_with_single_file() -> Result<()> {
        let tempdir = cap_std_ext::cap_tempfile::tempdir(ambient_authority())?;

        tempdir.atomic_write("policy.25", "single policy file")?;

        let result = find_latest_policy_file(&tempdir)?;
        assert_eq!(result, "policy.25");

        Ok(())
    }

    #[test]
    fn test_find_latest_policy_file_no_policy_files() {
        let tempdir = cap_std_ext::cap_tempfile::tempdir(ambient_authority()).unwrap();

        tempdir
            .atomic_write("not_policy.txt", "not a policy file")
            .unwrap();
        tempdir.atomic_write("other.txt", "invalid format").unwrap();

        let result = find_latest_policy_file(&tempdir);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to get latest SELinux policy")
        );
    }

    #[test]
    fn test_find_latest_policy_file_invalid_version() {
        let tempdir = cap_std_ext::cap_tempfile::tempdir(ambient_authority()).unwrap();

        tempdir
            .atomic_write("policy.abc", "invalid version")
            .unwrap();

        let result = find_latest_policy_file(&tempdir);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Parsing abc as int")
        );
    }

    #[test]
    fn test_find_latest_policy_file_negative_version() -> Result<()> {
        let tempdir = cap_std_ext::cap_tempfile::tempdir(ambient_authority())?;

        tempdir.atomic_write("policy.5", "positive version")?;
        tempdir.atomic_write("policy.-1", "negative version")?;

        let result = find_latest_policy_file(&tempdir)?;
        assert_eq!(result, "policy.5");

        Ok(())
    }

    #[test]
    fn test_find_latest_policy_file_skips_directories() -> Result<()> {
        let tempdir = cap_std_ext::cap_tempfile::tempdir(ambient_authority())?;

        tempdir.create_dir("policy.99")?; // This should be skipped
        tempdir.atomic_write("policy.5", "actual policy file")?;

        let result = find_latest_policy_file(&tempdir)?;
        assert_eq!(result, "policy.5");

        Ok(())
    }

    #[test]
    fn test_compute_policy_file_hash() -> Result<()> {
        let tempdir = cap_std_ext::cap_tempfile::tempdir(ambient_authority())?;

        let test_content = "test policy content for hashing";
        tempdir.atomic_write("test_policy.30", test_content)?;

        let hash = compute_policy_file_hash(&tempdir, "test_policy.30")?;

        // Verify the hash is a valid SHA256 hash (64 hex characters)
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));

        // Verify consistent hashing
        let hash2 = compute_policy_file_hash(&tempdir, "test_policy.30")?;
        assert_eq!(hash, hash2);

        Ok(())
    }

    #[test]
    fn test_compute_policy_file_hash_different_content() -> Result<()> {
        let tempdir = cap_std_ext::cap_tempfile::tempdir(ambient_authority())?;

        tempdir.atomic_write("policy1.30", "content 1")?;
        tempdir.atomic_write("policy2.30", "content 2")?;

        let hash1 = compute_policy_file_hash(&tempdir, "policy1.30")?;
        let hash2 = compute_policy_file_hash(&tempdir, "policy2.30")?;

        assert_ne!(hash1, hash2);

        Ok(())
    }

    #[test]
    fn test_compute_policy_file_hash_nonexistent_file() {
        let tempdir = cap_std_ext::cap_tempfile::tempdir(ambient_authority()).unwrap();

        let result = compute_policy_file_hash(&tempdir, "nonexistent.30");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Opening policy file")
        );
    }

    #[test]
    fn test_compute_policy_file_hash_empty_file() -> Result<()> {
        let tempdir = cap_std_ext::cap_tempfile::tempdir(ambient_authority())?;

        tempdir.atomic_write("empty_policy.30", "")?;

        let hash = compute_policy_file_hash(&tempdir, "empty_policy.30")?;

        // Should produce a valid hash even for empty file
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));

        // SHA256 of empty string
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        Ok(())
    }
}
