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

    let mut highest_policy_version = -1;
    let mut latest_policy_name = None;

    let policy_dir = deployment_root
        .open_dir(&policy_dir_path)
        .context("Opening selinux policy dir")?;

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

    let policy_name =
        latest_policy_name.ok_or_else(|| anyhow::anyhow!("Failed to get latest SELinux policy"))?;

    let full_path = format!("{policy_dir_path}/{policy_name}");

    let mut file = deployment_root
        .open(full_path)
        .context("Opening policy file")?;
    let mut hasher = openssl::hash::Hasher::new(openssl::hash::MessageDigest::sha256())?;
    std::io::copy(&mut file, &mut hasher)?;

    let hash = hex::encode(hasher.finish().context("Computing hash")?);

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
