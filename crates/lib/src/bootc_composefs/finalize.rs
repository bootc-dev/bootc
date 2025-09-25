use std::path::Path;

use crate::bootc_composefs::boot::{get_esp_partition, get_sysroot_parent_dev, BootType};
use crate::bootc_composefs::rollback::{rename_exchange_bls_entries, rename_exchange_user_cfg};
use crate::spec::Bootloader;
use crate::{
    bootc_composefs::status::composefs_deployment_status, composefs_consts::STATE_DIR_ABS,
};
use anyhow::{Context, Result};
use bootc_initramfs_setup::{mount_composefs_image, open_dir};
use bootc_mount::tempmount::TempMount;
use cap_std_ext::cap_std::{ambient_authority, fs::Dir};
use cap_std_ext::dirext::CapStdExtDirExt;
use etc_merge::{compute_diff, merge, traverse_etc};
use rustix::fs::{fsync, renameat, CWD};
use rustix::path::Arg;

use fn_error_context::context;

pub(crate) async fn composefs_native_finalize() -> Result<()> {
    let host = composefs_deployment_status().await?;

    let booted_composefs = host.require_composefs_booted()?;

    let Some(staged_depl) = host.status.staged.as_ref() else {
        tracing::debug!("No staged deployment found");
        return Ok(());
    };

    let staged_composefs = staged_depl.composefs.as_ref().ok_or(anyhow::anyhow!(
        "Staged deployment is not a composefs deployment"
    ))?;

    // Mount the booted EROFS image to get pristine etc
    let sysroot = open_dir(CWD, "/sysroot")?;
    let composefs_fd = mount_composefs_image(&sysroot, &booted_composefs.verity, false)?;

    let erofs_tmp_mnt = TempMount::mount_fd(&composefs_fd)?;

    // Perform the /etc merge
    let pristine_etc =
        Dir::open_ambient_dir(erofs_tmp_mnt.dir.path().join("etc"), ambient_authority())?;
    let current_etc = Dir::open_ambient_dir("/etc", ambient_authority())?;

    let new_etc_path = Path::new(STATE_DIR_ABS)
        .join(&staged_composefs.verity)
        .join("etc");

    let new_etc = Dir::open_ambient_dir(new_etc_path, ambient_authority())?;

    let (pristine_files, current_files, new_files) =
        traverse_etc(&pristine_etc, &current_etc, &new_etc)?;

    let diff = compute_diff(&pristine_files, &current_files)?;
    merge(&current_etc, &current_files, &new_etc, &new_files, diff)?;

    // Unmount EROFS
    drop(erofs_tmp_mnt);

    let sysroot_parent = get_sysroot_parent_dev()?;
    // NOTE: Assumption here that ESP will always be present
    let (esp_part, ..) = get_esp_partition(&sysroot_parent)?;

    let esp_mount = TempMount::mount_dev(&esp_part)?;
    let boot_dir = Dir::open_ambient_dir("/sysroot/boot", ambient_authority())
        .context("Opening sysroot/boot")?;

    // NOTE: Assuming here we won't have two bootloaders at the same time
    match booted_composefs.bootloader {
        Bootloader::Grub => match staged_composefs.boot_type {
            BootType::Bls => {
                let entries_dir = boot_dir.open_dir("loader")?;
                rename_exchange_bls_entries(&entries_dir)?;
            }
            BootType::Uki => finalize_staged_grub_uki(&esp_mount.fd, &boot_dir)?,
        },

        Bootloader::Systemd => match staged_composefs.boot_type {
            BootType::Bls => {
                let entries_dir = esp_mount.fd.open_dir("loader")?;
                rename_exchange_bls_entries(&entries_dir)?;
            }
            BootType::Uki => {
                rename_staged_uki_entries(&esp_mount.fd)?;

                let entries_dir = esp_mount.fd.open_dir("loader")?;
                rename_exchange_bls_entries(&entries_dir)?;
            }
        },
    };

    Ok(())
}

#[context("Grub: Finalizing staged UKI")]
fn finalize_staged_grub_uki(esp_mount: &Dir, boot_fd: &Dir) -> Result<()> {
    rename_staged_uki_entries(esp_mount)?;

    let entries_dir = boot_fd.open_dir("grub2")?;
    rename_exchange_user_cfg(&entries_dir)?;

    let entries_dir = entries_dir.reopen_as_ownedfd()?;
    fsync(entries_dir).context("fsync")?;

    Ok(())
}

#[context("Renaming staged UKI entries")]
fn rename_staged_uki_entries(esp_mount: &Dir) -> Result<()> {
    for entry in esp_mount.entries()? {
        let entry = entry?;

        let filename = entry.file_name();
        let filename = filename.as_str()?;

        if !filename.ends_with(".staged") {
            continue;
        }

        renameat(
            &esp_mount,
            filename,
            &esp_mount,
            // SAFETY: We won't reach here if not for the above condition
            filename.strip_suffix(".staged").unwrap(),
        )
        .context("Renaming {filename}")?;
    }

    let esp_mount = esp_mount.reopen_as_ownedfd()?;
    fsync(esp_mount).context("fsync")?;

    Ok(())
}
