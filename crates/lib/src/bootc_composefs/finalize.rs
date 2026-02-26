use std::path::Path;

use crate::bootc_composefs::boot::BootType;
use crate::bootc_composefs::rollback::{rename_exchange_bls_entries, rename_exchange_user_cfg};
use crate::bootc_composefs::status::get_composefs_status;
use crate::composefs_consts::STATE_DIR_ABS;
use crate::spec::Bootloader;
use crate::store::{BootedComposefs, Storage};
use anyhow::{Context, Result};
use bootc_initramfs_setup::mount_composefs_image;
use bootc_mount::tempmount::TempMount;
use cap_std_ext::cap_std::{ambient_authority, fs::Dir};
use cap_std_ext::dirext::CapStdExtDirExt;
use composefs::generic_tree::{Directory, Stat};
use etc_merge::{compute_diff, merge, print_diff, traverse_etc};
use rustix::fs::{fsync, renameat};
use rustix::path::Arg;

use fn_error_context::context;

pub(crate) async fn get_etc_diff(storage: &Storage, booted_cfs: &BootedComposefs) -> Result<()> {
    let host = get_composefs_status(storage, booted_cfs).await?;
    let booted_composefs = host.require_composefs_booted()?;

    // Mount the booted EROFS image to get pristine etc
    let sysroot_fd = storage.physical_root.reopen_as_ownedfd()?;
    let composefs_fd = mount_composefs_image(
        &sysroot_fd,
        &booted_composefs.verity,
        booted_cfs.cmdline.allow_missing_fsverity,
    )?;

    let erofs_tmp_mnt = TempMount::mount_fd(&composefs_fd)?;

    let pristine_etc =
        Dir::open_ambient_dir(erofs_tmp_mnt.dir.path().join("etc"), ambient_authority())?;
    let current_etc = Dir::open_ambient_dir("/etc", ambient_authority())?;

    let (pristine_files, current_files, _) = traverse_etc(&pristine_etc, &current_etc, None)?;
    let diff = compute_diff(
        &pristine_files,
        &current_files,
        &Directory::new(Stat::uninitialized()),
    )?;

    print_diff(&diff, &mut std::io::stdout());

    Ok(())
}

pub(crate) async fn composefs_backend_finalize(
    storage: &Storage,
    booted_cfs: &BootedComposefs,
) -> Result<()> {
    const COMPOSEFS_FINALIZE_JOURNAL_ID: &str = "0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4";

    tracing::info!(
        message_id = COMPOSEFS_FINALIZE_JOURNAL_ID,
        bootc.operation = "finalize",
        bootc.current_deployment = booted_cfs.cmdline.digest,
        "Starting composefs staged deployment finalization"
    );

    let host = get_composefs_status(storage, booted_cfs).await?;

    let booted_composefs = host.require_composefs_booted()?;

    let Some(staged_depl) = host.status.staged.as_ref() else {
        tracing::info!(
            message_id = COMPOSEFS_FINALIZE_JOURNAL_ID,
            bootc.operation = "finalize",
            "No staged deployment found"
        );
        return Ok(());
    };

    if staged_depl.download_only {
        tracing::info!(
            message_id = COMPOSEFS_FINALIZE_JOURNAL_ID,
            bootc.operation = "finalize",
            bootc.download_only = "true",
            "Staged deployment is marked download only. Won't finalize"
        );
        return Ok(());
    }

    let staged_composefs = staged_depl.composefs.as_ref().ok_or(anyhow::anyhow!(
        "Staged deployment is not a composefs deployment"
    ))?;

    // Mount the booted EROFS image to get pristine etc
    let sysroot_fd = storage.physical_root.reopen_as_ownedfd()?;
    let composefs_fd = mount_composefs_image(
        &sysroot_fd,
        &booted_composefs.verity,
        booted_cfs.cmdline.allow_missing_fsverity,
    )?;

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
        traverse_etc(&pristine_etc, &current_etc, Some(&new_etc))?;

    let new_files =
        new_files.ok_or_else(|| anyhow::anyhow!("Failed to get dirtree for new etc"))?;

    let diff = compute_diff(&pristine_files, &current_files, &new_files)?;
    merge(&current_etc, &current_files, &new_etc, &new_files, &diff)?;

    // Unmount EROFS
    drop(erofs_tmp_mnt);

    let boot_dir = storage.require_boot_dir()?;

    let esp_mount = storage
        .esp
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("ESP not found"))?;

    // NOTE: Assuming here we won't have two bootloaders at the same time
    match booted_composefs.bootloader {
        Bootloader::Grub => match staged_composefs.boot_type {
            BootType::Bls => {
                let entries_dir = boot_dir.open_dir("loader")?;
                rename_exchange_bls_entries(&entries_dir)?;
            }
            BootType::Uki => finalize_staged_grub_uki(&esp_mount.fd, boot_dir)?,
        },

        Bootloader::Systemd => {
            if matches!(staged_composefs.boot_type, BootType::Uki) {
                rename_staged_uki_entries(&esp_mount.fd)?;
            }

            let entries_dir = boot_dir.open_dir("loader")?;
            rename_exchange_bls_entries(&entries_dir)?;
        }

        Bootloader::None => unreachable!("Checked at install time"),
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
