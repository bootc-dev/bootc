use std::path::Path;

use crate::bootc_composefs::boot::BootType;
use crate::bootc_composefs::gc::{GCOpts, composefs_gc};
use crate::bootc_composefs::rollback::{rename_exchange_bls_entries, rename_exchange_user_cfg};
use crate::bootc_composefs::status::{StagedDeployment, get_composefs_status};
use crate::composefs_consts::{
    COMPOSEFS_STAGED_DEPLOYMENT_FNAME, COMPOSEFS_TRANSIENT_STATE_DIR, STATE_DIR_ABS,
};
use crate::spec::BootloaderKind;
use crate::store::{BootedComposefs, Storage};
use anyhow::{Context, Result};
use bootc_initramfs_setup::mount_composefs_image;
use bootc_mount::tempmount::TempMount;
use cap_std_ext::cap_std::{ambient_authority, fs::Dir};
use cap_std_ext::dirext::CapStdExtDirExt;
use composefs::generic_tree::{FileSystem, Stat};
use composefs_ctl::composefs;
use etc_merge::{Diff, compute_diff, merge, print_diff, traverse_etc};
use rustix::fs::fsync;

use fn_error_context::context;

pub(crate) async fn get_etc_diff(
    storage: &Storage,
    booted_cfs: &BootedComposefs,
    against_deployment: Option<&str>,
    print: bool,
) -> Result<Diff> {
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

    let new_etc = match against_deployment {
        Some(verity) => {
            let new_etc_path = Path::new(STATE_DIR_ABS).join(&verity).join("etc");
            Some(Dir::open_ambient_dir(&new_etc_path, ambient_authority())?)
        }
        None => None,
    };

    let (pristine_files, current_files, new_etc_files) =
        traverse_etc(&pristine_etc, &current_etc, new_etc.as_ref())?;

    let diff = compute_diff(
        &pristine_files,
        &current_files,
        &new_etc_files
            .as_ref()
            .unwrap_or(&FileSystem::new(Stat::uninitialized())),
    )?;

    if print {
        print_diff(&diff, &mut std::io::stdout());
    }

    Ok(diff)
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

    let staged_depl_dir = Dir::open_ambient_dir(COMPOSEFS_TRANSIENT_STATE_DIR, ambient_authority())
        .context("Opening transient state directory")?;

    let current = staged_depl_dir
        .read_to_string(COMPOSEFS_STAGED_DEPLOYMENT_FNAME)
        .context("Reading staged file")?;

    let staged_depl_file: StagedDeployment =
        serde_json::from_str(&current).context("Deserialzing staged file")?;

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

    let mut new_files =
        new_files.ok_or_else(|| anyhow::anyhow!("Failed to get dirtree for new etc"))?;

    let diff = compute_diff(&pristine_files, &current_files, &new_files)?;
    merge(
        &current_etc,
        &current_files,
        &new_etc,
        &mut new_files,
        &diff,
        staged_depl_file.merge_strategy,
    )?;

    // Remove /etc/.updated from the new deployment so that ConditionNeedsUpdate=|/etc
    // services (systemd-sysusers, systemd-tmpfiles) run on the first boot, mirroring
    // what ostree does in sysroot_finalize_deployment.
    new_etc
        .remove_file_optional(".updated")
        .context("Removing /etc/.updated from staged deployment")?;

    // Unmount EROFS
    drop(erofs_tmp_mnt);

    let boot_dir = storage.require_boot_dir()?;

    match booted_composefs.bootloader.kind()? {
        BootloaderKind::GRUBClassic => match staged_composefs.boot_type {
            BootType::Bls => {
                let entries_dir = boot_dir.open_dir("loader")?;
                rename_exchange_bls_entries(&entries_dir)?;
            }
            BootType::Uki => finalize_staged_grub_uki(boot_dir)?,
        },

        BootloaderKind::BLSCompatible => {
            let entries_dir = boot_dir.open_dir("loader")?;
            rename_exchange_bls_entries(&entries_dir)?;
        }
    };

    // Now that we have successfully updated bootloader entires, we can GC the unreferenced ones
    // We do not prune the composefs repository here though
    composefs_gc(
        storage,
        booted_cfs,
        GCOpts {
            dry_run: false,
            prune_repo: false,
        },
    )
    .await?;

    Ok(())
}

#[context("Grub: Finalizing staged UKI")]
fn finalize_staged_grub_uki(boot_fd: &Dir) -> Result<()> {
    let entries_dir = boot_fd.open_dir("grub2")?;
    rename_exchange_user_cfg(&entries_dir)?;

    let entries_dir = entries_dir.reopen_as_ownedfd()?;
    fsync(entries_dir).context("fsync")?;

    Ok(())
}
