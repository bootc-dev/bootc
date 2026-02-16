use std::io::Write;

use anyhow::{Context, Result, anyhow};
use cap_std_ext::cap_std::fs::Dir;
use cap_std_ext::dirext::CapStdExtDirExt;
use fn_error_context::context;
use rustix::fs::{AtFlags, RenameFlags, fsync, renameat_with};

use crate::bootc_composefs::boot::{
    BootType, FILENAME_PRIORITY_PRIMARY, FILENAME_PRIORITY_SECONDARY, primary_sort_key,
    secondary_sort_key, type1_entry_conf_file_name,
};
use crate::bootc_composefs::status::{get_composefs_status, get_sorted_type1_boot_entries};
use crate::composefs_consts::TYPE1_ENT_PATH_STAGED;
use crate::spec::Bootloader;
use crate::store::{BootedComposefs, Storage};
use crate::{
    bootc_composefs::{boot::get_efi_uuid_source, status::get_sorted_grub_uki_boot_entries},
    composefs_consts::{
        BOOT_LOADER_ENTRIES, STAGED_BOOT_LOADER_ENTRIES, USER_CFG, USER_CFG_STAGED,
    },
    spec::BootOrder,
};

/// Atomically rename exchange grub user.cfg with the staged version
/// Performed as the last step in rollback/update/switch operation
#[context("Atomically exchanging user.cfg")]
pub(crate) fn rename_exchange_user_cfg(entries_dir: &Dir) -> Result<()> {
    tracing::debug!("Atomically exchanging {USER_CFG_STAGED} and {USER_CFG}");
    renameat_with(
        &entries_dir,
        USER_CFG_STAGED,
        &entries_dir,
        USER_CFG,
        RenameFlags::EXCHANGE,
    )
    .context("renameat")?;

    tracing::debug!("Removing {USER_CFG_STAGED}");
    rustix::fs::unlinkat(&entries_dir, USER_CFG_STAGED, AtFlags::empty()).context("unlinkat")?;

    tracing::debug!("Syncing to disk");
    let entries_dir = entries_dir
        .reopen_as_ownedfd()
        .context("Reopening entries dir as owned fd")?;

    fsync(entries_dir).context("fsync entries dir")?;

    Ok(())
}

/// Atomically rename exchange "entries" <-> "entries.staged"
/// Performed as the last step in rollback/update/switch operation
///
/// `entries_dir` is the directory that contains the BLS entries directories
/// Ex: entries_dir = ESP/loader or boot/loader
#[context("Atomically exchanging BLS entries")]
pub(crate) fn rename_exchange_bls_entries(entries_dir: &Dir) -> Result<()> {
    tracing::debug!("Atomically exchanging {STAGED_BOOT_LOADER_ENTRIES} and {BOOT_LOADER_ENTRIES}");
    renameat_with(
        &entries_dir,
        STAGED_BOOT_LOADER_ENTRIES,
        &entries_dir,
        BOOT_LOADER_ENTRIES,
        RenameFlags::EXCHANGE,
    )
    .context("renameat")?;

    tracing::debug!("Removing {STAGED_BOOT_LOADER_ENTRIES}");
    entries_dir
        .remove_dir_all(STAGED_BOOT_LOADER_ENTRIES)
        .context("Removing staged dir")?;

    tracing::debug!("Syncing to disk");
    let entries_dir = entries_dir
        .reopen_as_ownedfd()
        .context("Reopening as owned fd")?;

    fsync(entries_dir).context("fsync")?;

    Ok(())
}

#[context("Rolling back Grub UKI")]
fn rollback_grub_uki_entries(boot_dir: &Dir) -> Result<()> {
    let mut str = String::new();
    let mut menuentries = get_sorted_grub_uki_boot_entries(&boot_dir, &mut str)
        .context("Getting UKI boot entries")?;

    // TODO(Johan-Liebert): Currently assuming there are only two deployments
    assert!(menuentries.len() == 2);

    let (first, second) = menuentries.split_at_mut(1);
    std::mem::swap(&mut first[0], &mut second[0]);

    let entries_dir = boot_dir.open_dir("grub2").context("Opening grub dir")?;

    entries_dir
        .atomic_replace_with(USER_CFG_STAGED, |f| -> std::io::Result<_> {
            f.write_all(get_efi_uuid_source().as_bytes())?;

            for entry in menuentries {
                f.write_all(entry.to_string().as_bytes())?;
            }

            Ok(())
        })
        .with_context(|| format!("Writing to {USER_CFG_STAGED}"))?;

    rename_exchange_user_cfg(&entries_dir)
}

/// Performs rollback for
/// - Grub Type1 boot entries
/// - Systemd Typ1 boot entries
/// - Systemd UKI (Type2) boot entries [since we use BLS entries for systemd boot]
#[context("Rolling back {bootloader} entries")]
fn rollback_composefs_entries(boot_dir: &Dir, bootloader: Bootloader) -> Result<()> {
    use crate::bootc_composefs::state::get_booted_bls;

    // Get all boot entries sorted in descending order by sort-key
    let mut all_configs = get_sorted_type1_boot_entries(&boot_dir, false)?;

    // TODO(Johan-Liebert): Currently assuming there are only two deployments
    assert!(all_configs.len() == 2);

    // Identify which entry is the currently booted one
    let booted_bls = get_booted_bls(&boot_dir)?;
    let booted_verity = booted_bls.get_verity()?;

    // For rollback: previous gets primary sort-key, booted gets secondary sort-key
    // Use "bootc" as default os_id for rollback scenarios
    // TODO: Extract actual os_id from deployment
    let os_id = "bootc";

    for cfg in &mut all_configs {
        let cfg_verity = cfg.get_verity()?;

        if cfg_verity == booted_verity {
            // This is the currently booted deployment - it should become secondary
            cfg.sort_key = Some(secondary_sort_key(os_id));
        } else {
            // This is the previous deployment - it should become primary (rollback target)
            cfg.sort_key = Some(primary_sort_key(os_id));
        }
    }

    // Write these
    boot_dir
        .create_dir_all(TYPE1_ENT_PATH_STAGED)
        .context("Creating staged dir")?;

    let rollback_entries_dir = boot_dir
        .open_dir(TYPE1_ENT_PATH_STAGED)
        .context("Opening staged entries dir")?;

    // Write the BLS configs in there
    for cfg in all_configs {
        let cfg_verity = cfg.get_verity()?;
        // After rollback: previous deployment becomes primary, booted becomes secondary
        let priority = if cfg_verity == booted_verity {
            FILENAME_PRIORITY_SECONDARY
        } else {
            FILENAME_PRIORITY_PRIMARY
        };

        let file_name = type1_entry_conf_file_name(os_id, &cfg.version(), priority);

        rollback_entries_dir
            .atomic_write(&file_name, cfg.to_string())
            .with_context(|| format!("Writing to {file_name}"))?;
    }

    let rollback_entries_dir = rollback_entries_dir
        .reopen_as_ownedfd()
        .context("Reopening as owned fd")?;

    // Should we sync after every write?
    fsync(rollback_entries_dir).context("fsync")?;

    // Atomically exchange "entries" <-> "entries.rollback"
    let dir = boot_dir.open_dir("loader").context("Opening loader dir")?;

    rename_exchange_bls_entries(&dir)
}

#[context("Rolling back composefs")]
pub(crate) async fn composefs_rollback(
    storage: &Storage,
    booted_cfs: &BootedComposefs,
) -> Result<()> {
    let host = get_composefs_status(storage, booted_cfs).await?;

    let new_spec = {
        let mut new_spec = host.spec.clone();
        new_spec.boot_order = new_spec.boot_order.swap();
        new_spec
    };

    // Just to be sure
    host.spec.verify_transition(&new_spec)?;

    let reverting = new_spec.boot_order == BootOrder::Default;
    if reverting {
        println!("notice: Reverting queued rollback state");
    }

    let rollback_status = host
        .status
        .rollback
        .ok_or_else(|| anyhow!("No rollback available"))?;

    // TODO: Handle staged deployment
    // Ostree will drop any staged deployment on rollback but will keep it if it is the first item
    // in the new deployment list
    let Some(rollback_entry) = &rollback_status.composefs else {
        anyhow::bail!("Rollback deployment not a composefs deployment")
    };

    let boot_dir = storage.require_boot_dir()?;

    match &rollback_entry.bootloader {
        Bootloader::Grub => match rollback_entry.boot_type {
            BootType::Bls => {
                rollback_composefs_entries(boot_dir, rollback_entry.bootloader.clone())?;
            }
            BootType::Uki => {
                rollback_grub_uki_entries(boot_dir)?;
            }
        },

        Bootloader::Systemd => {
            // We use BLS entries for systemd UKI as well
            rollback_composefs_entries(boot_dir, rollback_entry.bootloader.clone())?;
        }

        Bootloader::None => unreachable!("Checked at install time"),
    }

    if reverting {
        println!("Next boot: current deployment");
    } else {
        println!("Next boot: rollback deployment");
    }

    Ok(())
}
