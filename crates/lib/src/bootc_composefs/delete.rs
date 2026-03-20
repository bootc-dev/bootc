use std::{io::Write, path::Path};

use anyhow::{Context, Result};
use cap_std_ext::{cap_std::fs::Dir, dirext::CapStdExtDirExt};

use crate::{
    bootc_composefs::{
        boot::{BootType, get_efi_uuid_source},
        gc::composefs_gc,
        rollback::{composefs_rollback, rename_exchange_user_cfg},
        status::{get_composefs_status, get_sorted_grub_uki_boot_entries},
    },
    composefs_consts::{
        COMPOSEFS_STAGED_DEPLOYMENT_FNAME, COMPOSEFS_TRANSIENT_STATE_DIR, STATE_DIR_RELATIVE,
        TYPE1_ENT_PATH, TYPE1_ENT_PATH_STAGED, USER_CFG_STAGED,
    },
    parsers::bls_config::{BLSConfigType, parse_bls_config},
    spec::{BootEntry, Bootloader, DeploymentEntry},
    status::Slot,
    store::{BootedComposefs, Storage},
};

#[fn_error_context::context("Deleting Type1 Entry {}", depl.deployment.verity)]
fn delete_type1_conf_file(
    depl: &DeploymentEntry,
    boot_dir: &Dir,
    deleting_staged: bool,
) -> Result<()> {
    let entries_dir_path = if deleting_staged {
        TYPE1_ENT_PATH_STAGED
    } else {
        TYPE1_ENT_PATH
    };

    let entries_dir = boot_dir
        .open_dir(entries_dir_path)
        .context("Opening entries dir")?;

    for entry in entries_dir.entries_utf8()? {
        let entry = entry?;
        let file_name = entry.file_name()?;

        if !file_name.ends_with(".conf") {
            // We don't put any non .conf file in the entries dir
            // This is here just for sanity
            tracing::debug!("Found non .conf file '{file_name}' in entries dir");
            continue;
        }

        let cfg = entries_dir
            .read_to_string(&file_name)
            .with_context(|| format!("Reading {file_name}"))?;

        let bls_config = parse_bls_config(&cfg)?;

        match &bls_config.cfg_type {
            BLSConfigType::EFI { efi } => {
                if !efi.as_str().contains(&depl.deployment.verity) {
                    continue;
                }

                // Boot dir in case of EFI will be the ESP
                tracing::debug!("Deleting EFI .conf file: {}", file_name);
                entry.remove_file().context("Removing .conf file")?;

                break;
            }

            BLSConfigType::NonEFI { options, .. } => {
                let options = options
                    .as_ref()
                    .ok_or(anyhow::anyhow!("options not found in BLS config file"))?;

                if !options.contains(&depl.deployment.verity) {
                    continue;
                }

                tracing::debug!("Deleting non-EFI .conf file: {}", file_name);
                entry.remove_file().context("Removing .conf file")?;

                break;
            }

            BLSConfigType::Unknown => anyhow::bail!("Unknown BLS Config Type"),
        }
    }

    if deleting_staged {
        tracing::debug!(
            "Deleting staged entries directory: {}",
            TYPE1_ENT_PATH_STAGED
        );

        boot_dir
            .remove_dir_all(TYPE1_ENT_PATH_STAGED)
            .context("Removing staged entries dir")?;
    }

    Ok(())
}

#[fn_error_context::context("Removing Grub Menuentry")]
fn remove_grub_menucfg_entry(id: &str, boot_dir: &Dir, deleting_staged: bool) -> Result<()> {
    let grub_dir = boot_dir.open_dir("grub2").context("Opening grub2")?;

    if deleting_staged {
        tracing::debug!("Deleting staged grub menuentry file: {}", USER_CFG_STAGED);
        return grub_dir
            .remove_file(USER_CFG_STAGED)
            .context("Deleting staged Menuentry");
    }

    let mut string = String::new();
    let menuentries = get_sorted_grub_uki_boot_entries(boot_dir, &mut string)?;

    grub_dir
        .atomic_replace_with(USER_CFG_STAGED, move |f| -> std::io::Result<_> {
            f.write_all(get_efi_uuid_source().as_bytes())?;

            for entry in menuentries {
                if entry.body.chainloader.contains(id) {
                    continue;
                }

                f.write_all(entry.to_string().as_bytes())?;
            }

            Ok(())
        })
        .with_context(|| format!("Writing to {USER_CFG_STAGED}"))?;

    rustix::fs::fsync(grub_dir.reopen_as_ownedfd().context("Reopening")?).context("fsync")?;

    rename_exchange_user_cfg(&grub_dir)
}

/// Deletes the .conf files in case for systemd-boot and Type1 bootloader entries for Grub
/// or removes the corresponding menuentry from Grub's user.cfg in case for grub UKI
/// Does not delete the actual boot binaries
#[fn_error_context::context("Deleting boot entries for deployment {}", deployment.deployment.verity)]
fn delete_depl_boot_entries(
    deployment: &DeploymentEntry,
    storage: &Storage,
    deleting_staged: bool,
) -> Result<()> {
    let boot_dir = storage.require_boot_dir()?;

    match deployment.deployment.bootloader {
        Bootloader::Grub => match deployment.deployment.boot_type {
            BootType::Bls => delete_type1_conf_file(deployment, boot_dir, deleting_staged),
            BootType::Uki => {
                remove_grub_menucfg_entry(&deployment.deployment.verity, boot_dir, deleting_staged)
            }
        },

        Bootloader::Systemd => {
            // For Systemd UKI as well, we use .conf files
            delete_type1_conf_file(deployment, boot_dir, deleting_staged)
        }

        Bootloader::None => unreachable!("Checked at install time"),
    }
}


#[fn_error_context::context("Deleting state directory for deployment {}", deployment_id)]
pub(crate) fn delete_state_dir(sysroot: &Dir, deployment_id: &str, dry_run: bool) -> Result<()> {
    let state_dir = Path::new(STATE_DIR_RELATIVE).join(deployment_id);
    tracing::debug!("Deleting state directory: {:?}", state_dir);

    if dry_run {
        return Ok(());
    }

    sysroot
        .remove_dir_all(&state_dir)
        .with_context(|| format!("Removing dir {state_dir:?}"))
}

#[fn_error_context::context("Deleting staged deployment")]
pub(crate) fn delete_staged(
    staged: &Option<BootEntry>,
    cleanup_list: &Vec<&String>,
    dry_run: bool,
) -> Result<()> {
    let Some(staged_depl) = staged else {
        tracing::debug!("No staged deployment");
        return Ok(());
    };

    if !cleanup_list.contains(&&staged_depl.require_composefs()?.verity) {
        tracing::debug!("Staged deployment not in cleanup list");
        return Ok(());
    }

    let file = Path::new(COMPOSEFS_TRANSIENT_STATE_DIR).join(COMPOSEFS_STAGED_DEPLOYMENT_FNAME);

    if !dry_run && file.exists() {
        tracing::debug!("Deleting staged deployment file: {file:?}");
        std::fs::remove_file(file).context("Removing staged file")?;
    }

    Ok(())
}

#[fn_error_context::context("Deleting composefs deployment {}", deployment_id)]
pub(crate) async fn delete_composefs_deployment(
    deployment_id: &str,
    storage: &Storage,
    booted_cfs: &BootedComposefs,
) -> Result<()> {
    const COMPOSEFS_DELETE_JOURNAL_ID: &str = "2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6";

    tracing::info!(
        message_id = COMPOSEFS_DELETE_JOURNAL_ID,
        bootc.operation = "delete",
        bootc.current_deployment = booted_cfs.cmdline.digest,
        bootc.target_deployment = deployment_id,
        "Starting composefs deployment deletion for {}",
        deployment_id
    );

    let host = get_composefs_status(storage, booted_cfs).await?;

    let booted = host.require_composefs_booted()?;

    if deployment_id == &booted.verity {
        anyhow::bail!("Cannot delete currently booted deployment");
    }

    let all_depls = host.all_composefs_deployments()?;

    let depl_to_del = all_depls
        .iter()
        .find(|d| d.deployment.verity == deployment_id);

    let Some(depl_to_del) = depl_to_del else {
        anyhow::bail!("Deployment {deployment_id} not found");
    };

    let deleting_staged = host
        .status
        .staged
        .as_ref()
        .and_then(|s| s.composefs.as_ref())
        .map_or(false, |cfs| cfs.verity == deployment_id);

    // Unqueue rollback. This makes it easier to delete boot entries later on
    if matches!(depl_to_del.ty, Some(Slot::Rollback)) && host.status.rollback_queued {
        composefs_rollback(storage, booted_cfs).await?;
    }

    let kind = if depl_to_del.pinned {
        "pinned "
    } else if deleting_staged {
        "staged "
    } else {
        ""
    };

    tracing::info!("Deleting {kind}deployment '{deployment_id}'");

    delete_depl_boot_entries(&depl_to_del, &storage, deleting_staged)?;

    composefs_gc(storage, booted_cfs, true).await?;

    Ok(())
}
