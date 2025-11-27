use std::{collections::HashSet, io::Write, path::Path};

use anyhow::{Context, Result};
use cap_std_ext::{cap_std::fs::Dir, dirext::CapStdExtDirExt};
use composefs::fsverity::Sha512HashValue;
use composefs_boot::bootloader::{EFI_ADDON_DIR_EXT, EFI_EXT};

use crate::{
    bootc_composefs::{
        boot::{find_vmlinuz_initrd_duplicates, get_efi_uuid_source, BootType, SYSTEMD_UKI_DIR},
        gc::composefs_gc,
        repo::open_composefs_repo,
        rollback::{composefs_rollback, rename_exchange_user_cfg},
        status::{get_composefs_status, get_sorted_grub_uki_boot_entries},
    },
    composefs_consts::{
        COMPOSEFS_STAGED_DEPLOYMENT_FNAME, COMPOSEFS_TRANSIENT_STATE_DIR, STATE_DIR_RELATIVE,
        TYPE1_ENT_PATH, TYPE1_ENT_PATH_STAGED, USER_CFG_STAGED,
    },
    parsers::bls_config::{parse_bls_config, BLSConfigType},
    spec::{BootEntry, Bootloader, DeploymentEntry},
    status::Slot,
    store::{BootedComposefs, Storage},
};

#[fn_error_context::context("Deleting Type1 Entry {}", depl.deployment.verity)]
fn delete_type1_entry(depl: &DeploymentEntry, boot_dir: &Dir, deleting_staged: bool) -> Result<()> {
    let entries_dir_path = if deleting_staged {
        TYPE1_ENT_PATH_STAGED
    } else {
        TYPE1_ENT_PATH
    };

    let entries_dir = boot_dir
        .open_dir(entries_dir_path)
        .context("Opening entries dir")?;

    // We reuse kernel + initrd if they're the same for two deployments
    // We don't want to delete the (being deleted) deployment's kernel + initrd
    // if it's in use by any other deployment
    let should_del_kernel = match depl.deployment.boot_digest.as_ref() {
        Some(digest) => find_vmlinuz_initrd_duplicates(digest)?
            .is_some_and(|vec| vec.iter().any(|digest| *digest != depl.deployment.verity)),
        None => false,
    };

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
                delete_uki(&depl.deployment.verity, boot_dir)?;

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

                if should_del_kernel {
                    delete_kernel_initrd(&bls_config.cfg_type, boot_dir)?;
                }

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

#[fn_error_context::context("Deleting kernel and initrd")]
fn delete_kernel_initrd(bls_config: &BLSConfigType, boot_dir: &Dir) -> Result<()> {
    let BLSConfigType::NonEFI { linux, initrd, .. } = bls_config else {
        anyhow::bail!("Found EFI config")
    };

    // "linux" and "initrd" are relative to the boot_dir in our config files
    tracing::debug!("Deleting kernel: {:?}", linux);
    boot_dir
        .remove_file(linux)
        .with_context(|| format!("Removing {linux:?}"))?;

    for ird in initrd {
        tracing::debug!("Deleting initrd: {:?}", ird);
        boot_dir
            .remove_file(ird)
            .with_context(|| format!("Removing {ird:?}"))?;
    }

    // Remove the directory if it's empty
    //
    // This shouldn't ever error as we'll never have these in root
    let dir = linux
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Bad path for vmlinuz {linux}"))?;

    let kernel_parent_dir = boot_dir.open_dir(&dir)?;

    if kernel_parent_dir.entries().iter().len() == 0 {
        // We don't have anything other than kernel and initrd in this directory for now
        // So this directory should *always* be empty, for now at least
        tracing::debug!("Deleting empty kernel directory: {:?}", dir);
        kernel_parent_dir.remove_open_dir()?;
    };

    Ok(())
}

/// Deletes the UKI `uki_id` and any addons specific to it
#[fn_error_context::context("Deleting UKI and UKI addons {uki_id}")]
fn delete_uki(uki_id: &str, esp_mnt: &Dir) -> Result<()> {
    // TODO: We don't delete global addons here
    let ukis = esp_mnt.open_dir(SYSTEMD_UKI_DIR)?;

    for entry in ukis.entries_utf8()? {
        let entry = entry?;
        let entry_name = entry.file_name()?;

        // The actual UKI PE binary
        if entry_name == format!("{}{}", uki_id, EFI_EXT) {
            tracing::debug!("Deleting UKI: {}", entry_name);
            entry.remove_file().context("Deleting UKI")?;
        } else if entry_name == format!("{}{}", uki_id, EFI_ADDON_DIR_EXT) {
            // Addons dir
            tracing::debug!("Deleting UKI addons directory: {}", entry_name);
            ukis.remove_dir_all(entry_name)
                .context("Deleting UKI addons dir")?;
        }
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

#[fn_error_context::context("Deleting boot entries for deployment {}", deployment.deployment.verity)]
fn delete_depl_boot_entries(
    deployment: &DeploymentEntry,
    storage: &Storage,
    deleting_staged: bool,
) -> Result<()> {
    let boot_dir = storage.require_boot_dir()?;

    match deployment.deployment.bootloader {
        Bootloader::Grub => match deployment.deployment.boot_type {
            BootType::Bls => delete_type1_entry(deployment, boot_dir, deleting_staged),

            BootType::Uki => {
                let esp = storage
                    .esp
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("ESP not found"))?;

                remove_grub_menucfg_entry(
                    &deployment.deployment.verity,
                    boot_dir,
                    deleting_staged,
                )?;

                delete_uki(&deployment.deployment.verity, &esp.fd)
            }
        },

        Bootloader::Systemd => {
            // For Systemd UKI as well, we use .conf files
            delete_type1_entry(deployment, boot_dir, deleting_staged)
        }
    }
}

#[fn_error_context::context("Getting image objects")]
pub(crate) fn get_image_objects(sysroot: &Dir) -> Result<HashSet<Sha512HashValue>> {
    let repo = open_composefs_repo(&sysroot)?;

    let images_dir = sysroot
        .open_dir("composefs/images")
        .context("Opening images dir")?;

    let image_entries = images_dir
        .entries_utf8()
        .context("Reading entries in images dir")?;

    let mut object_refs = HashSet::new();

    for image in image_entries {
        let image = image?;

        let img_name = image.file_name().context("Getting image name")?;

        let objects = repo
            .objects_for_image(&img_name)
            .with_context(|| format!("Getting objects for image {img_name}"))?;

        object_refs.extend(objects);
    }

    Ok(object_refs)
}

#[fn_error_context::context("Deleting image for deployment {}", deployment_id)]
pub(crate) fn delete_image(sysroot: &Dir, deployment_id: &str) -> Result<()> {
    let img_path = Path::new("composefs").join("images").join(deployment_id);

    tracing::debug!("Deleting EROFS image: {:?}", img_path);
    sysroot
        .remove_file(&img_path)
        .context("Deleting EROFS image")
}

#[fn_error_context::context("Deleting state directory for deployment {}", deployment_id)]
pub(crate) fn delete_state_dir(sysroot: &Dir, deployment_id: &str) -> Result<()> {
    let state_dir = Path::new(STATE_DIR_RELATIVE).join(deployment_id);

    tracing::debug!("Deleting state directory: {:?}", state_dir);
    sysroot
        .remove_dir_all(&state_dir)
        .with_context(|| format!("Removing dir {state_dir:?}"))
}

#[fn_error_context::context("Deleting staged deployment")]
pub(crate) fn delete_staged(staged: &Option<BootEntry>) -> Result<()> {
    if staged.is_none() {
        tracing::debug!("No staged deployment");
        return Ok(());
    };

    let file = Path::new(COMPOSEFS_TRANSIENT_STATE_DIR).join(COMPOSEFS_STAGED_DEPLOYMENT_FNAME);
    tracing::debug!("Deleting staged deployment file: {file:?}");
    std::fs::remove_file(file).context("Removing staged file")?;

    Ok(())
}

#[fn_error_context::context("Deleting composefs deployment {}", deployment_id)]
pub(crate) async fn delete_composefs_deployment(
    deployment_id: &str,
    storage: &Storage,
    booted_cfs: &BootedComposefs,
) -> Result<()> {
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

    composefs_gc(storage, booted_cfs).await?;

    Ok(())
}
