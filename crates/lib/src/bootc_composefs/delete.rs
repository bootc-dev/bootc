use std::{collections::HashSet, io::Write, path::Path};

use anyhow::{Context, Result};
use cap_std_ext::{
    cap_std::{ambient_authority, fs::Dir},
    dirext::CapStdExtDirExt,
};
use composefs::fsverity::{FsVerityHashValue, Sha512HashValue};
use composefs_boot::bootloader::{EFI_ADDON_DIR_EXT, EFI_EXT};

use crate::{
    bootc_composefs::{
        boot::{
            find_vmlinuz_initrd_duplicates, get_efi_uuid_source, get_esp_partition,
            get_sysroot_parent_dev, mount_esp, BootType, SYSTEMD_UKI_DIR,
        },
        repo::open_composefs_repo,
        rollback::{composefs_rollback, rename_exchange_user_cfg},
        status::{composefs_deployment_status, get_sorted_grub_uki_boot_entries},
    },
    composefs_consts::{
        COMPOSEFS_STAGED_DEPLOYMENT_FNAME, COMPOSEFS_TRANSIENT_STATE_DIR, STATE_DIR_RELATIVE,
        TYPE1_ENT_PATH, TYPE1_ENT_PATH_STAGED, USER_CFG_STAGED,
    },
    parsers::bls_config::{parse_bls_config, BLSConfigType},
    spec::{Bootloader, DeploymentEntry},
    status::Slot,
};

struct ObjectRefs {
    other_depl: HashSet<Sha512HashValue>,
    depl_to_del: HashSet<Sha512HashValue>,
}

#[fn_error_context::context("Deleting Type1 Entry {}", depl.deployment.verity)]
fn delete_type1_entries(
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

    // We reuse kernel + initrd if they're the same for two deployments
    // We don't want to delete the (being deleted) deployment's kernel + initrd
    // if it's in use by any other deployment
    let should_del_kernel = match &depl.deployment.boot_digest {
        Some(digest) => find_vmlinuz_initrd_duplicates(&digest)?
            .is_some_and(|vec| vec.iter().any(|digest| *digest != depl.deployment.verity)),
        None => false,
    };

    for entry in entries_dir.entries_utf8()? {
        let entry = entry?;
        let file_name = entry.file_name()?;

        if !file_name.ends_with(".conf") {
            // We don't put any non .conf file in the entries dir
            // This is here just for sanity
            tracing::debug!("Found non .conf file '{file_name}' in entires dir");
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
                delete_uki(&depl.deployment.verity, boot_dir)?;
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

                if should_del_kernel {
                    delete_kernel_initrd(&bls_config.cfg_type, boot_dir)?;
                }

                entry.remove_file().context("Removing .conf file")?;

                break;
            }

            BLSConfigType::Unknown => anyhow::bail!("Unknown BLS Config Type"),
        }
    }

    if deleting_staged {
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
    boot_dir
        .remove_file(linux)
        .with_context(|| format!("Removing {linux:?}"))?;

    for ird in initrd {
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
        kernel_parent_dir.remove_open_dir()?;
    };

    Ok(())
}

/// Deletes the UKI `uki_id` and any addons specific to it
#[fn_error_context::context("Deleting UKI and UKI addons {uki_id}")]
fn delete_uki(uki_id: &str, esp_mnt: &Dir) -> Result<()> {
    let ukis = esp_mnt.open_dir(SYSTEMD_UKI_DIR)?;

    for entry in ukis.entries_utf8()? {
        let entry = entry?;
        let entry_name = entry.file_name()?;

        // The actual UKI PE binary
        if entry_name == format!("{}{}", uki_id, EFI_EXT) {
            entry.remove_file().context("Deleting UKI")?;
        } else if entry_name == format!("{}{}", uki_id, EFI_ADDON_DIR_EXT) {
            // Addons dir
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
        return grub_dir
            .remove_file(USER_CFG_STAGED)
            .context("Deleting staged Menuentry");
    }

    let mut string = String::new();
    let menuentries = get_sorted_grub_uki_boot_entries(boot_dir, &mut string)?;

    let mut buffer = vec![];

    buffer.write_all(get_efi_uuid_source().as_bytes())?;

    for entry in menuentries {
        if entry.body.chainloader.contains(id) {
            continue;
        }

        buffer.write_all(entry.to_string().as_bytes())?;
    }

    grub_dir
        .atomic_write(USER_CFG_STAGED, buffer)
        .with_context(|| format!("Writing to {USER_CFG_STAGED}"))?;

    rustix::fs::fsync(grub_dir.reopen_as_ownedfd().context("Reopening")?).context("fsync")?;

    rename_exchange_user_cfg(&grub_dir)
}

fn delete_depl_boot_entries(deployment: &DeploymentEntry, deleting_staged: bool) -> Result<()> {
    match deployment.deployment.bootloader {
        Bootloader::Grub => {
            let boot_dir = Dir::open_ambient_dir("/sysroot/boot", ambient_authority())
                .context("Opening boot dir")?;

            match deployment.deployment.boot_type {
                BootType::Bls => delete_type1_entries(deployment, &boot_dir, deleting_staged),

                BootType::Uki => {
                    let device = get_sysroot_parent_dev()?;
                    let (esp_part, ..) = get_esp_partition(&device)?;
                    let esp_mount = mount_esp(&esp_part)?;

                    delete_uki(&deployment.deployment.verity, &esp_mount.fd)?;

                    remove_grub_menucfg_entry(
                        &deployment.deployment.verity,
                        &boot_dir,
                        deleting_staged,
                    )
                }
            }
        }

        Bootloader::Systemd => {
            let device = get_sysroot_parent_dev()?;
            let (esp_part, ..) = get_esp_partition(&device)?;

            let esp_mount = mount_esp(&esp_part)?;

            // For Systemd UKI as well, we use .conf files
            delete_type1_entries(deployment, &esp_mount.fd, deleting_staged)
        }
    }
}

pub(crate) async fn delete_composefs_deployment(deployment_id: &str, delete: bool) -> Result<()> {
    let host = composefs_deployment_status().await?;

    let booted = host.require_composefs_booted()?;

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

    // Get all objects referenced by all images
    // Delete objects that are only referenced by the deployment to be deleted

    // Unqueue rollback. This makes it easier to delete boot entries later on
    if matches!(depl_to_del.ty, Some(Slot::Rollback)) && host.status.rollback_queued {
        composefs_rollback().await?;
    }

    let sysroot =
        Dir::open_ambient_dir("/sysroot", ambient_authority()).context("Opening sysroot")?;

    let repo = open_composefs_repo(&sysroot)?;

    let images_dir = sysroot
        .open_dir("composefs/images")
        .context("Opening images dir")?;

    let image_entries = images_dir
        .entries_utf8()
        .context("Reading entries in images dir")?;

    let mut object_refs = ObjectRefs {
        other_depl: HashSet::new(),
        depl_to_del: HashSet::new(),
    };

    for image in image_entries {
        let image = image?;

        let img_name = image.file_name().context("Getting image name")?;

        let objects = repo
            .objects_for_image(&img_name)
            .with_context(|| format!("Getting objects for image {img_name}"))?;

        if img_name == deployment_id {
            object_refs.depl_to_del.extend(objects);
        } else {
            object_refs.other_depl.extend(objects);
        }
    }

    let diff: Vec<&Sha512HashValue> = object_refs
        .depl_to_del
        .difference(&object_refs.other_depl)
        .collect();

    tracing::debug!("diff: {:#?}", diff);

    // For debugging, but maybe useful elsewhere?
    if !delete {
        return Ok(());
    }

    if deployment_id == &booted.verity {
        anyhow::bail!("Cannot delete currently booted deployment");
    }

    let kind = if depl_to_del.pinned {
        "pinned "
    } else if deleting_staged {
        "staged "
    } else {
        ""
    };

    tracing::info!("Deleting {kind}deployment '{deployment_id}'");

    delete_depl_boot_entries(&depl_to_del, deleting_staged)?;

    // Delete the image
    let img_path = Path::new("composefs").join("images").join(deployment_id);
    sysroot
        .remove_file(&img_path)
        .context("Deleting EROFS image")?;

    if deleting_staged {
        let file = Path::new(COMPOSEFS_TRANSIENT_STATE_DIR).join(COMPOSEFS_STAGED_DEPLOYMENT_FNAME);
        tracing::debug!("Deleting staged file {file:?}");
        std::fs::remove_file(file).context("Removing staged file")?;
    }

    let state_dir = Path::new(STATE_DIR_RELATIVE).join(deployment_id);
    sysroot
        .remove_dir_all(&state_dir)
        .with_context(|| format!("Removing dir {state_dir:?}"))?;

    for sha in diff {
        let object_path = Path::new("composefs")
            .join("objects")
            .join(sha.to_object_pathname());

        sysroot
            .remove_file(&object_path)
            .with_context(|| format!("Removing {object_path:?}"))?;
    }

    Ok(())
}
