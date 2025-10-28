//! This module handles the case when deleting a deployment fails midway
//!
//! There could be the following cases (See ./delete.rs:delete_composefs_deployment):
//! - We delete the bootloader entry but fail to delete image
//! - We delete bootloader + image but fail to delete the state/unrefenced objects etc

use anyhow::{Context, Result};
use cap_std_ext::{
    cap_std::{ambient_authority, fs::Dir},
    dirext::CapStdExtDirExt,
};
use composefs::fsverity::{FsVerityHashValue, Sha512HashValue};

use crate::{
    bootc_composefs::{
        boot::{get_esp_partition, get_sysroot_parent_dev, mount_esp},
        delete::{delete_image, delete_staged, delete_state_dir, get_image_objects},
        status::{
            composefs_deployment_status, get_bootloader, get_sorted_grub_uki_boot_entries,
            get_sorted_type1_boot_entries,
        },
    },
    composefs_consts::{STATE_DIR_RELATIVE, USER_CFG},
    spec::Bootloader,
};

fn list_erofs_images(sysroot: &Dir) -> Result<Vec<String>> {
    let images_dir = sysroot
        .open_dir("composefs/images")
        .context("Opening images dir")?;

    let mut images = vec![];

    for entry in images_dir.entries_utf8()? {
        let entry = entry?;
        let name = entry.file_name()?;
        images.push(name);
    }

    Ok(images)
}

/// Get all Type1/Type2 bootloader entries
///
/// # Returns
/// The fsverity of EROFS images corresponding to boot entries
fn list_bootloader_entries() -> Result<Vec<String>> {
    let bootloader = get_bootloader()?;

    let entries = match bootloader {
        Bootloader::Grub => {
            let boot_dir = Dir::open_ambient_dir("/sysroot/boot", ambient_authority())
                .context("Opening boot dir")?;

            // Grub entries are always in boot
            let grub_dir = boot_dir.open_dir("grub2").context("Opening grub dir")?;

            if grub_dir.exists(USER_CFG) {
                // Grub UKI
                let mut s = String::new();
                let boot_entries = get_sorted_grub_uki_boot_entries(&boot_dir, &mut s)?;

                boot_entries
                    .into_iter()
                    .map(|entry| entry.get_verity())
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                // Type1 Entry
                let boot_entries = get_sorted_type1_boot_entries(&boot_dir, true)?;

                boot_entries
                    .into_iter()
                    .map(|entry| entry.get_verity())
                    .collect::<Result<Vec<_>, _>>()?
            }
        }

        Bootloader::Systemd => {
            let device = get_sysroot_parent_dev()?;
            let (esp_part, ..) = get_esp_partition(&device)?;
            let esp_mount = mount_esp(&esp_part)?;

            let boot_entries = get_sorted_type1_boot_entries(&esp_mount.fd, true)?;

            boot_entries
                .into_iter()
                .map(|entry| entry.get_verity())
                .collect::<Result<Vec<_>, _>>()?
        }
    };

    Ok(entries)
}

fn list_state_dirs(sysroot: &Dir) -> Result<Vec<String>> {
    let state = sysroot
        .open_dir(STATE_DIR_RELATIVE)
        .context("Opening state dir")?;

    let mut dirs = vec![];

    for dir in state.entries_utf8()? {
        let dir = dir?;

        if dir.file_type()?.is_file() {
            continue;
        }

        dirs.push(dir.file_name()?);
    }

    Ok(dirs)
}

/// Deletes objects in sysroot/composefs/objects that are not being referenced by any of the
/// present EROFS images
///
/// We do not delete streams though
pub(crate) fn gc_objects(sysroot: &Dir) -> Result<()> {
    // Get all the objects referenced by all available images
    let obj_refs = get_image_objects(sysroot, None)?;

    // List all objects in the objects directory
    let objects_dir = sysroot
        .open_dir("composefs/objects")
        .context("Opening objects dir")?;

    for dir_name in 0x0..=0xff {
        let dir = objects_dir
            .open_dir_optional(dir_name.to_string())
            .with_context(|| format!("Opening {dir_name}"))?;

        let Some(dir) = dir else {
            continue;
        };

        for entry in dir.entries_utf8()? {
            let entry = entry?;
            let filename = entry.file_name()?;

            let id = Sha512HashValue::from_object_dir_and_basename(dir_name, filename.as_bytes())?;

            // If this object is not referenced by any image, delete it
            if !obj_refs.other_depl.contains(&id) {
                tracing::trace!("Removed unreferenced object: {filename}");

                entry
                    .remove_file()
                    .with_context(|| format!("Removing object {filename}"))?;
            }
        }
    }

    Ok(())
}

/// 1. List all bootloader entries
/// 2. List all EROFS images
/// 3. List all state directories
/// 4. List staged depl if any
///
/// If bootloader entry B1 doesn't exist, but EROFS image B1 does exist, then delete the image and
/// perform GC
///
/// Similarly if EROFS image B1 doesn't exist, but state dir does, then delete the state dir and
/// perform GC
pub(crate) async fn composefs_gc() -> Result<()> {
    let host = composefs_deployment_status().await?;
    let booted_cfs = host.require_composefs_booted()?;

    let sysroot =
        Dir::open_ambient_dir("/sysroot", ambient_authority()).context("Opening sysroot")?;

    let bootloader_entries = list_bootloader_entries()?;
    let images = list_erofs_images(&sysroot)?;

    // Collect the deployments that have an image but no bootloader entry
    let img_bootloader_diff = images
        .iter()
        .filter(|i| !bootloader_entries.contains(i))
        .collect::<Vec<_>>();

    let staged = &host.status.staged;

    if img_bootloader_diff.contains(&&booted_cfs.verity) {
        anyhow::bail!(
            "Inconsistent state. Booted entry '{}' found for cleanup",
            booted_cfs.verity
        )
    }

    for verity in &img_bootloader_diff {
        tracing::debug!("Cleaning up orphaned image: {verity}");

        delete_staged(staged)?;
        delete_image(&sysroot, verity)?;
        delete_state_dir(&sysroot, verity)?;
    }

    let state_dirs = list_state_dirs(&sysroot)?;

    // Collect all the deployments that have no image but have a state dir
    // This for the case where the gc was interrupted after deleting the image
    let state_img_diff = state_dirs
        .iter()
        .filter(|s| !images.contains(s))
        .collect::<Vec<_>>();

    for verity in &state_img_diff {
        tracing::debug!("Cleaning up orphaned state directory: {verity}");

        delete_staged(staged)?;
        delete_state_dir(&sysroot, verity)?;
    }

    // Run garbage collection on objects after deleting images
    gc_objects(&sysroot)?;

    Ok(())
}
