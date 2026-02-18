//! This module handles the case when deleting a deployment fails midway
//!
//! There could be the following cases (See ./delete.rs:delete_composefs_deployment):
//! - We delete the bootloader entry but fail to delete image
//! - We delete bootloader + image but fail to delete the state/unrefenced objects etc

use anyhow::{Context, Result};
use cap_std_ext::cap_std::fs::Dir;

use crate::{
    bootc_composefs::{
        delete::{delete_image, delete_staged, delete_state_dir},
        status::{get_composefs_status, get_imginfo, list_bootloader_entries},
    },
    composefs_consts::STATE_DIR_RELATIVE,
    store::{BootedComposefs, Storage},
};

#[fn_error_context::context("Listing EROFS images")]
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

#[fn_error_context::context("Listing state directories")]
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
//
// Cases
// - BLS Entries
//      - On upgrade/switch, if only two are left, the staged and the current, then no GC
//          - If there are three, rollback, booted and staged, GC the rollback, so the current
//          becomes rollback
#[fn_error_context::context("Running composefs garbage collection")]
pub(crate) async fn composefs_gc(
    storage: &Storage,
    booted_cfs: &BootedComposefs,
    dry_run: bool,
) -> Result<()> {
    const COMPOSEFS_GC_JOURNAL_ID: &str = "3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7";

    tracing::info!(
        message_id = COMPOSEFS_GC_JOURNAL_ID,
        bootc.operation = "gc",
        bootc.current_deployment = booted_cfs.cmdline.digest,
        "Starting composefs garbage collection"
    );

    let host = get_composefs_status(storage, booted_cfs).await?;
    let booted_cfs_status = host.require_composefs_booted()?;

    let sysroot = &storage.physical_root;

    let bootloader_entries = list_bootloader_entries(&storage)?;
    let images = list_erofs_images(&sysroot)?;

    // Collect the deployments that have an image but no bootloader entry
    // and vice versa
    let img_bootloader_diff = images
        .iter()
        .filter(|i| !bootloader_entries.contains(i))
        .chain(bootloader_entries.iter().filter(|b| !images.contains(b)))
        .collect::<Vec<_>>();

    println!("img_bootloader_diff: {img_bootloader_diff:#?}");

    let staged = &host.status.staged;

    if img_bootloader_diff.contains(&&booted_cfs_status.verity) {
        anyhow::bail!(
            "Inconsistent state. Booted entry '{}' found for cleanup",
            booted_cfs_status.verity
        )
    }

    for verity in &img_bootloader_diff {
        tracing::debug!("Cleaning up orphaned image: {verity}");

        delete_staged(staged, &img_bootloader_diff, dry_run)?;
        delete_image(&sysroot, verity, dry_run)?;
        delete_state_dir(&sysroot, verity, dry_run)?;
    }

    let state_dirs = list_state_dirs(&sysroot)?;

    // Collect all the deployments that have no image but have a state dir
    // This for the case where the gc was interrupted after deleting the image
    let state_img_diff = state_dirs
        .iter()
        .filter(|s| !images.contains(s))
        .collect::<Vec<_>>();

    for verity in &state_img_diff {
        delete_staged(staged, &state_img_diff, dry_run)?;
        delete_state_dir(&sysroot, verity, dry_run)?;
    }

    let mut additional_roots = vec![];

    for deployment in host
        .status
        .staged
        .iter()
        .chain(host.status.booted.iter())
        .chain(host.status.rollback.iter())
        .chain(host.status.other_deployments.iter())
    {
        let verity = &deployment.require_composefs()?.verity;

        let image = get_imginfo(storage, verity, None).await?;
        let stream = format!("oci-config-{}", image.manifest.config().digest());

        additional_roots.push(verity.clone());
        additional_roots.push(stream);
    }

    let additional_roots = additional_roots
        .iter()
        .map(|x| x.as_str())
        .collect::<Vec<_>>();

    // Run garbage collection on objects after deleting images
    let gc_result = if dry_run {
        booted_cfs.repo.gc_dry_run(&additional_roots)?
    } else {
        booted_cfs.repo.gc(&additional_roots)?
    };

    if dry_run {
        println!("Dry run (no files deleted):");
    }

    println!(
        "Objects: {} removed ({} bytes)",
        gc_result.objects_removed, gc_result.objects_bytes
    );

    if gc_result.images_pruned > 0 || gc_result.streams_pruned > 0 {
        println!(
            "Pruned symlinks: {} images, {} streams",
            gc_result.images_pruned, gc_result.streams_pruned
        );
    }

    Ok(())
}
