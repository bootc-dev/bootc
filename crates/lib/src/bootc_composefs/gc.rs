//! This module handles the case when deleting a deployment fails midway
//!
//! There could be the following cases (See ./delete.rs:delete_composefs_deployment):
//! - We delete the bootloader entry but fail to delete image
//! - We delete bootloader + image but fail to delete the state/unrefenced objects etc

use anyhow::{Context, Result};
use cap_std_ext::{cap_std::fs::Dir, dirext::CapStdExtDirExt};
use composefs::repository::GcResult;
use composefs_boot::bootloader::EFI_EXT;

use crate::{
    bootc_composefs::{
        boot::{BOOTC_UKI_DIR, BootType, get_type1_dir_name, get_uki_addon_dir_name, get_uki_name},
        delete::{delete_image, delete_staged, delete_state_dir},
        status::{get_composefs_status, get_imginfo, list_bootloader_entries},
    },
    composefs_consts::{STATE_DIR_RELATIVE, TYPE1_BOOT_DIR_PREFIX, UKI_NAME_PREFIX},
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

type BootBinary = (BootType, String);

/// Collect all BLS Type1 boot binaries and UKI binaries by scanning filesystem
///
/// Returns a vector of binary type (UKI/Type1) + name of all boot binaries
#[fn_error_context::context("Collecting boot binaries")]
fn collect_boot_binaries(storage: &Storage) -> Result<Vec<BootBinary>> {
    let mut boot_binaries = Vec::new();
    let boot_dir = storage.bls_boot_binaries_dir()?;
    let esp = storage.require_esp()?;

    // Scan for UKI binaries in EFI/Linux/bootc
    collect_uki_binaries(&esp.fd, &mut boot_binaries)?;

    // Scan for Type1 boot binaries (kernels + initrds) in `boot_dir`
    // depending upon whether systemd-boot is being used, or grub
    collect_type1_boot_binaries(&boot_dir, &mut boot_binaries)?;

    Ok(boot_binaries)
}

/// Scan for UKI binaries in EFI/Linux/bootc
#[fn_error_context::context("Collecting UKI binaries")]
fn collect_uki_binaries(boot_dir: &Dir, boot_binaries: &mut Vec<BootBinary>) -> Result<()> {
    let Ok(Some(efi_dir)) = boot_dir.open_dir_optional(BOOTC_UKI_DIR) else {
        return Ok(());
    };

    for entry in efi_dir.entries_utf8()? {
        let entry = entry?;
        let name = entry.file_name()?;

        let Some(verity) = name.strip_prefix(UKI_NAME_PREFIX) else {
            continue;
        };

        if name.ends_with(EFI_EXT) {
            boot_binaries.push((BootType::Uki, verity.into()));
        }
    }

    Ok(())
}

/// Scan for Type1 boot binaries (kernels + initrds) by looking for directories with
/// that start with bootc_composefs-
///
/// Strips the prefix and returns the rest of the string
#[fn_error_context::context("Collecting Type1 boot binaries")]
fn collect_type1_boot_binaries(boot_dir: &Dir, boot_binaries: &mut Vec<BootBinary>) -> Result<()> {
    for entry in boot_dir.entries_utf8()? {
        let entry = entry?;
        let dir_name = entry.file_name()?;

        if !entry.file_type()?.is_dir() {
            continue;
        }

        let Some(verity) = dir_name.strip_prefix(TYPE1_BOOT_DIR_PREFIX) else {
            continue;
        };

        // The directory name starts with our custom prefix
        boot_binaries.push((BootType::Bls, verity.to_string()));
    }

    Ok(())
}

#[fn_error_context::context("Deleting kernel and initrd")]
fn delete_kernel_initrd(storage: &Storage, dir_to_delete: &str, dry_run: bool) -> Result<()> {
    tracing::debug!("Deleting Type1 entry {dir_to_delete}");

    if dry_run {
        return Ok(());
    }

    let boot_dir = storage.bls_boot_binaries_dir()?;

    boot_dir
        .remove_dir_all(dir_to_delete)
        .with_context(|| anyhow::anyhow!("Deleting {dir_to_delete}"))
}

/// Deletes the UKI `uki_id` and any addons specific to it
#[fn_error_context::context("Deleting UKI and UKI addons {uki_id}")]
fn delete_uki(storage: &Storage, uki_id: &str, dry_run: bool) -> Result<()> {
    let esp_mnt = storage.require_esp()?;

    // NOTE: We don't delete global addons here
    // Which is fine as global addons don't belong to any single deployment
    let uki_dir = esp_mnt.fd.open_dir(BOOTC_UKI_DIR)?;

    for entry in uki_dir.entries_utf8()? {
        let entry = entry?;
        let entry_name = entry.file_name()?;

        // The actual UKI PE binary
        if entry_name == get_uki_name(uki_id) {
            tracing::debug!("Deleting UKI: {}", entry_name);

            if dry_run {
                continue;
            }

            entry.remove_file().context("Deleting UKI")?;
        } else if entry_name == get_uki_addon_dir_name(uki_id) {
            // Addons dir
            tracing::debug!("Deleting UKI addons directory: {}", entry_name);

            if dry_run {
                continue;
            }

            uki_dir
                .remove_dir_all(entry_name)
                .context("Deleting UKI addons dir")?;
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
//
// Cases
// - BLS Entries
//      - On upgrade/switch, if only two are left, the staged and the current, then no GC
//          - If there are three - rollback, booted and staged, GC the rollback, so the current
//          becomes rollback
#[fn_error_context::context("Running composefs garbage collection")]
pub(crate) async fn composefs_gc(
    storage: &Storage,
    booted_cfs: &BootedComposefs,
    dry_run: bool,
) -> Result<GcResult> {
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

    let bootloader_entries = list_bootloader_entries(storage)?;
    let boot_binaries = collect_boot_binaries(storage)?;

    tracing::debug!("bootloader_entries: {bootloader_entries:?}");
    tracing::debug!("boot_binaries: {boot_binaries:?}");

    // Bootloader entry is deleted, but the binary (UKI/kernel+initrd) still exists
    let unreferenced_boot_binaries = boot_binaries
        .iter()
        .filter(|bin_path| {
            // We reuse kernel + initrd if they're the same for two deployments
            // We don't want to delete the (being deleted) deployment's kernel + initrd
            // if it's in use by any other deployment
            //
            // filter the ones that are not referenced by any bootloader entry
            !bootloader_entries
                .iter()
                .any(|boot_entry| bin_path.1 == *boot_entry)
        })
        .collect::<Vec<_>>();

    tracing::debug!("unreferenced_boot_binaries: {unreferenced_boot_binaries:?}");

    if unreferenced_boot_binaries
        .iter()
        .find(|be| be.1 == booted_cfs_status.verity)
        .is_some()
    {
        anyhow::bail!(
            "Inconsistent state. Booted binaries '{}' found for cleanup",
            booted_cfs_status.verity
        )
    }

    for (ty, verity) in unreferenced_boot_binaries {
        match ty {
            BootType::Bls => delete_kernel_initrd(storage, &get_type1_dir_name(verity), dry_run)?,
            BootType::Uki => delete_uki(storage, verity, dry_run)?,
        }
    }

    let images = list_erofs_images(&sysroot)?;

    // Collect the deployments that have an image but no bootloader entry
    // and vice versa
    let img_bootloader_diff = images
        .iter()
        .filter(|i| !bootloader_entries.contains(i))
        .chain(bootloader_entries.iter().filter(|b| !images.contains(b)))
        .collect::<Vec<_>>();

    tracing::debug!("img_bootloader_diff: {img_bootloader_diff:#?}");

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

    // Now we GC the unrefenced objects in composefs repo
    let mut additional_roots = vec![];

    for deployment in host.list_deployments() {
        let verity = &deployment.require_composefs()?.verity;

        // These need to be GC'd
        if img_bootloader_diff.contains(&verity) || state_img_diff.contains(&verity) {
            continue;
        }

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

    Ok(gc_result)
}
