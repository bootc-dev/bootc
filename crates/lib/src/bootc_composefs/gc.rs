//! This module handles the case when deleting a deployment fails midway
//!
//! There could be the following cases (See ./delete.rs:delete_composefs_deployment):
//! - We delete the bootloader entry but fail to delete image
//! - We delete bootloader + image but fail to delete the state/unrefenced objects etc

use anyhow::{Context, Result};
use cap_std_ext::{cap_std::fs::Dir, dirext::CapStdExtDirExt};
use cfsctl::composefs;
use cfsctl::composefs_boot;
use cfsctl::composefs_oci;
use composefs::repository::GcResult;
use composefs_boot::bootloader::EFI_EXT;

use crate::{
    bootc_composefs::{
        boot::{BOOTC_UKI_DIR, BootType, get_type1_dir_name, get_uki_addon_dir_name, get_uki_name},
        delete::{delete_staged, delete_state_dir},
        repo::bootc_tag_for_manifest,
        state::read_origin,
        status::{get_composefs_status, list_bootloader_entries},
    },
    composefs_consts::{
        BOOTC_TAG_PREFIX, ORIGIN_KEY_IMAGE, ORIGIN_KEY_MANIFEST_DIGEST, STATE_DIR_RELATIVE,
        TYPE1_BOOT_DIR_PREFIX, UKI_NAME_PREFIX,
    },
    store::{BootedComposefs, Storage},
};

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

    // Identify orphaned deployments: state dirs or bootloader entries
    // that don't correspond to a live deployment. EROFS images in
    // composefs/images/ are NOT managed here — repo.gc() handles those
    // via the tag→manifest→config→image ref chain.
    let state_dirs = list_state_dirs(&sysroot)?;

    let staged = &host.status.staged;

    // State dirs without a bootloader entry are from interrupted deployments.
    let orphaned_state_dirs: Vec<_> = state_dirs
        .iter()
        .filter(|s| !bootloader_entries.contains(s))
        .collect();

    // Bootloader entries without a state dir are from interrupted cleanups.
    let orphaned_boot_entries: Vec<_> = bootloader_entries
        .iter()
        .filter(|b| !state_dirs.contains(b))
        .collect();

    let all_orphans: Vec<_> = orphaned_state_dirs
        .iter()
        .chain(orphaned_boot_entries.iter())
        .copied()
        .collect();

    if all_orphans.contains(&&booted_cfs_status.verity) {
        anyhow::bail!(
            "Inconsistent state. Booted entry '{}' found for cleanup",
            booted_cfs_status.verity
        )
    }

    for verity in &orphaned_state_dirs {
        tracing::debug!("Cleaning up orphaned state dir: {verity}");
        delete_staged(staged, &all_orphans, dry_run)?;
        delete_state_dir(&sysroot, verity, dry_run)?;
    }

    for verity in &orphaned_boot_entries {
        tracing::debug!("Cleaning up orphaned bootloader entry: {verity}");
        delete_staged(staged, &all_orphans, dry_run)?;
    }

    // Collect the set of manifest digests referenced by live deployments,
    // and track EROFS image verities as fallback additional_roots for
    // deployments that predate the manifest→image link.
    let mut live_manifest_digests = Vec::new();
    let mut additional_roots = Vec::new();

    for deployment in host.list_deployments() {
        let verity = &deployment.require_composefs()?.verity;

        // Skip deployments that are already being GC'd.
        if all_orphans.contains(&verity) {
            continue;
        }

        // Keep the EROFS image as an additional root until all deployments
        // have manifest→image refs. Once a deployment is pulled with the
        // new code, its EROFS image is reachable from the manifest and
        // this entry becomes redundant (but harmless).
        additional_roots.push(verity.clone());

        if let Some(ini) = read_origin(sysroot, verity)? {
            if let Some(manifest_digest) =
                ini.get::<String>(ORIGIN_KEY_IMAGE, ORIGIN_KEY_MANIFEST_DIGEST)
            {
                live_manifest_digests.push(manifest_digest);
            } else {
                tracing::warn!(
                    "Deployment {verity} has no manifest_digest in origin; \
                     OCI manifest/config metadata is unprotected from GC"
                );
            }
        }
    }

    // Migration: ensure every live deployment has a bootc-owned tag.
    // Deployments from before the tag-based GC won't have tags yet;
    // create them now so their OCI metadata survives this GC cycle.
    let existing_tags = composefs_oci::list_refs(&*booted_cfs.repo)
        .context("Listing OCI tags in composefs repo")?;

    for manifest_digest in &live_manifest_digests {
        let expected_tag = bootc_tag_for_manifest(manifest_digest);
        let has_tag = existing_tags
            .iter()
            .any(|(tag_name, _)| tag_name == &expected_tag);
        if !has_tag {
            tracing::info!("Creating missing bootc tag for live deployment: {expected_tag}");
            if !dry_run {
                composefs_oci::tag_image(&*booted_cfs.repo, manifest_digest, &expected_tag)
                    .with_context(|| format!("Creating migration tag {expected_tag}"))?;
            }
        }
    }

    // Re-read tags after potential migration.
    let all_tags = composefs_oci::list_refs(&*booted_cfs.repo)
        .context("Listing OCI tags in composefs repo")?;

    for (tag_name, manifest_digest) in &all_tags {
        if !tag_name.starts_with(BOOTC_TAG_PREFIX) {
            // Not a bootc-owned tag; leave it alone (could be an app image).
            continue;
        }

        if !live_manifest_digests.iter().any(|d| d == manifest_digest) {
            tracing::debug!("Removing unreferenced bootc tag: {tag_name}");
            if !dry_run {
                composefs_oci::untag_image(&*booted_cfs.repo, tag_name)
                    .with_context(|| format!("Removing tag {tag_name}"))?;
            }
        }
    }

    let additional_roots = additional_roots
        .iter()
        .map(|x| x.as_str())
        .collect::<Vec<_>>();

    // Run garbage collection. Tags root the OCI metadata chain
    // (manifest → config → layers). The additional_roots protect EROFS
    // images for deployments that predate the manifest→image link;
    // once all deployments have been pulled with the new code, these
    // become redundant.
    let gc_result = if dry_run {
        booted_cfs.repo.gc_dry_run(&additional_roots)?
    } else {
        booted_cfs.repo.gc(&additional_roots)?
    };

    Ok(gc_result)
}
