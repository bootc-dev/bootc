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
use composefs::fsverity::FsVerityHashValue;
use composefs::repository::GcResult;
use composefs_boot::bootloader::EFI_EXT;

use crate::{
    bootc_composefs::{
        boot::{BOOTC_UKI_DIR, BootType, get_type1_dir_name, get_uki_addon_dir_name, get_uki_name},
        delete::{delete_staged, delete_state_dir},
        repo::bootc_tag_for_manifest,
        state::read_origin,
        status::{BootloaderEntry, get_composefs_status, list_bootloader_entries},
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

        let Some(efi_name_no_prefix) = name.strip_prefix(UKI_NAME_PREFIX) else {
            continue;
        };

        if let Some(verity) = efi_name_no_prefix.strip_suffix(EFI_EXT) {
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

/// Find boot binaries on disk that are not referenced by any bootloader entry.
///
/// We compare against `boot_artifact_name` (the directory/file name on disk)
/// rather than `fsverity` (the composefs= cmdline digest), because a shared
/// entry's directory name may belong to a different deployment than the one
/// whose composefs digest is in the BLS options line.
fn unreferenced_boot_binaries<'a>(
    boot_binaries: &'a [BootBinary],
    bootloader_entries: &[BootloaderEntry],
) -> Vec<&'a BootBinary> {
    boot_binaries
        .iter()
        .filter(|bin| {
            !bootloader_entries
                .iter()
                .any(|entry| entry.boot_artifact_name == bin.1)
        })
        .collect()
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

    let unreferenced_boot_binaries =
        unreferenced_boot_binaries(&boot_binaries, &bootloader_entries);

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
        .filter(|s| !bootloader_entries.iter().any(|entry| &entry.fsverity == *s))
        .collect();

    // Bootloader entries without a state dir are from interrupted cleanups.
    let orphaned_boot_entries: Vec<_> = bootloader_entries
        .iter()
        .map(|entry| &entry.fsverity)
        .filter(|verity| !state_dirs.contains(verity))
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
    let mut live_manifest_digests: Vec<composefs_oci::OciDigest> = Vec::new();
    let mut additional_roots = Vec::new();
    // Container image names for containers-storage pruning.
    let mut live_container_images: std::collections::HashSet<String> = Default::default();

    // Read existing tags before the deployment loop so we can search
    // them for deployments that lack manifest_digest in their origin.
    let existing_tags = composefs_oci::list_refs(&*booted_cfs.repo)
        .context("Listing OCI tags in composefs repo")?;

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
            // Collect the container image name for containers-storage GC.
            if let Some(container_ref) =
                ini.get::<String>("origin", ostree_ext::container::deploy::ORIGIN_CONTAINER)
            {
                // Parse the ostree image reference to extract the bare image name
                // (e.g. "quay.io/foo:tag" from "ostree-unverified-image:docker://quay.io/foo:tag")
                let image_name = container_ref
                    .parse::<ostree_ext::container::OstreeImageReference>()
                    .map(|r| r.imgref.name)
                    .unwrap_or_else(|_| container_ref.clone());
                live_container_images.insert(image_name);
            }

            if let Some(manifest_digest_str) =
                ini.get::<String>(ORIGIN_KEY_IMAGE, ORIGIN_KEY_MANIFEST_DIGEST)
            {
                let digest: composefs_oci::OciDigest = manifest_digest_str
                    .parse()
                    .with_context(|| format!("Parsing manifest digest {manifest_digest_str}"))?;
                live_manifest_digests.push(digest);
            } else {
                // Pre-OCI-metadata deployment: search tagged manifests
                // for one whose config links to this EROFS image.
                let mut found_manifest = false;
                for (_, ref_digest) in &existing_tags {
                    if let Ok(img) = composefs_oci::oci_image::OciImage::open(
                        &*booted_cfs.repo,
                        ref_digest,
                        None,
                    ) {
                        if let Some(img_ref) = img.image_ref() {
                            if img_ref.to_hex() == *verity {
                                tracing::info!(
                                    "Deployment {verity} has no manifest_digest in origin; \
                                     found matching manifest {ref_digest} via image_ref"
                                );
                                live_manifest_digests.push(ref_digest.clone());
                                found_manifest = true;
                                break;
                            }
                        }
                    }
                }
                if !found_manifest {
                    tracing::warn!(
                        "Deployment {verity} has no manifest_digest in origin \
                         and no tagged manifest references it; \
                         EROFS image is protected but OCI metadata may be collected"
                    );
                }
            }
        }
    }

    // Migration: ensure every live deployment has a bootc-owned tag.
    // Deployments from before the tag-based GC won't have tags yet;
    // create them now so their OCI metadata survives this GC cycle.

    for manifest_digest in &live_manifest_digests {
        let expected_tag = bootc_tag_for_manifest(&manifest_digest.to_string());
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

    // Prune containers-storage: remove images not backing any live deployment.
    if !dry_run && !live_container_images.is_empty() {
        let subpath = crate::podstorage::CStorage::subpath();
        if sysroot.try_exists(&subpath).unwrap_or(false) {
            let run = Dir::open_ambient_dir("/run", cap_std_ext::cap_std::ambient_authority())?;
            let imgstore = crate::podstorage::CStorage::create(&sysroot, &run, None)?;
            let roots: std::collections::HashSet<&str> =
                live_container_images.iter().map(|s| s.as_str()).collect();
            let pruned = imgstore.prune_except_roots(&roots).await?;
            if !pruned.is_empty() {
                tracing::info!("Pruned {} images from containers-storage", pruned.len());
            }
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootc_composefs::status::list_type1_entries;
    use crate::testutils::{ChangeType, TestRoot};

    /// Reproduce the shared-entry GC bug from issue #2102.
    ///
    /// Scenario with both shared and non-shared kernels:
    ///
    /// 1. Install deployment A (kernel K1, boot dir "A")
    /// 2. Upgrade to B, same kernel → shares A's boot dir
    /// 3. Upgrade to C, new kernel K2 → gets its own boot dir "C"
    /// 4. Upgrade to D, same kernel as C → shares C's boot dir
    ///
    /// After GC of A (the creator of boot dir used by B):
    /// - A's boot dir must still exist (B references it)
    /// - C's boot dir must still exist (D references it)
    ///
    /// The old code compared `fsverity` instead of `boot_artifact_name`,
    /// which would incorrectly mark A's boot dir as unreferenced once A's
    /// BLS entry is gone — even though B still points its linux/initrd
    /// paths at A's directory.
    #[test]
    fn test_gc_shared_boot_binaries_not_deleted() -> anyhow::Result<()> {
        let mut root = TestRoot::new()?;
        let digest_a = root.current().verity.clone();

        // B shares A's kernel (userspace-only change)
        root.upgrade(1, ChangeType::Userspace)?;

        // C gets a new kernel
        root.upgrade(2, ChangeType::Kernel)?;
        let digest_c = root.current().verity.clone();

        // D shares C's kernel (userspace-only change)
        root.upgrade(3, ChangeType::Userspace)?;
        let digest_d = root.current().verity.clone();

        // Now GC deployment A — the one that *created* the shared boot dir
        root.gc_deployment(&digest_a)?;

        // At this point only C (secondary) and D (primary) have BLS entries.
        // But A's boot binary directory is still on disk because B used to
        // share it and we haven't cleaned up boot binaries yet — that's
        // what the GC filter decides.
        let boot_dir = root.boot_dir()?;

        // Collect what's on disk: two boot dirs (A's and C's)
        let mut on_disk = Vec::new();
        collect_type1_boot_binaries(&boot_dir, &mut on_disk)?;
        assert_eq!(
            on_disk.len(),
            2,
            "should have A's and C's boot dirs on disk"
        );

        // Collect what the BLS entries reference
        let bls_entries = list_type1_entries(&boot_dir)?;
        assert_eq!(bls_entries.len(), 2, "D (primary) + C (secondary)");

        // The fix: unreferenced_boot_binaries uses boot_artifact_name.
        // D's boot_artifact_name points to C's dir, C's points to itself.
        // A's boot dir is NOT referenced by any current BLS entry's
        // boot_artifact_name (B was the one referencing it, and B is no
        // longer in the BLS entries either).
        let unreferenced = unreferenced_boot_binaries(&on_disk, &bls_entries);

        // A's boot dir IS unreferenced (only B used it, and B isn't in BLS anymore)
        assert_eq!(unreferenced.len(), 1);
        assert_eq!(unreferenced[0].1, digest_a);

        // C's boot dir is still referenced (by both C and D via boot_artifact_name)
        assert!(
            !unreferenced.iter().any(|b| b.1 == digest_c),
            "C's boot dir must not be unreferenced"
        );

        // Now the more dangerous scenario: GC C, the creator of the boot
        // dir that D shares. After this, remaining deployments are [B, D].
        // B still shares A's boot dir, D still shares C's boot dir.
        root.gc_deployment(&digest_c)?;

        let mut on_disk_2 = Vec::new();
        collect_type1_boot_binaries(&root.boot_dir()?, &mut on_disk_2)?;
        // A's dir + C's dir still on disk (boot binary cleanup hasn't run)
        assert_eq!(on_disk_2.len(), 2);

        let bls_entries_2 = list_type1_entries(&root.boot_dir()?)?;
        // D (primary) + B (secondary)
        assert_eq!(bls_entries_2.len(), 2);

        let entry_d = bls_entries_2
            .iter()
            .find(|e| e.fsverity == digest_d)
            .unwrap();
        assert_eq!(
            entry_d.boot_artifact_name, digest_c,
            "D shares C's boot dir"
        );

        let unreferenced_2 = unreferenced_boot_binaries(&on_disk_2, &bls_entries_2);

        // Both boot dirs are still referenced:
        // - A's dir via B's boot_artifact_name
        // - C's dir via D's boot_artifact_name
        assert!(
            unreferenced_2.is_empty(),
            "no boot dirs should be unreferenced when both are shared"
        );

        // Prove the old buggy logic would fail: if we compared fsverity
        // instead of boot_artifact_name, BOTH dirs would be wrongly
        // unreferenced. Neither A nor C has a BLS entry with matching
        // fsverity — only B (verity=B) and D (verity=D) exist, but their
        // boot dirs are named after A and C respectively.
        let buggy_unreferenced: Vec<_> = on_disk_2
            .iter()
            .filter(|bin| !bls_entries_2.iter().any(|e| e.fsverity == bin.1))
            .collect();
        assert_eq!(
            buggy_unreferenced.len(),
            2,
            "old fsverity-based logic would incorrectly GC both boot dirs"
        );

        Ok(())
    }

    /// Verify that list_type1_entries correctly parses legacy (unprefixed) BLS
    /// entries. This is the code path that composefs_gc actually uses to find
    /// bootloader entries, so it's critical that it handles both layouts.
    #[test]
    fn test_list_type1_entries_handles_legacy_bls() -> anyhow::Result<()> {
        let mut root = TestRoot::new_legacy()?;
        let digest_a = root.current().verity.clone();

        root.upgrade(1, ChangeType::Userspace)?;
        let digest_b = root.current().verity.clone();

        let boot_dir = root.boot_dir()?;
        let bls_entries = list_type1_entries(&boot_dir)?;

        assert_eq!(bls_entries.len(), 2, "Should find both BLS entries");

        // boot_artifact_name should return the raw digest (no prefix)
        // because the legacy entries don't have the prefix
        for entry in &bls_entries {
            assert_eq!(
                entry.boot_artifact_name, digest_a,
                "Both entries should reference A's boot dir (shared kernel)"
            );
        }

        // fsverity should differ between the two entries
        let verity_set: std::collections::HashSet<&str> =
            bls_entries.iter().map(|e| e.fsverity.as_str()).collect();
        assert!(verity_set.contains(digest_a.as_str()));
        assert!(verity_set.contains(digest_b.as_str()));

        Ok(())
    }

    /// Legacy (unprefixed) boot dirs are invisible to collect_type1_boot_binaries,
    /// which only looks for the `bootc_composefs-` prefix. This test verifies
    /// that the GC scanner does not see unprefixed directories.
    ///
    /// This is the problem that PR #2128 solves by migrating legacy entries
    /// to the prefixed format before any GC or status operations run.
    #[test]
    fn test_legacy_boot_dirs_invisible_to_gc_scanner() -> anyhow::Result<()> {
        let root = TestRoot::new_legacy()?;

        // The legacy layout creates a boot dir without the prefix
        let boot_dir = root.boot_dir()?;
        let mut on_disk = Vec::new();
        collect_type1_boot_binaries(&boot_dir, &mut on_disk)?;

        // collect_type1_boot_binaries requires the prefix — legacy dirs
        // are invisible to it
        assert!(
            on_disk.is_empty(),
            "Legacy (unprefixed) boot dirs should not be found by collect_type1_boot_binaries"
        );

        Ok(())
    }

    /// After migration from legacy to prefixed layout, GC should work
    /// correctly — the boot binary directories become visible and
    /// the BLS entries reference them properly.
    #[test]
    fn test_gc_works_after_legacy_migration() -> anyhow::Result<()> {
        let mut root = TestRoot::new_legacy()?;
        let digest_a = root.current().verity.clone();

        // B shares A's kernel (userspace-only change)
        root.upgrade(1, ChangeType::Userspace)?;

        // C gets a new kernel
        root.upgrade(2, ChangeType::Kernel)?;

        // Simulate the migration that PR #2128 performs
        root.migrate_to_prefixed()?;

        // Now GC should see both boot dirs
        let boot_dir = root.boot_dir()?;
        let mut on_disk = Vec::new();
        collect_type1_boot_binaries(&boot_dir, &mut on_disk)?;
        assert_eq!(on_disk.len(), 2, "Should see A's and C's boot dirs");

        // BLS entries should correctly reference boot artifact names
        let bls_entries = list_type1_entries(&boot_dir)?;
        assert_eq!(bls_entries.len(), 2);

        // No boot dirs should be unreferenced (all are in use)
        let unreferenced = unreferenced_boot_binaries(&on_disk, &bls_entries);
        assert!(
            unreferenced.is_empty(),
            "All boot dirs should be referenced after migration"
        );

        // GC deployment A (the one that created the shared boot dir)
        root.gc_deployment(&digest_a)?;

        let boot_dir = root.boot_dir()?;
        let bls_entries = list_type1_entries(&boot_dir)?;
        assert_eq!(bls_entries.len(), 2, "B (secondary) + C (primary)");

        let mut on_disk = Vec::new();
        collect_type1_boot_binaries(&boot_dir, &mut on_disk)?;
        assert_eq!(on_disk.len(), 2, "Both boot dirs still on disk");

        let unreferenced = unreferenced_boot_binaries(&on_disk, &bls_entries);
        // A's boot dir is still referenced by B
        assert!(
            unreferenced.is_empty(),
            "A's boot dir should still be referenced by B after migration"
        );

        Ok(())
    }

    /// Test the full upgrade cycle with shared kernels after migration:
    /// install (legacy) → migrate → upgrade → GC.
    ///
    /// This verifies that GC correctly handles a system that was originally
    /// installed with old bootc, migrated, and then upgraded with new bootc.
    #[test]
    fn test_gc_post_migration_upgrade_cycle() -> anyhow::Result<()> {
        let mut root = TestRoot::new_legacy()?;
        let digest_a = root.current().verity.clone();

        // B shares A's kernel (still legacy)
        root.upgrade(1, ChangeType::Userspace)?;

        // Simulate migration
        root.migrate_to_prefixed()?;

        // Now upgrade with new bootc (creates prefixed entries)
        root.upgrade(2, ChangeType::Kernel)?;
        let digest_c = root.current().verity.clone();

        // D shares C's kernel
        root.upgrade(3, ChangeType::Userspace)?;
        let digest_d = root.current().verity.clone();

        // GC all old deployments, keeping only C and D
        root.gc_deployment(&digest_a)?;

        let boot_dir = root.boot_dir()?;
        let mut on_disk = Vec::new();
        collect_type1_boot_binaries(&boot_dir, &mut on_disk)?;

        let bls_entries = list_type1_entries(&boot_dir)?;
        assert_eq!(bls_entries.len(), 2, "D (primary) + C (secondary)");

        let unreferenced = unreferenced_boot_binaries(&on_disk, &bls_entries);
        // A's boot dir is unreferenced (B is gone, only C and D remain)
        assert_eq!(
            unreferenced.len(),
            1,
            "A's boot dir should be unreferenced after GC of A and B is evicted"
        );
        assert_eq!(unreferenced[0].1, digest_a);

        // C's boot dir must still be referenced by D
        assert!(
            !unreferenced.iter().any(|b| b.1 == digest_c),
            "C's boot dir must still be referenced by D"
        );

        // Verify D shares C's boot dir
        let entry_d = bls_entries
            .iter()
            .find(|e| e.fsverity == digest_d)
            .expect("D should have a BLS entry");
        assert_eq!(
            entry_d.boot_artifact_name, digest_c,
            "D should share C's boot dir"
        );

        Ok(())
    }

    /// Test deep transitive sharing: A → B → C → D all share A's boot dir
    /// via successive userspace-only upgrades. When we GC A (the creator
    /// of the boot dir), the dir must be kept because the remaining
    /// deployments still reference it.
    ///
    /// This tests that boot_dir_verity propagates correctly through
    /// a chain of userspace-only upgrades and that the GC filter handles
    /// the case where no remaining deployment's fsverity matches the
    /// boot directory name.
    #[test]
    fn test_gc_deep_transitive_sharing_chain() -> anyhow::Result<()> {
        let mut root = TestRoot::new()?;
        let digest_a = root.current().verity.clone();

        // B, C, D all share A's kernel via userspace-only upgrades
        root.upgrade(1, ChangeType::Userspace)?;
        root.upgrade(2, ChangeType::Userspace)?;
        root.upgrade(3, ChangeType::Userspace)?;
        let digest_d = root.current().verity.clone();

        // Only one boot dir on disk (all share A's)
        let boot_dir = root.boot_dir()?;
        let mut on_disk = Vec::new();
        collect_type1_boot_binaries(&boot_dir, &mut on_disk)?;
        assert_eq!(on_disk.len(), 1, "All deployments share one boot dir");
        assert_eq!(on_disk[0].1, digest_a, "The boot dir belongs to A");

        // BLS entries: D (primary) + C (secondary), both referencing A's dir
        let bls_entries = list_type1_entries(&boot_dir)?;
        assert_eq!(bls_entries.len(), 2);
        for entry in &bls_entries {
            assert_eq!(
                entry.boot_artifact_name, digest_a,
                "All entries reference A's boot dir"
            );
        }

        // GC deployment A (the creator of the shared boot dir)
        root.gc_deployment(&digest_a)?;

        let boot_dir = root.boot_dir()?;
        let bls_entries = list_type1_entries(&boot_dir)?;
        // D (primary) + C (secondary) — A was already evicted from BLS
        assert_eq!(bls_entries.len(), 2);

        let mut on_disk = Vec::new();
        collect_type1_boot_binaries(&boot_dir, &mut on_disk)?;

        let unreferenced = unreferenced_boot_binaries(&on_disk, &bls_entries);
        assert!(
            unreferenced.is_empty(),
            "A's boot dir must stay — C and D still reference it"
        );

        // Now also GC B and C, leaving only D
        let digest_b = crate::testutils::fake_digest_version(1);
        let digest_c = crate::testutils::fake_digest_version(2);
        root.gc_deployment(&digest_b)?;
        root.gc_deployment(&digest_c)?;

        // D is the only deployment left
        let boot_dir = root.boot_dir()?;
        let bls_entries = list_type1_entries(&boot_dir)?;
        assert_eq!(bls_entries.len(), 1, "Only D remains");
        assert_eq!(bls_entries[0].fsverity, digest_d);
        assert_eq!(
            bls_entries[0].boot_artifact_name, digest_a,
            "D still references A's boot dir"
        );

        let mut on_disk = Vec::new();
        collect_type1_boot_binaries(&boot_dir, &mut on_disk)?;
        let unreferenced = unreferenced_boot_binaries(&on_disk, &bls_entries);
        assert!(
            unreferenced.is_empty(),
            "A's boot dir must survive — D is the last deployment and still uses it"
        );

        Ok(())
    }

    /// Verify that boot_artifact_info().1 (has_prefix) is the correct
    /// signal for identifying entries that need migration, and that the
    /// GC filter works correctly at each stage of the migration pipeline.
    ///
    /// This exercises the API that stage_bls_entry_changes() in PR #2128
    /// uses to decide which entries to migrate.
    #[test]
    fn test_boot_artifact_info_drives_migration_decisions() -> anyhow::Result<()> {
        use crate::bootc_composefs::status::get_sorted_type1_boot_entries;

        let mut root = TestRoot::new_legacy()?;
        let digest_a = root.current().verity.clone();

        root.upgrade(1, ChangeType::Userspace)?;
        root.upgrade(2, ChangeType::Kernel)?;

        // -- Pre-migration: all entries lack the prefix --
        let boot_dir = root.boot_dir()?;
        let raw_entries = get_sorted_type1_boot_entries(&boot_dir, true)?;
        assert_eq!(raw_entries.len(), 2);

        let needs_migration: Vec<_> = raw_entries
            .iter()
            .filter(|e| !e.boot_artifact_info().unwrap().1)
            .collect();
        assert_eq!(
            needs_migration.len(),
            2,
            "All legacy entries should need migration (has_prefix=false)"
        );

        // GC scanner can't see the boot dirs (no prefix on disk)
        let mut on_disk = Vec::new();
        collect_type1_boot_binaries(&boot_dir, &mut on_disk)?;
        assert!(on_disk.is_empty(), "Legacy dirs invisible before migration");

        // -- Migrate --
        root.migrate_to_prefixed()?;

        // -- Post-migration: all entries have the prefix --
        let boot_dir = root.boot_dir()?;
        let raw_entries = get_sorted_type1_boot_entries(&boot_dir, true)?;
        assert_eq!(raw_entries.len(), 2);

        let needs_migration: Vec<_> = raw_entries
            .iter()
            .filter(|e| !e.boot_artifact_info().unwrap().1)
            .collect();
        assert!(
            needs_migration.is_empty(),
            "No entries should need migration after migrate_to_prefixed()"
        );

        // GC scanner can now see the boot dirs
        let mut on_disk = Vec::new();
        collect_type1_boot_binaries(&boot_dir, &mut on_disk)?;
        assert_eq!(on_disk.len(), 2, "Both dirs visible after migration");

        // GC filter correctly identifies all dirs as referenced
        let bls_entries = list_type1_entries(&boot_dir)?;
        let unreferenced = unreferenced_boot_binaries(&on_disk, &bls_entries);
        assert!(
            unreferenced.is_empty(),
            "All dirs referenced after migration"
        );

        // -- Upgrade with new bootc (prefixed from creation) --
        root.upgrade(3, ChangeType::Kernel)?;

        let boot_dir = root.boot_dir()?;
        let raw_entries = get_sorted_type1_boot_entries(&boot_dir, true)?;
        // All entries (both migrated and new) should have the prefix
        for entry in &raw_entries {
            let (_, has_prefix) = entry.boot_artifact_info()?;
            assert!(
                has_prefix,
                "All entries should have prefix after migration + upgrade"
            );
        }

        // GC should now see 3 boot dirs: A's, C's (from upgrade 2), and
        // the new one from upgrade 3
        let mut on_disk = Vec::new();
        collect_type1_boot_binaries(&boot_dir, &mut on_disk)?;
        assert_eq!(on_disk.len(), 3, "Three boot dirs on disk");

        // Only 2 BLS entries (primary + secondary), so one dir is unreferenced
        let bls_entries = list_type1_entries(&boot_dir)?;
        assert_eq!(bls_entries.len(), 2);
        let unreferenced = unreferenced_boot_binaries(&on_disk, &bls_entries);
        assert_eq!(
            unreferenced.len(),
            1,
            "A's boot dir should be unreferenced (B evicted from BLS)"
        );
        assert_eq!(unreferenced[0].1, digest_a);

        Ok(())
    }
}
