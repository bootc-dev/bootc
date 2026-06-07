//! APIs for operating on container images in the bootc storage.
//!
//! ## Unified storage overview
//!
//! Unified storage makes OS image data simultaneously visible to three stores:
//! bootc-owned containers-storage (for `podman run` / Logically Bound Images),
//! the composefs object store (for boot-time EROFS overlay), and the ostree
//! repo (for deployment tracking).  See [`crate::store`] for the architectural
//! rationale and the reflink sharing model.
//!
//! Whether unified storage is active on a system is recorded in
//! `composefs/bootc.json` ([`crate::store::BootcRepoMeta`]).  The flag is set
//! by `bootc image set-unified full` or at install time via the `[install.storage]`
//! config key.
//!
//! ## `bootc image set-unified full`
//!
//! `set_unified_entrypoint` onboards the ostree backend via `set_unified`.
//! Composefs-native onboarding is provided separately by the
//! composefs-native feature.
//!
//! After this, all subsequent upgrades/switches route through the forward
//! unified pipeline (cstorage → composefs reflink).  On a reflink-capable
//! filesystem (XFS, btrfs) each layer blob is block-shared via `FICLONE`; on
//! ext4 the `enabled-with-copy` config value allows a byte-copy fallback.
//!
//! ## Reconcile: the non-unified → unified migration bridge
//!
//! Once unified storage is enabled, the steady-state pull on a composefs system
//! is the *forward* path: every image is pulled into containers-storage first
//! and then reflinked into the composefs object store (see
//! [`crate::bootc_composefs::repo`]).  In steady state, therefore,
//! containers-storage is never missing a deployed image.
//!
//! Reconcile exists for the *transition*: a system that ran **non-unified**
//! before the flag was set pulled its deployments directly into the composefs
//! repo (via `pull_composefs_direct`), so its existing booted/rollback/staged
//! images are present in composefs but were never written to
//! containers-storage.  `reconcile_unified_storage` backfills exactly those
//! images, taking the *reverse* direction (composefs → containers-storage).
//!
//! The authoritative set of images to backfill is derived from the **bootloader
//! entries** (via `list_bootloader_entries` / `get_imginfo`), not from the
//! ostree deployment state directories, which can drift.  Images are matched
//! by their OCI **config digest** — a stable identifier that survives layer
//! recompression.
//!
//! `reconcile_unified_storage` iterates over all composefs-tagged images,
//! identifies those that are pinned (live in a bootloader entry) but missing
//! from containers-storage, and calls `repair_image_to_containers_storage` for
//! each one.  The export preserves the config digest exactly — each layer is
//! replayed byte-for-byte from the splitstream via `SplitStreamReader::cat()`
//! and the original config JSON is written verbatim, so the config digest
//! (which containers-storage uses as its image ID) is identical.
//!
//! ## `bootc image sync`
//!
//! `sync_entrypoint` is the user-facing entry point for a manual reconcile.
//! It is a no-op on systems where unified storage is not enabled.
//!
//! ## `bootc internals fsck images`
//!
//! `fsck_images` / `inspect_unified_storage` perform a read-only consistency
//! check: for each composefs-tagged image, check whether it is present in
//! containers-storage and whether it is referenced by a live bootloader entry.
//! `--repair` calls `reconcile_unified_storage` to fix any gaps found.

use anyhow::{Context, Result, bail};
use bootc_utils::CommandRunExt;
use cap_std_ext::cap_std::{self, fs::Dir};
use clap::ValueEnum;
use comfy_table::{Table, presets::NOTHING};
use composefs_ctl::composefs_oci;
use fn_error_context::context;
use ostree_ext::container::{ImageReference, Transport};
use serde::{Deserialize, Serialize};

use crate::{
    boundimage::query_bound_images,
    cli::{ImageListFormat, ImageListType},
    composefs_consts::BOOTC_TAG_PREFIX,
    podstorage::CStorage,
    spec::Host,
    store::Storage,
    utils::async_task_with_spinner,
};

/// The name of the image we push to containers-storage if nothing is specified.
pub(crate) const IMAGE_DEFAULT: &str = "localhost/bootc";

/// Check if an image exists in the default containers-storage (podman storage).
///
/// TODO: Using exit codes to check image existence is not ideal. We should use
/// the podman native libpod HTTP API to properly communicate with podman and
/// get structured responses.
async fn image_exists_in_host_storage(image: &str) -> Result<bool> {
    use tokio::process::Command as AsyncCommand;
    let mut cmd = AsyncCommand::new(bootc_utils::podman_bin());
    cmd.args(["image", "exists", image]);
    Ok(cmd.status().await?.success())
}

#[derive(Clone, Copy, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
enum ImageListTypeColumn {
    Host,
    Unified,
    /// Image is in bootc containers-storage but composefs import is incomplete
    /// or failed. Re-run `bootc upgrade` to complete the import.
    Partial,
    /// Image is bound in the composefs OCI repo (ostree↔composefs binding) but
    /// is not present in bootc's containers-storage (not visible to `podman run`).
    /// This is expected on systems installed with `--experimental-ostree-composefs-unified`.
    Bound,
    Logical,
}

impl std::fmt::Display for ImageListTypeColumn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_possible_value().unwrap().get_name().fmt(f)
    }
}

#[derive(Serialize)]
struct ImageOutput {
    image_type: ImageListTypeColumn,
    image: String,
    // TODO: Add hash, size, etc? Difficult because [`ostree_ext::container::store::list_images`]
    // only gives us the pullspec.
}

#[context("Listing host images")]
async fn list_host_images(sysroot: &crate::store::Storage) -> Result<Vec<ImageOutput>> {
    use crate::deploy::BindingState;

    let binding = crate::deploy::binding_state(sysroot)?;
    let mut result = Vec::new();
    if let Ok(ostree) = sysroot.get_ostree() {
        let repo = ostree.repo();
        let images = ostree_ext::container::store::list_images(&repo).context("Querying images")?;
        // On BoundOnly systems the ostree commits ARE the composefs-synthesized
        // bound images.  Relabel them as `Bound` (not `Host`) so they match the
        // expected type and to avoid a duplicate row: list_host_images_composefs
        // is skipped below for BoundOnly, so this is the sole source of those
        // entries.  On Disabled/Unified the original `Host` label is correct.
        let image_type = if matches!(binding, BindingState::BoundOnly) {
            ImageListTypeColumn::Bound
        } else {
            ImageListTypeColumn::Host
        };
        result.extend(
            images
                .into_iter()
                .map(|image| ImageOutput { image, image_type }),
        );
    }
    // For BoundOnly systems the ostree list above already emits every bound OS
    // image as `Bound`; calling list_host_images_composefs would re-enumerate
    // the same images from the composefs OCI repo and produce duplicate rows.
    // Skip it here; it is only needed for Unified (cstorage cross-ref) and
    // Disabled (legacy cstorage-only) paths.
    if !matches!(binding, BindingState::BoundOnly) {
        result.extend(list_host_images_composefs(sysroot).await?);
    }
    Ok(result)
}

#[context("Listing host images from containers-storage")]
async fn list_host_images_composefs(sysroot: &crate::store::Storage) -> Result<Vec<ImageOutput>> {
    use crate::deploy::BindingState;
    use composefs_ctl::composefs_oci::{self, OciImage};

    // Derive the binding tri-state.  Native composefs systems have no ostree
    // repo, so the repo-config binding signal reads false; absent a
    // BootcRepoMeta they resolve to Disabled and fall through to the standard
    // cstorage-only path below (a native system onboarded to cstorage instead
    // resolves to Unified via BootcRepoMeta).
    let state = crate::deploy::binding_state(sysroot)?;

    // BoundOnly: the OS image lives in the composefs repo but is NOT in
    // containers-storage.  Enumerate bootc-tagged composefs refs directly and
    // report each as `Bound`.  We skip the containers-storage path entirely
    // because it will be empty (or only contain LBIs).
    if matches!(state, BindingState::BoundOnly) {
        use composefs_ctl::composefs::fsverity::Sha512HashValue;
        let cfs_repo = match sysroot.get_ensure_composefs() {
            Ok(r) => r,
            Err(_) => return Ok(Vec::new()),
        };
        let bound_images: Vec<ImageOutput> = composefs_oci::list_refs(&*cfs_repo)
            .context("Listing composefs OCI refs")?
            .into_iter()
            .filter(|(tag, _)| tag.starts_with(BOOTC_TAG_PREFIX))
            .filter_map(|(tag, manifest_digest)| {
                // Derive a human-readable name from the OCI config label, just
                // like inspect_unified_storage does.  Fall back to the tag.
                let display_name =
                    OciImage::<Sha512HashValue>::open(&*cfs_repo, &manifest_digest, None)
                        .ok()
                        .and_then(|img| {
                            img.config()
                                .and_then(|cfg| cfg.config().as_ref())
                                .and_then(|c| c.labels().as_ref())
                                .and_then(|l| l.get("org.opencontainers.image.ref.name").cloned())
                        })
                        .unwrap_or(tag);
                Some(ImageOutput {
                    image: display_name,
                    image_type: ImageListTypeColumn::Bound,
                })
            })
            .collect();
        return Ok(bound_images);
    }

    let sysroot_dir = &sysroot.physical_root;
    let subpath = CStorage::subpath();
    if !sysroot_dir.try_exists(&subpath).unwrap_or(false) {
        return Ok(Vec::new());
    }
    let run = Dir::open_ambient_dir("/run", cap_std::ambient_authority())?;
    let imgstore = CStorage::create(sysroot_dir, &run, None)?;
    let images = imgstore
        .list_images()
        .await
        .context("Listing containers-storage images")?;

    // On Disabled systems (no composefs binding), all images in bootc's
    // containers-storage are reported as "unified" (original semantics: available
    // via bootc storage for podman). The composefs cross-reference check only
    // applies when the unified-storage flag has been set.
    if matches!(state, BindingState::Disabled) {
        return Ok(images
            .into_iter()
            .flat_map(|entry| {
                entry
                    .names
                    .unwrap_or_default()
                    .into_iter()
                    .map(|name| ImageOutput {
                        image: name,
                        image_type: ImageListTypeColumn::Unified,
                    })
            })
            .collect());
    }

    // Unified: cross-reference against composefs tags to determine whether each
    // image went through the full three-store pipeline.
    // We match by config digest (= image ID, stable across layer recompression)
    // rather than manifest digest (which may differ after copying).
    let composefs_config_digests = sysroot.composefs_config_digests()?;

    // Logically bound images (LBIs) are stored in bootc's containers-storage
    // but are not OS images — they are never imported into the composefs OCI
    // repo via the three-store pipeline.  Showing them as "partial" would be
    // misleading; they should remain "unified" (available to the system).
    let rootfs = cap_std_ext::cap_std::fs::Dir::open_ambient_dir(
        "/",
        cap_std_ext::cap_std::ambient_authority(),
    )
    .context("Opening rootfs")?;
    let lbi_names: std::collections::HashSet<String> =
        crate::boundimage::query_bound_images(&rootfs)
            .unwrap_or_default()
            .into_iter()
            .map(|b| b.image)
            .collect();

    Ok(images
        .into_iter()
        .flat_map(|entry| {
            let names = entry.names.unwrap_or_default();
            let image_type =
                if crate::store::cstorage_id_matches_digest(&composefs_config_digests, &entry.id) {
                    ImageListTypeColumn::Unified
                } else if names.iter().any(|n| lbi_names.contains(n.as_str())) {
                    // Logically bound image — not a host OS image, stays unified.
                    ImageListTypeColumn::Unified
                } else {
                    // In bootc storage but not composefs-tagged and not an LBI —
                    // the host image is present in cstorage but composefs import
                    // is not yet complete.
                    ImageListTypeColumn::Partial
                };
            names.into_iter().map(move |name| ImageOutput {
                image: name,
                image_type,
            })
        })
        .collect())
}

#[context("Listing logical images")]
fn list_logical_images(root: &Dir) -> Result<Vec<ImageOutput>> {
    let bound = query_bound_images(root)?;

    Ok(bound
        .into_iter()
        .map(|image| ImageOutput {
            image: image.image,
            image_type: ImageListTypeColumn::Logical,
        })
        .collect())
}

async fn list_images(list_type: ImageListType) -> Result<Vec<ImageOutput>> {
    let rootfs = cap_std::fs::Dir::open_ambient_dir("/", cap_std::ambient_authority())
        .context("Opening /")?;

    let sysroot: Option<crate::store::BootedStorage> =
        if ostree_ext::container_utils::running_in_container() {
            None
        } else {
            Some(crate::cli::get_storage().await?)
        };

    Ok(match (list_type, sysroot) {
        // TODO: Should we list just logical images silently here, or error?
        (ImageListType::All, None) => list_logical_images(&rootfs)?,
        (ImageListType::All, Some(sysroot)) => list_host_images(&sysroot)
            .await?
            .into_iter()
            .chain(list_logical_images(&rootfs)?)
            .collect(),
        (ImageListType::Logical, _) => list_logical_images(&rootfs)?,
        (ImageListType::Host, None) => {
            bail!("Listing host images requires a booted bootc system")
        }
        (ImageListType::Host, Some(sysroot)) => list_host_images(&sysroot).await?,
    })
}

#[context("Listing images")]
pub(crate) async fn list_entrypoint(
    list_type: ImageListType,
    list_format: ImageListFormat,
) -> Result<()> {
    let images = list_images(list_type).await?;

    match list_format {
        ImageListFormat::Table => {
            let mut table = Table::new();

            table
                .load_preset(NOTHING)
                .set_content_arrangement(comfy_table::ContentArrangement::Dynamic)
                .set_header(["REPOSITORY", "TYPE"]);

            for image in images {
                table.add_row([image.image, image.image_type.to_string()]);
            }

            println!("{table}");
        }
        ImageListFormat::Json => {
            let mut stdout = std::io::stdout();
            serde_json::to_writer_pretty(&mut stdout, &images)?;
        }
    }

    Ok(())
}

/// Collect the set of OCI *config* digests for every deployment that has a
/// bootloader entry (booted / staged / rollback / any bootable entry).
///
/// Bootloader entries are the authoritative source of truth for which images
/// are pinned: an image is "live" iff the system can actually boot a deployment
/// backed by it.  This replaces the previous state-dir origin scan, which read
/// secondary/derived state that could drift from the bootloader.
///
/// Returns config digests (not manifest digests) because containers-storage
/// presence is matched by config digest (podman recompresses layers on copy,
/// changing the manifest digest but not the config digest).
///
/// Returns `Ok(None)` on non-composefs systems (bootloader query fails) so
/// callers fall back to the previous `skip_live_filter` behavior.  Returns
/// `Err` on a genuine failure that should abort rather than silently pass.
fn collect_pinned_config_digests(
    sysroot: &Storage,
) -> Result<Option<std::collections::HashSet<String>>> {
    use crate::bootc_composefs::status::{get_imginfo, list_bootloader_entries};

    let entries = match list_bootloader_entries(sysroot) {
        Ok(e) => e,
        Err(e) => {
            // Not a composefs system (no bootloader / boot dir unavailable).
            // Fall back to skip_live_filter so callers treat everything as live.
            tracing::debug!("list_bootloader_entries failed (non-composefs system?): {e:#}");
            return Ok(None);
        }
    };

    if entries.is_empty() {
        // Composefs system but no bootloader entries yet (fresh install or
        // a system in an unusual state).
        tracing::warn!(
            "list_bootloader_entries returned an empty list on what appears to be \
             a composefs system; treating all tagged images as live"
        );
        return Ok(Some(std::collections::HashSet::new()));
    }

    let mut config_digests = std::collections::HashSet::new();
    let mut first_err: Option<anyhow::Error> = None;

    for entry in &entries {
        match get_imginfo(sysroot, &entry.fsverity) {
            Ok(info) => {
                config_digests.insert(info.manifest.config().digest().to_string());
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to read image info for bootloader entry {}: {e:#}",
                    entry.fsverity
                );
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
    }

    // Guard: if every get_imginfo call failed, the empty set would make fsck
    // pass vacuously while images are actually missing.  Surface the failure.
    if config_digests.is_empty() {
        if let Some(e) = first_err {
            return Err(e.context(
                "All bootloader entries failed image-info lookup; \
                 cannot determine which images are pinned",
            ));
        }
        // entries was non-empty but produced no digests and no errors —
        // shouldn't happen, but handle defensively (same as empty warning above).
        tracing::warn!(
            "No config digests collected from {} bootloader entries (all missing imginfo?); \
             treating all tagged images as live",
            entries.len()
        );
    }

    Ok(Some(config_digests))
}

/// Ensure every bootloader-pinned deployment has a bootc GC tag in the composefs
/// repo, so tag-based enumeration reconciles it even if it was never tagged
/// (e.g. legacy deployments).  Mirrors the migration step in `composefs_gc`.
///
/// This is called only from mutating contexts (`reconcile_unified_storage` and
/// `fsck_images --repair`) so that a plain read-only `fsck` still correctly
/// reports a pinned-but-untagged-and-missing image as a failure.
fn ensure_tags_for_pinned_deployments(
    sysroot: &Storage,
    cfs_repo: &crate::store::ComposefsRepository,
) -> Result<()> {
    use crate::bootc_composefs::repo::bootc_tag_for_manifest;
    use crate::bootc_composefs::state::read_origin;
    use crate::composefs_consts::{ORIGIN_KEY_IMAGE, ORIGIN_KEY_MANIFEST_DIGEST};
    use composefs_ctl::composefs_oci::tag_image;

    let entries = match crate::bootc_composefs::status::list_bootloader_entries(sysroot) {
        Ok(e) => e,
        Err(e) => {
            tracing::debug!(
                "ensure_tags_for_pinned_deployments: list_bootloader_entries failed \
                 (non-composefs system?): {e:#}"
            );
            return Ok(());
        }
    };

    let existing_refs = composefs_oci::list_refs(cfs_repo).context("Listing composefs OCI refs")?;

    for entry in &entries {
        let ini = match read_origin(&sysroot.physical_root, &entry.fsverity) {
            Ok(Some(i)) => i,
            Ok(None) => {
                tracing::warn!(
                    "No origin file for bootloader entry {}; skipping tag ensure",
                    entry.fsverity
                );
                continue;
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to read origin for bootloader entry {}: {e:#}",
                    entry.fsverity
                );
                continue;
            }
        };

        let Some(manifest_digest_str) =
            ini.get::<String>(ORIGIN_KEY_IMAGE, ORIGIN_KEY_MANIFEST_DIGEST)
        else {
            // Pure-legacy .imginfo-only deployment: no manifest digest in origin,
            // cannot construct a tag.
            tracing::warn!(
                "Bootloader entry {} has no manifest_digest in origin \
                 (legacy .imginfo-only deployment?); skipping tag ensure",
                entry.fsverity
            );
            continue;
        };

        let tag = bootc_tag_for_manifest(&manifest_digest_str);
        if existing_refs.iter().any(|(t, _)| t == &tag) {
            tracing::debug!(
                "Tag {tag} already exists for bootloader entry {}",
                entry.fsverity
            );
            continue;
        }

        let manifest_digest: composefs_oci::OciDigest = match manifest_digest_str.parse() {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(
                    "Failed to parse manifest digest {manifest_digest_str} for {}: {e:#}",
                    entry.fsverity
                );
                continue;
            }
        };

        tracing::info!(
            "Creating missing bootc tag {tag} for bootloader entry {}",
            entry.fsverity
        );
        if let Err(e) = tag_image(cfs_repo, &manifest_digest, &tag) {
            tracing::warn!("Failed to tag image {manifest_digest} as {tag}: {e:#}");
        }
    }

    Ok(())
}

/// JSON-serializable report from `bootc internals fsck images`.
///
/// When the system is in a "pending" state (binding enabled but the booted
/// deployment is not yet composefs-synthesized — the expected transient state
/// right after `bootc image set-unified composefs` and before the next reboot),
/// individual [`FsckImageResult`] entries may have `pending = true`.  The
/// overall `ok` field is still `true` in that case; pending is informational.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FsckReport {
    /// Whether containers-storage participation is active (`state == Unified`).
    /// Kept for backward compatibility with existing JSON consumers.
    pub unified_storage_enabled: bool,
    /// The ostree↔composefs binding state: `"disabled"`, `"bound-only"`, or `"unified"`.
    pub binding: String,
    /// Whether the filesystem supports reflinks (FICLONE). `None` if the probe failed.
    pub reflinks_supported: Option<bool>,
    /// Per-image check results for live unified-storage images.
    pub images: Vec<FsckImageResult>,
    /// Overall pass/fail: true if all checks passed (pending images do not flip this to false).
    pub ok: bool,
}

/// Per-image result from `bootc internals fsck images`.
///
/// A live image that is present but not yet composefs-synthesized is reported
/// as `pending = true` (ok stays true overall).  This is the expected transient
/// state after `bootc image set-unified composefs` and before the first reboot
/// onto the synthesized deployment.  Once the system reboots into the
/// synthesized deployment, `pending` becomes `false` and
/// `ostree_commit_synthesized` becomes `true`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FsckImageResult {
    /// Human-readable image name (from OCI label or composefs tag).
    pub name: String,
    /// Whether this image is present in the composefs repo.
    pub in_composefs: bool,
    /// Whether this image is present in bootc's containers-storage.
    pub in_containers_storage: bool,
    /// Whether a repair was attempted (only when --repair is passed).
    pub repaired: bool,
    /// BoundOnly: backing ostree commit was found.
    #[serde(default)]
    pub ostree_commit_present: bool,
    /// BoundOnly: backing ostree commit carries META_COMPOSEFS_SYNTHESIZED.
    #[serde(default)]
    pub ostree_commit_synthesized: bool,
    /// Whether this image backs a live (bootloader-pinned) deployment.
    #[serde(default)]
    pub is_live: bool,
    /// The live deployment is booted into a non-synthesized (classic) commit.
    ///
    /// This is the expected transient state right after `bootc image set-unified
    /// composefs` and before the next reboot.  A pending image is not a failure;
    /// the overall `ok` flag remains true.  Run `bootc upgrade` then reboot to
    /// activate the bound-only mode fully.
    #[serde(default)]
    pub pending: bool,
    /// Per-image problems (empty = healthy).  For a pending image this is
    /// always empty; the `pending` flag conveys the informational state.
    #[serde(default)]
    pub issues: Vec<String>,
}

/// Per-image data returned by [`inspect_unified_storage`].
///
/// Contains everything needed to drive both fsck reporting and reconciliation
/// without making any changes to system state.
struct ReconcileEntry {
    /// The composefs tag name (e.g. `localhost/bootc-sha256:abc...`).
    tag: String,
    /// The manifest digest this tag points to.
    manifest_digest: composefs_oci::OciDigest,
    /// Human-readable name: the `org.opencontainers.image.ref.name` label if
    /// present, otherwise the tag itself.
    display_name: String,
    /// Whether this image is already present in bootc's containers-storage,
    /// matched by config digest (image ID).
    in_cstor: bool,
    /// Whether this image backs a live deployment (booted / rollback / staged),
    /// or `true` if `skip_live_filter` is active (ostree systems / no state dir).
    is_live: bool,
}

/// Enumerate unified-storage entries without printing or modifying anything.
///
/// Returns one [`ReconcileEntry`] per bootc-tagged image in the composefs repo,
/// including stale / non-live entries (with `is_live = false`) so callers can
/// report or skip them.  Returns an empty `Vec` if the composefs repo is absent
/// (not an error — just nothing to inspect).
async fn inspect_unified_storage(sysroot: &Storage) -> Result<Vec<ReconcileEntry>> {
    use composefs_ctl::composefs::fsverity::Sha512HashValue;
    use composefs_ctl::composefs_oci::OciImage;

    let cfs_repo = match sysroot.get_ensure_composefs() {
        Ok(r) => r,
        Err(_) => return Ok(vec![]),
    };

    let bootc_tags: Vec<(String, composefs_oci::OciDigest)> = composefs_oci::list_refs(&*cfs_repo)
        .context("Listing composefs OCI refs")?
        .into_iter()
        .filter(|(tag, _)| tag.starts_with(BOOTC_TAG_PREFIX))
        .collect();

    if bootc_tags.is_empty() {
        return Ok(vec![]);
    }

    // Build the set of pinned config digests from bootloader entries — the
    // authoritative source of truth for which images are "live".
    // Returns None on non-composefs systems; in that case treat everything as live.
    let pinned_config_digests = collect_pinned_config_digests(sysroot)?;
    let skip_live_filter = pinned_config_digests.is_none();
    let pinned = pinned_config_digests.unwrap_or_default();

    // Build the set of image IDs (config sha256) present in containers-storage.
    // We match by config digest rather than manifest digest because podman may
    // report a different manifest digest than composefs when layers are
    // recompressed during the copy.  The config digest is stable.
    let cstor_id_to_names: std::collections::HashMap<String, Vec<String>> = {
        let run = cap_std_ext::cap_std::fs::Dir::open_ambient_dir(
            "/run",
            cap_std_ext::cap_std::ambient_authority(),
        )
        .context("Opening /run")?;
        let imgstore = CStorage::create(&sysroot.physical_root, &run, None)
            .context("Opening containers-storage")?;
        imgstore
            .list_images()
            .await
            .context("Listing containers-storage images")?
            .into_iter()
            .map(|entry| (entry.id, entry.names.unwrap_or_default()))
            .collect()
    };

    let mut entries = Vec::new();

    for (tag, manifest_digest) in bootc_tags {
        let oci_img = OciImage::<Sha512HashValue>::open(&cfs_repo, &manifest_digest, None).ok();

        let config_digest: Option<String> = oci_img
            .as_ref()
            .map(|img| img.manifest().config().digest().to_string());

        let display_name = oci_img
            .as_ref()
            .and_then(|img| {
                img.config()
                    .and_then(|cfg| cfg.config().as_ref())
                    .and_then(|c| c.labels().as_ref())
                    .and_then(|l| l.get("org.opencontainers.image.ref.name").cloned())
            })
            .unwrap_or_else(|| tag.clone());

        let in_cstor = if let Some(ref cdig) = config_digest {
            // containers-storage image IDs are the bare hex config digest;
            // our digests are "sha256:<hex>", so strip the prefix to compare.
            let bare = cdig.strip_prefix("sha256:").unwrap_or(cdig.as_str());
            cstor_id_to_names.contains_key(bare)
        } else {
            false
        };

        // Match by config digest: the pinned set (from bootloader entries via
        // get_imginfo) and this tag's config_digest are both "sha256:<hex>"
        // strings produced by the same OciImage path, so compare directly.
        let is_live = skip_live_filter
            || config_digest
                .as_ref()
                .is_some_and(|cdig| pinned.contains(cdig.as_str()));

        entries.push(ReconcileEntry {
            tag,
            manifest_digest,
            display_name,
            in_cstor,
            is_live,
        });
    }

    Ok(entries)
}

/// Reduced facts about one live bound deployment, for classification.
///
/// All fields are determined from I/O at collection time; classification is
/// pure (no I/O) and independently unit-testable.
struct BoundImageProbe {
    /// Human-readable name for output.
    name: String,
    /// The ostree commit for this deployment was successfully loaded.
    commit_present: bool,
    /// The commit carries `META_COMPOSEFS_SYNTHESIZED`.
    synthesized: bool,
    /// A manifest digest was extractable from the commit metadata.
    has_manifest_digest: bool,
    /// A bootc composefs tag for this digest exists in the composefs repo.
    tag_present: bool,
    /// The OCI image for this digest can be opened (manifest+config present).
    oci_openable: bool,
    /// Whether this image backs a live (booted/rollback/staged) deployment.
    is_live: bool,
    /// The parsed OciDigest for the manifest, if available.  Carried here so
    /// that repair can call tag_image / OciImage::open without re-parsing.
    oci_digest: Option<composefs_oci::OciDigest>,
}

/// Pure classification: returns the list of consistency issues (empty = healthy).
///
/// This function performs no I/O and is independently unit-testable.
///
/// Note: callers should check [`is_pending`] before treating these issues as
/// hard failures.  A live image that is not yet synthesized but whose commit IS
/// present is in the expected post-bind / pre-reboot transient state; its
/// issues (not-synthesized plus downstream consequences) should not count as
/// failures.
fn classify_bound_image(p: &BoundImageProbe) -> Vec<String> {
    let mut issues = Vec::new();
    if !p.commit_present {
        issues.push("ostree commit missing".to_string());
        return issues;
    }
    if !p.synthesized {
        issues.push(
            "ostree commit is not composefs-synthesized (expected on a bound system)".to_string(),
        );
    }
    if !p.has_manifest_digest {
        issues.push("synthesized commit has no manifest digest".to_string());
    }
    if p.has_manifest_digest && !p.tag_present {
        issues.push("no composefs tag backs this commit (objects may have been GC'd)".to_string());
    }
    if p.tag_present && !p.oci_openable {
        issues.push("composefs OCI image failed to open (objects missing/corrupt)".to_string());
    }
    issues
}

/// Returns `true` when a probe represents the expected transient "pending" state:
/// the system is booted into a live deployment whose commit IS present but is NOT
/// composefs-synthesized yet.
///
/// This is the normal state right after `bootc image set-unified composefs` and
/// before the first reboot onto the synthesized deployment.  It is NOT a
/// failure: the overall fsck `ok` flag stays `true`.  All issues produced by
/// [`classify_bound_image`] for a pending probe are consequences of the
/// not-yet-synthesized state and must not be treated as hard faults.
fn is_pending(p: &BoundImageProbe) -> bool {
    p.is_live && p.commit_present && !p.synthesized
}

/// Build [`BoundImageProbe`]s for every ostree deployment, plus stale tags.
///
/// IMPORTANT: this function must NOT call `inspect_unified_storage`,
/// `CStorage::create`, or any other code that initialises containers-storage.
/// On a BoundOnly system containers-storage intentionally does not exist;
/// touching it as a side effect would be wrong.
fn collect_bound_image_probes(sysroot: &Storage) -> Result<Vec<BoundImageProbe>> {
    use crate::bootc_composefs::repo::bootc_tag_for_manifest;
    use composefs_ctl::composefs::fsverity::Sha512HashValue;
    use composefs_ctl::composefs_oci::OciImage;

    let ostree = sysroot.get_ostree()?;
    let repo = ostree.repo();

    let cfs_repo = match sysroot.get_ensure_composefs() {
        Ok(r) => r,
        Err(_) => return Ok(vec![]),
    };

    // Build the tag map ONCE: tag-name → OciDigest.
    let tag_map: std::collections::HashMap<String, composefs_oci::OciDigest> =
        composefs_oci::list_refs(&*cfs_repo)
            .context("Listing composefs OCI refs")?
            .into_iter()
            .filter(|(tag, _)| tag.starts_with(BOOTC_TAG_PREFIX))
            .collect();

    let mut probes: Vec<BoundImageProbe> = Vec::new();
    // Track which digest strings are covered by a live deployment so we can
    // append stale-tag probes afterwards.
    let mut live_digest_strings: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    // Deduplicate deployments by commit checksum.
    let mut seen_csums: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Collect booted and staged checksums so rollback deployments (which may
    // predate the composefs binding) are marked is_live=false.  On a freshly
    // bound system the rollback will not be synthesized and must not be
    // flagged as a consistency failure.
    let booted_csum = ostree.booted_deployment().map(|d| d.csum().to_string());
    let staged_csum = ostree.staged_deployment().map(|d| d.csum().to_string());

    for deployment in ostree.deployments() {
        let csum = deployment.csum().to_string();
        if !seen_csums.insert(csum.clone()) {
            continue;
        }
        // A deployment is "live" (requiring full consistency) only if it is the
        // currently booted deployment or the pending staged deployment.  The
        // rollback deployment may legitimately predate the ostree↔composefs
        // binding (e.g. right after `bootc image set-unified composefs` runs for
        // the first time) so it is reported but not flagged as a failure.
        let is_live = booted_csum.as_deref() == Some(csum.as_str())
            || staged_csum.as_deref() == Some(csum.as_str());

        let (commit_present, commit_obj_opt) = match repo.load_commit(csum.as_str()) {
            Ok((obj, _)) => (true, Some(obj)),
            Err(e) => {
                tracing::warn!("Failed to load commit {csum}: {e:#}");
                (false, None)
            }
        };

        let synthesized = commit_obj_opt
            .as_ref()
            .map(|obj| {
                let meta = ostree_ext::ostree::glib::VariantDict::new(Some(&obj.child_value(0)));
                meta.lookup::<bool>(ostree_ext::container::store::META_COMPOSEFS_SYNTHESIZED)
                    .unwrap_or(None)
                    .unwrap_or(false)
            })
            .unwrap_or(false);

        // Extract the manifest digest string from the commit metadata.
        let digest_string_opt: Option<String> = commit_obj_opt.as_ref().and_then(|obj| {
            ostree_ext::container::store::manifest_digest_from_commit(obj)
                .ok()
                .map(|d| d.to_string())
        });

        let has_manifest_digest = digest_string_opt.is_some();

        // Parse the digest string into an OciDigest for tag lookup and open.
        let oci_digest_opt: Option<composefs_oci::OciDigest> =
            digest_string_opt.as_deref().and_then(|s| s.parse().ok());

        let expected_tag = digest_string_opt.as_deref().map(bootc_tag_for_manifest);

        let tag_present = expected_tag
            .as_deref()
            .is_some_and(|t| tag_map.contains_key(t));

        // Record this digest so we can detect stale tags later.
        if let Some(ref ds) = digest_string_opt {
            live_digest_strings.insert(ds.clone());
        }

        // Attempt to open the OCI image by its parsed digest (not by tag),
        // so we can check object integrity even when the tag is missing.
        let oci_digest_for_open = oci_digest_opt.clone().or_else(|| {
            // Fall back: if we have a tag, use its digest from the map.
            expected_tag
                .as_deref()
                .and_then(|t| tag_map.get(t).cloned())
        });

        let (oci_openable, oci_digest) = if let Some(ref d) = oci_digest_for_open {
            let ok = OciImage::<Sha512HashValue>::open(&*cfs_repo, d, None).is_ok();
            (ok, Some(d.clone()))
        } else {
            (false, None)
        };

        // Derive a display name from the OCI image labels or fall back to the tag.
        let name = oci_digest
            .as_ref()
            .and_then(|d| OciImage::<Sha512HashValue>::open(&*cfs_repo, d, None).ok())
            .and_then(|img| {
                img.config()
                    .and_then(|cfg| cfg.config().as_ref())
                    .and_then(|c| c.labels().as_ref())
                    .and_then(|l| l.get("org.opencontainers.image.ref.name").cloned())
            })
            .or_else(|| expected_tag.clone())
            .unwrap_or_else(|| csum.clone());

        probes.push(BoundImageProbe {
            name,
            commit_present,
            synthesized,
            has_manifest_digest,
            tag_present,
            oci_openable,
            is_live,
            oci_digest,
        });
    }

    // Append stale-tag probes (is_live=false) for tags not backed by any live deployment.
    for (tag, oci_digest) in &tag_map {
        let digest_str = tag.strip_prefix(BOOTC_TAG_PREFIX).unwrap_or(tag.as_str());
        if live_digest_strings.contains(digest_str) {
            continue;
        }
        // Try to open to check object integrity (informational only).
        let oci_openable = OciImage::<Sha512HashValue>::open(&*cfs_repo, oci_digest, None).is_ok();
        probes.push(BoundImageProbe {
            name: tag.clone(),
            commit_present: true,
            synthesized: true,
            has_manifest_digest: true,
            tag_present: true,
            oci_openable,
            is_live: false,
            oci_digest: Some(oci_digest.clone()),
        });
    }

    Ok(probes)
}

/// Check image store consistency across containers-storage and composefs.
///
/// Enumerates all bootc-tagged images in the composefs OCI repo and verifies
/// that each is also present in bootc's containers-storage.  Returns `true`
/// if all checks pass, `false` if any inconsistency is found.
///
/// When `repair` is `true`, images missing from containers-storage are
/// restored by re-importing from the composefs repo.  When `json` is `true`,
/// emits a machine-readable [`FsckReport`] instead of human-readable output.
///
/// When binding is disabled (classic ostree, no composefs), prints a note and
/// returns `true` — nothing to check.  For `BoundOnly` systems the composefs
/// binding is intact but containers-storage participation is absent; images are
/// reported as OK (the absence from containers-storage is intentional).
pub(crate) async fn fsck_images(
    sysroot: &Storage,
    repair: bool,
    json: bool,
) -> anyhow::Result<bool> {
    use crate::deploy::BindingState;

    // Derive the tri-state binding signal from the repo config + bootc.json.
    let state = crate::deploy::binding_state(sysroot)?;

    let binding_str = match state {
        BindingState::Disabled => "disabled",
        BindingState::BoundOnly => "bound-only",
        BindingState::Unified => "unified",
    };

    let reflinks_supported = match sysroot.reflinks_supported() {
        Ok(v) => Some(v),
        Err(_) => None,
    };

    if matches!(state, BindingState::Disabled) {
        if json {
            let report = FsckReport {
                unified_storage_enabled: false,
                binding: binding_str.to_string(),
                reflinks_supported,
                images: vec![],
                ok: true,
            };
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            println!("bootc fsck images: unified storage not enabled; nothing to check");
        }
        return Ok(true);
    }

    // BoundOnly: the OS image lives in the composefs repo and is intentionally
    // absent from containers-storage.  Drive checks from live ostree deployments
    // (the real source of truth) rather than enumerating composefs tags naively.
    // IMPORTANT: we must NOT call inspect_unified_storage or CStorage::create —
    // those initialise the containers-storage directory as a side effect on a
    // BoundOnly system.
    if matches!(state, BindingState::BoundOnly) {
        if !json {
            println!("bootc fsck: checking bound-only image stores");
        }

        let probes = match collect_bound_image_probes(sysroot) {
            Ok(p) => p,
            Err(_) => {
                // No composefs repo: nothing to check.
                if json {
                    let report = FsckReport {
                        unified_storage_enabled: false,
                        binding: binding_str.to_string(),
                        reflinks_supported,
                        images: vec![],
                        ok: true,
                    };
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    println!("bootc fsck: no composefs repo found; nothing to check");
                }
                return Ok(true);
            }
        };

        // Obtain the composefs repo for repair operations.  We need this only
        // when --repair is requested; on read-only fsck we skip it to avoid
        // any side effects.
        let cfs_repo_for_repair = if repair {
            sysroot.get_ensure_composefs().ok()
        } else {
            None
        };

        let mut images: Vec<FsckImageResult> = Vec::new();
        let mut n_ok = 0usize;
        let mut n_fail = 0usize;
        let mut n_pending = 0usize;

        for probe in &probes {
            let mut issues = classify_bound_image(probe);
            let mut repaired = false;

            // Detect the "pending" transient state: live deployment whose commit
            // IS present but is not yet composefs-synthesized.  This is the
            // expected state right after `bootc image set-unified composefs` and
            // before the first reboot.  All issues produced by
            // classify_bound_image in this case are consequences of the
            // not-yet-synthesized commit (not genuine faults), so we suppress
            // them and report `pending = true` instead.
            let pending = is_pending(probe);
            if pending {
                issues.clear();
            }

            // Attempt repair only for live, non-pending images when --repair was requested.
            if repair && probe.is_live && !pending && !issues.is_empty() {
                use crate::bootc_composefs::repo::bootc_tag_for_manifest;
                use composefs_ctl::composefs_oci::tag_image;

                // The only safely repairable issue is a missing tag when the
                // OCI objects are still present on disk.  We verify object
                // presence by attempting OciImage::open on the known digest
                // (which does not require a tag).
                //
                // All other problems (commit missing, not synthesized, objects
                // corrupt) require a full re-bind or upgrade and cannot be
                // fixed by a simple re-tag.
                let missing_tag_only = issues.len() == 1 && issues[0].contains("no composefs tag");

                if missing_tag_only {
                    if let Some(ref cfs_repo) = cfs_repo_for_repair {
                        if let Some(ref oci_digest) = probe.oci_digest {
                            // oci_openable was already set via an OciImage::open
                            // attempt at probe-collection time, but re-verify
                            // here to be explicit about the safety condition.
                            if probe.oci_openable {
                                let digest_str = oci_digest.to_string();
                                let tag = bootc_tag_for_manifest(&digest_str);
                                if !json {
                                    println!(
                                        "  [REPAIR] Re-tagging {} in composefs repo...",
                                        probe.name
                                    );
                                }
                                match tag_image(&**cfs_repo, oci_digest, &tag) {
                                    Ok(()) => {
                                        issues.clear();
                                        repaired = true;
                                        if !json {
                                            println!(
                                                "  [REPAIRED] Re-tagged {} successfully",
                                                probe.name
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        if !json {
                                            println!("  [REPAIR FAILED] {}: {e:#}", probe.name);
                                        }
                                    }
                                }
                            } else {
                                if !json {
                                    println!(
                                        "  [REPAIR UNAVAILABLE] {}: objects missing from composefs; \
                                         run 'bootc image set-unified composefs' or 'bootc upgrade'",
                                        probe.name
                                    );
                                }
                            }
                        }
                    }
                } else {
                    if !json {
                        println!(
                            "  [REPAIR UNAVAILABLE] {}: run 'bootc image set-unified composefs' \
                             or 'bootc upgrade' to fix: {}",
                            probe.name,
                            issues.join("; ")
                        );
                    }
                }
            }

            if !json {
                if !probe.is_live {
                    println!(
                        "  [NOTE] {} (stale composefs tag, not a live deployment)",
                        probe.name
                    );
                } else if pending {
                    println!(
                        "  [PENDING] {} (bound; booted deployment not yet composefs-backed \
                         — reboot to activate)",
                        probe.name
                    );
                } else if issues.is_empty() {
                    println!("  [OK]  {} (composefs: yes, bound-only)", probe.name);
                } else if !repair {
                    // Only print FAIL here on read-only runs; repair already printed above.
                    println!("  [FAIL] {}: {}", probe.name, issues.join("; "));
                }
            }

            // Only live images affect the ok flag.  Pending images are live but
            // not a failure — they are counted separately so the summary is
            // accurate, and ok stays true.
            if probe.is_live {
                if pending {
                    n_pending += 1;
                } else if issues.is_empty() {
                    n_ok += 1;
                } else {
                    n_fail += 1;
                }
            }

            images.push(FsckImageResult {
                name: probe.name.clone(),
                in_composefs: probe.tag_present || repaired,
                in_containers_storage: false,
                repaired,
                ostree_commit_present: probe.commit_present,
                ostree_commit_synthesized: probe.synthesized,
                is_live: probe.is_live,
                pending,
                issues,
            });
        }

        let ok = n_fail == 0;

        if json {
            let report = FsckReport {
                unified_storage_enabled: false,
                binding: binding_str.to_string(),
                reflinks_supported,
                images,
                ok,
            };
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else if ok {
            if n_pending > 0 {
                println!(
                    "bootc fsck: checks passed ({n_ok} OK, {n_pending} pending reboot to activate)"
                );
            } else {
                println!("bootc fsck: all checks passed ({n_ok} image(s) OK)");
            }
        } else {
            println!("bootc fsck: {n_fail} failure(s) found ({n_ok} OK, {n_fail} FAIL)");
        }
        return Ok(ok);
    }

    if !json {
        println!("bootc fsck: checking image stores");
    }

    // Warn if the filesystem does not support reflinks — unified storage
    // depends on extent sharing between the composefs and ostree repos.
    if !json {
        match reflinks_supported {
            Some(true) => tracing::debug!("Reflink probe: filesystem supports FICLONE"),
            Some(false) => {
                println!(
                    "bootc fsck: WARNING: filesystem does not support reflinks (FICLONE); \
                     composefs and ostree object stores are NOT sharing blocks"
                );
            }
            None => {}
        }
    }

    // When repairing, first ensure every bootloader-pinned deployment has a GC
    // tag so that inspect_unified_storage can discover it.  In read-only mode
    // we intentionally skip this: a pinned-but-untagged-and-missing image should
    // still be reported as a failure by plain fsck.
    let cfs_repo = if repair {
        match sysroot.get_ensure_composefs() {
            Ok(repo) => {
                if let Err(e) = ensure_tags_for_pinned_deployments(sysroot, &repo) {
                    tracing::warn!("ensure_tags_for_pinned_deployments failed (continuing): {e:#}");
                }
                Some(repo)
            }
            Err(_) => None,
        }
    } else {
        None
    };

    // inspect_unified_storage returns Ok(vec![]) if the composefs repo is absent.
    let reconcile_entries = inspect_unified_storage(sysroot).await?;

    if reconcile_entries.is_empty() {
        // Either no composefs repo or no bootc-managed images.
        if json {
            let report = FsckReport {
                unified_storage_enabled: matches!(state, BindingState::Unified),
                binding: binding_str.to_string(),
                reflinks_supported,
                images: vec![],
                ok: true,
            };
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            // Try to distinguish "no repo" from "no tags" for human output.
            // We can't differentiate easily here, so use a generic message.
            println!("bootc fsck: no bootc-managed images in composefs; nothing to check");
        }
        return Ok(true);
    }

    // Obtain the composefs repo handle for repair operations (if not already obtained).
    let cfs_repo = match cfs_repo {
        Some(r) => r,
        None => sysroot.get_ensure_composefs()?,
    };

    let mut n_ok = 0usize;
    let mut n_fail = 0usize;
    let mut images = Vec::new();

    for entry in &reconcile_entries {
        // Only enforce containers-storage presence for images that back a live
        // deployment.  Tags for stale images (e.g. a prior rollback that was
        // displaced by a second upgrade) will be cleaned up by composefs-gc and
        // are harmless to skip here.
        //
        // On ostree-backed systems `is_live` is always true (skip_live_filter
        // was active), so all bootc-tagged images are checked.
        if !entry.is_live {
            tracing::debug!(
                "Skipping stale composefs tag {} ({}): not a live deployment",
                entry.tag,
                entry.manifest_digest,
            );
            continue;
        }

        let in_cstor = entry.in_cstor;
        let mut repaired = false;

        // in_composefs is always true here: we iterated over composefs list_refs.
        //
        // For BoundOnly systems the image is intentionally absent from
        // containers-storage — that is the defining property of bound-only mode.
        // We verify only that the composefs binding is intact (guaranteed by
        // being in the iterated list_refs) and report OK.  We do NOT repair and
        // do NOT count the cstor absence as a failure.
        if matches!(state, BindingState::BoundOnly) {
            if !json {
                println!(
                    "  [OK]  {} (composefs: yes, bound-only)",
                    entry.display_name
                );
            }
            n_ok += 1;
            images.push(FsckImageResult {
                name: entry.display_name.clone(),
                in_composefs: true,
                in_containers_storage: in_cstor,
                repaired: false,
                ostree_commit_present: false,
                ostree_commit_synthesized: false,
                is_live: true,
                pending: false,
                issues: vec![],
            });
            continue;
        }

        // Unified: containers-storage participation is required.
        let mut in_cstor = in_cstor;
        if in_cstor {
            if !json {
                println!(
                    "  [OK]  {} (composefs: yes, containers-storage: yes)",
                    entry.display_name
                );
            }
            n_ok += 1;
        } else if repair {
            if !json {
                println!(
                    "  [REPAIR] Restoring {} to containers-storage...",
                    entry.display_name
                );
            }
            repaired = true;
            match repair_image_to_containers_storage(sysroot, &cfs_repo, &entry.manifest_digest)
                .await
            {
                Ok(()) => {
                    in_cstor = true;
                    if !json {
                        println!(
                            "  [REPAIRED] Successfully restored {} to containers-storage",
                            entry.display_name
                        );
                    }
                    n_ok += 1;
                }
                Err(e) => {
                    if !json {
                        println!("  [REPAIR FAILED] {}: {e:#}", entry.display_name);
                    }
                    n_fail += 1;
                }
            }
        } else {
            if !json {
                println!(
                    "  [FAIL] {} - in composefs but not in containers-storage",
                    entry.display_name
                );
                println!(
                    "         Hint: re-run with `--repair` to restore, or `bootc upgrade` to re-pull"
                );
            }
            n_fail += 1;
        }

        images.push(FsckImageResult {
            name: entry.display_name.clone(),
            in_composefs: true,
            in_containers_storage: in_cstor,
            repaired,
            ostree_commit_present: false,
            ostree_commit_synthesized: false,
            is_live: true,
            pending: false,
            issues: vec![],
        });
    }

    let ok = n_fail == 0;

    if json {
        let report = FsckReport {
            unified_storage_enabled: matches!(state, BindingState::Unified),
            binding: binding_str.to_string(),
            reflinks_supported,
            images,
            ok,
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
        Ok(ok)
    } else {
        if ok {
            println!("bootc fsck: all checks passed ({n_ok} image(s) OK)");
            Ok(true)
        } else {
            println!("bootc fsck: {n_fail} failure(s) found ({n_ok} OK, {n_fail} FAIL)");
            Ok(false)
        }
    }
}

/// Restore an image from the composefs repo into bootc's private containers-storage.
///
/// Used by `bootc internals fsck --repair` and `reconcile_unified_storage` when
/// an image is present in the composefs repo (has a bootc GC tag) but missing
/// from bootc's private containers-storage instance.
///
/// Assembles the image into a temporary OCI directory on the persistent
/// sysroot filesystem (see [`crate::store::Storage::oci_scratch_dir`], using
/// the config-digest-preserving writer from `export_composefs_to_oci_dir`), then
/// imports it into the bootc private store via
/// `CStorage::import_from_oci_dir` which uses the same `bind_storage_roots` /
/// `[overlay@{STORAGE_ALIAS_DIR}+/proc/self/fd/{STORAGE_RUN_FD}]` plumbing as
/// `pull_from_storage_root`.  This ensures the image lands in the store that
/// `fsck`/`list_images` read, not in the default `/var/lib/containers` host
/// store that a plain `containers-storage:` reference would target.
///
/// TODO(unified-storage): This re-exports through a gzip-recompressed OCI tar,
/// which breaks reflink sharing with the composefs object store (config digest
/// is preserved but layer blobs are fresh copies). Replace with a direct,
/// reflink-aware writer once composefs-rs lands splitfdstream support.
async fn repair_image_to_containers_storage(
    sysroot: &crate::store::Storage,
    cfs_repo: &crate::store::ComposefsRepository,
    manifest_digest: &composefs_oci::OciDigest,
) -> Result<()> {
    use composefs_ctl::composefs::fsverity::Sha512HashValue;
    use composefs_ctl::composefs_oci::OciImage;
    use ocidir::OciDir;

    // Ensure floating containers-storage is set up before we try to write to it.
    crate::podstorage::ensure_floating_c_storage_initialized();

    // Load the manifest to obtain the config digest (image ID) for naming.
    let oci_image = OciImage::<Sha512HashValue>::open(cfs_repo, manifest_digest, None)
        .with_context(|| {
            format!("Opening OCI image for manifest digest {manifest_digest} from composefs")
        })?;

    // Always derive a unique name from the config digest (image ID) so that
    // importing the booted image and rollback image under different tags never
    // steals the tag from an already-imported image.  Using the ref.name label
    // would cause both images (which share the same label) to collide on the
    // same tag, making the first import dangling.
    let config_digest_str = oci_image.config_digest().to_string();
    let short = config_digest_str
        .strip_prefix("sha256:")
        .unwrap_or(config_digest_str.as_str())
        .get(..12)
        .unwrap_or(config_digest_str.as_str());
    let image_name = format!("localhost/bootc-recovered:{short}");

    // Build the assembled OCI layout into a temporary directory on the
    // persistent sysroot filesystem rather than `/var/tmp`, which may be a
    // small tmpfs (e.g. a volatile `/var`) and would overflow when writing the
    // image's freshly-compressed layer blobs.  The scratch lives inside the
    // store root, so it is on the same filesystem as the destination (reflinks
    // work, no cross-device copy).  The guard keeps the directory alive until
    // after the import completes.
    let scratch = sysroot.oci_scratch_dir()?;
    let tmpdir = tempfile::Builder::new()
        .prefix("oci-")
        .tempdir_in(&scratch)
        .context("Creating temporary OCI dir in bootc storage scratch")?;
    let oci_abs = camino::Utf8Path::from_path(tmpdir.path())
        .ok_or_else(|| anyhow::anyhow!("Temp OCI dir path is not valid UTF-8"))?;
    let oci_cap_dir = Dir::open_ambient_dir(tmpdir.path(), cap_std::ambient_authority())
        .context("Opening temp OCI dir")?;
    let oci_dir = OciDir::ensure(oci_cap_dir).context("Initialising OCI dir")?;

    crate::bootc_composefs::export::export_composefs_to_oci_dir(
        cfs_repo,
        manifest_digest,
        &oci_dir,
    )
    .await
    .with_context(|| {
        format!("Assembling composefs image {manifest_digest} into temporary OCI dir")
    })?;

    // Import from the absolute path; skopeo (and its forked helpers) resolve it
    // in bootc's mount namespace.
    let imgstore = sysroot
        .get_ensure_imgstore()
        .context("Accessing bootc private containers-storage")?;
    imgstore
        .import_from_oci_dir(oci_abs.as_str(), &image_name)
        .await
        .with_context(|| {
            format!(
                "Importing composefs image {manifest_digest} into bootc private store as {image_name}"
            )
        })?;

    // Explicit drop to ensure the temp dir is not cleaned up before import.
    drop(tmpdir);
    Ok(())
}

/// Summary returned by [`reconcile_unified_storage`].
pub(crate) struct ReconcileSummary {
    /// Total number of live images inspected.
    pub checked: usize,
    /// Number of images that were successfully restored to containers-storage.
    pub restored: usize,
    /// Number of images that were already present in containers-storage.
    pub already_present: usize,
    /// Images that failed to reconcile: `(display_name, error)`.
    pub failures: Vec<(String, anyhow::Error)>,
}

/// Ensure every live deployment's image is present in containers-storage.
///
/// Calls [`inspect_unified_storage`] to enumerate bootc-tagged images in the
/// composefs repo and their containers-storage presence, then for each live
/// image that is missing from containers-storage calls
/// [`repair_image_to_containers_storage`] to export it via skopeo.
///
/// Errors are collected per-image rather than aborting the whole loop; the
/// caller decides whether any failures are fatal (e.g. `set-unified` treats
/// non-empty `failures` as fatal; `bootc image sync` exits non-zero).
///
/// **Important**: this is a containers-storage onboarding operation.  It must
/// only be called when containers-storage participation is intended, i.e. when
/// the binding state is [`crate::deploy::BindingState::Unified`].  Calling it
/// on a `BoundOnly` system would incorrectly backfill containers-storage,
/// defeating the purpose of the bound-only mode.
///
/// ## Tag-ensuring note
///
/// Before enumerating via [`inspect_unified_storage`], this function calls
/// [`ensure_tags_for_pinned_deployments`] to guarantee that every bootloader
/// entry has a composefs GC tag.  This covers legacy deployments that were
/// created before the tag-based reconcile path existed, so that their images
/// are discovered and restored to containers-storage even on the first run.
pub(crate) async fn reconcile_unified_storage(sysroot: &Storage) -> Result<ReconcileSummary> {
    // Ensure floating containers-storage is initialised before we try to write.
    crate::podstorage::ensure_floating_c_storage_initialized();

    // Ensure every bootloader-pinned deployment has a GC tag before we
    // enumerate via list_refs; otherwise legacy deployments are invisible.
    let cfs_repo = sysroot.get_ensure_composefs()?;
    if let Err(e) = ensure_tags_for_pinned_deployments(sysroot, &cfs_repo) {
        tracing::warn!("ensure_tags_for_pinned_deployments failed (continuing): {e:#}");
    }

    let entries = inspect_unified_storage(sysroot).await?;

    let mut checked = 0usize;
    let mut restored = 0usize;
    let mut already_present = 0usize;
    let mut failures = Vec::new();

    for entry in &entries {
        if !entry.is_live {
            tracing::debug!(
                "reconcile: skipping stale tag {} (not a live deployment)",
                entry.tag
            );
            continue;
        }

        checked += 1;

        if entry.in_cstor {
            tracing::debug!(
                "reconcile: {} already in containers-storage",
                entry.display_name
            );
            already_present += 1;
        } else {
            tracing::info!(
                "reconcile: restoring {} ({}) to containers-storage",
                entry.display_name,
                entry.manifest_digest,
            );
            match repair_image_to_containers_storage(sysroot, &cfs_repo, &entry.manifest_digest)
                .await
            {
                Ok(()) => {
                    tracing::info!("reconcile: successfully restored {}", entry.display_name);
                    restored += 1;
                }
                Err(e) => {
                    tracing::warn!("reconcile: failed to restore {}: {e:#}", entry.display_name);
                    failures.push((entry.display_name.clone(), e));
                }
            }
        }
    }

    Ok(ReconcileSummary {
        checked,
        restored,
        already_present,
        failures,
    })
}

/// Returns the source and target ImageReference
/// If the source isn't specified, we use booted image
/// If the target isn't specified, we push to containers-storage with our default image
pub(crate) async fn get_imgrefs_for_copy(
    host: &Host,
    source: Option<&str>,
    target: Option<&str>,
) -> Result<(ImageReference, ImageReference)> {
    // Initialize floating c_storage early - needed for container operations
    crate::podstorage::ensure_floating_c_storage_initialized();

    // If the target isn't specified, push to containers-storage + our default image
    let dest_imgref = match target {
        Some(target) => ostree_ext::container::ImageReference {
            transport: Transport::ContainerStorage,
            name: target.to_owned(),
        },
        None => ostree_ext::container::ImageReference {
            transport: Transport::ContainerStorage,
            name: IMAGE_DEFAULT.into(),
        },
    };

    // If the source isn't specified, we use the booted image
    let src_imgref = match source {
        Some(source) => ostree_ext::container::ImageReference::try_from(source)
            .context("Parsing source image")?,

        None => {
            let booted = host
                .status
                .booted
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Booted deployment not found"))?;

            let booted_image = &booted.image.as_ref().unwrap().image;

            ImageReference {
                transport: Transport::try_from(booted_image.transport.as_str()).unwrap(),
                name: booted_image.image.clone(),
            }
        }
    };

    return Ok((src_imgref, dest_imgref));
}

/// Implementation of `bootc image push-to-storage`.
#[context("Pushing image")]
pub(crate) async fn push_entrypoint(
    storage: &Storage,
    host: &Host,
    source: Option<&str>,
    target: Option<&str>,
) -> Result<()> {
    let explicit_source = source.is_some();
    let (source, target) = get_imgrefs_for_copy(host, source, target).await?;

    let ostree = storage.get_ostree()?;
    let repo = &ostree.repo();

    // Resolve the ostree commit backing the source image.
    //
    // For the booted image (no explicit `--source`) we key off the booted
    // deployment's commit checksum directly, exactly as `bootc status` does.
    // This is necessary because the deployment's recorded spec transport (e.g.
    // `registry`) need not match the transport of the ostree-container ref that
    // actually backs the commit (e.g. a digest-pinned `containers-storage:`
    // ref written at install time); re-deriving a ref from the spec would fail
    // to find the image. For an explicit `--source` we look up by reference.
    let source_rev = if explicit_source {
        let ostree_ref = ostree_ext::container::store::ref_for_image(&source)?;
        repo.resolve_rev(&ostree_ref, true)?.map(|r| r.to_string())
    } else {
        Some(ostree.require_booted_deployment()?.csum().to_string())
    };

    // Images pulled via the composefs-unified pipeline are stored in the composefs
    // repository with a synthesized ostree commit that has no per-layer blob refs.
    // Detect this case and fall through to the composefs export path which reads
    // directly from the composefs splitstreams instead of ostree blob refs.
    if let Some(rev) = source_rev.as_deref() {
        let (commit_obj, _) = repo.load_commit(rev)?;
        let commit_meta =
            ostree_ext::ostree::glib::VariantDict::new(Some(&commit_obj.child_value(0)));
        let is_composefs_synthesized = commit_meta
            .lookup::<bool>(ostree_ext::container::store::META_COMPOSEFS_SYNTHESIZED)?
            .unwrap_or(false);

        if is_composefs_synthesized {
            // For composefs-synthesized commits, the manifest digest is stored in the
            // commit metadata.  Retrieve it so we can open OciImage in the composefs
            // repo and preserve the config digest on export.
            let manifest_digest =
                ostree_ext::container::store::manifest_digest_from_commit(&commit_obj)
                    .context("Getting manifest digest from composefs-synthesized commit")?;

            let composefs_repo = storage.get_ensure_composefs()?;

            println!("Copying local image {source} to {target} ...");
            crate::bootc_composefs::export::export_composefs_to_dest(
                storage,
                &composefs_repo,
                &manifest_digest,
                &target,
            )
            .await?;
            println!("Pushed: {target}");
            return Ok(());
        }
    }

    let mut opts = ostree_ext::container::store::ExportToOCIOpts::default();
    opts.progress_to_stdout = true;
    println!("Copying local image {source} to {target} ...");
    // For the booted image, export by the resolved commit so we don't depend on
    // the spec transport matching the backing ostree-container ref (see above).
    // For an explicit `--source`, export by reference.
    let r = if explicit_source {
        ostree_ext::container::store::export(repo, &source, &target, Some(opts)).await?
    } else {
        let rev = source_rev
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("No commit for booted deployment"))?;
        ostree_ext::container::store::export_commit(repo, rev, &target, Some(opts)).await?
    };

    println!("Pushed: {target} {r}");
    Ok(())
}

/// Thin wrapper for invoking `podman image <X>` but set up for our internal
/// image store (as distinct from /var/lib/containers default).
pub(crate) async fn imgcmd_entrypoint(
    storage: &CStorage,
    arg: &str,
    args: &[std::ffi::OsString],
) -> std::result::Result<(), anyhow::Error> {
    let mut cmd = storage.new_image_cmd()?;
    cmd.arg(arg);
    cmd.args(args);
    cmd.run_capture_stderr()
}

/// Re-pull the currently booted image into the bootc-owned container storage.
///
/// This onboards the system to unified storage for host images so that
/// upgrade/switch can use the unified path automatically when the image is present.
///
/// `enabled_with_copy`: if true, allow byte-copy fallback when reflinks are unavailable
/// (writes `enabled-with-copy` to bootc.json); if false, fail hard if FICLONE is not
/// supported (writes `enabled`).
#[context("Setting unified storage for booted image")]
pub(crate) async fn set_unified_entrypoint(enabled_with_copy: bool) -> Result<()> {
    use composefs_ctl::composefs_oci::LocalFetchOpt;
    let local_fetch = if enabled_with_copy {
        LocalFetchOpt::IfPossible
    } else {
        LocalFetchOpt::ZeroCopy
    };

    let storage = crate::cli::get_storage().await?;

    if let crate::store::BootedStorageKind::Composefs(_) = storage.kind()? {
        anyhow::bail!(
            "unified storage onboarding on the composefs-native backend requires the composefs-native feature"
        );
    }

    // Initialize floating c_storage early - needed for container operations
    crate::podstorage::ensure_floating_c_storage_initialized();

    set_unified(&storage, local_fetch).await
}

/// Entrypoint for `bootc image sync`.
///
/// Ensures every live deployment's image is present in both the composefs repo
/// and bootc's containers-storage.  Prints a human-readable summary and
/// returns an error if any image could not be reconciled.
///
/// On a BoundOnly system (composefs binding active, containers-storage
/// participation disabled) this is a no-op: reconciling cstorage would
/// defeat the purpose of bound-only mode.
pub(crate) async fn sync_entrypoint() -> Result<()> {
    let storage = crate::cli::get_storage().await?;
    match crate::deploy::binding_state(&storage)? {
        crate::deploy::BindingState::BoundOnly => {
            println!(
                "ostree\u{2194}composefs binding is enabled but containers-storage participation is not; nothing to reconcile."
            );
            println!(
                "Run `bootc image set-unified full` to enable containers-storage participation."
            );
            return Ok(());
        }
        _ => {}
    }
    // reconcile_unified_storage initializes the floating containers-storage itself.
    let summary = reconcile_unified_storage(&storage).await?;
    println!(
        "Reconciled {} image(s) ({} restored, {} already present).",
        summary.checked, summary.restored, summary.already_present,
    );
    if !summary.failures.is_empty() {
        let msgs: Vec<String> = summary
            .failures
            .iter()
            .map(|(name, e)| format!("{name}: {e:#}"))
            .collect();
        bail!(
            "Failed to reconcile {} image(s):\n{}",
            summary.failures.len(),
            msgs.join("\n")
        );
    }
    Ok(())
}

/// Entrypoint for `bootc image set-unified composefs`.
///
/// Sets the ostree↔composefs binding flag without fetching or synthesizing
/// anything.  No-op on the native composefs backend.
///
/// After this returns, the user should run `bootc upgrade` which re-fetches
/// the image, synthesizes the composefs-backed ostree commit, and stages a new
/// deployment.  Rebooting into that deployment fully activates bound-only mode.
pub(crate) async fn bind_ostree_composefs_entrypoint(enabled_with_copy: bool) -> Result<()> {
    // enabled_with_copy was previously used to select ZeroCopy vs IfPossible
    // local-fetch mode.  The binding is now flag-only (no fetch/synthesis here),
    // so the value is not used in this path.  We keep the parameter so the CLI
    // call-site is unchanged.
    let _ = enabled_with_copy;

    let storage = crate::cli::get_storage().await?;

    if let crate::store::BootedStorageKind::Composefs(_) = storage.kind()? {
        println!(
            "System uses the native composefs backend; ostree\u{2194}composefs binding is intrinsic and not applicable (no-op)."
        );
        return Ok(());
    }

    bind_ostree_composefs(&storage).await
}

/// Set the ostree↔composefs binding flag for the booted system (flag-only).
///
/// This is a lightweight, pure-config operation: it writes `[composefs]
/// unified = true` to the ostree repo config and returns.  No image fetch,
/// no composefs synthesis, and no staging takes place here.
///
/// The next `bootc upgrade` will re-fetch the image, synthesize the
/// composefs-backed ostree commit, and stage a new deployment.  Rebooting
/// into that staged deployment fully activates bound-only mode.
///
/// `bootc internals fsck images` will report the live image as `pending`
/// (ok=true) between this call and the reboot.
#[context("Binding ostree to composefs for booted image")]
async fn bind_ostree_composefs(sysroot: &crate::store::Storage) -> Result<()> {
    // Already bound (BoundOnly or Unified)? No-op.
    if !matches!(
        crate::deploy::binding_state(sysroot)?,
        crate::deploy::BindingState::Disabled
    ) {
        println!("ostree\u{2194}composefs binding already enabled.");
        return Ok(());
    }

    let ostree = sysroot.get_ostree()?;
    let repo = &ostree.repo();

    // Flag-only: set [composefs] unified=true. No fetch, no synthesis, no stage.
    // The next `bootc upgrade` re-pulls, synthesizes the composefs-backed commit,
    // and stages a new deployment; reboot then activates bound-only mode.
    crate::deploy::set_ostree_composefs_bound(repo)
        .context("Writing composefs binding to ostree repo config")?;

    println!("ostree\u{2194}composefs binding enabled; run `bootc upgrade` to fetch and activate.");
    Ok(())
}

/// Inner implementation of set_unified for ostree that accepts a storage reference.
#[context("Setting unified storage for booted image")]
pub(crate) async fn set_unified(
    sysroot: &crate::store::Storage,
    local_fetch: composefs_ctl::composefs_oci::LocalFetchOpt,
) -> Result<()> {
    let ostree = sysroot.get_ostree()?;
    let repo = &ostree.repo();

    // Discover the currently booted image reference.
    // get_status_require_booted validates that we have a booted deployment with an image.
    let (_booted_ostree, _deployments, host) = crate::status::get_status_require_booted(ostree)?;

    // Use the booted deployment's image from the status we just retrieved.
    // get_status_require_booted guarantees host.status.booted is Some.
    let booted_entry = host
        .status
        .booted
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No booted deployment found"))?;
    let image_status = booted_entry
        .image
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Booted deployment is not from a container image"))?;

    // Extract the ImageReference from the ImageStatus
    let imgref = &image_status.image;

    // Canonicalize for pull display only, but we want to preserve original pullspec
    let imgref_display = imgref.clone().canonicalize()?;

    let imgstore = sysroot.get_ensure_imgstore()?;

    const SET_UNIFIED_JOURNAL_ID: &str = "1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d";
    tracing::info!(
        message_id = SET_UNIFIED_JOURNAL_ID,
        bootc.image.reference = &imgref_display.image,
        bootc.image.transport = &imgref_display.transport,
        "Onboarding booted image to unified storage: {}",
        imgref_display
    );

    // If the image is already present in bootc-owned containers-storage, skip
    // the pull/copy entirely.  This makes `set-unified` idempotent and avoids
    // a redundant network round-trip on repeated invocations.
    let img_transport = imgref.to_transport_image()?;
    if imgstore.exists(&img_transport).await? {
        tracing::info!(
            message_id = SET_UNIFIED_JOURNAL_ID,
            bootc.status = "already_in_bootc_storage",
            "Image already present in bootc containers-storage, skipping pull",
        );
    } else {
        // Determine the appropriate source for pulling the image into bootc storage.
        //
        // Case 1: If source transport is containers-storage, the image was installed from
        //         local container storage. Copy it from the default containers-storage to
        //         the bootc storage if it exists there, if not pull from ostree store.
        // Case 2: Otherwise, pull from the specified transport (usually a remote registry).
        let is_containers_storage = imgref.transport()? == Transport::ContainerStorage;

        if is_containers_storage {
            tracing::info!(
                "Source transport is containers-storage; checking if image exists in host storage"
            );

            // Check if the image already exists in the default containers-storage.
            // This can happen if someone did a local build (e.g., podman build) and
            // we don't want to overwrite it with an export from ostree.
            let image_exists = image_exists_in_host_storage(&imgref.image).await?;

            if image_exists {
                tracing::info!(
                    "Image {} already exists in containers-storage, skipping ostree export",
                    &imgref.image
                );
            } else {
                // The image was installed from containers-storage and now only exists in ostree.
                // We need to export from ostree to default containers-storage (/var/lib/containers)
                tracing::info!("Image not found in containers-storage; exporting from ostree");
                let source = ImageReference {
                    transport: Transport::try_from(imgref.transport.as_str())?,
                    name: imgref.image.clone(),
                };
                let target = ImageReference {
                    transport: Transport::ContainerStorage,
                    name: imgref.image.clone(),
                };
                let mut opts = ostree_ext::container::store::ExportToOCIOpts::default();
                // TODO: bridge to progress API
                opts.progress_to_stdout = true;
                tracing::info!(
                    "Exporting ostree deployment to default containers-storage: {}",
                    &imgref.image
                );
                ostree_ext::container::store::export(repo, &source, &target, Some(opts)).await?;
            }

            // Now copy from default containers-storage to bootc storage
            tracing::info!(
                "Copying from default containers-storage to bootc storage: {}",
                &imgref.image
            );
            let image_name = imgref.image.clone();
            let copy_msg = format!("Copying {} to bootc storage", &image_name);
            async_task_with_spinner(&copy_msg, async move {
                imgstore.pull_from_host_storage(&image_name).await
            })
            .await?;
        } else {
            // For registry and other transports, check if the image already exists in
            // the host's default container storage (/var/lib/containers/storage).
            // If so, we can copy from there instead of pulling from the network,
            // which is faster (especially after https://github.com/containers/container-libs/issues/144
            // enables reflinks between container storages).
            let image_in_host = image_exists_in_host_storage(&imgref.image).await?;

            if image_in_host {
                tracing::info!(
                    "Image {} found in host container storage; copying to bootc storage",
                    &imgref.image
                );
                let image_name = imgref.image.clone();
                let copy_msg = format!("Copying {} to bootc storage", &image_name);
                async_task_with_spinner(&copy_msg, async move {
                    imgstore.pull_from_host_storage(&image_name).await
                })
                .await?;
            } else {
                // Image not in host containers-storage and source is a remote registry.
                //
                // TODO: The ideal path here is `import_from_composefs_repo` — synthesize
                // the OCI content directly from the composefs object store into bootc's
                // containers-storage with FICLONE reflinks (zero physical copy, same as
                // the install-time pipeline).  This requires the composefs repo to already
                // be populated for this image, which is only true if the system was
                // installed with --experimental-unified-storage.  For a plain ostree
                // system that is onboarding via `set-unified`, the composefs repo is
                // empty, so we must re-pull from the registry to populate it correctly.
                //
                // The ostree→OCI export path (`container::store::export`) is deliberately
                // NOT used here because it re-serializes ostree objects through the tar
                // pipeline (no reflinks, two full physical copies: ostree→OCI→cstor).
                // That would defeat the entire purpose of unified storage.
                //
                // So for registry-transport systems `set-unified` requires network access.
                // Systems installed via containers-storage (e.g. bootc image cmd build)
                // always have the image locally, so they take the fast path above.
                let img_transport_pull = img_transport.clone();
                let pull_msg = format!("Pulling {} to bootc storage", &img_transport);
                async_task_with_spinner(&pull_msg, async move {
                    imgstore
                        .pull(
                            &img_transport_pull,
                            crate::podstorage::PullMode::IfNotExists,
                        )
                        .await
                })
                .await?;
            }
        }
    }

    // Verify the image is now in bootc storage
    let imgstore = sysroot.get_ensure_imgstore()?;
    if !imgstore.exists(&img_transport).await? {
        anyhow::bail!(
            "Image was pushed to bootc storage but not found: {}. \
             This may indicate a storage configuration issue.",
            &imgref.image
        );
    }
    tracing::info!("Image verified in bootc storage: {}", &imgref.image);

    // Import the image from containers-storage into the composefs OCI repo and tag it
    // as a bootc GC root. This mirrors Stage 2 of pull_via_composefs in deploy.rs so
    // that `bootc image list` shows the image as fully present (not "partial").
    {
        use composefs_ctl::composefs_oci::{PullOptions, tag_image};

        let cfs_repo = sysroot.get_ensure_composefs()?;
        let image_id = imgstore
            .image_id(&img_transport)
            .await
            .context("Resolving containers-storage image id for composefs import")?;
        let cstor_imgref_str = format!("containers-storage:{image_id}");
        let storage_path = format!("{}/{}", sysroot.physical_root_path, CStorage::subpath());
        tracing::info!(
            "Importing {} from containers-storage into composefs repo",
            &imgref.image
        );
        let pull_opts = PullOptions {
            local_fetch,
            storage_root: Some(std::path::Path::new(&storage_path)),
            ..Default::default()
        };
        let pull_result = composefs_oci::pull(&cfs_repo, &cstor_imgref_str, None, pull_opts)
            .await
            .context("Importing from containers-storage into composefs repo")?;

        let tag = crate::bootc_composefs::repo::bootc_tag_for_manifest(
            &pull_result.manifest_digest.to_string(),
        );
        tag_image(&*cfs_repo, &pull_result.manifest_digest, &tag)
            .context("Tagging pulled image as bootc GC root in composefs repo")?;
    }

    // Ensure the composefs directory exists (it may not on a fresh ostree system
    // that has never run pull_via_composefs), then write the bootc.json flag.
    crate::store::ensure_composefs_dir(&sysroot.physical_root)?;
    {
        let mut meta =
            crate::store::BootcRepoMeta::read(&sysroot.physical_root)?.unwrap_or_default();
        meta.version = 1;
        meta.unified = if local_fetch == composefs_ctl::composefs_oci::LocalFetchOpt::ZeroCopy {
            crate::spec::UnifiedStorageState::Enabled
        } else {
            crate::spec::UnifiedStorageState::EnabledWithCopy
        };
        meta.write(&sysroot.physical_root)
            .context("Writing unified-storage flag to composefs/bootc.json")?;
    }

    tracing::info!(
        message_id = SET_UNIFIED_JOURNAL_ID,
        bootc.status = "set_unified_complete",
        "Unified storage set for current image. Future upgrade/switch will use it automatically."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: a fully-healthy probe.
    fn healthy_probe() -> BoundImageProbe {
        BoundImageProbe {
            name: "quay.io/example/os:latest".to_string(),
            commit_present: true,
            synthesized: true,
            has_manifest_digest: true,
            tag_present: true,
            oci_openable: true,
            is_live: true,
            oci_digest: None,
        }
    }

    #[test]
    fn test_classify_healthy() {
        let issues = classify_bound_image(&healthy_probe());
        assert!(issues.is_empty(), "expected no issues, got: {issues:?}");
    }

    #[test]
    fn test_classify_commit_missing() {
        let p = BoundImageProbe {
            commit_present: false,
            synthesized: false,
            has_manifest_digest: false,
            tag_present: false,
            oci_openable: false,
            ..healthy_probe()
        };
        let issues = classify_bound_image(&p);
        assert_eq!(issues.len(), 1);
        assert!(
            issues[0].contains("ostree commit missing"),
            "unexpected: {issues:?}"
        );
    }

    #[test]
    fn test_classify_not_synthesized() {
        let p = BoundImageProbe {
            synthesized: false,
            ..healthy_probe()
        };
        let issues = classify_bound_image(&p);
        assert_eq!(issues.len(), 1);
        assert!(
            issues[0].contains("not composefs-synthesized"),
            "unexpected: {issues:?}"
        );
    }

    #[test]
    fn test_classify_synthesized_no_digest() {
        let p = BoundImageProbe {
            has_manifest_digest: false,
            tag_present: false,
            oci_openable: false,
            ..healthy_probe()
        };
        let issues = classify_bound_image(&p);
        assert_eq!(issues.len(), 1);
        assert!(
            issues[0].contains("no manifest digest"),
            "unexpected: {issues:?}"
        );
    }

    #[test]
    fn test_classify_tag_missing() {
        let p = BoundImageProbe {
            tag_present: false,
            oci_openable: false,
            ..healthy_probe()
        };
        let issues = classify_bound_image(&p);
        assert_eq!(issues.len(), 1);
        assert!(
            issues[0].contains("no composefs tag"),
            "unexpected: {issues:?}"
        );
    }

    #[test]
    fn test_classify_tag_present_open_fails() {
        let p = BoundImageProbe {
            oci_openable: false,
            ..healthy_probe()
        };
        let issues = classify_bound_image(&p);
        assert_eq!(issues.len(), 1);
        assert!(
            issues[0].contains("failed to open"),
            "unexpected: {issues:?}"
        );
    }

    // --- pending state tests ---

    /// A live probe whose commit is present but not synthesized is "pending".
    /// This represents the expected transient state right after
    /// `bootc image set-unified composefs` and before the first reboot.
    #[test]
    fn test_is_pending_live_not_synthesized() {
        let p = BoundImageProbe {
            synthesized: false,
            has_manifest_digest: false,
            tag_present: false,
            oci_openable: false,
            is_live: true,
            commit_present: true,
            ..healthy_probe()
        };
        assert!(
            is_pending(&p),
            "live + commit_present + !synthesized must be pending"
        );
        // classify produces issues (not-synthesized + downstream), but they should
        // not be treated as hard failures when pending.
        let issues = classify_bound_image(&p);
        assert!(
            !issues.is_empty(),
            "classify still returns issues for pending probe (callers suppress them)"
        );
    }

    /// A live probe with a MISSING commit is NOT pending — it is a genuine failure.
    #[test]
    fn test_is_pending_commit_missing_is_not_pending() {
        let p = BoundImageProbe {
            commit_present: false,
            synthesized: false,
            has_manifest_digest: false,
            tag_present: false,
            oci_openable: false,
            is_live: true,
            ..healthy_probe()
        };
        assert!(
            !is_pending(&p),
            "commit missing must NOT be pending — it is a real failure"
        );
        let issues = classify_bound_image(&p);
        assert_eq!(issues.len(), 1);
        assert!(issues[0].contains("ostree commit missing"));
    }

    /// A non-live probe (rollback / stale tag) that is not synthesized is NOT pending.
    #[test]
    fn test_is_pending_non_live_not_pending() {
        let p = BoundImageProbe {
            synthesized: false,
            is_live: false,
            ..healthy_probe()
        };
        assert!(
            !is_pending(&p),
            "non-live probe must not be classified as pending"
        );
    }

    /// A fully healthy (synthesized) live probe is not pending.
    #[test]
    fn test_is_pending_healthy_not_pending() {
        assert!(
            !is_pending(&healthy_probe()),
            "fully synthesized probe must not be pending"
        );
    }

    /// Data-driven table covering is_pending / classify combinations.
    #[test]
    fn test_pending_decision_table() {
        struct Case {
            is_live: bool,
            commit_present: bool,
            synthesized: bool,
            expect_pending: bool,
            desc: &'static str,
        }
        let cases = [
            Case {
                is_live: true,
                commit_present: true,
                synthesized: false,
                expect_pending: true,
                desc: "live, commit present, not synthesized → pending",
            },
            Case {
                is_live: true,
                commit_present: false,
                synthesized: false,
                expect_pending: false,
                desc: "live, commit MISSING → not pending (real failure)",
            },
            Case {
                is_live: false,
                commit_present: true,
                synthesized: false,
                expect_pending: false,
                desc: "non-live, not synthesized → not pending",
            },
            Case {
                is_live: true,
                commit_present: true,
                synthesized: true,
                expect_pending: false,
                desc: "live, synthesized → not pending (healthy)",
            },
        ];
        for c in &cases {
            let p = BoundImageProbe {
                is_live: c.is_live,
                commit_present: c.commit_present,
                synthesized: c.synthesized,
                has_manifest_digest: c.synthesized,
                tag_present: c.synthesized,
                oci_openable: c.synthesized,
                ..healthy_probe()
            };
            assert_eq!(is_pending(&p), c.expect_pending, "CASE: {}", c.desc);
        }
    }
}
