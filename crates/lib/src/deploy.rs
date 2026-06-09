//! Pull dispatch and deployment staging for the ostree backend.
//!
//! ## Planned Pull paths
//!
//! The top-level entry point for upgrade/switch will eventually select
//! among three paths based on the `unified` flag and filesystem capability:
//!
//! - **Unified + reflinks** (`unified = true`, XFS/btrfs): `pull_via_composefs_unified`
//!   — the planned three-store pipeline. Pulls into containers-storage first, then
//!   ZeroCopy into composefs, then synthesizes the ostree commit via FICLONE.
//!   See [`crate::store`] for the architecture diagram.
//!
//! - **Non-unified + reflinks** (`unified = false`, XFS/btrfs): `pull_via_composefs`
//!   — fetches from registry directly into composefs (no containers-storage),
//!   then synthesizes the ostree commit via FICLONE.
//!
//! - **No reflinks** (ext4): `pull` — the legacy ostree-native tar importer
//!   (`ostree_container::store::ImageImporter`).
//!
//! ## Planned composefs → ostree synthesis
//!
//! The synthesis plan relies on `import_from_composefs_repo` from
//! `ostree_ext::container::composefs_import` to walk the composefs
//! filesystem tree and for each regular file:
//!
//! 1. Reads uid/gid/mode/xattrs from composefs metadata. SELinux labels are
//!    computed in bulk before the walk via `selabel()` and looked up per-file;
//!    a NUL terminator is appended because composefs-rs omits it but the kernel
//!    stores it.
//! 2. Computes the ostree content checksum in-memory (SHA-256 of
//!    `uid:gid:mode:xattrs:file-content`).
//! 3. Issues `ioctl(FICLONE)` from the composefs object fd into a new `O_TMPFILE`
//!    in the ostree object directory.
//! 4. Applies metadata (`fchown`, `fchmod`, `fsetxattr`) and links the tmpfile
//!    into the ostree content-addressed path.
//!
//! `/etc` is remapped to `usr/etc`; virtual toplevel paths (`proc`, `sys`,
//! `dev`, etc.) are excluded — matching the ostree-container tar importer.
//!
//! ## Auto-detection
//!
//! `image_exists_in_unified_storage` checks whether the target image is already
//! present in bootc-owned containers-storage. Call sites use this to select
//! `unified = true` automatically without requiring an explicit flag from the
//! user once `bootc image set-unified full` has been run.

use std::collections::HashSet;
use std::io::{BufRead, Write};
use std::os::fd::AsFd;

use anyhow::{Context, Result, anyhow};
use bootc_kernel_cmdline::utf8::CmdlineOwned;
use cap_std::fs::{Dir, MetadataExt};
use cap_std_ext::cap_std;
use cap_std_ext::dirext::CapStdExtDirExt;
use fn_error_context::context;
use ostree::{gio, glib};
use ostree_container::OstreeImageReference;
use ostree_ext::container as ostree_container;
use ostree_ext::container::store::{
    ImageImporter, ImportProgress, META_COMPOSEFS_SYNTHESIZED, PrepareResult, PreparedImport,
};
use ostree_ext::keyfileext::KeyFileExt;
use ostree_ext::oci_spec::image::{Descriptor, Digest};
use ostree_ext::ostree::Deployment;
use ostree_ext::ostree::{self, Sysroot};
use ostree_ext::sysroot::SysrootLock;
use ostree_ext::tokio_util::spawn_blocking_cancellable_flatten;

use crate::progress_jsonl::{Event, ProgressWriter, SubTaskBytes, SubTaskStep};
use crate::spec::ImageReference;
use crate::spec::{BootOrder, HostSpec};
use crate::status::labels_of_config;
use crate::store::Storage;
use crate::utils::async_task_with_spinner;

// TODO use https://github.com/ostreedev/ostree-rs-ext/pull/493/commits/afc1837ff383681b947de30c0cefc70080a4f87a
const BASE_IMAGE_PREFIX: &str = "ostree/container/baseimage/bootc";

/// Group name in the ostree repo config that holds the composefs binding flag.
pub(crate) const COMPOSEFS_CONFIG_GROUP: &str = "composefs";

/// Key in the `[composefs]` group that records the ostree↔composefs binding.
///
/// When `true`, the ostree repo commit objects are synthesized from the
/// composefs tree rather than imported via the classic tar-based importer.
/// This signal lives in the repo config so it is intrinsic to the repository
/// itself (and therefore persists across deploys), separately from the
/// containers-storage participation flag in `composefs/bootc.json`.
pub(crate) const COMPOSEFS_CONFIG_UNIFIED: &str = "unified";

/// Read the ostree↔composefs binding flag (`[composefs] unified`) from the
/// ostree repo config.  Returns `false` if the key or group is absent.
pub(crate) fn ostree_composefs_bound(repo: &ostree::Repo) -> Result<bool> {
    let cfg = repo.copy_config();
    Ok(cfg
        .optional_bool(COMPOSEFS_CONFIG_GROUP, COMPOSEFS_CONFIG_UNIFIED)?
        .unwrap_or(false))
}

/// Idempotently set `[composefs] unified = true` in the ostree repo config.
///
/// This marks the ostree repo as bound to the composefs tree so that future
/// pulls know to use the composefs→ostree synthesis path.  The write is
/// skipped when the flag is already set to avoid an unnecessary fsync.
pub(crate) fn set_ostree_composefs_bound(repo: &ostree::Repo) -> Result<()> {
    if ostree_composefs_bound(repo)? {
        return Ok(());
    }
    let config = repo.copy_config();
    config.set_boolean(COMPOSEFS_CONFIG_GROUP, COMPOSEFS_CONFIG_UNIFIED, true);
    repo.write_config(&config)?;
    repo.reload_config(gio::Cancellable::NONE)?;
    Ok(())
}

/// Create an ImageProxyConfig with bootc's user agent prefix set.
///
/// This allows registries to distinguish "image pulls for bootc client runs"
/// from other skopeo/containers-image users.
pub(crate) fn new_proxy_config() -> ostree_ext::containers_image_proxy::ImageProxyConfig {
    let mut c = ostree_ext::containers_image_proxy::ImageProxyConfig::default();
    c.user_agent_prefix = Some(format!("bootc/{}", env!("CARGO_PKG_VERSION")));
    c
}

/// Set on an ostree commit if this is a derived commit
const BOOTC_DERIVED_KEY: &str = "bootc.derived";

/// Variant of HostSpec but required to be filled out
pub(crate) struct RequiredHostSpec<'a> {
    pub(crate) image: &'a ImageReference,
}

/// State of a locally fetched image
pub(crate) struct ImageState {
    pub(crate) manifest_digest: Digest,
    pub(crate) version: Option<String>,
    pub(crate) ostree_commit: String,
}

impl<'a> RequiredHostSpec<'a> {
    /// Given a (borrowed) host specification, "unwrap" its internal
    /// options, giving a spec that is required to have a base container image.
    pub(crate) fn from_spec(spec: &'a HostSpec) -> Result<Self> {
        let image = spec
            .image
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing image in specification"))?;
        Ok(Self { image })
    }
}

impl From<ostree_container::store::LayeredImageState> for ImageState {
    fn from(value: ostree_container::store::LayeredImageState) -> Self {
        let version = value.version().map(|v| v.to_owned());
        let ostree_commit = value.get_commit().to_owned();
        Self {
            manifest_digest: value.manifest_digest,
            version,
            ostree_commit,
        }
    }
}

impl ImageState {
    /// Fetch the manifest corresponding to this image.  May not be available in all backends.
    pub(crate) fn get_manifest(
        &self,
        repo: &ostree::Repo,
    ) -> Result<Option<ostree_ext::oci_spec::image::ImageManifest>> {
        ostree_container::store::query_image_commit(repo, &self.ostree_commit)
            .map(|v| Some(v.manifest))
    }
}

/// Wrapper for pulling a container image, wiring up status output.
pub(crate) async fn new_importer(
    repo: &ostree::Repo,
    imgref: &ostree_container::OstreeImageReference,
    booted_deployment: Option<&ostree::Deployment>,
) -> Result<ostree_container::store::ImageImporter> {
    let config = new_proxy_config();
    let mut imp = ostree_container::store::ImageImporter::new(repo, imgref, config).await?;
    imp.require_bootable();
    // We do our own GC/prune in deploy::prune(), so skip the importer's internal one.
    imp.disable_gc();
    if let Some(deployment) = booted_deployment {
        imp.set_sepolicy_commit(deployment.csum().to_string());
    }
    Ok(imp)
}

pub(crate) fn check_bootc_label(config: &ostree_ext::oci_spec::image::ImageConfiguration) {
    if let Some(label) =
        labels_of_config(config).and_then(|labels| labels.get(crate::metadata::BOOTC_COMPAT_LABEL))
    {
        match label.as_str() {
            crate::metadata::COMPAT_LABEL_V1 => {}
            o => crate::journal::journal_print(
                libsystemd::logging::Priority::Warning,
                &format!(
                    "notice: Unknown {} value {}",
                    crate::metadata::BOOTC_COMPAT_LABEL,
                    o
                ),
            ),
        }
    } else {
        crate::journal::journal_print(
            libsystemd::logging::Priority::Warning,
            &format!(
                "notice: Image is missing label: {}",
                crate::metadata::BOOTC_COMPAT_LABEL
            ),
        )
    }
}

fn descriptor_of_progress(p: &ImportProgress) -> &Descriptor {
    match p {
        ImportProgress::OstreeChunkStarted(l) => l,
        ImportProgress::OstreeChunkCompleted(l) => l,
        ImportProgress::DerivedLayerStarted(l) => l,
        ImportProgress::DerivedLayerCompleted(l) => l,
    }
}

fn prefix_of_progress(p: &ImportProgress) -> &'static str {
    match p {
        ImportProgress::OstreeChunkStarted(_) | ImportProgress::OstreeChunkCompleted(_) => {
            "ostree chunk"
        }
        ImportProgress::DerivedLayerStarted(_) | ImportProgress::DerivedLayerCompleted(_) => {
            "layer"
        }
    }
}

/// Configuration for layer progress printing
struct LayerProgressConfig {
    layers: tokio::sync::mpsc::Receiver<ostree_container::store::ImportProgress>,
    layer_bytes: tokio::sync::watch::Receiver<Option<ostree_container::store::LayerProgress>>,
    digest: Box<str>,
    n_layers_to_fetch: usize,
    layers_total: usize,
    bytes_to_download: u64,
    bytes_total: u64,
    prog: ProgressWriter,
    quiet: bool,
}

/// Write container fetch progress to standard output.
async fn handle_layer_progress_print(mut config: LayerProgressConfig) -> ProgressWriter {
    let start = std::time::Instant::now();
    let mut total_read = 0u64;
    let bar = indicatif::MultiProgress::new();
    if config.quiet {
        bar.set_draw_target(indicatif::ProgressDrawTarget::hidden());
    }
    let layers_bar = bar.add(indicatif::ProgressBar::new(
        config.n_layers_to_fetch.try_into().unwrap(),
    ));
    let byte_bar = bar.add(indicatif::ProgressBar::new(0));
    // let byte_bar = indicatif::ProgressBar::new(0);
    // byte_bar.set_draw_target(indicatif::ProgressDrawTarget::hidden());
    layers_bar.set_style(
        indicatif::ProgressStyle::default_bar()
            .template("{prefix} {bar} {pos}/{len} {wide_msg}")
            .unwrap(),
    );
    let taskname = "Fetching layers";
    layers_bar.set_prefix(taskname);
    layers_bar.set_message("");
    byte_bar.set_prefix("Fetching");
    byte_bar.set_style(
        indicatif::ProgressStyle::default_bar()
                .template(
                    " └ {prefix} {bar} {binary_bytes}/{binary_total_bytes} ({binary_bytes_per_sec}) {wide_msg}",
                )
                .unwrap()
        );

    let mut subtasks = vec![];
    let mut subtask: SubTaskBytes = Default::default();
    loop {
        tokio::select! {
            // Always handle layer changes first.
            biased;
            layer = config.layers.recv() => {
                if let Some(l) = layer {
                    let layer = descriptor_of_progress(&l);
                    let layer_type = prefix_of_progress(&l);
                    let short_digest = &layer.digest().digest()[0..21];
                    let layer_size = layer.size();
                    if l.is_starting() {
                        // Reset the progress bar
                        byte_bar.reset_elapsed();
                        byte_bar.reset_eta();
                        byte_bar.set_length(layer_size);
                        byte_bar.set_message(format!("{layer_type} {short_digest}"));

                        subtask = SubTaskBytes {
                            subtask: layer_type.into(),
                            description: format!("{layer_type}: {short_digest}").clone().into(),
                            id: short_digest.to_string().clone().into(),
                            bytes_cached: 0,
                            bytes: 0,
                            bytes_total: layer_size,
                        };
                    } else {
                        // Use the bar's length (actual blob size) rather than
                        // the manifest descriptor size for completion accounting.
                        let actual_size = byte_bar.length().unwrap_or(layer_size);
                        byte_bar.set_position(actual_size);
                        layers_bar.inc(1);
                        total_read = total_read.saturating_add(actual_size);
                        // Emit an event where bytes == total to signal completion.
                        subtask.bytes_total = actual_size;
                        subtask.bytes = actual_size;
                        subtasks.push(subtask.clone());
                        config.prog.send(Event::ProgressBytes {
                            task: "pulling".into(),
                            description: format!("Pulling Image: {}", config.digest).into(),
                            id: (*config.digest).into(),
                            bytes_cached: config.bytes_total - config.bytes_to_download,
                            bytes: total_read,
                            bytes_total: config.bytes_to_download,
                            steps_cached: (config.layers_total - config.n_layers_to_fetch) as u64,
                            steps: layers_bar.position(),
                            steps_total: config.n_layers_to_fetch as u64,
                            subtasks: subtasks.clone(),
                        }).await;
                    }
                } else {
                    // If the receiver is disconnected, then we're done
                    break
                };
            },
            r = config.layer_bytes.changed() => {
                if r.is_err() {
                    // If the receiver is disconnected, then we're done
                    break
                }
                let bytes = {
                    let bytes = config.layer_bytes.borrow_and_update();
                    bytes.as_ref().cloned()
                };
                if let Some(bytes) = bytes {
                    // Update the bar length from the actual blob size, which
                    // may differ from the manifest descriptor size (e.g.
                    // containers-storage stores layers uncompressed).
                    byte_bar.set_length(bytes.total);
                    byte_bar.set_position(bytes.fetched);
                    subtask.bytes_total = bytes.total;
                    subtask.bytes = byte_bar.position();
                    config.prog.send_lossy(Event::ProgressBytes {
                        task: "pulling".into(),
                        description: format!("Pulling Image: {}", config.digest).into(),
                        id: (*config.digest).into(),
                        bytes_cached: config.bytes_total - config.bytes_to_download,
                        bytes: total_read + byte_bar.position(),
                        bytes_total: config.bytes_to_download,
                        steps_cached: (config.layers_total - config.n_layers_to_fetch) as u64,
                        steps: layers_bar.position(),
                        steps_total: config.n_layers_to_fetch as u64,
                        subtasks: subtasks.clone().into_iter().chain([subtask.clone()]).collect(),
                    }).await;
                }
            }
        }
    }
    byte_bar.finish_and_clear();
    layers_bar.finish_and_clear();
    if let Err(e) = bar.clear() {
        tracing::warn!("clearing bar: {e}");
    }
    let end = std::time::Instant::now();
    let elapsed = end.duration_since(start);
    let persec = total_read as f64 / elapsed.as_secs_f64();
    let persec = indicatif::HumanBytes(persec as u64);
    if let Err(e) = bar.println(&format!(
        "Fetched layers: {} in {} ({}/s)",
        indicatif::HumanBytes(total_read),
        indicatif::HumanDuration(elapsed),
        persec,
    )) {
        tracing::warn!("writing to stdout: {e}");
    }

    // Since the progress notifier closed, we know import has started
    // use as a heuristic to begin import progress
    // Cannot be lossy or it is dropped
    config
        .prog
        .send(Event::ProgressSteps {
            task: "importing".into(),
            description: "Importing Image".into(),
            id: (*config.digest).into(),
            steps_cached: 0,
            steps: 0,
            steps_total: 1,
            subtasks: [SubTaskStep {
                subtask: "importing".into(),
                description: "Importing Image".into(),
                id: "importing".into(),
                completed: false,
            }]
            .into(),
        })
        .await;

    // Return the writer
    config.prog
}

/// Gather all bound images in all deployments, then prune the image store,
/// using the gathered images as the roots (that will not be GC'd).
pub(crate) async fn prune_container_store(sysroot: &Storage) -> Result<()> {
    let ostree = sysroot.get_ostree()?;
    let deployments = ostree.deployments();
    let mut all_bound_images = Vec::new();
    for deployment in deployments {
        let bound = crate::boundimage::query_bound_images_for_deployment(ostree, &deployment)?;
        all_bound_images.extend(bound.into_iter());
        // Also include the host image itself
        // Note: Use just the image name (not the full transport:image format) because
        // podman's image names don't include the transport prefix.
        if let Some(host_image) = crate::status::boot_entry_from_deployment(ostree, &deployment)?
            .image
            .map(|i| i.image)
        {
            all_bound_images.push(crate::boundimage::BoundImage {
                image: host_image.image.clone(),
                auth_file: None,
            });
        }
    }

    let imgstore = sysroot.get_ensure_imgstore()?;

    // Also protect images that have composefs tags — these are managed by the unified
    // storage pipeline and must not be pruned even if no live deployment currently
    // references them (e.g. after `bootc switch`). The composefs splitstreams depend
    // on the containers-storage data being present. Storage reconciles this binding;
    // see [`Storage::composefs_protected_image_names`].
    let composefs_protected = sysroot.composefs_protected_image_names().await?;

    let mut image_names: HashSet<&str> = all_bound_images
        .iter()
        .map(|img| img.image.as_str())
        .collect();
    image_names.extend(composefs_protected.iter().map(|s| s.as_str()));

    let pruned = imgstore.prune_except_roots(&image_names).await?;
    tracing::debug!("Pruned images: {}", pruned.len());
    Ok(())
}

/// Core disk space check: verify that `bytes_to_fetch` fits within available space,
/// leaving at least `min_free` bytes reserved.
fn check_disk_space_inner(
    fd: impl AsFd,
    bytes_to_fetch: u64,
    min_free: u64,
    imgref: &ImageReference,
) -> Result<()> {
    let stat = rustix::fs::fstatvfs(fd)?;
    let bytes_avail = stat.f_bsize.checked_mul(stat.f_bavail).unwrap_or(u64::MAX);
    let usable = bytes_avail.saturating_sub(min_free);
    tracing::trace!("bytes_avail: {bytes_avail} min_free: {min_free} usable: {usable}");

    if bytes_to_fetch > usable {
        anyhow::bail!(
            "Insufficient free space for {image} (available: {available} required: {required})",
            available = ostree_ext::glib::format_size(usable),
            required = ostree_ext::glib::format_size(bytes_to_fetch),
            image = imgref.image,
        );
    }
    Ok(())
}

/// Verify there is sufficient disk space to pull an image into the ostree repo.
/// Respects the repository's configured min-free-space threshold.
pub(crate) fn check_disk_space_ostree(
    repo: &ostree::Repo,
    image_meta: &PreparedImportMeta,
    imgref: &ImageReference,
) -> Result<()> {
    let min_free = repo.min_free_space_bytes().unwrap_or(0);
    check_disk_space_inner(
        repo.dfd_borrow(),
        image_meta.bytes_to_fetch,
        min_free,
        imgref,
    )
}

/// Verify there is sufficient disk space to pull an image into the composefs store
/// for the native composefs backend (uses a raw `ImageManifest`).
pub(crate) fn check_disk_space_composefs(
    cfs: &crate::store::ComposefsRepository,
    manifest: &ostree_ext::oci_spec::image::ImageManifest,
    imgref: &ImageReference,
) -> Result<()> {
    let bytes_to_fetch: u64 = manifest
        .layers()
        .iter()
        .map(|l: &ostree_ext::oci_spec::image::Descriptor| l.size())
        .sum();
    check_disk_space_inner(cfs.objects_dir()?, bytes_to_fetch, 0, imgref)
}

pub(crate) struct PreparedImportMeta {
    pub imp: ImageImporter,
    pub prep: Box<PreparedImport>,
    pub digest: Digest,
    pub n_layers_to_fetch: usize,
    pub layers_total: usize,
    pub bytes_to_fetch: u64,
    pub bytes_total: u64,
}

pub(crate) enum PreparedPullResult {
    Ready(Box<PreparedImportMeta>),
    AlreadyPresent(Box<ImageState>),
}

pub(crate) async fn prepare_for_pull(
    repo: &ostree::Repo,
    imgref: &ImageReference,
    target_imgref: Option<&OstreeImageReference>,
    booted_deployment: Option<&ostree::Deployment>,
) -> Result<PreparedPullResult> {
    let imgref_canonicalized = imgref.clone().canonicalize()?;
    tracing::debug!("Canonicalized image reference: {imgref_canonicalized:#}");
    let ostree_imgref = &OstreeImageReference::from(imgref_canonicalized);
    let mut imp = new_importer(repo, ostree_imgref, booted_deployment).await?;
    if let Some(target) = target_imgref {
        imp.set_target(target);
    }
    let prep = match imp.prepare().await? {
        PrepareResult::AlreadyPresent(c) => {
            println!("No changes in {imgref:#} => {}", c.manifest_digest);
            return Ok(PreparedPullResult::AlreadyPresent(Box::new((*c).into())));
        }
        PrepareResult::Ready(p) => p,
    };
    check_bootc_label(&prep.config);
    if let Some(warning) = prep.deprecated_warning() {
        ostree_ext::cli::print_deprecated_warning(warning).await;
    }
    ostree_ext::cli::print_layer_status(&prep);
    let layers_to_fetch = prep.layers_to_fetch().collect::<Result<Vec<_>>>()?;

    let prepared_image = PreparedImportMeta {
        imp,
        n_layers_to_fetch: layers_to_fetch.len(),
        layers_total: prep.all_layers().count(),
        bytes_to_fetch: layers_to_fetch.iter().map(|(l, _)| l.layer.size()).sum(),
        bytes_total: prep.all_layers().map(|l| l.layer.size()).sum(),
        digest: prep.manifest_digest.clone(),
        prep,
    };

    Ok(PreparedPullResult::Ready(Box::new(prepared_image)))
}

/// Check whether unified base-image storage is enabled on this system.
///
/// Returns `true` iff `composefs/bootc.json` exists and has `unified-storage: true`.
/// This is the authoritative signal written by `bootc image set-unified full` (and by
/// `bootc install --experimental-unified-storage`).
///
/// If the composefs repository doesn't exist yet, the file is absent and this
/// returns `false` — a single cheap file-open attempt with no side effects.
pub(crate) fn unified_storage_enabled(store: &Storage) -> Result<bool> {
    Ok(crate::store::BootcRepoMeta::read(&store.physical_root)?
        .map(|m| m.unified != crate::spec::UnifiedStorageState::Disabled)
        .unwrap_or(false))
}

/// The ostree↔composefs storage binding state of the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BindingState {
    /// Classic ostree: no composefs binding, no containers-storage participation.
    Disabled,
    /// ostree commit synthesized from the composefs tree, but the image is NOT
    /// in bootc-owned containers-storage (not visible to `podman run`).
    BoundOnly,
    /// Bound AND participating in containers-storage.
    Unified,
}

/// Pure classification of a (bound, cstorage) pair into a [`BindingState`].
///
/// Extracted into its own function so it can be unit-tested without a live
/// `Storage` or `ostree::Repo`.
pub(crate) fn classify_binding(bound: bool, cstorage: bool) -> BindingState {
    match (bound, cstorage) {
        (false, _) => BindingState::Disabled,
        (true, false) => BindingState::BoundOnly,
        (true, true) => BindingState::Unified,
    }
}

/// Derive the binding state from both signals: the `[composefs] unified` repo
/// config key (binding) and `BootcRepoMeta.unified` (containers-storage).
///
/// Backward compat: systems onboarded before the repo-config signal existed
/// have `BootcRepoMeta.unified != Disabled` but NO repo key — so cstorage
/// participation implies the binding.  The OR below is load-bearing.
///
/// On a native composefs system there is no ostree repo; `get_ostree()` errors
/// and we treat the binding signal as absent.
pub(crate) fn binding_state(store: &Storage) -> Result<BindingState> {
    let cstorage = unified_storage_enabled(store)?;
    let bound_cfg = match store.get_ostree() {
        Ok(ostree) => ostree_composefs_bound(&ostree.repo())?,
        Err(_) => false,
    };
    let bound = bound_cfg || cstorage;
    Ok(classify_binding(bound, cstorage))
}

/// Full unified pipeline: containers-storage → composefs → ostree.
///
/// Stage 1: Pull the image into bootc-owned containers-storage.
/// Stage 2: Zero-copy import from containers-storage into the composefs OCI repo.
/// Stage 3: Synthesize an ostree commit from the composefs filesystem tree.
///
/// This is the implementation of `--experimental-unified-storage` for the ostree backend.
pub(crate) async fn pull_via_composefs(
    repo: &ostree::Repo,
    imgref: &ImageReference,
    store: &Storage,
    local_fetch: composefs_ctl::composefs_oci::LocalFetchOpt,
    cstorage: bool,
) -> Result<Box<ImageState>> {
    use composefs_ctl::composefs_oci;
    use composefs_ctl::composefs_oci::oci_image::OciImage;
    use composefs_ctl::composefs_oci::{LocalFetchOpt, PullOptions, tag_image};
    use ostree_ext::container::composefs_import;
    use ostree_ext::container::store::ref_for_image;

    // Short-circuit if the image is already present and unchanged.
    //
    // This mirrors the classic (non-unified) pull path: cheaply resolve the
    // remote manifest digest and compare it against the ostree ref for *this*
    // image (the synthesized commit records its manifest digest). If unchanged
    // we return the existing state immediately, avoiding a wasteful network
    // re-pull, a redundant composefs re-import, and synthesizing a fresh ostree
    // commit for an identical image. Comparing against this image's own ref
    // (rather than the booted commit) keeps `switch` and first-time `install`
    // correct: a never-seen image has no ref and falls through to a full pull.
    //
    // Skip this for the `containers-storage` transport: `prepare()` resolves the
    // reference via the default host storage proxy, which cannot see images that
    // live only in the bootc-owned store (e.g. one built with `bootc image cmd
    // build`). Stage 1's `pull_from_containers_storage` already has its own cheap
    // skip-if-present check against the bootc store, so the redundant-work guard
    // is preserved there.
    if imgref.transport != "containers-storage" {
        let ostree_imgref = OstreeImageReference::from(imgref.clone().canonicalize()?);
        let mut imp = new_importer(repo, &ostree_imgref, None).await?;
        if let PrepareResult::AlreadyPresent(state) = imp.prepare().await? {
            // Guard: only short-circuit when the existing commit was synthesized
            // via the composefs→ostree path.  If it is a *classic* ostree commit
            // (no META_COMPOSEFS_SYNTHESIZED flag), we must NOT skip the pipeline
            // — the composefs repo has not been populated and the repo-config
            // binding key has not been written.  This is the case on a system
            // booted classically that runs `bootc image set-unified composefs`:
            // prepare() resolves the ostree ref and returns AlreadyPresent, but
            // the commit was imported the old way and must be re-synthesized.
            let existing_commit = state.get_commit();
            let commit_obj = repo.load_commit(existing_commit)?.0;
            let commit_meta_variant = commit_obj.child_value(0);
            let commit_meta = glib::VariantDict::new(Some(&commit_meta_variant));
            let is_synthesized = commit_meta
                .lookup::<bool>(META_COMPOSEFS_SYNTHESIZED)?
                .unwrap_or(false);
            if is_synthesized {
                tracing::info!(
                    "Composefs unified pull: synthesized image already present, skipping: {}",
                    state.manifest_digest
                );
                // Ensure the repo-config binding key is set in case this is a
                // Disabled→bind transition on an already-synthesized commit.
                set_ostree_composefs_bound(repo)
                    .context("Writing composefs binding to ostree repo config")?;
                return Ok(Box::new((*state).into()));
            }
            tracing::info!(
                "Composefs unified pull: existing commit is classic (non-synthesized), \
                 falling through to full pipeline: {}",
                state.manifest_digest
            );
        }
    }

    // Stage 1 (optional): pull into bootc-owned containers-storage.
    //
    // When `cstorage` is false we skip this entirely and pull directly from the
    // source transport in Stage 2.  When `cstorage` is true we follow the
    // existing three-store pipeline.
    //
    // The ensure_floating_c_storage_initialized() call must come first so that
    // libpod's database is set up with the correct static_dir before any image
    // operations (avoids code 125 mismatch on `podman image exists`).
    if cstorage {
        crate::podstorage::ensure_floating_c_storage_initialized();
        let imgstore = store.get_ensure_imgstore()?;
        let image_ref_str = imgref.to_transport_image()?;
        tracing::info!(
            "Composefs unified pull: staging {} into containers-storage",
            imgref.image
        );
        if imgref.transport == "containers-storage" {
            imgstore
                .pull_from_containers_storage(&imgref.image)
                .await
                .context("Copying image from host containers-storage into bootc storage")?;
        } else {
            imgstore
                .pull_with_progress(&image_ref_str)
                .await
                .context("Pulling image into bootc containers-storage")?;
        }
    }

    // Stage 2: import the image into the composefs OCI repo.
    let cfs_repo = store.get_ensure_composefs()?;
    let pull_result = if cstorage {
        // Zero-copy import from bootc-owned containers-storage.
        let imgstore = store.get_ensure_imgstore()?;
        let image_ref_str = imgref.to_transport_image()?;
        let image_id = imgstore
            .image_id(&image_ref_str)
            .await
            .context("Resolving containers-storage image id for composefs import")?;
        let cstor_imgref_str = format!("containers-storage:{image_id}");
        let storage_path = format!(
            "{}/{}",
            store.physical_root_path,
            crate::podstorage::CStorage::subpath()
        );
        tracing::info!(
            "Composefs unified pull: importing {} into composefs repo (zero-copy)",
            cstor_imgref_str
        );
        let pull_opts = PullOptions {
            local_fetch,
            storage_root: Some(std::path::Path::new(&storage_path)),
            ..Default::default()
        };
        composefs_oci::pull(&cfs_repo, &cstor_imgref_str, None, pull_opts)
            .await
            .context("Importing from containers-storage into composefs repo")?
    } else {
        // Bound-only: pull directly from the source transport into composefs.
        // Use the typed containers_image_proxy::ImageReference so the resulting
        // string includes the transport prefix (e.g. "docker://quay.io/…") that
        // composefs_oci::pull requires.  Passing a bare registry hostname such as
        // "quay.io/…" (which is what to_transport_image() returns for registry
        // transport) causes composefs_oci::pull to split on ":" and interpret the
        // hostname as a transport name → "Invalid transport: quay.io".
        let proxy_ref = imgref.to_image_proxy_ref()?;
        let imgref_str = proxy_ref.to_string();
        tracing::info!(
            "Composefs bound pull: fetching {} directly into composefs repo",
            imgref.image
        );
        composefs_oci::pull(&cfs_repo, &imgref_str, None, PullOptions::default())
            .await
            .context("Pulling image directly into composefs repo")?
    };

    // Tag the manifest as a GC root in the composefs repo.
    let tag = crate::bootc_composefs::repo::bootc_tag_for_manifest(
        &pull_result.manifest_digest.to_string(),
    );
    tag_image(&*cfs_repo, &pull_result.manifest_digest, &tag)
        .context("Tagging pulled image as bootc GC root in composefs repo")?;

    // Open the OCI image to retrieve manifest + config for the ostree synthesis.
    let oci_image = OciImage::open(&cfs_repo, &pull_result.manifest_digest, None)
        .context("Opening OCI image from composefs repo")?;
    let manifest = oci_image.manifest().clone();
    let config = oci_image
        .config()
        .cloned()
        .context("OCI image has no config (artifact, not a container image)")?;

    let manifest_digest_str = pull_result.manifest_digest.to_string();

    // Stage 3: synthesize ostree commit from composefs tree (blocking, CPU-bound).
    tracing::info!(
        "Composefs unified pull: synthesizing ostree commit from composefs tree (digest {})",
        manifest_digest_str
    );
    let repo_clone = repo.clone();
    let cfs_repo_clone = std::sync::Arc::clone(&cfs_repo);
    let config_digest = pull_result.config_digest.clone();
    let manifest_digest_str2 = manifest_digest_str.clone();
    let ostree_commit = tokio::task::spawn_blocking(move || {
        composefs_import::import_from_composefs_repo(
            &repo_clone,
            &cfs_repo_clone,
            &config_digest,
            &manifest_digest_str2,
            &manifest,
            &config,
            local_fetch == LocalFetchOpt::ZeroCopy,
        )
    })
    .await
    .context("join error in composefs→ostree import task")?
    .context("Synthesizing ostree commit from composefs tree")?;

    // Write the ostree ref so the deployment machinery can find the commit.
    {
        let ostree_imgref = OstreeImageReference::from(imgref.clone());
        let ostree_ref =
            ref_for_image(&ostree_imgref.imgref).context("Computing ostree ref for image")?;
        let txn = repo
            .auto_transaction(gio::Cancellable::NONE)
            .context("Beginning ostree transaction for ref write")?;
        repo.transaction_set_ref(None, &ostree_ref, Some(ostree_commit.as_str()));
        txn.commit(gio::Cancellable::NONE)
            .context("Committing ostree ref transaction")?;
    }

    // Extract version from the config labels.
    let version = oci_image
        .config()
        .and_then(|cfg| ostree_ext::container::version_for_config(cfg))
        .map(|s| s.to_owned());

    // Parse the manifest digest into the oci_spec::image::Digest type that
    // ImageState expects.  The string is already in "sha256:..." format.
    let manifest_digest: Digest = manifest_digest_str
        .parse()
        .with_context(|| format!("Parsing manifest digest {manifest_digest_str}"))?;

    // Always set the [composefs] unified = true binding signal in the ostree
    // repo config.  This records that the repo's commit objects are synthesized
    // from the composefs tree, persisting the binding across future deploys.
    set_ostree_composefs_bound(repo).context("Writing composefs binding to ostree repo config")?;

    // Only write composefs/bootc.json when containers-storage is active.
    // For bound-only pulls we must not touch (or create) this file — doing so
    // would incorrectly signal cstorage participation on a system that has none,
    // and would downgrade an existing Unified system if called in that path.
    if cstorage {
        crate::store::ensure_composefs_dir(&store.physical_root)?;
        let mut meta = crate::store::BootcRepoMeta::read(&store.physical_root)?.unwrap_or_default();
        meta.version = 1;
        meta.unified = if local_fetch == LocalFetchOpt::ZeroCopy {
            crate::spec::UnifiedStorageState::Enabled
        } else {
            crate::spec::UnifiedStorageState::EnabledWithCopy
        };
        meta.write(&store.physical_root)
            .context("Writing unified-storage flag after composefs pull")?;
    }

    tracing::info!(
        "Composefs unified pull complete: commit {} digest {}",
        ostree_commit,
        manifest_digest
    );

    Ok(Box::new(ImageState {
        manifest_digest,
        version,
        ostree_commit,
    }))
}

#[context("Pulling")]
pub(crate) async fn pull_from_prepared(
    imgref: &ImageReference,
    quiet: bool,
    prog: ProgressWriter,
    mut prepared_image: PreparedImportMeta,
) -> Result<Box<ImageState>> {
    let layer_progress = prepared_image.imp.request_progress();
    let layer_byte_progress = prepared_image.imp.request_layer_progress();
    let digest = prepared_image.digest.clone();
    let digest_imp = prepared_image.digest.clone();

    let printer = tokio::task::spawn(async move {
        handle_layer_progress_print(LayerProgressConfig {
            layers: layer_progress,
            layer_bytes: layer_byte_progress,
            digest: digest.as_ref().into(),
            n_layers_to_fetch: prepared_image.n_layers_to_fetch,
            layers_total: prepared_image.layers_total,
            bytes_to_download: prepared_image.bytes_to_fetch,
            bytes_total: prepared_image.bytes_total,
            prog,
            quiet,
        })
        .await
    });
    let import = prepared_image.imp.import(prepared_image.prep).await;
    let prog = printer.await?;
    // Both the progress and the import are done, so import is done as well
    prog.send(Event::ProgressSteps {
        task: "importing".into(),
        description: "Importing Image".into(),
        id: digest_imp.clone().as_ref().into(),
        steps_cached: 0,
        steps: 1,
        steps_total: 1,
        subtasks: [SubTaskStep {
            subtask: "importing".into(),
            description: "Importing Image".into(),
            id: "importing".into(),
            completed: true,
        }]
        .into(),
    })
    .await;
    let import = import?;
    let imgref_canonicalized = imgref.clone().canonicalize()?;
    tracing::debug!("Canonicalized image reference: {imgref_canonicalized:#}");

    // Log successful import completion (skip if using unified storage to avoid double logging)
    let is_unified_path = imgref.transport == "containers-storage";
    if !is_unified_path {
        const IMPORT_COMPLETE_JOURNAL_ID: &str = "7e957f234eaa4933911c79921141f036";

        tracing::info!(
            message_id = IMPORT_COMPLETE_JOURNAL_ID,
            bootc.image.reference = &imgref.image,
            bootc.image.transport = &imgref.transport,
            bootc.manifest_digest = import.manifest_digest.as_ref(),
            bootc.ostree_commit = &import.merge_commit,
            "Successfully imported image: {}",
            imgref
        );
    }

    if let Some(msg) =
        ostree_container::store::image_filtered_content_warning(&import.filtered_files)
            .context("Image content warning")?
    {
        tracing::info!("{}", msg);
    }
    Ok(Box::new((*import).into()))
}

/// Wrapper for pulling a container image, wiring up status output.
pub(crate) async fn pull(
    repo: &ostree::Repo,
    imgref: &ImageReference,
    target_imgref: Option<&OstreeImageReference>,
    quiet: bool,
    prog: ProgressWriter,
    booted_deployment: Option<&ostree::Deployment>,
) -> Result<Box<ImageState>> {
    match prepare_for_pull(repo, imgref, target_imgref, booted_deployment).await? {
        PreparedPullResult::AlreadyPresent(existing) => {
            // Log that the image was already present (Debug level since it's not actionable)
            const IMAGE_ALREADY_PRESENT_ID: &str = "3d9f60e7e6764fea915eda15487a09e9";
            tracing::debug!(
                message_id = IMAGE_ALREADY_PRESENT_ID,
                bootc.image.reference = &imgref.image,
                bootc.image.transport = &imgref.transport,
                bootc.status = "already_present",
                "Image already present: {}",
                imgref
            );
            Ok(existing)
        }
        PreparedPullResult::Ready(prepared_image_meta) => {
            // Check disk space before attempting to pull
            check_disk_space_ostree(repo, &prepared_image_meta, imgref)?;
            // Log that we're pulling a new image
            const PULLING_NEW_IMAGE_ID: &str = "c9784b417efb49009602f81064cfd4ad";
            tracing::info!(
                message_id = PULLING_NEW_IMAGE_ID,
                bootc.image.reference = &imgref.image,
                bootc.image.transport = &imgref.transport,
                bootc.status = "pulling_new",
                "Pulling new image: {}",
                imgref
            );
            Ok(pull_from_prepared(imgref, quiet, prog, *prepared_image_meta).await?)
        }
    }
}

pub(crate) async fn wipe_ostree(sysroot: Sysroot) -> Result<()> {
    tokio::task::spawn_blocking(move || {
        sysroot
            .write_deployments(&[], gio::Cancellable::NONE)
            .context("removing deployments")
    })
    .await??;

    Ok(())
}

/// Prune composefs objects no longer referenced by any live deployment.
///
/// This is a no-op if unified storage is not enabled or the composefs
/// repository doesn't exist yet.
///
/// On an ostree+unified-storage system every `bootc upgrade` tags the newly
/// pulled manifest in the composefs repo (`localhost/bootc-sha256:<digest>`).
/// After the ostree prune step those old tags are no longer anchored to any
/// deployment.  This function:
///
/// 1. Collects the manifest digests of all current ostree deployments.
/// 2. Untagges any composefs bootc-tag whose digest is not in that set.
/// 3. Runs `repo.gc()` to drop orphaned splitstream objects.
#[context("Pruning composefs store")]
async fn prune_composefs_store(sysroot: &Storage) -> Result<()> {
    // Prune applies to any system with an active composefs binding (BoundOnly or
    // Unified); only skip on pure classic ostree (Disabled).
    if matches!(binding_state(sysroot)?, BindingState::Disabled) {
        return Ok(());
    }
    let cfs_repo = match sysroot.get_ensure_composefs() {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("Composefs repo not available, skipping prune: {e}");
            return Ok(());
        }
    };

    let ostree = match sysroot.get_ostree() {
        Ok(o) => o,
        Err(_) => return Ok(()),
    };
    let repo = ostree.repo();

    // Collect manifest digests from all current ostree deployments.
    // Deployments pulled via pull_via_composefs store META_MANIFEST_DIGEST
    // (`ostree.manifest-digest`) in their commit metadata.
    let mut live_digests: std::collections::HashSet<String> = std::collections::HashSet::new();
    for deployment in ostree.deployments() {
        let commit_str = deployment.csum();
        match repo.load_commit(commit_str.as_str()) {
            Ok((commitv, _)) => {
                match ostree_ext::container::store::manifest_digest_from_commit(&commitv) {
                    Ok(digest) => {
                        live_digests.insert(digest.to_string());
                    }
                    Err(e) => {
                        // Not every deployment was pulled via composefs; skip gracefully.
                        tracing::debug!("No manifest digest in commit {commit_str}: {e}");
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to load commit {commit_str}: {e}");
            }
        }
    }

    // The composefs repository API is synchronous; move the work off the
    // async executor thread.
    let cfs_repo = std::sync::Arc::clone(&cfs_repo);
    tokio::task::spawn_blocking(move || -> Result<()> {
        use crate::composefs_consts::BOOTC_TAG_PREFIX;
        use composefs_ctl::composefs_oci;

        let all_tags =
            composefs_oci::list_refs(&*cfs_repo).context("Listing composefs OCI refs")?;

        let mut untagged = 0usize;
        for (tag_name, _manifest_digest) in &all_tags {
            if !tag_name.starts_with(BOOTC_TAG_PREFIX) {
                // Not a bootc-owned tag; leave it for the user / other tools.
                continue;
            }
            // The tag is `localhost/bootc-sha256:<hex>`.  Strip the prefix to
            // recover the canonical digest string (`sha256:<hex>`).
            let digest_str = tag_name
                .strip_prefix(BOOTC_TAG_PREFIX)
                .expect("checked above");
            if !live_digests.contains(digest_str) {
                tracing::debug!("Removing unreferenced composefs bootc tag: {tag_name}");
                composefs_oci::untag_image(&*cfs_repo, tag_name)
                    .with_context(|| format!("Removing composefs tag {tag_name}"))?;
                untagged += 1;
            }
        }

        if untagged > 0 {
            tracing::info!("Removed {untagged} unreferenced composefs tag(s); running GC");
            let gc_result = cfs_repo.gc(&[]).context("Running composefs GC")?;
            tracing::debug!("Composefs GC result: {:?}", gc_result);
        } else {
            tracing::debug!("No unreferenced composefs tags; skipping GC");
        }

        Ok(())
    })
    .await
    .context("composefs prune task join error")?
}

pub(crate) async fn cleanup(sysroot: &Storage) -> Result<()> {
    // Log the cleanup operation to systemd journal
    const CLEANUP_JOURNAL_ID: &str = "c0ce56c6c48e4055bca6a88e01b2b15d";

    tracing::info!(
        message_id = CLEANUP_JOURNAL_ID,
        "Starting cleanup of old images and deployments"
    );

    let bound_prune = prune_container_store(sysroot);

    // We create clones (just atomic reference bumps) here to move to the thread.
    let ostree = sysroot.get_ostree_cloned()?;
    let repo = ostree.repo();
    let repo_prune =
        ostree_ext::tokio_util::spawn_blocking_cancellable_flatten(move |cancellable| {
            let locked_sysroot = &SysrootLock::from_assumed_locked(&ostree);
            let cancellable = Some(cancellable);
            let repo = &repo;
            let txn = repo.auto_transaction(cancellable)?;
            let repo = txn.repo();

            // Regenerate our base references.  First, we delete the ones that exist
            for ref_entry in repo
                .list_refs_ext(
                    Some(BASE_IMAGE_PREFIX),
                    ostree::RepoListRefsExtFlags::NONE,
                    cancellable,
                )
                .context("Listing refs")?
                .keys()
            {
                repo.transaction_set_refspec(ref_entry, None);
            }

            // Then, for each deployment which is derived (e.g. has configmaps) we synthesize
            // a base ref to ensure that it's not GC'd.
            for (i, deployment) in ostree.deployments().into_iter().enumerate() {
                let commit = deployment.csum();
                if let Some(base) = get_base_commit(repo, &commit)? {
                    repo.transaction_set_refspec(&format!("{BASE_IMAGE_PREFIX}/{i}"), Some(&base));
                }
            }

            let pruned =
                ostree_container::deploy::prune(locked_sysroot).context("Pruning images")?;
            if !pruned.is_empty() {
                let size = glib::format_size(pruned.objsize);
                println!(
                    "Pruned images: {} (layers: {}, objsize: {})",
                    pruned.n_images, pruned.n_layers, size
                );
            } else {
                tracing::debug!("Nothing to prune");
            }

            Ok(())
        });

    // We run these in parallel mostly because we can.
    tokio::try_join!(repo_prune, bound_prune)?;

    // After ostree prune, clean up any stale composefs tags and GC orphaned
    // splitstream objects on unified-storage systems.
    prune_composefs_store(sysroot)
        .await
        .context("Pruning composefs store")?;

    Ok(())
}

/// If commit is a bootc-derived commit (e.g. has configmaps), return its base.
#[context("Finding base commit")]
pub(crate) fn get_base_commit(repo: &ostree::Repo, commit: &str) -> Result<Option<String>> {
    let commitv = repo.load_commit(commit)?.0;
    let commitmeta = commitv.child_value(0);
    let commitmeta = &glib::VariantDict::new(Some(&commitmeta));
    let r = commitmeta.lookup::<String>(BOOTC_DERIVED_KEY)?;
    Ok(r)
}

#[context("Writing deployment")]
async fn deploy(
    sysroot: &Storage,
    from: MergeState,
    image: &ImageState,
    origin: &glib::KeyFile,
    lock_finalization: bool,
) -> Result<Deployment> {
    // Compute the kernel argument overrides. In practice today this API is always expecting
    // a merge deployment. The kargs code also always looks at the booted root (which
    // is a distinct minor issue, but not super important as right now the install path
    // doesn't use this API).
    let (stateroot, override_kargs) = match &from {
        MergeState::MergeDeployment(deployment) => {
            let kargs = crate::bootc_kargs::get_kargs(sysroot, &deployment, image)?;
            (deployment.stateroot().into(), Some(kargs))
        }
        MergeState::Reset { stateroot, kargs } => (stateroot.clone(), Some(kargs.clone())),
    };
    // Clone all the things to move to worker thread
    let ostree = sysroot.get_ostree_cloned()?;
    // ostree::Deployment is incorrectly !Send 😢 so convert it to an integer
    let merge_deployment = from.as_merge_deployment();
    let merge_deployment = merge_deployment.map(|d| d.index() as usize);
    let ostree_commit = image.ostree_commit.to_string();
    // GKeyFile also isn't Send! So we serialize that as a string...
    let origin_data = origin.to_data();
    let r = async_task_with_spinner(
        "Deploying",
        spawn_blocking_cancellable_flatten(move |cancellable| -> Result<_> {
            let ostree = ostree;
            let stateroot = Some(stateroot);
            let mut opts = ostree::SysrootDeployTreeOpts::default();

            // Set finalization lock if requested
            opts.locked = lock_finalization;

            // Because the C API expects a Vec<&str>, convert the Cmdline to string slices.
            // The references borrow from the Cmdline, which outlives this usage.
            let override_kargs_refs = override_kargs
                .as_ref()
                .map(|kargs| kargs.iter_str().collect::<Vec<_>>());
            if let Some(kargs) = override_kargs_refs.as_ref() {
                opts.override_kernel_argv = Some(kargs);
            }

            let deployments = ostree.deployments();
            let merge_deployment = merge_deployment.map(|m| &deployments[m]);
            let origin = glib::KeyFile::new();
            origin.load_from_data(&origin_data, glib::KeyFileFlags::NONE)?;
            let d = ostree.stage_tree_with_options(
                stateroot.as_deref(),
                &ostree_commit,
                Some(&origin),
                merge_deployment,
                &opts,
                Some(cancellable),
            )?;
            Ok(d.index())
        }),
    )
    .await?;
    // SAFETY: We must have a staged deployment
    let ostree = sysroot.get_ostree()?;
    let staged = ostree.staged_deployment().unwrap();
    assert_eq!(staged.index(), r);
    Ok(staged)
}

#[context("Generating origin")]
fn origin_from_imageref(imgref: &ImageReference) -> Result<glib::KeyFile> {
    let origin = glib::KeyFile::new();
    let imgref = OstreeImageReference::from(imgref.clone());
    origin.set_string(
        "origin",
        ostree_container::deploy::ORIGIN_CONTAINER,
        imgref.to_string().as_str(),
    );
    Ok(origin)
}

/// The source of data for staging a new deployment
#[derive(Debug)]
pub(crate) enum MergeState {
    /// Use the provided merge deployment
    MergeDeployment(Deployment),
    /// Don't use a merge deployment, but only this
    /// provided initial state.
    Reset {
        stateroot: String,
        kargs: CmdlineOwned,
    },
}
impl MergeState {
    /// Initialize using the default merge deployment for the given stateroot.
    pub(crate) fn from_stateroot(sysroot: &Storage, stateroot: &str) -> Result<Self> {
        let ostree = sysroot.get_ostree()?;
        let merge_deployment = ostree.merge_deployment(Some(stateroot)).ok_or_else(|| {
            anyhow::anyhow!("No merge deployment found for stateroot {stateroot}")
        })?;
        Ok(Self::MergeDeployment(merge_deployment))
    }

    /// Cast this to a merge deployment case.
    pub(crate) fn as_merge_deployment(&self) -> Option<&Deployment> {
        match self {
            Self::MergeDeployment(d) => Some(d),
            Self::Reset { .. } => None,
        }
    }
}

/// Stage (queue deployment of) a fetched container image.
#[context("Staging")]
pub(crate) async fn stage(
    sysroot: &Storage,
    from: MergeState,
    image: &ImageState,
    spec: &RequiredHostSpec<'_>,
    prog: ProgressWriter,
    lock_finalization: bool,
) -> Result<()> {
    // Log the staging operation to systemd journal with comprehensive upgrade information
    const STAGE_JOURNAL_ID: &str = "8f7a2b1c3d4e5f6a7b8c9d0e1f2a3b4c";

    tracing::info!(
        message_id = STAGE_JOURNAL_ID,
        bootc.image.reference = &spec.image.image,
        bootc.image.transport = &spec.image.transport,
        bootc.manifest_digest = image.manifest_digest.as_ref(),
        "Staging image for deployment: {} (digest: {})",
        spec.image,
        image.manifest_digest
    );

    let mut subtask = SubTaskStep {
        subtask: "merging".into(),
        description: "Merging Image".into(),
        id: "fetching".into(),
        completed: false,
    };
    let mut subtasks = vec![];
    prog.send(Event::ProgressSteps {
        task: "staging".into(),
        description: "Deploying Image".into(),
        id: image.manifest_digest.clone().as_ref().into(),
        steps_cached: 0,
        steps: 0,
        steps_total: 3,
        subtasks: subtasks
            .clone()
            .into_iter()
            .chain([subtask.clone()])
            .collect(),
    })
    .await;

    subtask.completed = true;
    subtasks.push(subtask.clone());
    subtask.subtask = "deploying".into();
    subtask.id = "deploying".into();
    subtask.description = "Deploying Image".into();
    subtask.completed = false;
    prog.send(Event::ProgressSteps {
        task: "staging".into(),
        description: "Deploying Image".into(),
        id: image.manifest_digest.clone().as_ref().into(),
        steps_cached: 0,
        steps: 1,
        steps_total: 3,
        subtasks: subtasks
            .clone()
            .into_iter()
            .chain([subtask.clone()])
            .collect(),
    })
    .await;
    let origin = origin_from_imageref(spec.image)?;
    let deployment =
        crate::deploy::deploy(sysroot, from, image, &origin, lock_finalization).await?;

    subtask.completed = true;
    subtasks.push(subtask.clone());
    subtask.subtask = "bound_images".into();
    subtask.id = "bound_images".into();
    subtask.description = "Pulling Bound Images".into();
    subtask.completed = false;
    prog.send(Event::ProgressSteps {
        task: "staging".into(),
        description: "Deploying Image".into(),
        id: image.manifest_digest.clone().as_ref().into(),
        steps_cached: 0,
        steps: 1,
        steps_total: 3,
        subtasks: subtasks
            .clone()
            .into_iter()
            .chain([subtask.clone()])
            .collect(),
    })
    .await;
    crate::boundimage::pull_bound_images(sysroot, &deployment).await?;

    subtask.completed = true;
    subtasks.push(subtask.clone());
    subtask.subtask = "cleanup".into();
    subtask.id = "cleanup".into();
    subtask.description = "Removing old images".into();
    subtask.completed = false;
    prog.send(Event::ProgressSteps {
        task: "staging".into(),
        description: "Deploying Image".into(),
        id: image.manifest_digest.clone().as_ref().into(),
        steps_cached: 0,
        steps: 2,
        steps_total: 3,
        subtasks: subtasks
            .clone()
            .into_iter()
            .chain([subtask.clone()])
            .collect(),
    })
    .await;
    crate::deploy::cleanup(sysroot).await?;
    println!("Queued for next boot: {:#}", spec.image);
    if let Some(version) = image.version.as_deref() {
        println!("  Version: {version}");
    }
    println!("  Digest: {}", image.manifest_digest);

    subtask.completed = true;
    subtasks.push(subtask.clone());
    prog.send(Event::ProgressSteps {
        task: "staging".into(),
        description: "Deploying Image".into(),
        id: image.manifest_digest.clone().as_ref().into(),
        steps_cached: 0,
        steps: 3,
        steps_total: 3,
        subtasks: subtasks
            .clone()
            .into_iter()
            .chain([subtask.clone()])
            .collect(),
    })
    .await;

    // Unconditionally create or update /run/reboot-required to signal a reboot is needed.
    // This is monitored by kured (Kubernetes Reboot Daemon).
    write_reboot_required(&image.manifest_digest.as_ref())?;

    Ok(())
}

/// Update the /run/reboot-required file with the image that will be active after a reboot.
fn write_reboot_required(image: &str) -> Result<()> {
    let reboot_message = format!("bootc: Reboot required for image: {}", image);
    let run_dir = Dir::open_ambient_dir("/run", cap_std::ambient_authority())?;
    run_dir
        .atomic_write("reboot-required", reboot_message.as_bytes())
        .context("Creating /run/reboot-required")?;

    Ok(())
}

/// Implementation of rollback functionality
pub(crate) async fn rollback(sysroot: &Storage) -> Result<()> {
    const ROLLBACK_JOURNAL_ID: &str = "26f3b1eb24464d12aa5e7b544a6b5468";
    let ostree = sysroot.get_ostree()?;
    let (booted_ostree, deployments, host) = crate::status::get_status_require_booted(ostree)?;

    let new_spec = {
        let mut new_spec = host.spec.clone();
        new_spec.boot_order = new_spec.boot_order.swap();
        new_spec
    };

    let repo = &booted_ostree.repo();

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
    let rollback_image = rollback_status
        .query_image(repo)?
        .ok_or_else(|| anyhow!("Rollback is not container image based"))?;

    // Get current booted image for comparison
    let current_image = host
        .status
        .booted
        .as_ref()
        .and_then(|b| b.query_image(repo).ok()?);

    tracing::info!(
        message_id = ROLLBACK_JOURNAL_ID,
        bootc.manifest_digest = rollback_image.manifest_digest.as_ref(),
        bootc.ostree_commit = &rollback_image.merge_commit,
        bootc.rollback_type = if reverting { "revert" } else { "rollback" },
        bootc.current_manifest_digest = current_image
            .as_ref()
            .map(|i| i.manifest_digest.as_ref())
            .unwrap_or("none"),
        "Rolling back to image: {}",
        rollback_image.manifest_digest
    );
    // SAFETY: If there's a rollback status, then there's a deployment
    let rollback_deployment = deployments.rollback.expect("rollback deployment");
    let new_deployments = if reverting {
        [booted_ostree.deployment, rollback_deployment]
    } else {
        [rollback_deployment, booted_ostree.deployment]
    };
    let new_deployments = new_deployments
        .into_iter()
        .chain(deployments.other)
        .collect::<Vec<_>>();
    tracing::debug!("Writing new deployments: {new_deployments:?}");
    booted_ostree
        .sysroot
        .write_deployments(&new_deployments, gio::Cancellable::NONE)?;
    if reverting {
        println!("Next boot: current deployment");
    } else {
        println!("Next boot: rollback deployment");
    }

    write_reboot_required(rollback_image.manifest_digest.as_ref())?;

    sysroot.update_mtime()?;

    Ok(())
}

fn find_newest_deployment_name(deploysdir: &Dir) -> Result<String> {
    let mut dirs = Vec::new();
    for ent in deploysdir.entries()? {
        let ent = ent?;
        if !ent.file_type()?.is_dir() {
            continue;
        }
        let name = ent.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        dirs.push((name.to_owned(), ent.metadata()?.mtime()));
    }
    dirs.sort_unstable_by(|a, b| a.1.cmp(&b.1));
    if let Some((name, _ts)) = dirs.pop() {
        Ok(name)
    } else {
        anyhow::bail!("No deployment directory found")
    }
}

// Implementation of `bootc switch --in-place`
pub(crate) fn switch_origin_inplace(root: &Dir, imgref: &ImageReference) -> Result<String> {
    // Log the in-place switch operation to systemd journal
    const SWITCH_INPLACE_JOURNAL_ID: &str = "135b37b98ff94f268906a367e7f779bd";

    tracing::info!(
        message_id = SWITCH_INPLACE_JOURNAL_ID,
        bootc.image.reference = &imgref.image,
        bootc.image.transport = &imgref.transport,
        bootc.switch_type = "in_place",
        "Performing in-place switch to image: {}",
        imgref
    );

    // First, just create the new origin file
    let origin = origin_from_imageref(imgref)?;
    let serialized_origin = origin.to_data();

    // Now, we can't rely on being officially booted (e.g. with the `ostree=` karg)
    // in a scenario like running in the anaconda %post.
    // Eventually, we should support a setup here where ostree-prepare-root
    // can officially be run to "enter" an ostree root in a supportable way.
    // Anyways for now, the brutal hack is to just scrape through the deployments
    // and find the newest one, which we will mutate.  If there's more than one,
    // ultimately the calling tooling should be fixed to set things up correctly.

    let mut ostree_deploys = root.open_dir("sysroot/ostree/deploy")?.entries()?;
    let deploydir = loop {
        if let Some(ent) = ostree_deploys.next() {
            let ent = ent?;
            if !ent.file_type()?.is_dir() {
                continue;
            }
            tracing::debug!("Checking {:?}", ent.file_name());
            let child_dir = ent
                .open_dir()
                .with_context(|| format!("Opening dir {:?}", ent.file_name()))?;
            if let Some(d) = child_dir.open_dir_optional("deploy")? {
                break d;
            }
        } else {
            anyhow::bail!("Failed to find a deployment");
        }
    };
    let newest_deployment = find_newest_deployment_name(&deploydir)?;
    let origin_path = format!("{newest_deployment}.origin");
    if !deploydir.try_exists(&origin_path)? {
        tracing::warn!("No extant origin for {newest_deployment}");
    }
    deploydir
        .atomic_write(&origin_path, serialized_origin.as_bytes())
        .context("Writing origin")?;
    Ok(newest_deployment)
}

/// A workaround for <https://github.com/ostreedev/ostree/issues/3193>
/// as generated by anaconda.
#[context("Updating /etc/fstab for anaconda+composefs")]
pub(crate) fn fixup_etc_fstab(root: &Dir) -> Result<()> {
    let fstab_path = "etc/fstab";
    // Read the old file
    let fd = root
        .open(fstab_path)
        .with_context(|| format!("Opening {fstab_path}"))
        .map(std::io::BufReader::new)?;

    // Helper function to possibly change a line from /etc/fstab.
    // Returns Ok(true) if we made a change (and we wrote the modified line)
    // otherwise returns Ok(false) and the caller should write the original line.
    fn edit_fstab_line(line: &str, mut w: impl Write) -> Result<bool> {
        if line.starts_with('#') {
            return Ok(false);
        }
        let parts = line.split_ascii_whitespace().collect::<Vec<_>>();

        let path_idx = 1;
        let options_idx = 3;
        let (&path, &options) = match (parts.get(path_idx), parts.get(options_idx)) {
            (None, _) => {
                tracing::debug!("No path in entry: {line}");
                return Ok(false);
            }
            (_, None) => {
                tracing::debug!("No options in entry: {line}");
                return Ok(false);
            }
            (Some(p), Some(o)) => (p, o),
        };
        // If this is not the root, we're not matching on it
        if path != "/" {
            return Ok(false);
        }
        // If options already contains `ro`, nothing to do
        if options.split(',').any(|s| s == "ro") {
            return Ok(false);
        }

        writeln!(w, "# {}", crate::generator::BOOTC_EDITED_STAMP)?;

        // SAFETY: we unpacked the options before.
        // This adds `ro` to the option list
        assert!(!options.is_empty()); // Split wouldn't have turned this up if it was empty
        let options = format!("{options},ro");
        for (i, part) in parts.into_iter().enumerate() {
            // TODO: would obviously be nicer to preserve whitespace...but...eh.
            if i > 0 {
                write!(w, " ")?;
            }
            if i == options_idx {
                write!(w, "{options}")?;
            } else {
                write!(w, "{part}")?
            }
        }
        // And add the trailing newline
        writeln!(w)?;
        Ok(true)
    }

    // Read the input, and atomically write a modified version
    root.atomic_replace_with(fstab_path, move |mut w| -> Result<()> {
        for line in fd.lines() {
            let line = line?;
            if !edit_fstab_line(&line, &mut w)? {
                writeln!(w, "{line}")?;
            }
        }
        Ok(())
    })
    .context("Replacing /etc/fstab")?;

    println!("Updated /etc/fstab to add `ro` for `/`");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_proxy_config_user_agent() {
        let config = new_proxy_config();
        let prefix = config
            .user_agent_prefix
            .expect("user_agent_prefix should be set");
        // Verify the version is present (not just "bootc/")
        let version = prefix
            .strip_prefix("bootc/")
            .expect("User agent should start with bootc/");
        assert!(
            !version.is_empty(),
            "Version should be present after bootc/"
        );
    }

    #[test]
    fn test_switch_inplace() -> Result<()> {
        use cap_std::fs::DirBuilderExt;

        let td = cap_std_ext::cap_tempfile::TempDir::new(cap_std::ambient_authority())?;
        let mut builder = cap_std::fs::DirBuilder::new();
        let builder = builder.recursive(true).mode(0o755);
        let deploydir = "sysroot/ostree/deploy/default/deploy";
        let target_deployment =
            "af36eb0086bb55ac601600478c6168f834288013d60f8870b7851f44bf86c3c5.0";
        td.ensure_dir_with(
            format!("sysroot/ostree/deploy/default/deploy/{target_deployment}"),
            builder,
        )?;
        let deploydir = &td.open_dir(deploydir)?;
        let orig_imgref = ImageReference {
            image: "quay.io/exampleos/original:sometag".into(),
            transport: "registry".into(),
            signature: None,
        };
        {
            let origin = origin_from_imageref(&orig_imgref)?;
            deploydir.atomic_write(
                format!("{target_deployment}.origin"),
                origin.to_data().as_bytes(),
            )?;
        }

        let target_imgref = ImageReference {
            image: "quay.io/someother/otherimage:latest".into(),
            transport: "registry".into(),
            signature: None,
        };

        let replaced = switch_origin_inplace(&td, &target_imgref).unwrap();
        assert_eq!(replaced, target_deployment);
        Ok(())
    }

    #[test]
    fn test_fixup_etc_fstab_default() -> Result<()> {
        let tempdir = cap_std_ext::cap_tempfile::tempdir(cap_std::ambient_authority())?;
        let default = "UUID=f7436547-20ac-43cb-aa2f-eac9632183f6 /boot auto ro 0 0\n";
        tempdir.create_dir_all("etc")?;
        tempdir.atomic_write("etc/fstab", default)?;
        fixup_etc_fstab(&tempdir).unwrap();
        assert_eq!(tempdir.read_to_string("etc/fstab")?, default);
        Ok(())
    }

    #[test]
    fn test_fixup_etc_fstab_multi() -> Result<()> {
        let tempdir = cap_std_ext::cap_tempfile::tempdir(cap_std::ambient_authority())?;
        let default = "UUID=f7436547-20ac-43cb-aa2f-eac9632183f6 /boot auto ro 0 0\n\
UUID=6907-17CA          /boot/efi               vfat    umask=0077,shortname=winnt 0 2\n";
        tempdir.create_dir_all("etc")?;
        tempdir.atomic_write("etc/fstab", default)?;
        fixup_etc_fstab(&tempdir).unwrap();
        assert_eq!(tempdir.read_to_string("etc/fstab")?, default);
        Ok(())
    }

    #[test]
    fn test_fixup_etc_fstab_ro() -> Result<()> {
        let tempdir = cap_std_ext::cap_tempfile::tempdir(cap_std::ambient_authority())?;
        let default = "UUID=f7436547-20ac-43cb-aa2f-eac9632183f6 /boot auto ro 0 0\n\
UUID=1eef9f42-40e3-4bd8-ae20-e9f2325f8b52 /                     xfs   ro 0 0\n\
UUID=6907-17CA          /boot/efi               vfat    umask=0077,shortname=winnt 0 2\n";
        tempdir.create_dir_all("etc")?;
        tempdir.atomic_write("etc/fstab", default)?;
        fixup_etc_fstab(&tempdir).unwrap();
        assert_eq!(tempdir.read_to_string("etc/fstab")?, default);
        Ok(())
    }

    #[test]
    fn test_fixup_etc_fstab_rw() -> Result<()> {
        let tempdir = cap_std_ext::cap_tempfile::tempdir(cap_std::ambient_authority())?;
        // This case uses `defaults`
        let default = "UUID=f7436547-20ac-43cb-aa2f-eac9632183f6 /boot auto ro 0 0\n\
UUID=1eef9f42-40e3-4bd8-ae20-e9f2325f8b52 /                     xfs   defaults 0 0\n\
UUID=6907-17CA          /boot/efi               vfat    umask=0077,shortname=winnt 0 2\n";
        let modified = "UUID=f7436547-20ac-43cb-aa2f-eac9632183f6 /boot auto ro 0 0\n\
# Updated by bootc-fstab-edit.service\n\
UUID=1eef9f42-40e3-4bd8-ae20-e9f2325f8b52 / xfs defaults,ro 0 0\n\
UUID=6907-17CA          /boot/efi               vfat    umask=0077,shortname=winnt 0 2\n";
        tempdir.create_dir_all("etc")?;
        tempdir.atomic_write("etc/fstab", default)?;
        fixup_etc_fstab(&tempdir).unwrap();
        assert_eq!(tempdir.read_to_string("etc/fstab")?, modified);
        Ok(())
    }
    #[test]
    fn test_check_disk_space_inner() -> Result<()> {
        let td = cap_std_ext::cap_tempfile::TempDir::new(cap_std::ambient_authority())?;
        let imgref = ImageReference {
            image: "quay.io/exampleos/exampleos:latest".into(),
            transport: "registry".into(),
            signature: None,
        };

        // 0 bytes needed always passes
        check_disk_space_inner(&*td, 0, 0, &imgref)?;

        // u64::MAX bytes needed always fails
        assert!(check_disk_space_inner(&*td, u64::MAX, 0, &imgref).is_err());

        // With min_free consuming all usable space, even a tiny fetch fails
        assert!(check_disk_space_inner(&*td, 1, u64::MAX, &imgref).is_err());

        Ok(())
    }

    /// Test the `optional_bool` semantics used by `ostree_composefs_bound`.
    ///
    /// We cannot construct a real `ostree::Repo` in a unit test (it requires
    /// filesystem access), so we exercise the underlying `KeyFile` logic
    /// directly — this is precisely the layer `ostree_composefs_bound` uses.
    #[test]
    fn test_composefs_bound_keyfile_semantics() {
        let kf = glib::KeyFile::new();

        // Key absent → optional_bool returns None → bound() would return false
        let absent = kf
            .optional_bool(COMPOSEFS_CONFIG_GROUP, COMPOSEFS_CONFIG_UNIFIED)
            .expect("no error for absent key");
        assert_eq!(absent, None);

        // Key present and true → Some(true)
        kf.set_boolean(COMPOSEFS_CONFIG_GROUP, COMPOSEFS_CONFIG_UNIFIED, true);
        let present_true = kf
            .optional_bool(COMPOSEFS_CONFIG_GROUP, COMPOSEFS_CONFIG_UNIFIED)
            .expect("no error for present key");
        assert_eq!(present_true, Some(true));

        // Key present and false → Some(false)
        kf.set_boolean(COMPOSEFS_CONFIG_GROUP, COMPOSEFS_CONFIG_UNIFIED, false);
        let present_false = kf
            .optional_bool(COMPOSEFS_CONFIG_GROUP, COMPOSEFS_CONFIG_UNIFIED)
            .expect("no error for present false key");
        assert_eq!(present_false, Some(false));
    }

    /// Test all (bound, cstorage) combinations for classify_binding.
    ///
    /// The back-compat case — cstorage=true, bound_cfg=false — must yield
    /// Unified, because systems onboarded before the repo-config signal existed
    /// have a cstorage flag but no repo key.  The OR in binding_state() ensures
    /// that cstorage participation implies the binding.
    #[test]
    fn test_classify_binding() {
        use BindingState::*;

        // Neither signal → Disabled
        assert_eq!(classify_binding(false, false), Disabled);

        // bound_cfg set but no cstorage → BoundOnly
        assert_eq!(classify_binding(true, false), BoundOnly);

        // Back-compat: systems that have cstorage but no repo key.
        // binding_state() computes: bound = bound_cfg || cstorage = false || true = true,
        // then calls classify_binding(true, true) → Unified.
        assert_eq!(classify_binding(true, true), Unified);
    }
}
