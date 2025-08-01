//! # Write deployments merging image with configmap
//!
//! Create a merged filesystem tree with the image and mounted configmaps.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::fs::create_dir_all;
use std::io::{BufRead, Read, Write};
use std::path::PathBuf;

use anyhow::Ok;
use anyhow::{anyhow, Context, Result};
use cap_std::fs::{Dir, MetadataExt};
use cap_std_ext::cap_std;
use cap_std_ext::dirext::CapStdExtDirExt;
use fn_error_context::context;
use ostree::{gio, glib};
use ostree_container::OstreeImageReference;
use ostree_ext::container as ostree_container;
use ostree_ext::container::store::{ImageImporter, ImportProgress, PrepareResult, PreparedImport};
use ostree_ext::oci_spec::image::{Descriptor, Digest};
use ostree_ext::ostree::Deployment;
use ostree_ext::ostree::{self, Sysroot};
use ostree_ext::sysroot::SysrootLock;
use ostree_ext::tokio_util::spawn_blocking_cancellable_flatten;
use rustix::fs::{fsync, renameat_with, AtFlags, RenameFlags};

use crate::composefs_consts::{
    BOOT_LOADER_ENTRIES, ROLLBACK_BOOT_LOADER_ENTRIES, USER_CFG, USER_CFG_ROLLBACK,
};
use crate::install::{get_efi_uuid_source, BootType};
use crate::parsers::bls_config::{parse_bls_config, BLSConfig};
use crate::parsers::grub_menuconfig::{parse_grub_menuentry_file, MenuEntry};
use crate::progress_jsonl::{Event, ProgressWriter, SubTaskBytes, SubTaskStep};
use crate::spec::ImageReference;
use crate::spec::{BootOrder, HostSpec};
use crate::status::{composefs_deployment_status, labels_of_config};
use crate::store::Storage;
use crate::utils::async_task_with_spinner;

// TODO use https://github.com/ostreedev/ostree-rs-ext/pull/493/commits/afc1837ff383681b947de30c0cefc70080a4f87a
const BASE_IMAGE_PREFIX: &str = "ostree/container/baseimage/bootc";

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
) -> Result<ostree_container::store::ImageImporter> {
    let config = Default::default();
    let mut imp = ostree_container::store::ImageImporter::new(repo, imgref, config).await?;
    imp.require_bootable();
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

/// Write container fetch progress to standard output.
async fn handle_layer_progress_print(
    mut layers: tokio::sync::mpsc::Receiver<ostree_container::store::ImportProgress>,
    mut layer_bytes: tokio::sync::watch::Receiver<Option<ostree_container::store::LayerProgress>>,
    digest: Box<str>,
    n_layers_to_fetch: usize,
    layers_total: usize,
    bytes_to_download: u64,
    bytes_total: u64,
    prog: ProgressWriter,
    quiet: bool,
) -> ProgressWriter {
    let start = std::time::Instant::now();
    let mut total_read = 0u64;
    let bar = indicatif::MultiProgress::new();
    if quiet {
        bar.set_draw_target(indicatif::ProgressDrawTarget::hidden());
    }
    let layers_bar = bar.add(indicatif::ProgressBar::new(
        n_layers_to_fetch.try_into().unwrap(),
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
            layer = layers.recv() => {
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
                            id: format!("{short_digest}").clone().into(),
                            bytes_cached: 0,
                            bytes: 0,
                            bytes_total: layer_size,
                        };
                    } else {
                        byte_bar.set_position(layer_size);
                        layers_bar.inc(1);
                        total_read = total_read.saturating_add(layer_size);
                        // Emit an event where bytes == total to signal completion.
                        subtask.bytes = layer_size;
                        subtasks.push(subtask.clone());
                        prog.send(Event::ProgressBytes {
                            task: "pulling".into(),
                            description: format!("Pulling Image: {digest}").into(),
                            id: (*digest).into(),
                            bytes_cached: bytes_total - bytes_to_download,
                            bytes: total_read,
                            bytes_total: bytes_to_download,
                            steps_cached: (layers_total - n_layers_to_fetch) as u64,
                            steps: layers_bar.position(),
                            steps_total: n_layers_to_fetch as u64,
                            subtasks: subtasks.clone(),
                        }).await;
                    }
                } else {
                    // If the receiver is disconnected, then we're done
                    break
                };
            },
            r = layer_bytes.changed() => {
                if r.is_err() {
                    // If the receiver is disconnected, then we're done
                    break
                }
                let bytes = {
                    let bytes = layer_bytes.borrow_and_update();
                    bytes.as_ref().cloned()
                };
                if let Some(bytes) = bytes {
                    byte_bar.set_position(bytes.fetched);
                    subtask.bytes = byte_bar.position();
                    prog.send_lossy(Event::ProgressBytes {
                        task: "pulling".into(),
                        description: format!("Pulling Image: {digest}").into(),
                        id: (*digest).into(),
                        bytes_cached: bytes_total - bytes_to_download,
                        bytes: total_read + byte_bar.position(),
                        bytes_total: bytes_to_download,
                        steps_cached: (layers_total - n_layers_to_fetch) as u64,
                        steps: layers_bar.position(),
                        steps_total: n_layers_to_fetch as u64,
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
    prog.send(Event::ProgressSteps {
        task: "importing".into(),
        description: "Importing Image".into(),
        id: (*digest).into(),
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
    prog
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
    }
    // Convert to a hashset of just the image names
    let image_names = HashSet::from_iter(all_bound_images.iter().map(|img| img.image.as_str()));
    let pruned = sysroot
        .get_ensure_imgstore()?
        .prune_except_roots(&image_names)
        .await?;
    tracing::debug!("Pruned images: {}", pruned.len());
    Ok(())
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
    Ready(PreparedImportMeta),
    AlreadyPresent(Box<ImageState>),
}

pub(crate) async fn prepare_for_pull(
    repo: &ostree::Repo,
    imgref: &ImageReference,
    target_imgref: Option<&OstreeImageReference>,
) -> Result<PreparedPullResult> {
    let imgref_canonicalized = imgref.clone().canonicalize()?;
    tracing::debug!("Canonicalized image reference: {imgref_canonicalized:#}");
    let ostree_imgref = &OstreeImageReference::from(imgref_canonicalized);
    let mut imp = new_importer(repo, ostree_imgref).await?;
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

    Ok(PreparedPullResult::Ready(prepared_image))
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
        handle_layer_progress_print(
            layer_progress,
            layer_byte_progress,
            digest.as_ref().into(),
            prepared_image.n_layers_to_fetch,
            prepared_image.layers_total,
            prepared_image.bytes_to_fetch,
            prepared_image.bytes_total,
            prog,
            quiet,
        )
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

    if let Some(msg) =
        ostree_container::store::image_filtered_content_warning(&import.filtered_files)
            .context("Image content warning")?
    {
        crate::journal::journal_print(libsystemd::logging::Priority::Notice, &msg);
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
) -> Result<Box<ImageState>> {
    match prepare_for_pull(repo, imgref, target_imgref).await? {
        PreparedPullResult::AlreadyPresent(existing) => Ok(existing),
        PreparedPullResult::Ready(prepared_image_meta) => {
            Ok(pull_from_prepared(imgref, quiet, prog, prepared_image_meta).await?)
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

pub(crate) async fn cleanup(sysroot: &Storage) -> Result<()> {
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
    merge_deployment: Option<&Deployment>,
    stateroot: &str,
    image: &ImageState,
    origin: &glib::KeyFile,
) -> Result<Deployment> {
    // Compute the kernel argument overrides. In practice today this API is always expecting
    // a merge deployment. The kargs code also always looks at the booted root (which
    // is a distinct minor issue, but not super important as right now the install path
    // doesn't use this API).
    let override_kargs = if let Some(deployment) = merge_deployment {
        Some(crate::bootc_kargs::get_kargs(sysroot, &deployment, image)?)
    } else {
        None
    };
    // Clone all the things to move to worker thread
    let ostree = sysroot.get_ostree_cloned()?;
    // ostree::Deployment is incorrectly !Send 😢 so convert it to an integer
    let merge_deployment = merge_deployment.map(|d| d.index() as usize);
    let stateroot = stateroot.to_string();
    let ostree_commit = image.ostree_commit.to_string();
    // GKeyFile also isn't Send! So we serialize that as a string...
    let origin_data = origin.to_data();
    let r = async_task_with_spinner(
        "Deploying",
        spawn_blocking_cancellable_flatten(move |cancellable| -> Result<_> {
            let ostree = ostree;
            let stateroot = Some(stateroot);
            let mut opts = ostree::SysrootDeployTreeOpts::default();

            // Because the C API expects a Vec<&str>, we need to generate a new Vec<>
            // that borrows.
            let override_kargs = override_kargs
                .as_deref()
                .map(|v| v.iter().map(|s| s.as_str()).collect::<Vec<_>>());
            if let Some(kargs) = override_kargs.as_deref() {
                opts.override_kernel_argv = Some(&kargs);
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

/// Stage (queue deployment of) a fetched container image.
#[context("Staging")]
pub(crate) async fn stage(
    sysroot: &Storage,
    stateroot: &str,
    image: &ImageState,
    spec: &RequiredHostSpec<'_>,
    prog: ProgressWriter,
) -> Result<()> {
    let ostree = sysroot.get_ostree()?;
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
    let merge_deployment = ostree.merge_deployment(Some(stateroot));

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
    let deployment = crate::deploy::deploy(
        sysroot,
        merge_deployment.as_ref(),
        stateroot,
        image,
        &origin,
    )
    .await?;

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
    let run_dir = Dir::open_ambient_dir("/run", cap_std::ambient_authority())?;
    run_dir
        .atomic_write("reboot-required", b"")
        .context("Creating /run/reboot-required")?;

    Ok(())
}

#[context("Rolling back UKI")]
pub(crate) fn rollback_composefs_uki() -> Result<()> {
    let user_cfg_path = PathBuf::from("/sysroot/boot/grub2");

    let mut str = String::new();
    let boot_dir =
        cap_std::fs::Dir::open_ambient_dir("/sysroot/boot", cap_std::ambient_authority())
            .context("Opening boot dir")?;
    let mut menuentries =
        get_sorted_uki_boot_entries(&boot_dir, &mut str).context("Getting UKI boot entries")?;

    // TODO(Johan-Liebert): Currently assuming there are only two deployments
    assert!(menuentries.len() == 2);

    let (first, second) = menuentries.split_at_mut(1);
    std::mem::swap(&mut first[0], &mut second[0]);

    let mut buffer = get_efi_uuid_source();

    for entry in menuentries {
        write!(buffer, "{entry}")?;
    }

    let entries_dir =
        cap_std::fs::Dir::open_ambient_dir(&user_cfg_path, cap_std::ambient_authority())
            .with_context(|| format!("Opening {user_cfg_path:?}"))?;

    entries_dir
        .atomic_write(USER_CFG_ROLLBACK, buffer)
        .with_context(|| format!("Writing to {USER_CFG_ROLLBACK}"))?;

    tracing::debug!("Atomically exchanging for {USER_CFG_ROLLBACK} and {USER_CFG}");
    renameat_with(
        &entries_dir,
        USER_CFG_ROLLBACK,
        &entries_dir,
        USER_CFG,
        RenameFlags::EXCHANGE,
    )
    .context("renameat")?;

    tracing::debug!("Removing {USER_CFG_ROLLBACK}");
    rustix::fs::unlinkat(&entries_dir, USER_CFG_ROLLBACK, AtFlags::empty()).context("unlinkat")?;

    tracing::debug!("Syncing to disk");
    fsync(
        entries_dir
            .reopen_as_ownedfd()
            .with_context(|| format!("Reopening {user_cfg_path:?} as owned fd"))?,
    )
    .with_context(|| format!("fsync {user_cfg_path:?}"))?;

    Ok(())
}

// Need str to store lifetime
pub(crate) fn get_sorted_uki_boot_entries<'a>(
    boot_dir: &Dir,
    str: &'a mut String,
) -> Result<Vec<MenuEntry<'a>>> {
    let mut file = boot_dir
        .open(format!("grub2/{USER_CFG}"))
        .with_context(|| format!("Opening {USER_CFG}"))?;
    file.read_to_string(str)?;
    parse_grub_menuentry_file(str)
}

#[context("Getting sorted BLS entries")]
pub(crate) fn get_sorted_bls_boot_entries(
    boot_dir: &Dir,
    ascending: bool,
) -> Result<Vec<BLSConfig>> {
    let mut all_configs = vec![];

    for entry in boot_dir.read_dir(format!("loader/{BOOT_LOADER_ENTRIES}"))? {
        let entry = entry?;

        let file_name = entry.file_name();

        let file_name = file_name
            .to_str()
            .ok_or(anyhow::anyhow!("Found non UTF-8 characters in filename"))?;

        if !file_name.ends_with(".conf") {
            continue;
        }

        let mut file = entry
            .open()
            .with_context(|| format!("Failed to open {:?}", file_name))?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .with_context(|| format!("Failed to read {:?}", file_name))?;

        let config = parse_bls_config(&contents).context("Parsing bls config")?;

        all_configs.push(config);
    }

    all_configs.sort_by(|a, b| if ascending { a.cmp(b) } else { b.cmp(a) });

    return Ok(all_configs);
}

#[context("Rolling back BLS")]
pub(crate) fn rollback_composefs_bls() -> Result<()> {
    let boot_dir =
        cap_std::fs::Dir::open_ambient_dir("/sysroot/boot", cap_std::ambient_authority())
            .context("Opening boot dir")?;

    // Sort in descending order as that's the order they're shown on the boot screen
    // After this:
    // all_configs[0] -> booted depl
    // all_configs[1] -> rollback depl
    let mut all_configs = get_sorted_bls_boot_entries(&boot_dir, false)?;

    // Update the indicies so that they're swapped
    for (idx, cfg) in all_configs.iter_mut().enumerate() {
        cfg.sort_key = Some(idx.to_string());
    }

    // TODO(Johan-Liebert): Currently assuming there are only two deployments
    assert!(all_configs.len() == 2);

    // Write these
    let dir_path = PathBuf::from(format!(
        "/sysroot/boot/loader/{ROLLBACK_BOOT_LOADER_ENTRIES}"
    ));
    create_dir_all(&dir_path).with_context(|| format!("Failed to create dir: {dir_path:?}"))?;

    let rollback_entries_dir =
        cap_std::fs::Dir::open_ambient_dir(&dir_path, cap_std::ambient_authority())
            .with_context(|| format!("Opening {dir_path:?}"))?;

    // Write the BLS configs in there
    for cfg in all_configs {
        // SAFETY: We set sort_key above
        let file_name = format!("bootc-composefs-{}.conf", cfg.sort_key.as_ref().unwrap());

        rollback_entries_dir
            .atomic_write(&file_name, cfg.to_string())
            .with_context(|| format!("Writing to {file_name}"))?;
    }

    // Should we sync after every write?
    fsync(
        rollback_entries_dir
            .reopen_as_ownedfd()
            .with_context(|| format!("Reopening {dir_path:?} as owned fd"))?,
    )
    .with_context(|| format!("fsync {dir_path:?}"))?;

    // Atomically exchange "entries" <-> "entries.rollback"
    let dir = Dir::open_ambient_dir("/sysroot/boot/loader", cap_std::ambient_authority())
        .context("Opening loader dir")?;

    tracing::debug!(
        "Atomically exchanging for {ROLLBACK_BOOT_LOADER_ENTRIES} and {BOOT_LOADER_ENTRIES}"
    );
    renameat_with(
        &dir,
        ROLLBACK_BOOT_LOADER_ENTRIES,
        &dir,
        BOOT_LOADER_ENTRIES,
        RenameFlags::EXCHANGE,
    )
    .context("renameat")?;

    tracing::debug!("Removing {ROLLBACK_BOOT_LOADER_ENTRIES}");
    rustix::fs::unlinkat(&dir, ROLLBACK_BOOT_LOADER_ENTRIES, AtFlags::empty())
        .context("unlinkat")?;

    tracing::debug!("Syncing to disk");
    fsync(
        dir.reopen_as_ownedfd()
            .with_context(|| format!("Reopening /sysroot/boot/loader as owned fd"))?,
    )
    .context("fsync")?;

    Ok(())
}

#[context("Rolling back composefs")]
pub(crate) async fn composefs_rollback() -> Result<()> {
    let host = composefs_deployment_status().await?;

    let new_spec = {
        let mut new_spec = host.spec.clone();
        new_spec.boot_order = new_spec.boot_order.swap();
        new_spec
    };

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

    // TODO: Handle staged deployment
    // Ostree will drop any staged deployment on rollback but will keep it if it is the first item
    // in the new deployment list
    let Some(rollback_composefs_entry) = &rollback_status.composefs else {
        anyhow::bail!("Rollback deployment not a composefs deployment")
    };

    match rollback_composefs_entry.boot_type {
        BootType::Bls => rollback_composefs_bls(),
        BootType::Uki => rollback_composefs_uki(),
    }?;

    if reverting {
        println!("Next boot: current deployment");
    } else {
        println!("Next boot: rollback deployment");
    }

    Ok(())
}

/// Implementation of rollback functionality
pub(crate) async fn rollback(sysroot: &Storage) -> Result<()> {
    const ROLLBACK_JOURNAL_ID: &str = "26f3b1eb24464d12aa5e7b544a6b5468";
    let ostree = sysroot.get_ostree()?;
    let (booted_deployment, deployments, host) = crate::status::get_status_require_booted(ostree)?;

    let new_spec = {
        let mut new_spec = host.spec.clone();
        new_spec.boot_order = new_spec.boot_order.swap();
        new_spec
    };

    let repo = &ostree.repo();

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
    let msg = format!("Rolling back to image: {}", rollback_image.manifest_digest);
    libsystemd::logging::journal_send(
        libsystemd::logging::Priority::Info,
        &msg,
        [
            ("MESSAGE_ID", ROLLBACK_JOURNAL_ID),
            (
                "BOOTC_MANIFEST_DIGEST",
                rollback_image.manifest_digest.as_ref(),
            ),
        ]
        .into_iter(),
    )?;
    // SAFETY: If there's a rollback status, then there's a deployment
    let rollback_deployment = deployments.rollback.expect("rollback deployment");
    let new_deployments = if reverting {
        [booted_deployment, rollback_deployment]
    } else {
        [rollback_deployment, booted_deployment]
    };
    let new_deployments = new_deployments
        .into_iter()
        .chain(deployments.other)
        .collect::<Vec<_>>();
    tracing::debug!("Writing new deployments: {new_deployments:?}");
    ostree.write_deployments(&new_deployments, gio::Cancellable::NONE)?;
    if reverting {
        println!("Next boot: current deployment");
    } else {
        println!("Next boot: rollback deployment");
    }

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

/// A workaround for https://github.com/ostreedev/ostree/issues/3193
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
    root.atomic_replace_with(fstab_path, move |mut w| {
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
    use std::collections::HashMap;

    use crate::parsers::grub_menuconfig::MenuentryBody;

    use super::*;

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
    fn test_sorted_bls_boot_entries() -> Result<()> {
        let tempdir = cap_std_ext::cap_tempfile::tempdir(cap_std::ambient_authority())?;

        let entry1 = r#"
            title Fedora 42.20250623.3.1 (CoreOS)
            version 1
            linux /boot/7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6/vmlinuz-5.14.10
            initrd /boot/7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6/initramfs-5.14.10.img
            options root=UUID=abc123 rw composefs=7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6
        "#;

        let entry2 = r#"
            title Fedora 41.20250214.2.0 (CoreOS)
            version 2
            linux /boot/febdf62805de2ae7b6b597f2a9775d9c8a753ba1e5f09298fc8fbe0b0d13bf01/vmlinuz-5.14.10
            initrd /boot/febdf62805de2ae7b6b597f2a9775d9c8a753ba1e5f09298fc8fbe0b0d13bf01/initramfs-5.14.10.img
            options root=UUID=abc123 rw composefs=febdf62805de2ae7b6b597f2a9775d9c8a753ba1e5f09298fc8fbe0b0d13bf01
        "#;

        tempdir.create_dir_all("loader/entries")?;
        tempdir.atomic_write(
            "loader/entries/random_file.txt",
            "Random file that we won't parse",
        )?;
        tempdir.atomic_write("loader/entries/entry1.conf", entry1)?;
        tempdir.atomic_write("loader/entries/entry2.conf", entry2)?;

        let result = get_sorted_bls_boot_entries(&tempdir, true);

        let mut expected = vec![
            BLSConfig {
                title: Some("Fedora 42.20250623.3.1 (CoreOS)".into()),
                version: 1,
                linux: "/boot/7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6/vmlinuz-5.14.10".into(),
                initrd: "/boot/7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6/initramfs-5.14.10.img".into(),
                options: "root=UUID=abc123 rw composefs=7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6".into(),
                extra: HashMap::new(),
            },
            BLSConfig {
                title: Some("Fedora 41.20250214.2.0 (CoreOS)".into()),
                version: 2,
                linux: "/boot/febdf62805de2ae7b6b597f2a9775d9c8a753ba1e5f09298fc8fbe0b0d13bf01/vmlinuz-5.14.10".into(),
                initrd: "/boot/febdf62805de2ae7b6b597f2a9775d9c8a753ba1e5f09298fc8fbe0b0d13bf01/initramfs-5.14.10.img".into(),
                options: "root=UUID=abc123 rw composefs=febdf62805de2ae7b6b597f2a9775d9c8a753ba1e5f09298fc8fbe0b0d13bf01".into(),
                extra: HashMap::new(),
            },
        ];

        assert_eq!(result.unwrap(), expected);

        let result = get_sorted_bls_boot_entries(&tempdir, false);
        expected.reverse();
        assert_eq!(result.unwrap(), expected);

        Ok(())
    }

    #[test]
    fn test_sorted_uki_boot_entries() -> Result<()> {
        let user_cfg = r#"
            if [ -f ${config_directory}/efiuuid.cfg ]; then
                    source ${config_directory}/efiuuid.cfg
            fi

            menuentry "Fedora Bootc UKI: (f7415d75017a12a387a39d2281e033a288fc15775108250ef70a01dcadb93346)" {
                insmod fat
                insmod chain
                search --no-floppy --set=root --fs-uuid "${EFI_PART_UUID}"
                chainloader /EFI/Linux/f7415d75017a12a387a39d2281e033a288fc15775108250ef70a01dcadb93346.efi
            }

            menuentry "Fedora Bootc UKI: (7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6)" {
                insmod fat
                insmod chain
                search --no-floppy --set=root --fs-uuid "${EFI_PART_UUID}"
                chainloader /EFI/Linux/7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6.efi
            }
        "#;

        let bootdir = cap_std_ext::cap_tempfile::tempdir(cap_std::ambient_authority())?;
        bootdir.create_dir_all(format!("grub2"))?;
        bootdir.atomic_write(format!("grub2/{USER_CFG}"), user_cfg)?;

        let mut s = String::new();
        let result = get_sorted_uki_boot_entries(&bootdir, &mut s)?;

        let expected = vec![
            MenuEntry {
                title: "Fedora Bootc UKI: (f7415d75017a12a387a39d2281e033a288fc15775108250ef70a01dcadb93346)".into(),
                body: MenuentryBody {
                    insmod: vec!["fat", "chain"],
                    chainloader: "/EFI/Linux/f7415d75017a12a387a39d2281e033a288fc15775108250ef70a01dcadb93346.efi".into(),
                    search: "--no-floppy --set=root --fs-uuid \"${EFI_PART_UUID}\"",
                    version: 0,
                    extra: vec![],
                },
            },
            MenuEntry {
                title: "Fedora Bootc UKI: (7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6)".into(),
                body: MenuentryBody {
                    insmod: vec!["fat", "chain"],
                    chainloader: "/EFI/Linux/7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6.efi".into(),
                    search: "--no-floppy --set=root --fs-uuid \"${EFI_PART_UUID}\"",
                    version: 0,
                    extra: vec![],
                },
            },
        ];

        assert_eq!(result, expected);

        Ok(())
    }
}
