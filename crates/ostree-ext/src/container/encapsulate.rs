//! APIs for creating container images from OSTree commits

use super::{COMPONENT_SEPARATOR, CONTENT_ANNOTATION, OstreeImageReference, Transport};
use super::{ImageReference, OSTREE_COMMIT_LABEL, SignatureSource};
use crate::chunking::{Chunk, ChunkMapping, Chunking, ObjectMetaSized, RcStr};
use crate::container::skopeo;
use crate::objectsource::ContentID;
use crate::tar as ostree_tar;
use anyhow::{Context, Result, anyhow};
use camino::{Utf8Path, Utf8PathBuf};
use cap_std::fs::Dir;
use cap_std_ext::cap_std;
use chrono::DateTime;
use containers_image_proxy::oci_spec;
use flate2::Compression;
use fn_error_context::context;
use gio::glib;
use oci_spec::image as oci_image;
use ocidir::{Layer, OciDir};
use ostree::gio;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use tracing::instrument;

/// The label which may be used in addition to the standard OCI label.
pub const LEGACY_VERSION_LABEL: &str = "version";
/// The label which indicates where the ostree layers stop, and the
/// derived ones start.
pub const DIFFID_LABEL: &str = "ostree.final-diffid";
/// The label for bootc.
pub const BOOTC_LABEL: &str = "containers.bootc";

/// Annotation injected into the layer to say that this is an ostree commit.
/// However, because this gets lost when converted to D2S2 <https://docs.docker.com/registry/spec/manifest-v2-2/>
/// schema, it's not actually useful today.  But, we keep it
/// out of principle.
const BLOB_OSTREE_ANNOTATION: &str = "ostree.encapsulated";

/// Progress event emitted while exporting OCI layers.
#[derive(Clone, Debug)]
pub enum ExportProgress {
    /// A layer export has started.
    Started {
        /// One-based layer number in export work order.
        index: usize,
        /// Total layers to export.
        total: usize,
        /// Human-readable layer name.
        name: String,
    },
    /// A layer export has completed.
    Finished {
        /// One-based layer number in export work order.
        index: usize,
        /// Total layers to export.
        total: usize,
        /// Human-readable layer name.
        name: String,
    },
}

/// Configuration for the generated container.
#[derive(Debug, Default)]
pub struct Config {
    /// Additional labels.
    pub labels: Option<BTreeMap<String, String>>,
    /// The equivalent of a `Dockerfile`'s `CMD` instruction.
    pub cmd: Option<Vec<String>>,
}

fn commit_meta_to_labels<'a>(
    meta: &glib::VariantDict,
    keys: impl IntoIterator<Item = &'a str>,
    opt_keys: impl IntoIterator<Item = &'a str>,
    labels: &mut HashMap<String, String>,
) -> Result<()> {
    for k in keys {
        let v = meta
            .lookup::<String>(k)
            .context("Expected string for commit metadata value")?
            .ok_or_else(|| anyhow!("Could not find commit metadata key: {}", k))?;
        labels.insert(k.to_string(), v);
    }
    for k in opt_keys {
        let v = meta
            .lookup::<String>(k)
            .context("Expected string for commit metadata value")?;
        if let Some(v) = v {
            labels.insert(k.to_string(), v);
        }
    }
    // Copy standard metadata keys `ostree.bootable` and `ostree.linux`.
    // Bootable is an odd one out in being a boolean.
    #[allow(clippy::explicit_auto_deref)]
    if let Some(v) = meta.lookup::<bool>(ostree::METADATA_KEY_BOOTABLE)? {
        labels.insert(ostree::METADATA_KEY_BOOTABLE.to_string(), v.to_string());
        labels.insert(BOOTC_LABEL.into(), "1".into());
    }
    // Handle any other string-typed values here.
    for k in &[&ostree::METADATA_KEY_LINUX] {
        if let Some(v) = meta.lookup::<String>(k)? {
            labels.insert(k.to_string(), v);
        }
    }
    Ok(())
}

#[derive(Debug)]
struct SendableChunk {
    name: String,
    content: Vec<(String, u64, Vec<Utf8PathBuf>)>,
    size: u64,
    packages: Vec<String>,
}

#[derive(Debug)]
enum LayerJobKind {
    Component(SendableChunk),
    Final(SendableChunk),
}

#[derive(Debug)]
struct LayerJob {
    manifest_index: usize,
    progress_index: usize,
    total: usize,
    name: String,
    kind: LayerJobKind,
}

#[derive(Debug)]
struct ExportedLayer {
    manifest_index: usize,
    layer: Layer,
    name: String,
    packages: Vec<String>,
}

#[derive(Clone, Debug)]
struct LayerExportOpts {
    compression: Compression,
    tar_create_parent_dirs: bool,
    progress: Option<mpsc::Sender<ExportProgress>>,
}

impl From<&ExportOpts<'_, '_>> for LayerExportOpts {
    fn from(opts: &ExportOpts<'_, '_>) -> Self {
        Self {
            compression: opts.compression(),
            tar_create_parent_dirs: opts.tar_create_parent_dirs,
            progress: opts.progress.clone(),
        }
    }
}

fn send_progress(progress: &Option<mpsc::Sender<ExportProgress>>, event: ExportProgress) {
    if let Some(progress) = progress {
        let _ = progress.send(event);
    }
}

fn sendable_chunk_from_chunk(chunk: Chunk) -> SendableChunk {
    SendableChunk {
        name: chunk.name,
        content: chunk
            .content
            .into_iter()
            .map(|(checksum, (size, paths))| (checksum.to_string(), size, paths))
            .collect(),
        size: chunk.size,
        packages: chunk.packages,
    }
}

fn chunk_mapping_from_sendable(content: Vec<(String, u64, Vec<Utf8PathBuf>)>) -> ChunkMapping {
    content
        .into_iter()
        .map(|(checksum, size, paths)| (RcStr::from(checksum), (size, paths)))
        .collect()
}

fn chunk_from_sendable(chunk: SendableChunk) -> Chunk {
    Chunk {
        name: chunk.name,
        content: chunk_mapping_from_sendable(chunk.content),
        size: chunk.size,
        packages: chunk.packages,
    }
}

fn export_one_layer(
    repo: &ostree::Repo,
    commit: &str,
    ociw: &OciDir,
    job: LayerJob,
    opts: &LayerExportOpts,
) -> Result<ExportedLayer> {
    send_progress(
        &opts.progress,
        ExportProgress::Started {
            index: job.progress_index,
            total: job.total,
            name: job.name.clone(),
        },
    );
    let result = (|| -> Result<ExportedLayer> {
        match job.kind {
            LayerJobKind::Component(chunk) => {
                let SendableChunk {
                    name,
                    content,
                    packages,
                    ..
                } = chunk;
                let mut w = ociw.create_layer(Some(opts.compression))?;
                ostree_tar::export_chunk(
                    repo,
                    commit,
                    chunk_mapping_from_sendable(content),
                    &mut w,
                    opts.tar_create_parent_dirs,
                )
                .with_context(|| format!("Exporting chunk {}", job.progress_index - 1))?;
                let w = w.into_inner()?;
                Ok(ExportedLayer {
                    manifest_index: job.manifest_index,
                    layer: w.complete()?,
                    name,
                    packages,
                })
            }
            LayerJobKind::Final(chunk) => {
                let mut w = ociw.create_layer(Some(opts.compression))?;
                ostree_tar::export_final_chunk(
                    repo,
                    commit,
                    chunk_from_sendable(chunk),
                    &mut w,
                    opts.tar_create_parent_dirs,
                )?;
                let w = w.into_inner()?;
                Ok(ExportedLayer {
                    manifest_index: job.manifest_index,
                    layer: w.complete()?,
                    name: job.name.clone(),
                    packages: Vec::new(),
                })
            }
        }
    })();
    if result.is_ok() {
        send_progress(
            &opts.progress,
            ExportProgress::Finished {
                index: job.progress_index,
                total: job.total,
                name: job.name,
            },
        );
    }
    result
}

fn build_layer_jobs(mut chunking: Chunking, total: usize, description: &str) -> Vec<LayerJob> {
    let mut jobs: Vec<_> = chunking
        .take_chunks()
        .into_iter()
        .enumerate()
        .map(|(i, chunk)| LayerJob {
            manifest_index: i + 1,
            progress_index: i + 1,
            total,
            name: chunk.name.clone(),
            kind: LayerJobKind::Component(sendable_chunk_from_chunk(chunk)),
        })
        .collect();
    let final_name = if description.is_empty() {
        "ostree commit".to_string()
    } else {
        description.to_string()
    };
    jobs.push(LayerJob {
        manifest_index: 0,
        progress_index: total,
        total,
        name: final_name,
        kind: LayerJobKind::Final(sendable_chunk_from_chunk(chunking.remainder)),
    });
    jobs
}

fn resolve_export_jobs(requested: Option<NonZeroUsize>, total: usize) -> usize {
    let requested = requested
        .or_else(|| thread::available_parallelism().ok())
        .map(NonZeroUsize::get)
        .unwrap_or(1);
    requested.min(total.max(1))
}

fn export_layers_serial(
    repo: &ostree::Repo,
    commit: &str,
    ociw: &OciDir,
    jobs: Vec<LayerJob>,
    opts: &ExportOpts,
) -> Result<Vec<ExportedLayer>> {
    let opts = LayerExportOpts::from(opts);
    jobs.into_iter()
        .map(|job| export_one_layer(repo, commit, ociw, job, &opts))
        .collect()
}

fn export_layers_parallel(
    repo: &ostree::Repo,
    commit: &str,
    ociw: &OciDir,
    jobs: Vec<LayerJob>,
    opts: &ExportOpts,
) -> Result<Vec<ExportedLayer>> {
    let worker_count = resolve_export_jobs(opts.jobs, jobs.len());
    if worker_count <= 1 {
        return export_layers_serial(repo, commit, ociw, jobs, opts);
    }

    let queue = Arc::new(Mutex::new(VecDeque::from(jobs)));
    let (result_tx, result_rx) = mpsc::channel();
    let worker_opts = LayerExportOpts::from(opts);
    let mut handles = Vec::with_capacity(worker_count);
    for _ in 0..worker_count {
        let queue = Arc::clone(&queue);
        let result_tx = result_tx.clone();
        let repo = repo.clone();
        let commit = commit.to_string();
        let ocidir = ociw.dir().try_clone().context("Cloning OCI directory")?;
        let opts = worker_opts.clone();
        handles.push(thread::spawn(move || {
            let ocidir = match OciDir::open(ocidir).context("Opening OCI directory in worker") {
                Ok(ocidir) => ocidir,
                Err(err) => {
                    let _ = result_tx.send(Err(err));
                    return;
                }
            };
            loop {
                let job = match queue.lock().unwrap().pop_front() {
                    Some(job) => job,
                    None => break,
                };
                let result = export_one_layer(&repo, &commit, &ocidir, job, &opts);
                if result_tx.send(result).is_err() {
                    break;
                }
            }
        }));
    }
    drop(result_tx);

    let mut layers = Vec::new();
    let mut first_error = None;
    for result in result_rx {
        match result {
            Ok(layer) => layers.push(layer),
            Err(err) if first_error.is_none() => first_error = Some(err),
            Err(_) => {}
        }
    }
    for handle in handles {
        if handle.join().is_err() && first_error.is_none() {
            first_error = Some(anyhow!("OCI layer export worker panicked"));
        }
    }
    if let Some(err) = first_error {
        return Err(err);
    }
    layers.sort_by_key(|layer| layer.manifest_index);
    Ok(layers)
}

fn export_chunks(
    repo: &ostree::Repo,
    commit: &str,
    ociw: &OciDir,
    chunking: Chunking,
    opts: &ExportOpts,
    description: &str,
) -> Result<Vec<ExportedLayer>> {
    let total = chunking.chunks.len() + 1;
    let jobs = build_layer_jobs(chunking, total, description);
    let mut layers = export_layers_parallel(repo, commit, ociw, jobs, opts)?;
    layers.sort_by_key(|layer| layer.manifest_index);
    Ok(layers)
}

/// Write an ostree commit to an OCI blob
#[context("Writing ostree root to blob")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn export_chunked(
    repo: &ostree::Repo,
    commit: &str,
    ociw: &mut OciDir,
    manifest: &mut oci_image::ImageManifest,
    imgcfg: &mut oci_image::ImageConfiguration,
    labels: &mut HashMap<String, String>,
    chunking: Chunking,
    opts: &ExportOpts,
    description: &str,
) -> Result<()> {
    let mut layers = export_chunks(repo, commit, ociw, chunking, opts, description)?;
    let ostree_layer = layers.remove(0);

    // Then, we have a label that points to the last chunk.
    // Note in the pathological case of a single layer chunked v1 image, this could be the ostree layer.
    let last_digest = layers
        .last()
        .map(|v| &v.layer)
        .unwrap_or(&ostree_layer.layer)
        .uncompressed_sha256
        .clone();

    let created = imgcfg
        .created()
        .as_deref()
        .and_then(bootc_utils::try_deserialize_timestamp)
        .unwrap_or_default();
    // Add the ostree layer
    ociw.push_layer_full(
        manifest,
        imgcfg,
        ostree_layer.layer,
        None::<HashMap<String, String>>,
        description,
        created,
    );
    // Add the component/content layers
    let mut buf = [0; 8];
    let sep = COMPONENT_SEPARATOR.encode_utf8(&mut buf);
    for ExportedLayer {
        layer,
        name,
        mut packages,
        ..
    } in layers
    {
        let mut annotation_component_layer = HashMap::new();
        packages.sort();
        annotation_component_layer.insert(CONTENT_ANNOTATION.to_string(), packages.join(sep));
        ociw.push_layer_full(
            manifest,
            imgcfg,
            layer,
            Some(annotation_component_layer),
            name.as_str(),
            created,
        );
    }

    // This label (mentioned above) points to the last layer that is part of
    // the ostree commit.
    labels.insert(
        DIFFID_LABEL.into(),
        format!("sha256:{}", last_digest.digest()),
    );
    Ok(())
}

/// Generate an OCI image from a given ostree root
#[context("Building oci")]
#[allow(clippy::too_many_arguments)]
fn build_oci(
    repo: &ostree::Repo,
    rev: &str,
    writer: &mut OciDir,
    tag: Option<&str>,
    config: &Config,
    opts: ExportOpts,
) -> Result<()> {
    let commit = repo.require_rev(rev)?;
    let commit = commit.as_str();
    let (commit_v, _) = repo.load_commit(commit)?;
    let commit_timestamp = DateTime::from_timestamp(
        ostree::commit_get_timestamp(&commit_v).try_into().unwrap(),
        0,
    )
    .unwrap();
    let commit_subject = commit_v.child_value(3);
    let commit_subject = commit_subject.str().ok_or_else(|| {
        anyhow::anyhow!(
            "Corrupted commit {}; expecting string value for subject",
            commit
        )
    })?;
    let commit_meta = &commit_v.child_value(0);
    let commit_meta = glib::VariantDict::new(Some(commit_meta));

    let mut ctrcfg = opts.container_config.clone().unwrap_or_default();
    let mut imgcfg = oci_image::ImageConfiguration::default();
    // If a platform was provided, propagate it to the config
    if let Some(platform) = opts.platform.as_ref() {
        imgcfg.set_architecture(platform.architecture().clone());
        imgcfg.set_os(platform.os().clone());
    }

    let created_at = opts
        .created
        .clone()
        .unwrap_or_else(|| commit_timestamp.format("%Y-%m-%dT%H:%M:%SZ").to_string());
    imgcfg.set_created(Some(created_at));
    let mut labels = HashMap::new();

    commit_meta_to_labels(
        &commit_meta,
        opts.copy_meta_keys.iter().map(|k| k.as_str()),
        opts.copy_meta_opt_keys.iter().map(|k| k.as_str()),
        &mut labels,
    )?;

    let mut manifest = writer.new_empty_manifest()?.build().unwrap();

    let chunking = opts
        .package_contentmeta
        .as_ref()
        .map(|meta| {
            crate::chunking::Chunking::from_mapping(
                repo,
                commit,
                meta,
                &opts.max_layers,
                opts.prior_build,
                opts.specific_contentmeta,
            )
        })
        .transpose()?;
    // If no chunking was provided, create a logical single chunk.
    let chunking = chunking
        .map(Ok)
        .unwrap_or_else(|| crate::chunking::Chunking::new(repo, commit))?;

    if let Some(version) = commit_meta.lookup::<String>("version")? {
        if opts.legacy_version_label {
            labels.insert(LEGACY_VERSION_LABEL.into(), version.clone());
        }
        labels.insert(oci_image::ANNOTATION_VERSION.into(), version);
    }
    labels.insert(OSTREE_COMMIT_LABEL.into(), commit.into());

    for (k, v) in config.labels.iter().flat_map(|k| k.iter()) {
        labels.insert(k.into(), v.into());
    }

    let mut annos = HashMap::new();
    annos.insert(BLOB_OSTREE_ANNOTATION.to_string(), "true".to_string());
    let description = if commit_subject.is_empty() {
        Cow::Owned(format!("ostree export of commit {commit}"))
    } else {
        Cow::Borrowed(commit_subject)
    };

    export_chunked(
        repo,
        commit,
        writer,
        &mut manifest,
        &mut imgcfg,
        &mut labels,
        chunking,
        &opts,
        &description,
    )?;

    // Lookup the cmd embedded in commit metadata
    let cmd = commit_meta.lookup::<Vec<String>>(ostree::COMMIT_META_CONTAINER_CMD)?;
    // But support it being overridden by CLI options

    // https://github.com/rust-lang/rust-clippy/pull/7639#issuecomment-1050340564
    #[allow(clippy::unnecessary_lazy_evaluations)]
    let cmd = config.cmd.as_ref().or_else(|| cmd.as_ref());
    if let Some(cmd) = cmd {
        ctrcfg.set_cmd(Some(cmd.clone()));
    }

    // Our platform uses the image config
    let platform = oci_image::PlatformBuilder::default()
        .architecture(imgcfg.architecture().clone())
        .os(imgcfg.os().clone())
        .build()
        .unwrap();

    ctrcfg
        .labels_mut()
        .get_or_insert_with(Default::default)
        .extend(labels.clone());
    imgcfg.set_config(Some(ctrcfg));
    let ctrcfg = writer.write_config(imgcfg)?;
    manifest.set_config(ctrcfg);
    manifest.set_annotations(Some(labels));

    if let Some(tag) = tag {
        writer.insert_manifest(manifest, Some(tag), platform)?;
    } else {
        writer.replace_with_single_manifest(manifest, platform)?;
    }

    Ok(())
}

/// Interpret a filesystem path as optionally including a tag.  Paths
/// such as `/foo/bar` will return `("/foo/bar"`, None)`, whereas
/// e.g. `/foo/bar:latest` will return `("/foo/bar", Some("latest"))`.
pub(crate) fn parse_oci_path_and_tag(path: &str) -> (&str, Option<&str>) {
    match path.split_once(':') {
        Some((path, tag)) => (path, Some(tag)),
        None => (path, None),
    }
}

/// Helper for `build()` that avoids generics
#[instrument(level = "debug", skip_all)]
async fn build_impl(
    repo: &ostree::Repo,
    ostree_ref: &str,
    config: &Config,
    opts: Option<ExportOpts<'_, '_>>,
    dest: &ImageReference,
) -> Result<oci_image::Digest> {
    let mut opts = opts.unwrap_or_default();
    if dest.transport == Transport::ContainerStorage {
        opts.skip_compression = true;
    }
    let digest = if dest.transport == Transport::OciDir {
        let (path, tag) = parse_oci_path_and_tag(dest.name.as_str());
        tracing::debug!("using OCI path={path} tag={tag:?}");
        if !Utf8Path::new(path).exists() {
            std::fs::create_dir(path).with_context(|| format!("Creating {path}"))?;
        }
        let ocidir = Dir::open_ambient_dir(path, cap_std::ambient_authority())
            .with_context(|| format!("Opening {path}"))?;
        let mut ocidir = OciDir::ensure(ocidir).context("Opening OCI")?;
        build_oci(repo, ostree_ref, &mut ocidir, tag, config, opts)?;
        None
    } else {
        let tempdir = {
            let vartmp = Dir::open_ambient_dir("/var/tmp", cap_std::ambient_authority())?;
            cap_std_ext::cap_tempfile::tempdir_in(&vartmp)?
        };
        let mut ocidir = OciDir::ensure(tempdir.try_clone()?)?;

        // Minor TODO: refactor to avoid clone
        let authfile = opts.authfile.clone();
        build_oci(repo, ostree_ref, &mut ocidir, None, config, opts)?;
        drop(ocidir);

        // Pass the temporary oci directory as the current working directory for the skopeo process
        let target_fd = 3i32;
        let tempoci = ImageReference {
            transport: Transport::OciDir,
            name: format!("/proc/self/fd/{target_fd}"),
        };
        let digest = skopeo::copy(
            &tempoci,
            dest,
            authfile.as_deref(),
            Some((std::sync::Arc::new(tempdir.try_clone()?.into()), target_fd)),
            false,
        )
        .await?;
        Some(digest)
    };
    if let Some(digest) = digest {
        Ok(digest)
    } else {
        // If `skopeo copy` doesn't have `--digestfile` yet, then fall back
        // to running an inspect cycle.
        let imgref = OstreeImageReference {
            sigverify: SignatureSource::ContainerPolicyAllowInsecure,
            imgref: dest.to_owned(),
        };
        let (_, digest) = super::unencapsulate::fetch_manifest(&imgref)
            .await
            .context("Querying manifest after push")?;
        Ok(digest)
    }
}

/// Options controlling commit export into OCI
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct ExportOpts<'m, 'o> {
    /// If true, do not perform gzip compression of the tar layers.
    pub skip_compression: bool,
    /// A set of commit metadata keys to copy as image labels.
    pub copy_meta_keys: Vec<String>,
    /// A set of optionally-present commit metadata keys to copy as image labels.
    pub copy_meta_opt_keys: Vec<String>,
    /// Maximum number of layers to use
    pub max_layers: Option<NonZeroU32>,
    /// Path to Docker-formatted authentication file.
    pub authfile: Option<std::path::PathBuf>,
    /// Also include the legacy `version` label.
    pub legacy_version_label: bool,
    /// Image runtime configuration that will be used as a base
    pub container_config: Option<oci_image::Config>,
    /// Override the default platform
    pub platform: Option<oci_image::Platform>,
    /// A reference to the metadata for a previous build; used to optimize
    /// the packing structure.
    pub prior_build: Option<&'m oci_image::ImageManifest>,
    /// Metadata mapping between objects and their owning component/package;
    /// used to optimize packing.
    pub package_contentmeta: Option<&'o ObjectMetaSized>,
    /// Metadata for exclusive components that should have their own layers.
    /// Map from component -> (path, checksum)
    pub specific_contentmeta: Option<&'o BTreeMap<ContentID, Vec<(Utf8PathBuf, String)>>>,
    /// Sets the created tag in the image manifest.
    pub created: Option<String>,
    /// Whether to explicitly create all parent directories in the tar layers.
    pub tar_create_parent_dirs: bool,
    /// Number of worker threads to use for exporting OCI layers. If unset, use available parallelism.
    pub jobs: Option<NonZeroUsize>,
    /// Optional progress event sink for OCI layer export.
    pub progress: Option<mpsc::Sender<ExportProgress>>,
}

impl ExportOpts<'_, '_> {
    /// Return the gzip compression level to use, as configured by the export options.
    fn compression(&self) -> Compression {
        if self.skip_compression {
            Compression::fast()
        } else {
            Compression::default()
        }
    }
}

/// Given an OSTree repository and ref, generate a container image.
///
/// The returned `ImageReference` will contain a digested (e.g. `@sha256:`) version of the destination.
pub async fn encapsulate<S: AsRef<str>>(
    repo: &ostree::Repo,
    ostree_ref: S,
    config: &Config,
    opts: Option<ExportOpts<'_, '_>>,
    dest: &ImageReference,
) -> Result<oci_image::Digest> {
    build_impl(repo, ostree_ref.as_ref(), config, opts, dest).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ocipath() {
        let default = "/foo/bar";
        let untagged = "/foo/bar:baz";
        let tagged = "/foo/bar:baz:latest";
        assert_eq!(parse_oci_path_and_tag(default), ("/foo/bar", None));
        assert_eq!(
            parse_oci_path_and_tag(tagged),
            ("/foo/bar", Some("baz:latest"))
        );
        assert_eq!(parse_oci_path_and_tag(untagged), ("/foo/bar", Some("baz")));
    }
}
