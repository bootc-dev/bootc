//! APIs for storing (layered) container images as OSTree commits
//!
//! # Extension of encapsulation support
//!
//! This code supports ingesting arbitrary layered container images from an ostree-exported
//! base.  See [`encapsulate`][`super::encapsulate()`] for more information on encaspulation of images.

use super::*;
use crate::chunking::{self, Chunk};
use crate::container::Decompressor;
use crate::logging::system_repo_journal_print;
use crate::refescape;
use crate::sysroot::SysrootLock;
use crate::utils::ResultExt;
use anyhow::{anyhow, Context};
use camino::{Utf8Path, Utf8PathBuf};
use cap_std_ext::cap_std;
use cap_std_ext::cap_std::fs::{Dir, MetadataExt};
use cap_std_ext::cmdext::CapStdExtCommandExt;
use cap_std_ext::dirext::CapStdExtDirExt;
use containers_image_proxy::{ImageProxy, OpenedImage};
use flate2::Compression;
use fn_error_context::context;
use futures_util::TryFutureExt;
use glib::prelude::*;
use oci_spec::image::{
    self as oci_image, Arch, Descriptor, Digest, History, ImageConfiguration, ImageManifest,
};
use ostree::prelude::{Cast, FileEnumeratorExt, FileExt, ToVariant};
use ostree::{gio, glib};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::iter::FromIterator;
use std::num::NonZeroUsize;
use tokio::sync::mpsc::{Receiver, Sender};

/// Configuration for the proxy.
///
/// We re-export this rather than inventing our own wrapper
/// in the interest of avoiding duplication.
pub use containers_image_proxy::ImageProxyConfig;

/// The ostree ref prefix for blobs.
const LAYER_PREFIX: &str = "ostree/container/blob";
/// The ostree ref prefix for image references.
const IMAGE_PREFIX: &str = "ostree/container/image";
/// The ostree ref prefix for "base" image references that are used by derived images.
/// If you maintain tooling which is locally building derived commits, write a ref
/// with this prefix that is owned by your code.  It's a best practice to prefix the
/// ref with the project name, so the final ref may be of the form e.g. `ostree/container/baseimage/bootc/foo`.
pub const BASE_IMAGE_PREFIX: &str = "ostree/container/baseimage";

/// The key injected into the merge commit for the manifest digest.
pub(crate) const META_MANIFEST_DIGEST: &str = "ostree.manifest-digest";
/// The key injected into the merge commit with the manifest serialized as JSON.
const META_MANIFEST: &str = "ostree.manifest";
/// The key injected into the merge commit with the image configuration serialized as JSON.
const META_CONFIG: &str = "ostree.container.image-config";
/// Value of type `a{sa{su}}` containing number of filtered out files
pub const META_FILTERED: &str = "ostree.tar-filtered";
/// The type used to store content filtering information with `META_FILTERED`.
pub type MetaFilteredData = HashMap<String, HashMap<String, u32>>;

/// The ref prefixes which point to ostree deployments.  (TODO: Add an official API for this)
const OSTREE_BASE_DEPLOYMENT_REFS: &[&str] = &["ostree/0", "ostree/1"];
/// A layering violation we'll carry for a bit to band-aid over https://github.com/coreos/rpm-ostree/issues/4185
const RPMOSTREE_BASE_REFS: &[&str] = &["rpmostree/base"];

/// Convert e.g. sha256:12345... into `/ostree/container/blob/sha256_2B12345...`.
fn ref_for_blob_digest(d: &str) -> Result<String> {
    refescape::prefix_escape_for_ref(LAYER_PREFIX, d)
}

/// Convert e.g. sha256:12345... into `/ostree/container/blob/sha256_2B12345...`.
fn ref_for_layer(l: &oci_image::Descriptor) -> Result<String> {
    ref_for_blob_digest(&l.digest().as_ref())
}

/// Convert e.g. sha256:12345... into `/ostree/container/blob/sha256_2B12345...`.
fn ref_for_image(l: &ImageReference) -> Result<String> {
    refescape::prefix_escape_for_ref(IMAGE_PREFIX, &l.to_string())
}

/// Sent across a channel to track start and end of a container fetch.
#[derive(Debug)]
pub enum ImportProgress {
    /// Started fetching this layer.
    OstreeChunkStarted(Descriptor),
    /// Successfully completed the fetch of this layer.
    OstreeChunkCompleted(Descriptor),
    /// Started fetching this layer.
    DerivedLayerStarted(Descriptor),
    /// Successfully completed the fetch of this layer.
    DerivedLayerCompleted(Descriptor),
}

impl ImportProgress {
    /// Returns `true` if this message signifies the start of a new layer being fetched.
    pub fn is_starting(&self) -> bool {
        match self {
            ImportProgress::OstreeChunkStarted(_) => true,
            ImportProgress::OstreeChunkCompleted(_) => false,
            ImportProgress::DerivedLayerStarted(_) => true,
            ImportProgress::DerivedLayerCompleted(_) => false,
        }
    }
}

/// Sent across a channel to track the byte-level progress of a layer fetch.
#[derive(Clone, Debug)]
pub struct LayerProgress {
    /// Index of the layer in the manifest
    pub layer_index: usize,
    /// Number of bytes downloaded
    pub fetched: u64,
    /// Total number of bytes outstanding
    pub total: u64,
}

/// State of an already pulled layered image.
#[derive(Debug, PartialEq, Eq)]
pub struct LayeredImageState {
    /// The base ostree commit
    pub base_commit: String,
    /// The merge commit unions all layers
    pub merge_commit: String,
    /// The digest of the original manifest
    pub manifest_digest: Digest,
    /// The image manifest
    pub manifest: ImageManifest,
    /// The image configuration
    pub configuration: ImageConfiguration,
    /// Metadata for (cached, previously fetched) updates to the image, if any.
    pub cached_update: Option<CachedImageUpdate>,
    /// The signature verification text from libostree for the base commit;
    /// in the future we should probably instead just proxy a signature object
    /// instead, but this is sufficient for now.
    pub verify_text: Option<String>,
}

impl LayeredImageState {
    /// Return the merged ostree commit for this image.
    ///
    /// This is not the same as the underlying base ostree commit.
    pub fn get_commit(&self) -> &str {
        self.merge_commit.as_str()
    }

    /// Retrieve the container image version.
    pub fn version(&self) -> Option<&str> {
        super::version_for_config(&self.configuration)
    }
}

/// Locally cached metadata for an update to an existing image.
#[derive(Debug, PartialEq, Eq)]
pub struct CachedImageUpdate {
    /// The image manifest
    pub manifest: ImageManifest,
    /// The image configuration
    pub config: ImageConfiguration,
    /// The digest of the manifest
    pub manifest_digest: Digest,
}

impl CachedImageUpdate {
    /// Retrieve the container image version.
    pub fn version(&self) -> Option<&str> {
        super::version_for_config(&self.config)
    }
}

/// Context for importing a container image.
#[derive(Debug)]
pub struct ImageImporter {
    repo: ostree::Repo,
    pub(crate) proxy: ImageProxy,
    imgref: OstreeImageReference,
    target_imgref: Option<OstreeImageReference>,
    no_imgref: bool,  // If true, do not write final image ref
    disable_gc: bool, // If true, don't prune unused image layers
    /// If true, require the image has the bootable flag
    require_bootable: bool,
    /// If true, we have ostree v2024.3 or newer.
    ostree_v2024_3: bool,
    pub(crate) proxy_img: OpenedImage,

    layer_progress: Option<Sender<ImportProgress>>,
    layer_byte_progress: Option<tokio::sync::watch::Sender<Option<LayerProgress>>>,
}

/// Result of invoking [`ImageImporter::prepare`].
#[derive(Debug)]
pub enum PrepareResult {
    /// The image reference is already present; the contained string is the OSTree commit.
    AlreadyPresent(Box<LayeredImageState>),
    /// The image needs to be downloaded
    Ready(Box<PreparedImport>),
}

/// A container image layer with associated downloaded-or-not state.
#[derive(Debug)]
pub struct ManifestLayerState {
    /// The underlying layer descriptor.
    pub layer: oci_image::Descriptor,
    // TODO semver: Make this readonly via an accessor
    /// The ostree ref name for this layer.
    pub ostree_ref: String,
    // TODO semver: Make this readonly via an accessor
    /// The ostree commit that caches this layer, if present.
    pub commit: Option<String>,
}

impl ManifestLayerState {
    /// Return the layer descriptor.
    pub fn layer(&self) -> &oci_image::Descriptor {
        &self.layer
    }
}

/// Information about which layers need to be downloaded.
#[derive(Debug)]
pub struct PreparedImport {
    /// The manifest digest that was found
    pub manifest_digest: Digest,
    /// The deserialized manifest.
    pub manifest: oci_image::ImageManifest,
    /// The deserialized configuration.
    pub config: oci_image::ImageConfiguration,
    /// The previous manifest
    pub previous_state: Option<Box<LayeredImageState>>,
    /// The previously stored manifest digest.
    pub previous_manifest_digest: Option<Digest>,
    /// The previously stored image ID.
    pub previous_imageid: Option<String>,
    /// The layers containing split objects
    pub ostree_layers: Vec<ManifestLayerState>,
    /// The layer for the ostree commit.
    pub ostree_commit_layer: Option<ManifestLayerState>,
    /// Any further non-ostree (derived) layers.
    pub layers: Vec<ManifestLayerState>,
    /// OSTree remote signature verification text, if enabled.
    pub verify_text: Option<String>,
}

impl PreparedImport {
    /// Iterate over all layers; the commit layer, the ostree split object layers, and any non-ostree layers.
    pub fn all_layers(&self) -> impl Iterator<Item = &ManifestLayerState> {
        self.ostree_commit_layer
            .iter()
            .chain(self.ostree_layers.iter())
            .chain(self.layers.iter())
    }

    /// Retrieve the container image version.
    pub fn version(&self) -> Option<&str> {
        super::version_for_config(&self.config)
    }

    /// If this image is using any deprecated features, return a message saying so.
    pub fn deprecated_warning(&self) -> Option<&'static str> {
        None
    }

    /// Iterate over all layers paired with their history entry.
    /// An error will be returned if the history does not cover all entries.
    pub fn layers_with_history(
        &self,
    ) -> impl Iterator<Item = Result<(&ManifestLayerState, &History)>> {
        // FIXME use .filter(|h| h.empty_layer.unwrap_or_default()) after https://github.com/containers/oci-spec-rs/pull/100 lands.
        let truncated = std::iter::once_with(|| Err(anyhow::anyhow!("Truncated history")));
        let history = self.config.history().iter().map(Ok).chain(truncated);
        self.all_layers()
            .zip(history)
            .map(|(s, h)| h.map(|h| (s, h)))
    }

    /// Iterate over all layers that are not present, along with their history description.
    pub fn layers_to_fetch(&self) -> impl Iterator<Item = Result<(&ManifestLayerState, &str)>> {
        self.layers_with_history().filter_map(|r| {
            r.map(|(l, h)| {
                l.commit.is_none().then(|| {
                    let comment = h.created_by().as_deref().unwrap_or("");
                    (l, comment)
                })
            })
            .transpose()
        })
    }

    /// Common helper to format a string for the status
    pub(crate) fn format_layer_status(&self) -> Option<String> {
        let (stored, to_fetch, to_fetch_size) =
            self.all_layers()
                .fold((0u32, 0u32, 0u64), |(stored, to_fetch, sz), v| {
                    if v.commit.is_some() {
                        (stored + 1, to_fetch, sz)
                    } else {
                        (stored, to_fetch + 1, sz + v.layer().size())
                    }
                });
        (to_fetch > 0).then(|| {
            let size = crate::glib::format_size(to_fetch_size);
            format!("layers already present: {stored}; layers needed: {to_fetch} ({size})")
        })
    }
}

// Given a manifest, compute its ostree ref name and cached ostree commit
pub(crate) fn query_layer(
    repo: &ostree::Repo,
    layer: oci_image::Descriptor,
) -> Result<ManifestLayerState> {
    let ostree_ref = ref_for_layer(&layer)?;
    let commit = repo.resolve_rev(&ostree_ref, true)?.map(|s| s.to_string());
    Ok(ManifestLayerState {
        layer,
        ostree_ref,
        commit,
    })
}

#[context("Reading manifest data from commit")]
fn manifest_data_from_commitmeta(
    commit_meta: &glib::VariantDict,
) -> Result<(oci_image::ImageManifest, Digest)> {
    let digest = commit_meta
        .lookup::<String>(META_MANIFEST_DIGEST)?
        .ok_or_else(|| anyhow!("Missing {} metadata on merge commit", META_MANIFEST_DIGEST))?;
    let digest = Digest::from_str(&digest)?;
    let manifest_bytes: String = commit_meta
        .lookup::<String>(META_MANIFEST)?
        .ok_or_else(|| anyhow!("Failed to find {} metadata key", META_MANIFEST))?;
    let r = serde_json::from_str(&manifest_bytes)?;
    Ok((r, digest))
}

fn image_config_from_commitmeta(commit_meta: &glib::VariantDict) -> Result<ImageConfiguration> {
    let config = if let Some(config) = commit_meta
        .lookup::<String>(META_CONFIG)?
        .filter(|v| v != "null") // Format v0 apparently old versions injected `null` here sadly...
        .map(|v| serde_json::from_str(&v).map_err(anyhow::Error::msg))
        .transpose()?
    {
        config
    } else {
        tracing::debug!("No image configuration found");
        Default::default()
    };
    Ok(config)
}

/// Return the original digest of the manifest stored in the commit metadata.
/// This will be a string of the form e.g. `sha256:<digest>`.
///
/// This can be used to uniquely identify the image.  For example, it can be used
/// in a "digested pull spec" like `quay.io/someuser/exampleos@sha256:...`.
pub fn manifest_digest_from_commit(commit: &glib::Variant) -> Result<Digest> {
    let commit_meta = &commit.child_value(0);
    let commit_meta = &glib::VariantDict::new(Some(commit_meta));
    Ok(manifest_data_from_commitmeta(commit_meta)?.1)
}

/// Given a target diffid, return its corresponding layer.  In our current model,
/// we require a 1-to-1 mapping between the two up until the ostree level.
/// For a bit more information on this, see https://github.com/opencontainers/image-spec/blob/main/config.md
fn layer_from_diffid<'a>(
    manifest: &'a ImageManifest,
    config: &ImageConfiguration,
    diffid: &str,
) -> Result<&'a Descriptor> {
    let idx = config
        .rootfs()
        .diff_ids()
        .iter()
        .position(|x| x.as_str() == diffid)
        .ok_or_else(|| anyhow!("Missing {} {}", DIFFID_LABEL, diffid))?;
    manifest.layers().get(idx).ok_or_else(|| {
        anyhow!(
            "diffid position {} exceeds layer count {}",
            idx,
            manifest.layers().len()
        )
    })
}

#[context("Parsing manifest layout")]
pub(crate) fn parse_manifest_layout<'a>(
    manifest: &'a ImageManifest,
    config: &ImageConfiguration,
) -> Result<(
    Option<&'a Descriptor>,
    Vec<&'a Descriptor>,
    Vec<&'a Descriptor>,
)> {
    let config_labels = super::labels_of(config);

    let first_layer = manifest
        .layers()
        .first()
        .ok_or_else(|| anyhow!("No layers in manifest"))?;
    let Some(target_diffid) = config_labels.and_then(|labels| labels.get(DIFFID_LABEL)) else {
        return Ok((None, Vec::new(), manifest.layers().iter().collect()));
    };

    let target_layer = layer_from_diffid(manifest, config, target_diffid.as_str())?;
    let mut chunk_layers = Vec::new();
    let mut derived_layers = Vec::new();
    let mut after_target = false;
    // Gather the ostree layer
    let ostree_layer = first_layer;
    for layer in manifest.layers() {
        if layer == target_layer {
            if after_target {
                anyhow::bail!("Multiple entries for {}", layer.digest());
            }
            after_target = true;
            if layer != ostree_layer {
                chunk_layers.push(layer);
            }
        } else if !after_target {
            if layer != ostree_layer {
                chunk_layers.push(layer);
            }
        } else {
            derived_layers.push(layer);
        }
    }

    Ok((Some(ostree_layer), chunk_layers, derived_layers))
}

/// Like [`parse_manifest_layout`] but requires the image has an ostree base.
#[context("Parsing manifest layout")]
pub(crate) fn parse_ostree_manifest_layout<'a>(
    manifest: &'a ImageManifest,
    config: &ImageConfiguration,
) -> Result<(&'a Descriptor, Vec<&'a Descriptor>, Vec<&'a Descriptor>)> {
    let (ostree_layer, component_layers, derived_layers) = parse_manifest_layout(manifest, config)?;
    let ostree_layer = ostree_layer.ok_or_else(|| {
        anyhow!("No {DIFFID_LABEL} label found, not an ostree encapsulated container")
    })?;
    Ok((ostree_layer, component_layers, derived_layers))
}

/// Find the timestamp of the manifest (or config), ignoring errors.
fn timestamp_of_manifest_or_config(
    manifest: &ImageManifest,
    config: &ImageConfiguration,
) -> Option<u64> {
    // The manifest timestamp seems to not be widely used, but let's
    // try it in preference to the config one.
    let timestamp = manifest
        .annotations()
        .as_ref()
        .and_then(|a| a.get(oci_image::ANNOTATION_CREATED))
        .or_else(|| config.created().as_ref());
    // Try to parse the timestamp
    timestamp
        .map(|t| {
            chrono::DateTime::parse_from_rfc3339(t)
                .context("Failed to parse manifest timestamp")
                .map(|t| t.timestamp() as u64)
        })
        .transpose()
        .log_err_default()
}

/// Automatically clean up files that may have been injected by container
/// builds. xref https://github.com/containers/buildah/issues/4242
fn cleanup_root(root: &Dir) -> Result<()> {
    const RUNTIME_INJECTED: &[&str] = &["usr/etc/hostname", "usr/etc/resolv.conf"];
    for ent in RUNTIME_INJECTED {
        if let Some(meta) = root.symlink_metadata_optional(ent)? {
            if meta.is_file() && meta.size() == 0 {
                tracing::debug!("Removing {ent}");
                root.remove_file(ent)?;
            }
        }
    }
    Ok(())
}

impl ImageImporter {
    /// The metadata key used in ostree commit metadata to serialize
    const CACHED_KEY_MANIFEST_DIGEST: &'static str = "ostree-ext.cached.manifest-digest";
    const CACHED_KEY_MANIFEST: &'static str = "ostree-ext.cached.manifest";
    const CACHED_KEY_CONFIG: &'static str = "ostree-ext.cached.config";

    /// Create a new importer.
    #[context("Creating importer")]
    pub async fn new(
        repo: &ostree::Repo,
        imgref: &OstreeImageReference,
        mut config: ImageProxyConfig,
    ) -> Result<Self> {
        if imgref.imgref.transport == Transport::ContainerStorage {
            // Fetching from containers-storage, may require privileges to read files
            merge_default_container_proxy_opts_with_isolation(&mut config, None)?;
        } else {
            // Apply our defaults to the proxy config
            merge_default_container_proxy_opts(&mut config)?;
        }
        let proxy = ImageProxy::new_with_config(config).await?;

        system_repo_journal_print(
            repo,
            libsystemd::logging::Priority::Info,
            &format!("Fetching {}", imgref),
        );

        let proxy_img = proxy.open_image(&imgref.imgref.to_string()).await?;
        let repo = repo.clone();
        Ok(ImageImporter {
            repo,
            proxy,
            proxy_img,
            target_imgref: None,
            no_imgref: false,
            ostree_v2024_3: ostree::check_version(2024, 3),
            disable_gc: false,
            require_bootable: false,
            imgref: imgref.clone(),
            layer_progress: None,
            layer_byte_progress: None,
        })
    }

    /// Write cached data as if the image came from this source.
    pub fn set_target(&mut self, target: &OstreeImageReference) {
        self.target_imgref = Some(target.clone())
    }

    /// Do not write the final image ref, but do write refs for shared layers.
    /// This is useful in scenarios where you want to "pre-pull" an image,
    /// but in such a way that it does not need to be manually removed later.
    pub fn set_no_imgref(&mut self) {
        self.no_imgref = true;
    }

    /// Require that the image has the bootable metadata field
    pub fn require_bootable(&mut self) {
        self.require_bootable = true;
    }

    /// Override the ostree version being targeted
    pub fn set_ostree_version(&mut self, year: u32, v: u32) {
        self.ostree_v2024_3 = (year > 2024) || (year == 2024 && v >= 3)
    }

    /// Do not prune image layers.
    pub fn disable_gc(&mut self) {
        self.disable_gc = true;
    }

    /// Determine if there is a new manifest, and if so return its digest.
    /// This will also serialize the new manifest and configuration into
    /// metadata associated with the image, so that invocations of `[query_cached]`
    /// can re-fetch it without accessing the network.
    #[context("Preparing import")]
    pub async fn prepare(&mut self) -> Result<PrepareResult> {
        self.prepare_internal(false).await
    }

    /// Create a channel receiver that will get notifications for layer fetches.
    pub fn request_progress(&mut self) -> Receiver<ImportProgress> {
        assert!(self.layer_progress.is_none());
        let (s, r) = tokio::sync::mpsc::channel(2);
        self.layer_progress = Some(s);
        r
    }

    /// Create a channel receiver that will get notifications for byte-level progress of layer fetches.
    pub fn request_layer_progress(
        &mut self,
    ) -> tokio::sync::watch::Receiver<Option<LayerProgress>> {
        assert!(self.layer_byte_progress.is_none());
        let (s, r) = tokio::sync::watch::channel(None);
        self.layer_byte_progress = Some(s);
        r
    }

    /// Serialize the metadata about a pending fetch as detached metadata on the commit object,
    /// so it can be retrieved later offline
    #[context("Writing cached pending manifest")]
    pub(crate) async fn cache_pending(
        &self,
        commit: &str,
        manifest_digest: &Digest,
        manifest: &ImageManifest,
        config: &ImageConfiguration,
    ) -> Result<()> {
        let commitmeta = glib::VariantDict::new(None);
        commitmeta.insert(
            Self::CACHED_KEY_MANIFEST_DIGEST,
            manifest_digest.to_string(),
        );
        let cached_manifest = serde_json::to_string(manifest).context("Serializing manifest")?;
        commitmeta.insert(Self::CACHED_KEY_MANIFEST, cached_manifest);
        let cached_config = serde_json::to_string(config).context("Serializing config")?;
        commitmeta.insert(Self::CACHED_KEY_CONFIG, cached_config);
        let commitmeta = commitmeta.to_variant();
        // Clone these to move into blocking method
        let commit = commit.to_string();
        let repo = self.repo.clone();
        crate::tokio_util::spawn_blocking_cancellable_flatten(move |cancellable| {
            repo.write_commit_detached_metadata(&commit, Some(&commitmeta), Some(cancellable))
                .map_err(anyhow::Error::msg)
        })
        .await
    }

    /// Given existing metadata (manifest, config, previous image statE) generate a PreparedImport structure
    /// which e.g. includes a diff of the layers.
    fn create_prepared_import(
        &mut self,
        manifest_digest: Digest,
        manifest: ImageManifest,
        config: ImageConfiguration,
        previous_state: Option<Box<LayeredImageState>>,
        previous_imageid: Option<String>,
    ) -> Result<Box<PreparedImport>> {
        let config_labels = super::labels_of(&config);
        if self.require_bootable {
            let bootable_key = ostree::METADATA_KEY_BOOTABLE;
            let bootable = config_labels.map_or(false, |l| {
                l.contains_key(bootable_key.as_str()) || l.contains_key(BOOTC_LABEL)
            });
            if !bootable {
                anyhow::bail!("Target image does not have {bootable_key} label");
            }
            let container_arch = config.architecture();
            let target_arch = &Arch::default();
            if container_arch != target_arch {
                anyhow::bail!("Image has architecture {container_arch}; expected {target_arch}");
            }
        }

        let (commit_layer, component_layers, remaining_layers) =
            parse_manifest_layout(&manifest, &config)?;

        let query = |l: &Descriptor| query_layer(&self.repo, l.clone());
        let commit_layer = commit_layer.map(query).transpose()?;
        let component_layers = component_layers
            .into_iter()
            .map(query)
            .collect::<Result<Vec<_>>>()?;
        let remaining_layers = remaining_layers
            .into_iter()
            .map(query)
            .collect::<Result<Vec<_>>>()?;

        let previous_manifest_digest = previous_state.as_ref().map(|s| s.manifest_digest.clone());
        let imp = PreparedImport {
            manifest_digest,
            manifest,
            config,
            previous_state,
            previous_manifest_digest,
            previous_imageid,
            ostree_layers: component_layers,
            ostree_commit_layer: commit_layer,
            layers: remaining_layers,
            verify_text: None,
        };
        Ok(Box::new(imp))
    }

    /// Determine if there is a new manifest, and if so return its digest.
    #[context("Fetching manifest")]
    pub(crate) async fn prepare_internal(&mut self, verify_layers: bool) -> Result<PrepareResult> {
        match &self.imgref.sigverify {
            SignatureSource::ContainerPolicy if skopeo::container_policy_is_default_insecure()? => {
                return Err(anyhow!("containers-policy.json specifies a default of `insecureAcceptAnything`; refusing usage"));
            }
            SignatureSource::OstreeRemote(_) if verify_layers => {
                return Err(anyhow!(
                    "Cannot currently verify layered containers via ostree remote"
                ));
            }
            _ => {}
        }

        let (manifest_digest, manifest) = self.proxy.fetch_manifest(&self.proxy_img).await?;
        let manifest_digest = Digest::from_str(&manifest_digest)?;
        let new_imageid = manifest.config().digest();

        // Query for previous stored state

        let (previous_state, previous_imageid) =
            if let Some(previous_state) = try_query_image(&self.repo, &self.imgref.imgref)? {
                // If the manifest digests match, we're done.
                if previous_state.manifest_digest == manifest_digest {
                    return Ok(PrepareResult::AlreadyPresent(previous_state));
                }
                // Failing that, if they have the same imageID, we're also done.
                let previous_imageid = previous_state.manifest.config().digest();
                if previous_imageid == new_imageid {
                    return Ok(PrepareResult::AlreadyPresent(previous_state));
                }
                let previous_imageid = previous_imageid.to_string();
                (Some(previous_state), Some(previous_imageid))
            } else {
                (None, None)
            };

        let config = self.proxy.fetch_config(&self.proxy_img).await?;

        // If there is a currently fetched image, cache the new pending manifest+config
        // as detached commit metadata, so that future fetches can query it offline.
        if let Some(previous_state) = previous_state.as_ref() {
            self.cache_pending(
                previous_state.merge_commit.as_str(),
                &manifest_digest,
                &manifest,
                &config,
            )
            .await?;
        }

        let imp = self.create_prepared_import(
            manifest_digest,
            manifest,
            config,
            previous_state,
            previous_imageid,
        )?;
        Ok(PrepareResult::Ready(imp))
    }

    /// Extract the base ostree commit.
    #[context("Unencapsulating base")]
    pub(crate) async fn unencapsulate_base(
        &self,
        import: &mut store::PreparedImport,
        require_ostree: bool,
        write_refs: bool,
    ) -> Result<()> {
        tracing::debug!("Fetching base");
        if matches!(self.imgref.sigverify, SignatureSource::ContainerPolicy)
            && skopeo::container_policy_is_default_insecure()?
        {
            return Err(anyhow!("containers-policy.json specifies a default of `insecureAcceptAnything`; refusing usage"));
        }
        let remote = match &self.imgref.sigverify {
            SignatureSource::OstreeRemote(remote) => Some(remote.clone()),
            SignatureSource::ContainerPolicy | SignatureSource::ContainerPolicyAllowInsecure => {
                None
            }
        };
        let Some(commit_layer) = import.ostree_commit_layer.as_mut() else {
            if require_ostree {
                anyhow::bail!(
                    "No {DIFFID_LABEL} label found, not an ostree encapsulated container"
                );
            }
            return Ok(());
        };
        let des_layers = self.proxy.get_layer_info(&self.proxy_img).await?;
        for layer in import.ostree_layers.iter_mut() {
            if layer.commit.is_some() {
                continue;
            }
            if let Some(p) = self.layer_progress.as_ref() {
                p.send(ImportProgress::OstreeChunkStarted(layer.layer.clone()))
                    .await?;
            }
            let (blob, driver, media_type) = fetch_layer(
                &self.proxy,
                &self.proxy_img,
                &import.manifest,
                &layer.layer,
                self.layer_byte_progress.as_ref(),
                des_layers.as_ref(),
                self.imgref.imgref.transport,
            )
            .await?;
            let repo = self.repo.clone();
            let target_ref = layer.ostree_ref.clone();
            let import_task =
                crate::tokio_util::spawn_blocking_cancellable_flatten(move |cancellable| {
                    let txn = repo.auto_transaction(Some(cancellable))?;
                    let mut importer = crate::tar::Importer::new_for_object_set(&repo);
                    let blob = tokio_util::io::SyncIoBridge::new(blob);
                    let mut blob = Decompressor::new(&media_type, blob)?;
                    let mut archive = tar::Archive::new(&mut blob);
                    importer.import_objects(&mut archive, Some(cancellable))?;
                    let commit = if write_refs {
                        let commit = importer.finish_import_object_set()?;
                        repo.transaction_set_ref(None, &target_ref, Some(commit.as_str()));
                        tracing::debug!("Wrote {} => {}", target_ref, commit);
                        Some(commit)
                    } else {
                        None
                    };
                    txn.commit(Some(cancellable))?;
                    blob.finish()?;
                    Ok::<_, anyhow::Error>(commit)
                })
                .map_err(|e| e.context(format!("Layer {}", layer.layer.digest())));
            let commit = super::unencapsulate::join_fetch(import_task, driver).await?;
            layer.commit = commit;
            if let Some(p) = self.layer_progress.as_ref() {
                p.send(ImportProgress::OstreeChunkCompleted(layer.layer.clone()))
                    .await?;
            }
        }
        if commit_layer.commit.is_none() {
            if let Some(p) = self.layer_progress.as_ref() {
                p.send(ImportProgress::OstreeChunkStarted(
                    commit_layer.layer.clone(),
                ))
                .await?;
            }
            let (blob, driver, media_type) = fetch_layer(
                &self.proxy,
                &self.proxy_img,
                &import.manifest,
                &commit_layer.layer,
                self.layer_byte_progress.as_ref(),
                des_layers.as_ref(),
                self.imgref.imgref.transport,
            )
            .await?;
            let repo = self.repo.clone();
            let target_ref = commit_layer.ostree_ref.clone();
            let import_task =
                crate::tokio_util::spawn_blocking_cancellable_flatten(move |cancellable| {
                    let txn = repo.auto_transaction(Some(cancellable))?;
                    let mut importer = crate::tar::Importer::new_for_commit(&repo, remote);
                    let blob = tokio_util::io::SyncIoBridge::new(blob);
                    let mut blob = Decompressor::new(&media_type, blob)?;
                    let mut archive = tar::Archive::new(&mut blob);
                    importer.import_commit(&mut archive, Some(cancellable))?;
                    let (commit, verify_text) = importer.finish_import_commit();
                    if write_refs {
                        repo.transaction_set_ref(None, &target_ref, Some(commit.as_str()));
                        tracing::debug!("Wrote {} => {}", target_ref, commit);
                    }
                    repo.mark_commit_partial(&commit, false)?;
                    txn.commit(Some(cancellable))?;
                    blob.finish()?;
                    Ok::<_, anyhow::Error>((commit, verify_text))
                });
            let (commit, verify_text) =
                super::unencapsulate::join_fetch(import_task, driver).await?;
            commit_layer.commit = Some(commit);
            import.verify_text = verify_text;
            if let Some(p) = self.layer_progress.as_ref() {
                p.send(ImportProgress::OstreeChunkCompleted(
                    commit_layer.layer.clone(),
                ))
                .await?;
            }
        };
        Ok(())
    }

    /// Retrieve an inner ostree commit.
    ///
    /// This does not write cached references for each blob, and errors out if
    /// the image has any non-ostree layers.
    pub async fn unencapsulate(mut self) -> Result<Import> {
        let mut prep = match self.prepare_internal(false).await? {
            PrepareResult::AlreadyPresent(_) => {
                panic!("Should not have image present for unencapsulation")
            }
            PrepareResult::Ready(r) => r,
        };
        if !prep.layers.is_empty() {
            anyhow::bail!("Image has {} non-ostree layers", prep.layers.len());
        }
        let deprecated_warning = prep.deprecated_warning().map(ToOwned::to_owned);
        self.unencapsulate_base(&mut prep, true, false).await?;
        // TODO change the imageproxy API to ensure this happens automatically when
        // the image reference is dropped
        self.proxy.close_image(&self.proxy_img).await?;
        // SAFETY: We know we have a commit
        let ostree_commit = prep.ostree_commit_layer.unwrap().commit.unwrap();
        let image_digest = prep.manifest_digest;
        Ok(Import {
            ostree_commit,
            image_digest,
            deprecated_warning,
        })
    }

    /// Import a layered container image.
    ///
    /// If enabled, this will also prune unused container image layers.
    #[context("Importing")]
    pub async fn import(
        mut self,
        mut import: Box<PreparedImport>,
    ) -> Result<Box<LayeredImageState>> {
        if let Some(status) = import.format_layer_status() {
            system_repo_journal_print(&self.repo, libsystemd::logging::Priority::Info, &status);
        }
        // First download all layers for the base image (if necessary) - we need the SELinux policy
        // there to label all following layers.
        self.unencapsulate_base(&mut import, false, true).await?;
        let des_layers = self.proxy.get_layer_info(&self.proxy_img).await?;
        let proxy = self.proxy;
        let proxy_img = self.proxy_img;
        let target_imgref = self.target_imgref.as_ref().unwrap_or(&self.imgref);
        let base_commit = import
            .ostree_commit_layer
            .as_ref()
            .map(|c| c.commit.clone().unwrap());

        let root_is_transient = if let Some(base) = base_commit.as_ref() {
            let rootf = self.repo.read_commit(&base, gio::Cancellable::NONE)?.0;
            let rootf = rootf.downcast_ref::<ostree::RepoFile>().unwrap();
            crate::ostree_prepareroot::overlayfs_root_enabled(rootf)?
        } else {
            // For generic images we assume they're using composefs
            true
        };
        tracing::debug!("Base rootfs is transient: {root_is_transient}");

        let ostree_ref = ref_for_image(&target_imgref.imgref)?;

        let mut layer_commits = Vec::new();
        let mut layer_filtered_content: MetaFilteredData = HashMap::new();
        let have_derived_layers = !import.layers.is_empty();
        tracing::debug!("Processing layers: {}", import.layers.len());
        for layer in import.layers {
            if let Some(c) = layer.commit {
                tracing::debug!("Reusing fetched commit {}", c);
                layer_commits.push(c.to_string());
            } else {
                if let Some(p) = self.layer_progress.as_ref() {
                    p.send(ImportProgress::DerivedLayerStarted(layer.layer.clone()))
                        .await?;
                }
                let (blob, driver, media_type) = super::unencapsulate::fetch_layer(
                    &proxy,
                    &proxy_img,
                    &import.manifest,
                    &layer.layer,
                    self.layer_byte_progress.as_ref(),
                    des_layers.as_ref(),
                    self.imgref.imgref.transport,
                )
                .await?;
                // An important aspect of this is that we SELinux label the derived layers using
                // the base policy.
                let opts = crate::tar::WriteTarOptions {
                    base: base_commit.clone(),
                    selinux: true,
                    allow_nonusr: root_is_transient,
                    retain_var: self.ostree_v2024_3,
                };
                let r = crate::tar::write_tar(
                    &self.repo,
                    blob,
                    media_type,
                    layer.ostree_ref.as_str(),
                    Some(opts),
                );
                let r = super::unencapsulate::join_fetch(r, driver)
                    .await
                    .with_context(|| format!("Parsing layer blob {}", layer.layer.digest()))?;
                tracing::debug!("Imported layer: {}", r.commit.as_str());
                layer_commits.push(r.commit);
                let filtered_owned = HashMap::from_iter(r.filtered.clone());
                if let Some((filtered, n_rest)) = bootc_utils::collect_until(
                    r.filtered.iter(),
                    const { NonZeroUsize::new(5).unwrap() },
                ) {
                    let mut msg = String::new();
                    for (path, n) in filtered {
                        write!(msg, "{path}: {n} ").unwrap();
                    }
                    if n_rest > 0 {
                        write!(msg, "...and {n_rest} more").unwrap();
                    }
                    tracing::debug!("Found filtered toplevels: {msg}");
                    layer_filtered_content.insert(layer.layer.digest().to_string(), filtered_owned);
                } else {
                    tracing::debug!("No filtered content");
                }
                if let Some(p) = self.layer_progress.as_ref() {
                    p.send(ImportProgress::DerivedLayerCompleted(layer.layer.clone()))
                        .await?;
                }
            }
        }

        // TODO change the imageproxy API to ensure this happens automatically when
        // the image reference is dropped
        proxy.close_image(&proxy_img).await?;

        // We're done with the proxy, make sure it didn't have any errors.
        proxy.finalize().await?;
        tracing::debug!("finalized proxy");

        // Disconnect progress notifiers to signal we're done with fetching.
        let _ = self.layer_byte_progress.take();
        let _ = self.layer_progress.take();

        let serialized_manifest = serde_json::to_string(&import.manifest)?;
        let serialized_config = serde_json::to_string(&import.config)?;
        let mut metadata = HashMap::new();
        metadata.insert(
            META_MANIFEST_DIGEST,
            import.manifest_digest.to_string().to_variant(),
        );
        metadata.insert(META_MANIFEST, serialized_manifest.to_variant());
        metadata.insert(META_CONFIG, serialized_config.to_variant());
        metadata.insert(
            "ostree.importer.version",
            env!("CARGO_PKG_VERSION").to_variant(),
        );
        let filtered = layer_filtered_content.to_variant();
        metadata.insert(META_FILTERED, filtered);
        let metadata = metadata.to_variant();

        let timestamp = timestamp_of_manifest_or_config(&import.manifest, &import.config)
            .unwrap_or_else(|| chrono::offset::Utc::now().timestamp() as u64);
        // Destructure to transfer ownership to thread
        let repo = self.repo;
        let mut state = crate::tokio_util::spawn_blocking_cancellable_flatten(
            move |cancellable| -> Result<Box<LayeredImageState>> {
                use rustix::fd::AsRawFd;

                let cancellable = Some(cancellable);
                let repo = &repo;
                let txn = repo.auto_transaction(cancellable)?;

                let devino = ostree::RepoDevInoCache::new();
                let repodir = Dir::reopen_dir(&repo.dfd_borrow())?;
                let repo_tmp = repodir.open_dir("tmp")?;
                let td = cap_std_ext::cap_tempfile::TempDir::new_in(&repo_tmp)?;

                let rootpath = "root";
                let checkout_mode = if repo.mode() == ostree::RepoMode::Bare {
                    ostree::RepoCheckoutMode::None
                } else {
                    ostree::RepoCheckoutMode::User
                };
                let mut checkout_opts = ostree::RepoCheckoutAtOptions {
                    mode: checkout_mode,
                    overwrite_mode: ostree::RepoCheckoutOverwriteMode::UnionFiles,
                    devino_to_csum_cache: Some(devino.clone()),
                    no_copy_fallback: true,
                    force_copy_zerosized: true,
                    process_whiteouts: false,
                    ..Default::default()
                };
                if let Some(base) = base_commit.as_ref() {
                    repo.checkout_at(
                        Some(&checkout_opts),
                        (*td).as_raw_fd(),
                        rootpath,
                        &base,
                        cancellable,
                    )
                    .context("Checking out base commit")?;
                }

                // Layer all subsequent commits
                checkout_opts.process_whiteouts = true;
                for commit in layer_commits {
                    tracing::debug!("Unpacking {commit}");
                    repo.checkout_at(
                        Some(&checkout_opts),
                        (*td).as_raw_fd(),
                        rootpath,
                        &commit,
                        cancellable,
                    )
                    .with_context(|| format!("Checking out layer {commit}"))?;
                }

                let root_dir = td.open_dir(rootpath)?;

                let modifier =
                    ostree::RepoCommitModifier::new(ostree::RepoCommitModifierFlags::empty(), None);
                modifier.set_devino_cache(&devino);
                // If we have derived layers, then we need to handle the case where
                // the derived layers include custom policy. Just relabel everything
                // in this case.
                if have_derived_layers {
                    let sepolicy = ostree::SePolicy::new_at(root_dir.as_raw_fd(), cancellable)?;
                    tracing::debug!("labeling from merged tree");
                    modifier.set_sepolicy(Some(&sepolicy));
                } else if let Some(base) = base_commit.as_ref() {
                    tracing::debug!("labeling from base tree");
                    // TODO: We can likely drop this; we know all labels should be pre-computed.
                    modifier.set_sepolicy_from_commit(repo, &base, cancellable)?;
                } else {
                    unreachable!()
                }

                cleanup_root(&root_dir)?;

                let mt = ostree::MutableTree::new();
                repo.write_dfd_to_mtree(
                    (*td).as_raw_fd(),
                    rootpath,
                    &mt,
                    Some(&modifier),
                    cancellable,
                )
                .context("Writing merged filesystem to mtree")?;

                let merged_root = repo
                    .write_mtree(&mt, cancellable)
                    .context("Writing mtree")?;
                let merged_root = merged_root.downcast::<ostree::RepoFile>().unwrap();
                let merged_commit = repo
                    .write_commit_with_time(
                        None,
                        None,
                        None,
                        Some(&metadata),
                        &merged_root,
                        timestamp,
                        cancellable,
                    )
                    .context("Writing commit")?;
                if !self.no_imgref {
                    repo.transaction_set_ref(None, &ostree_ref, Some(merged_commit.as_str()));
                }
                txn.commit(cancellable)?;

                if !self.disable_gc {
                    let n: u32 = gc_image_layers_impl(repo, cancellable)?;
                    tracing::debug!("pruned {n} layers");
                }

                // Here we re-query state just to run through the same code path,
                // though it'd be cheaper to synthesize it from the data we already have.
                let state = query_image_commit(repo, &merged_commit)?;
                Ok(state)
            },
        )
        .await?;
        // We can at least avoid re-verifying the base commit.
        state.verify_text = import.verify_text;
        Ok(state)
    }
}

/// List all images stored
pub fn list_images(repo: &ostree::Repo) -> Result<Vec<String>> {
    let cancellable = gio::Cancellable::NONE;
    let refs = repo.list_refs_ext(
        Some(IMAGE_PREFIX),
        ostree::RepoListRefsExtFlags::empty(),
        cancellable,
    )?;
    refs.keys()
        .map(|imgname| refescape::unprefix_unescape_ref(IMAGE_PREFIX, imgname))
        .collect()
}

/// Attempt to query metadata for a pulled image; if it is corrupted,
/// the error is printed to stderr and None is returned.
fn try_query_image(
    repo: &ostree::Repo,
    imgref: &ImageReference,
) -> Result<Option<Box<LayeredImageState>>> {
    let ostree_ref = &ref_for_image(imgref)?;
    if let Some(merge_rev) = repo.resolve_rev(ostree_ref, true)? {
        match query_image_commit(repo, merge_rev.as_str()) {
            Ok(r) => Ok(Some(r)),
            Err(e) => {
                eprintln!("error: failed to query image commit: {e}");
                Ok(None)
            }
        }
    } else {
        Ok(None)
    }
}

/// Query metadata for a pulled image.
#[context("Querying image {imgref}")]
pub fn query_image(
    repo: &ostree::Repo,
    imgref: &ImageReference,
) -> Result<Option<Box<LayeredImageState>>> {
    let ostree_ref = &ref_for_image(imgref)?;
    let merge_rev = repo.resolve_rev(ostree_ref, true)?;
    merge_rev
        .map(|r| query_image_commit(repo, r.as_str()))
        .transpose()
}

/// Given detached commit metadata, parse the data that we serialized for a pending update (if any).
fn parse_cached_update(meta: &glib::VariantDict) -> Result<Option<CachedImageUpdate>> {
    // Try to retrieve the manifest digest key from the commit detached metadata.
    let manifest_digest =
        if let Some(d) = meta.lookup::<String>(ImageImporter::CACHED_KEY_MANIFEST_DIGEST)? {
            d
        } else {
            // It's possible that something *else* wrote detached metadata, but without
            // our key; gracefully handle that.
            return Ok(None);
        };
    let manifest_digest = Digest::from_str(&manifest_digest)?;
    // If we found the cached manifest digest key, then we must have the manifest and config;
    // otherwise that's an error.
    let manifest = meta.lookup_value(ImageImporter::CACHED_KEY_MANIFEST, None);
    let manifest: oci_image::ImageManifest = manifest
        .as_ref()
        .and_then(|v| v.str())
        .map(serde_json::from_str)
        .transpose()?
        .ok_or_else(|| {
            anyhow!(
                "Expected cached manifest {}",
                ImageImporter::CACHED_KEY_MANIFEST
            )
        })?;
    let config = meta.lookup_value(ImageImporter::CACHED_KEY_CONFIG, None);
    let config: oci_image::ImageConfiguration = config
        .as_ref()
        .and_then(|v| v.str())
        .map(serde_json::from_str)
        .transpose()?
        .ok_or_else(|| {
            anyhow!(
                "Expected cached manifest {}",
                ImageImporter::CACHED_KEY_CONFIG
            )
        })?;
    Ok(Some(CachedImageUpdate {
        manifest,
        config,
        manifest_digest,
    }))
}

/// Remove any cached
#[context("Clearing cached update {imgref}")]
pub fn clear_cached_update(repo: &ostree::Repo, imgref: &ImageReference) -> Result<()> {
    let cancellable = gio::Cancellable::NONE;
    let ostree_ref = ref_for_image(imgref)?;
    let rev = repo.require_rev(&ostree_ref)?;
    let Some(commitmeta) = repo.read_commit_detached_metadata(&rev, cancellable)? else {
        return Ok(());
    };

    // SAFETY: We know this is an a{sv}
    let mut commitmeta: BTreeMap<String, glib::Variant> =
        BTreeMap::from_variant(&commitmeta).unwrap();
    let mut changed = false;
    for key in [
        ImageImporter::CACHED_KEY_CONFIG,
        ImageImporter::CACHED_KEY_MANIFEST,
        ImageImporter::CACHED_KEY_MANIFEST_DIGEST,
    ] {
        if commitmeta.remove(key).is_some() {
            changed = true;
        }
    }
    if !changed {
        return Ok(());
    }
    let commitmeta = glib::Variant::from(commitmeta);
    repo.write_commit_detached_metadata(&rev, Some(&commitmeta), cancellable)?;
    Ok(())
}

/// Query metadata for a pulled image via an OSTree commit digest.
/// The digest must refer to a pulled container image's merge commit.
pub fn query_image_commit(repo: &ostree::Repo, commit: &str) -> Result<Box<LayeredImageState>> {
    let merge_commit = commit.to_string();
    let merge_commit_obj = repo.load_commit(commit)?.0;
    let commit_meta = &merge_commit_obj.child_value(0);
    let commit_meta = &ostree::glib::VariantDict::new(Some(commit_meta));
    let (manifest, manifest_digest) = manifest_data_from_commitmeta(commit_meta)?;
    let configuration = image_config_from_commitmeta(commit_meta)?;
    let mut layers = manifest.layers().iter().cloned();
    // We require a base layer.
    let base_layer = layers.next().ok_or_else(|| anyhow!("No layers found"))?;
    let base_layer = query_layer(repo, base_layer)?;
    let ostree_ref = base_layer.ostree_ref.as_str();
    let base_commit = base_layer
        .commit
        .ok_or_else(|| anyhow!("Missing base image ref {ostree_ref}"))?;

    let detached_commitmeta =
        repo.read_commit_detached_metadata(&merge_commit, gio::Cancellable::NONE)?;
    let detached_commitmeta = detached_commitmeta
        .as_ref()
        .map(|v| glib::VariantDict::new(Some(v)));
    let cached_update = detached_commitmeta
        .as_ref()
        .map(parse_cached_update)
        .transpose()?
        .flatten();
    let state = Box::new(LayeredImageState {
        base_commit,
        merge_commit,
        manifest_digest,
        manifest,
        configuration,
        cached_update,
        // we can't cross-reference with a remote here
        verify_text: None,
    });
    tracing::debug!("Wrote merge commit {}", state.merge_commit);
    Ok(state)
}

fn manifest_for_image(repo: &ostree::Repo, imgref: &ImageReference) -> Result<ImageManifest> {
    let ostree_ref = ref_for_image(imgref)?;
    let rev = repo.require_rev(&ostree_ref)?;
    let (commit_obj, _) = repo.load_commit(rev.as_str())?;
    let commit_meta = &glib::VariantDict::new(Some(&commit_obj.child_value(0)));
    Ok(manifest_data_from_commitmeta(commit_meta)?.0)
}

/// Copy a downloaded image from one repository to another, while also
/// optionally changing the image reference type.
#[context("Copying image")]
pub async fn copy(
    src_repo: &ostree::Repo,
    src_imgref: &ImageReference,
    dest_repo: &ostree::Repo,
    dest_imgref: &ImageReference,
) -> Result<()> {
    let src_ostree_ref = ref_for_image(src_imgref)?;
    let src_commit = src_repo.require_rev(&src_ostree_ref)?;
    let manifest = manifest_for_image(src_repo, src_imgref)?;
    // Create a task to copy each layer, plus the final ref
    let layer_refs = manifest
        .layers()
        .iter()
        .map(ref_for_layer)
        .chain(std::iter::once(Ok(src_commit.to_string())));
    for ostree_ref in layer_refs {
        let ostree_ref = ostree_ref?;
        let src_repo = src_repo.clone();
        let dest_repo = dest_repo.clone();
        crate::tokio_util::spawn_blocking_cancellable_flatten(move |cancellable| -> Result<_> {
            let cancellable = Some(cancellable);
            let srcfd = &format!("file:///proc/self/fd/{}", src_repo.dfd());
            let flags = ostree::RepoPullFlags::MIRROR;
            let opts = glib::VariantDict::new(None);
            let refs = [ostree_ref.as_str()];
            // Some older archives may have bindings, we don't need to verify them.
            opts.insert("disable-verify-bindings", true);
            opts.insert("refs", &refs[..]);
            opts.insert("flags", flags.bits() as i32);
            let options = opts.to_variant();
            dest_repo.pull_with_options(srcfd, &options, None, cancellable)?;
            Ok(())
        })
        .await?;
    }

    let dest_ostree_ref = ref_for_image(dest_imgref)?;
    dest_repo.set_ref_immediate(
        None,
        &dest_ostree_ref,
        Some(&src_commit),
        gio::Cancellable::NONE,
    )?;

    Ok(())
}

/// Options controlling commit export into OCI
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct ExportToOCIOpts {
    /// If true, do not perform gzip compression of the tar layers.
    pub skip_compression: bool,
    /// Path to Docker-formatted authentication file.
    pub authfile: Option<std::path::PathBuf>,
    /// Output progress to stdout
    pub progress_to_stdout: bool,
}

/// The way we store "chunk" layers in ostree is by writing a commit
/// whose filenames are their own object identifier. This function parses
/// what is written by the `ImporterMode::ObjectSet` logic, turning
/// it back into a "chunked" structure that is used by the export code.
fn chunking_from_layer_committed(
    repo: &ostree::Repo,
    l: &Descriptor,
    chunking: &mut chunking::Chunking,
) -> Result<()> {
    let mut chunk = Chunk::default();
    let layer_ref = &ref_for_layer(l)?;
    let root = repo.read_commit(layer_ref, gio::Cancellable::NONE)?.0;
    let e = root.enumerate_children(
        "standard::name,standard::size",
        gio::FileQueryInfoFlags::NOFOLLOW_SYMLINKS,
        gio::Cancellable::NONE,
    )?;
    for child in e.clone() {
        let child = &child?;
        // The name here should be a valid checksum
        let name = child.name();
        // SAFETY: ostree doesn't give us non-UTF8 filenames
        let name = Utf8Path::from_path(&name).unwrap();
        ostree::validate_checksum_string(name.as_str())?;
        chunking.remainder.move_obj(&mut chunk, name.as_str());
    }
    chunking.chunks.push(chunk);
    Ok(())
}

/// Export an imported container image to a target OCI directory.
#[context("Copying image")]
pub(crate) fn export_to_oci(
    repo: &ostree::Repo,
    imgref: &ImageReference,
    dest_oci: &Dir,
    tag: Option<&str>,
    opts: ExportToOCIOpts,
) -> Result<Descriptor> {
    let srcinfo = query_image(repo, imgref)?.ok_or_else(|| anyhow!("No such image"))?;
    let (commit_layer, component_layers, remaining_layers) =
        parse_manifest_layout(&srcinfo.manifest, &srcinfo.configuration)?;
    let commit_layer = commit_layer.ok_or_else(|| anyhow!("Missing {DIFFID_LABEL}"))?;
    let commit_chunk_ref = ref_for_layer(commit_layer)?;
    let commit_chunk_rev = repo.require_rev(&commit_chunk_ref)?;
    let mut chunking = chunking::Chunking::new(repo, &commit_chunk_rev)?;
    for layer in component_layers {
        chunking_from_layer_committed(repo, layer, &mut chunking)?;
    }
    // Unfortunately today we can't guarantee we reserialize the same tar stream
    // or compression, so we'll need to generate a new copy of the manifest and config
    // with the layers reset.
    let mut new_manifest = srcinfo.manifest.clone();
    new_manifest.layers_mut().clear();
    let mut new_config = srcinfo.configuration.clone();
    new_config.history_mut().clear();
    new_config.rootfs_mut().diff_ids_mut().clear();

    let mut dest_oci = ocidir::OciDir::ensure(dest_oci)?;

    let opts = ExportOpts {
        skip_compression: opts.skip_compression,
        authfile: opts.authfile,
        ..Default::default()
    };

    let mut labels = HashMap::new();

    // Given the object chunking information we recomputed from what
    // we found on disk, re-serialize to layers (tarballs).
    export_chunked(
        repo,
        &srcinfo.base_commit,
        &mut dest_oci,
        &mut new_manifest,
        &mut new_config,
        &mut labels,
        chunking,
        &opts,
        "",
    )?;

    // Now, handle the non-ostree layers; this is a simple conversion of
    //
    let compression = opts.skip_compression.then_some(Compression::none());
    for (i, layer) in remaining_layers.iter().enumerate() {
        let layer_ref = &ref_for_layer(layer)?;
        let mut target_blob = dest_oci.create_gzip_layer(compression)?;
        // Sadly the libarchive stuff isn't exposed via Rust due to type unsafety,
        // so we'll just fork off the CLI.
        let repo_dfd = repo.dfd_borrow();
        let repo_dir = cap_std_ext::cap_std::fs::Dir::reopen_dir(&repo_dfd)?;
        let mut subproc = std::process::Command::new("ostree")
            .args(["--repo=.", "export", layer_ref.as_str()])
            .stdout(std::process::Stdio::piped())
            .cwd_dir(repo_dir)
            .spawn()?;
        // SAFETY: we piped just above
        let mut stdout = subproc.stdout.take().unwrap();
        std::io::copy(&mut stdout, &mut target_blob).context("Creating blob")?;
        let layer = target_blob.complete()?;
        let previous_annotations = srcinfo
            .manifest
            .layers()
            .get(i)
            .and_then(|l| l.annotations().as_ref())
            .cloned();
        let previous_description = srcinfo
            .configuration
            .history()
            .get(i)
            .and_then(|h| h.comment().as_deref())
            .unwrap_or_default();

        let previous_created = srcinfo
            .configuration
            .history()
            .get(i)
            .and_then(|h| h.created().as_deref())
            .and_then(bootc_utils::try_deserialize_timestamp)
            .unwrap_or_default();

        dest_oci.push_layer_full(
            &mut new_manifest,
            &mut new_config,
            layer,
            previous_annotations,
            previous_description,
            previous_created,
        )
    }

    let new_config = dest_oci.write_config(new_config)?;
    new_manifest.set_config(new_config);

    Ok(dest_oci.insert_manifest(new_manifest, tag, oci_image::Platform::default())?)
}

/// Given a container image reference which is stored in `repo`, export it to the
/// target image location.
#[context("Export")]
pub async fn export(
    repo: &ostree::Repo,
    src_imgref: &ImageReference,
    dest_imgref: &ImageReference,
    opts: Option<ExportToOCIOpts>,
) -> Result<oci_image::Digest> {
    let opts = opts.unwrap_or_default();
    let target_oci = dest_imgref.transport == Transport::OciDir;
    let tempdir = if !target_oci {
        let vartmp = cap_std::fs::Dir::open_ambient_dir("/var/tmp", cap_std::ambient_authority())?;
        let td = cap_std_ext::cap_tempfile::TempDir::new_in(&vartmp)?;
        // Always skip compression when making a temporary copy
        let opts = ExportToOCIOpts {
            skip_compression: true,
            progress_to_stdout: opts.progress_to_stdout,
            ..Default::default()
        };
        export_to_oci(repo, src_imgref, &td, None, opts)?;
        td
    } else {
        let (path, tag) = parse_oci_path_and_tag(dest_imgref.name.as_str());
        tracing::debug!("using OCI path={path} tag={tag:?}");
        let path = Dir::open_ambient_dir(path, cap_std::ambient_authority())
            .with_context(|| format!("Opening {path}"))?;
        let descriptor = export_to_oci(repo, src_imgref, &path, tag, opts)?;
        return Ok(descriptor.digest().clone());
    };
    // Pass the temporary oci directory as the current working directory for the skopeo process
    let target_fd = 3i32;
    let tempoci = ImageReference {
        transport: Transport::OciDir,
        name: format!("/proc/self/fd/{target_fd}"),
    };
    let authfile = opts.authfile.as_deref();
    skopeo::copy(
        &tempoci,
        dest_imgref,
        authfile,
        Some((std::sync::Arc::new(tempdir.try_clone()?.into()), target_fd)),
        opts.progress_to_stdout,
    )
    .await
}

/// Iterate over deployment commits, returning the manifests from
/// commits which point to a container image.
#[context("Listing deployment manifests")]
fn list_container_deployment_manifests(
    repo: &ostree::Repo,
    cancellable: Option<&gio::Cancellable>,
) -> Result<Vec<ImageManifest>> {
    // Gather all refs which start with ostree/0/ or ostree/1/ or rpmostree/base/
    // and create a set of the commits which they reference.
    let commits = OSTREE_BASE_DEPLOYMENT_REFS
        .iter()
        .chain(RPMOSTREE_BASE_REFS)
        .chain(std::iter::once(&BASE_IMAGE_PREFIX))
        .try_fold(
            std::collections::HashSet::new(),
            |mut acc, &p| -> Result<_> {
                let refs = repo.list_refs_ext(
                    Some(p),
                    ostree::RepoListRefsExtFlags::empty(),
                    cancellable,
                )?;
                for (_, v) in refs {
                    acc.insert(v);
                }
                Ok(acc)
            },
        )?;
    // Loop over the commits - if they refer to a container image, add that to our return value.
    let mut r = Vec::new();
    for commit in commits {
        let commit_obj = repo.load_commit(&commit)?.0;
        let commit_meta = &glib::VariantDict::new(Some(&commit_obj.child_value(0)));
        if commit_meta
            .lookup::<String>(META_MANIFEST_DIGEST)?
            .is_some()
        {
            tracing::trace!("Commit {commit} is a container image");
            let manifest = manifest_data_from_commitmeta(commit_meta)?.0;
            r.push(manifest);
        }
    }
    Ok(r)
}

/// Garbage collect unused image layer references.
///
/// This function assumes no transaction is active on the repository.
/// The underlying objects are *not* pruned; that requires a separate invocation
/// of [`ostree::Repo::prune`].
pub fn gc_image_layers(repo: &ostree::Repo) -> Result<u32> {
    gc_image_layers_impl(repo, gio::Cancellable::NONE)
}

#[context("Pruning image layers")]
fn gc_image_layers_impl(
    repo: &ostree::Repo,
    cancellable: Option<&gio::Cancellable>,
) -> Result<u32> {
    let all_images = list_images(repo)?;
    let deployment_commits = list_container_deployment_manifests(repo, cancellable)?;
    let all_manifests = all_images
        .into_iter()
        .map(|img| {
            ImageReference::try_from(img.as_str()).and_then(|ir| manifest_for_image(repo, &ir))
        })
        .chain(deployment_commits.into_iter().map(Ok))
        .collect::<Result<Vec<_>>>()?;
    tracing::debug!("Images found: {}", all_manifests.len());
    let mut referenced_layers = BTreeSet::new();
    for m in all_manifests.iter() {
        for layer in m.layers() {
            referenced_layers.insert(layer.digest().to_string());
        }
    }
    tracing::debug!("Referenced layers: {}", referenced_layers.len());
    let found_layers = repo
        .list_refs_ext(
            Some(LAYER_PREFIX),
            ostree::RepoListRefsExtFlags::empty(),
            cancellable,
        )?
        .into_iter()
        .map(|v| v.0);
    tracing::debug!("Found layers: {}", found_layers.len());
    let mut pruned = 0u32;
    for layer_ref in found_layers {
        let layer_digest = refescape::unprefix_unescape_ref(LAYER_PREFIX, &layer_ref)?;
        if referenced_layers.remove(layer_digest.as_str()) {
            continue;
        }
        pruned += 1;
        tracing::debug!("Pruning: {}", layer_ref.as_str());
        repo.set_ref_immediate(None, layer_ref.as_str(), None, cancellable)?;
    }

    Ok(pruned)
}

#[cfg(feature = "internal-testing-api")]
/// Return how many container blobs (layers) are stored
pub fn count_layer_references(repo: &ostree::Repo) -> Result<u32> {
    let cancellable = gio::Cancellable::NONE;
    let n = repo
        .list_refs_ext(
            Some(LAYER_PREFIX),
            ostree::RepoListRefsExtFlags::empty(),
            cancellable,
        )?
        .len();
    Ok(n as u32)
}

/// Given an image, if it has any non-ostree compatible content, return a suitable
/// warning message.
pub fn image_filtered_content_warning(
    repo: &ostree::Repo,
    image: &ImageReference,
) -> Result<Option<String>> {
    use std::fmt::Write;

    let ostree_ref = ref_for_image(image)?;
    let rev = repo.require_rev(&ostree_ref)?;
    let commit_obj = repo.load_commit(rev.as_str())?.0;
    let commit_meta = &glib::VariantDict::new(Some(&commit_obj.child_value(0)));

    let r = commit_meta
        .lookup::<MetaFilteredData>(META_FILTERED)?
        .filter(|v| !v.is_empty())
        .map(|v| {
            let mut filtered = HashMap::<&String, u32>::new();
            for paths in v.values() {
                for (k, v) in paths {
                    let e = filtered.entry(k).or_default();
                    *e += v;
                }
            }
            let mut buf = "Image contains non-ostree compatible file paths:".to_string();
            for (k, v) in filtered {
                write!(buf, " {k}: {v}").unwrap();
            }
            buf
        });
    Ok(r)
}

/// Remove the specified image reference.  If the image is already
/// not present, this function will successfully perform no operation.
///
/// This function assumes no transaction is active on the repository.
/// The underlying layers are *not* pruned; that requires a separate invocation
/// of [`gc_image_layers`].
#[context("Pruning {img}")]
pub fn remove_image(repo: &ostree::Repo, img: &ImageReference) -> Result<bool> {
    let ostree_ref = &ref_for_image(img)?;
    let found = repo.resolve_rev(ostree_ref, true)?.is_some();
    // Note this API is already idempotent, but we might as well avoid another
    // trip into ostree.
    if found {
        repo.set_ref_immediate(None, ostree_ref, None, gio::Cancellable::NONE)?;
    }
    Ok(found)
}

/// Remove the specified image references.  If an image is not found, further
/// images will be removed, but an error will be returned.
///
/// This function assumes no transaction is active on the repository.
/// The underlying layers are *not* pruned; that requires a separate invocation
/// of [`gc_image_layers`].
pub fn remove_images<'a>(
    repo: &ostree::Repo,
    imgs: impl IntoIterator<Item = &'a ImageReference>,
) -> Result<()> {
    let mut missing = Vec::new();
    for img in imgs.into_iter() {
        let found = remove_image(repo, img)?;
        if !found {
            missing.push(img);
        }
    }
    if !missing.is_empty() {
        let missing = missing.into_iter().fold("".to_string(), |mut a, v| {
            a.push_str(&v.to_string());
            a
        });
        return Err(anyhow::anyhow!("Missing images: {missing}"));
    }
    Ok(())
}

#[derive(Debug, Default)]
struct CompareState {
    verified: BTreeSet<Utf8PathBuf>,
    inode_corrupted: BTreeSet<Utf8PathBuf>,
    unknown_corrupted: BTreeSet<Utf8PathBuf>,
}

impl CompareState {
    fn is_ok(&self) -> bool {
        self.inode_corrupted.is_empty() && self.unknown_corrupted.is_empty()
    }
}

fn compare_file_info(src: &gio::FileInfo, target: &gio::FileInfo) -> bool {
    if src.file_type() != target.file_type() {
        return false;
    }
    if src.size() != target.size() {
        return false;
    }
    for attr in ["unix::uid", "unix::gid", "unix::mode"] {
        if src.attribute_uint32(attr) != target.attribute_uint32(attr) {
            return false;
        }
    }
    true
}

#[context("Querying object inode")]
fn inode_of_object(repo: &ostree::Repo, checksum: &str) -> Result<u64> {
    let repodir = Dir::reopen_dir(&repo.dfd_borrow())?;
    let (prefix, suffix) = checksum.split_at(2);
    let objpath = format!("objects/{}/{}.file", prefix, suffix);
    let metadata = repodir.symlink_metadata(objpath)?;
    Ok(metadata.ino())
}

fn compare_commit_trees(
    repo: &ostree::Repo,
    root: &Utf8Path,
    target: &ostree::RepoFile,
    expected: &ostree::RepoFile,
    exact: bool,
    colliding_inodes: &BTreeSet<u64>,
    state: &mut CompareState,
) -> Result<()> {
    let cancellable = gio::Cancellable::NONE;
    let queryattrs = "standard::name,standard::type";
    let queryflags = gio::FileQueryInfoFlags::NOFOLLOW_SYMLINKS;
    let expected_iter = expected.enumerate_children(queryattrs, queryflags, cancellable)?;

    while let Some(expected_info) = expected_iter.next_file(cancellable)? {
        let expected_child = expected_iter.child(&expected_info);
        let name = expected_info.name();
        let name = name.to_str().expect("UTF-8 ostree name");
        let path = Utf8PathBuf::from(format!("{root}{name}"));
        let target_child = target.child(name);
        let target_info = crate::diff::query_info_optional(&target_child, queryattrs, queryflags)
            .context("querying optional to")?;
        let is_dir = matches!(expected_info.file_type(), gio::FileType::Directory);
        if let Some(target_info) = target_info {
            let to_child = target_child
                .downcast::<ostree::RepoFile>()
                .expect("downcast");
            to_child.ensure_resolved()?;
            let from_child = expected_child
                .downcast::<ostree::RepoFile>()
                .expect("downcast");
            from_child.ensure_resolved()?;

            if is_dir {
                let from_contents_checksum = from_child.tree_get_contents_checksum();
                let to_contents_checksum = to_child.tree_get_contents_checksum();
                if from_contents_checksum != to_contents_checksum {
                    let subpath = Utf8PathBuf::from(format!("{}/", path));
                    compare_commit_trees(
                        repo,
                        &subpath,
                        &from_child,
                        &to_child,
                        exact,
                        colliding_inodes,
                        state,
                    )?;
                }
            } else {
                let from_checksum = from_child.checksum();
                let to_checksum = to_child.checksum();
                let matches = if exact {
                    from_checksum == to_checksum
                } else {
                    compare_file_info(&target_info, &expected_info)
                };
                if !matches {
                    let from_inode = inode_of_object(repo, &from_checksum)?;
                    let to_inode = inode_of_object(repo, &to_checksum)?;
                    if colliding_inodes.contains(&from_inode)
                        || colliding_inodes.contains(&to_inode)
                    {
                        state.inode_corrupted.insert(path);
                    } else {
                        state.unknown_corrupted.insert(path);
                    }
                } else {
                    state.verified.insert(path);
                }
            }
        } else {
            eprintln!("Missing {path}");
            state.unknown_corrupted.insert(path);
        }
    }
    Ok(())
}

#[context("Verifying container image state")]
pub(crate) fn verify_container_image(
    sysroot: &SysrootLock,
    imgref: &ImageReference,
    state: &LayeredImageState,
    colliding_inodes: &BTreeSet<u64>,
    verbose: bool,
) -> Result<bool> {
    let cancellable = gio::Cancellable::NONE;
    let repo = &sysroot.repo();
    let merge_commit = state.merge_commit.as_str();
    let merge_commit_root = repo.read_commit(merge_commit, gio::Cancellable::NONE)?.0;
    let merge_commit_root = merge_commit_root
        .downcast::<ostree::RepoFile>()
        .expect("downcast");
    merge_commit_root.ensure_resolved()?;

    let (commit_layer, _component_layers, remaining_layers) =
        parse_manifest_layout(&state.manifest, &state.configuration)?;

    let mut comparison_state = CompareState::default();

    let query = |l: &Descriptor| query_layer(repo, l.clone());

    let base_tree = repo
        .read_commit(&state.base_commit, cancellable)?
        .0
        .downcast::<ostree::RepoFile>()
        .expect("downcast");
    if let Some(commit_layer) = commit_layer {
        println!(
            "Verifying with base ostree layer {}",
            ref_for_layer(commit_layer)?
        );
    }
    compare_commit_trees(
        repo,
        "/".into(),
        &merge_commit_root,
        &base_tree,
        true,
        colliding_inodes,
        &mut comparison_state,
    )?;

    let remaining_layers = remaining_layers
        .into_iter()
        .map(query)
        .collect::<Result<Vec<_>>>()?;

    println!("Image has {} derived layers", remaining_layers.len());

    for layer in remaining_layers.iter().rev() {
        let layer_ref = layer.ostree_ref.as_str();
        let layer_commit = layer
            .commit
            .as_deref()
            .ok_or_else(|| anyhow!("Missing layer {layer_ref}"))?;
        let layer_tree = repo
            .read_commit(layer_commit, cancellable)?
            .0
            .downcast::<ostree::RepoFile>()
            .expect("downcast");
        compare_commit_trees(
            repo,
            "/".into(),
            &merge_commit_root,
            &layer_tree,
            false,
            colliding_inodes,
            &mut comparison_state,
        )?;
    }

    let n_verified = comparison_state.verified.len();
    if comparison_state.is_ok() {
        println!("OK image {imgref} (verified={n_verified})");
        println!();
    } else {
        let n_inode = comparison_state.inode_corrupted.len();
        let n_other = comparison_state.unknown_corrupted.len();
        eprintln!("warning: Found corrupted merge commit");
        eprintln!("  inode clashes: {n_inode}");
        eprintln!("  unknown:       {n_other}");
        eprintln!("  ok:            {n_verified}");
        if verbose {
            eprintln!("Mismatches:");
            for path in comparison_state.inode_corrupted {
                eprintln!("  inode: {path}");
            }
            for path in comparison_state.unknown_corrupted {
                eprintln!("  other: {path}");
            }
        }
        eprintln!();
        return Ok(false);
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use cap_std_ext::cap_tempfile;
    use oci_image::{DescriptorBuilder, MediaType, Sha256Digest};

    use super::*;

    #[test]
    fn test_ref_for_descriptor() {
        let d = DescriptorBuilder::default()
            .size(42u64)
            .media_type(MediaType::ImageManifest)
            .digest(
                Sha256Digest::from_str(
                    "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
                )
                .unwrap(),
            )
            .build()
            .unwrap();
        assert_eq!(ref_for_layer(&d).unwrap(), "ostree/container/blob/sha256_3A_2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae");
    }

    #[test]
    fn test_cleanup_root() -> Result<()> {
        let td = cap_tempfile::TempDir::new(cap_std::ambient_authority())?;
        let usretc = "usr/etc";
        cleanup_root(&td).unwrap();
        td.create_dir_all(usretc)?;
        let usretc = &td.open_dir(usretc)?;
        usretc.write("hostname", b"hostname")?;
        cleanup_root(&td).unwrap();
        assert!(usretc.try_exists("hostname")?);
        usretc.write("hostname", b"")?;
        cleanup_root(&td).unwrap();
        assert!(!td.try_exists("hostname")?);

        usretc.symlink_contents("../run/systemd/stub-resolv.conf", "resolv.conf")?;
        cleanup_root(&td).unwrap();
        assert!(usretc.symlink_metadata("resolv.conf")?.is_symlink());
        usretc.remove_file("resolv.conf")?;
        usretc.write("resolv.conf", b"")?;
        cleanup_root(&td).unwrap();
        assert!(!usretc.try_exists("resolv.conf")?);

        Ok(())
    }
}
