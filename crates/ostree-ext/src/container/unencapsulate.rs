//! APIs for "unencapsulating" OSTree commits from container images
//!
//! This code only operates on container images that were created via
//! [`encapsulate`].
//!
//! # External dependency on container-image-proxy
//!
//! This code requires <https://github.com/cgwalters/container-image-proxy>
//! installed as a binary in $PATH.
//!
//! The rationale for this is that while there exist Rust crates to speak
//! the Docker distribution API, the Go library <https://github.com/containers/image/>
//! supports key things we want for production use like:
//!
//! - Image mirroring and remapping; effectively `man containers-registries.conf`
//!   For example, we need to support an administrator mirroring an ostree-container
//!   into a disconnected registry, without changing all the pull specs.
//! - Signing
//!
//! Additionally, the proxy "upconverts" manifests into OCI, so we don't need to care
//! about parsing the Docker manifest format (as used by most registries still).
//!
//! [`encapsulate`]: [`super::encapsulate()`]

// # Implementation
//
// First, we support explicitly fetching just the manifest: https://github.com/opencontainers/image-spec/blob/main/manifest.md
// This will give us information about the layers it contains, and crucially the digest (sha256) of
// the manifest is how higher level software can detect changes.
//
// Once we have the manifest, we expect it to point to a single `application/vnd.oci.image.layer.v1.tar+gzip` layer,
// which is exactly what is exported by the [`crate::tar::export`] process.

use crate::container::store::LayerProgress;

use super::*;
use anyhow::Context as _;
use camino::{Utf8Path, Utf8PathBuf};
use containers_image_proxy::{ImageProxy, OpenedImage};
use fn_error_context::context;
use futures_util::{Future, FutureExt};
use oci_spec::image::{self as oci_image, Digest};
use std::sync::{Arc, Mutex};
use tokio::{
    io::{AsyncBufRead, AsyncRead},
    sync::watch::{Receiver, Sender},
};
use tracing::instrument;

type Progress = tokio::sync::watch::Sender<u64>;

/// A read wrapper that updates the download progress.
#[pin_project::pin_project]
#[derive(Debug)]
pub(crate) struct ProgressReader<T> {
    #[pin]
    pub(crate) reader: T,
    #[pin]
    pub(crate) progress: Arc<Mutex<Progress>>,
}

impl<T: AsyncRead> ProgressReader<T> {
    pub(crate) fn new(reader: T) -> (Self, Receiver<u64>) {
        let (progress, r) = tokio::sync::watch::channel(1);
        let progress = Arc::new(Mutex::new(progress));
        (ProgressReader { reader, progress }, r)
    }
}

impl<T: AsyncRead> AsyncRead for ProgressReader<T> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.project();
        let len = buf.filled().len();
        match this.reader.poll_read(cx, buf) {
            v @ std::task::Poll::Ready(Ok(_)) => {
                let progress = this.progress.lock().unwrap();
                let state = {
                    let mut state = *progress.borrow();
                    let newlen = buf.filled().len();
                    debug_assert!(newlen >= len);
                    let read = (newlen - len) as u64;
                    state += read;
                    state
                };
                // Ignore errors, if the caller disconnected from progress that's OK.
                let _ = progress.send(state);
                v
            }
            o => o,
        }
    }
}

async fn fetch_manifest_impl(
    proxy: &mut ImageProxy,
    imgref: &OstreeImageReference,
) -> Result<(oci_image::ImageManifest, oci_image::Digest)> {
    let oi = &proxy.open_image(&imgref.imgref.to_string()).await?;
    let (digest, manifest) = proxy.fetch_manifest(oi).await?;
    proxy.close_image(oi).await?;
    Ok((manifest, oci_image::Digest::from_str(digest.as_str())?))
}

/// Download the manifest for a target image and its sha256 digest.
#[context("Fetching manifest")]
pub async fn fetch_manifest(
    imgref: &OstreeImageReference,
) -> Result<(oci_image::ImageManifest, oci_image::Digest)> {
    let mut proxy = ImageProxy::new().await?;
    fetch_manifest_impl(&mut proxy, imgref).await
}

/// Download the manifest for a target image and its sha256 digest, as well as the image configuration.
#[context("Fetching manifest and config")]
pub async fn fetch_manifest_and_config(
    imgref: &OstreeImageReference,
) -> Result<(
    oci_image::ImageManifest,
    oci_image::Digest,
    oci_image::ImageConfiguration,
)> {
    let proxy = ImageProxy::new().await?;
    let oi = &proxy.open_image(&imgref.imgref.to_string()).await?;
    let (digest, manifest) = proxy.fetch_manifest(oi).await?;
    let digest = oci_image::Digest::from_str(&digest)?;
    let config = proxy.fetch_config(oi).await?;
    Ok((manifest, digest, config))
}

/// The result of an import operation
#[derive(Debug)]
pub struct Import {
    /// The ostree commit that was imported
    pub ostree_commit: String,
    /// The image digest retrieved
    pub image_digest: Digest,

    /// Any deprecation warning
    pub deprecated_warning: Option<String>,
}

/// Use this to process potential errors from a worker and a driver.
/// This is really a brutal hack around the fact that an error can occur
/// on either our side or in the proxy.  But if an error occurs on our
/// side, then we will close the pipe, which will *also* cause the proxy
/// to error out.
///
/// What we really want is for the proxy to tell us when it got an
/// error from us closing the pipe.  Or, we could store that state
/// on our side.  Both are slightly tricky, so we have this (again)
/// hacky thing where we just search for `broken pipe` in the error text.
///
/// Or to restate all of the above - what this function does is check
/// to see if the worker function had an error *and* if the proxy
/// had an error, but if the proxy's error ends in `broken pipe`
/// then it means the real only error is from the worker.
pub(crate) async fn join_fetch<T: std::fmt::Debug>(
    worker: impl Future<Output = Result<T>>,
    driver: impl Future<Output = Result<()>>,
) -> Result<T> {
    let (worker, driver) = tokio::join!(worker, driver);
    match (worker, driver) {
        (Ok(t), Ok(())) => Ok(t),
        (Err(worker), Err(driver)) => {
            let text = driver.root_cause().to_string();
            if text.ends_with("broken pipe") {
                tracing::trace!("Ignoring broken pipe failure from driver");
                Err(worker)
            } else {
                Err(worker.context(format!("proxy failure: {text} and client error")))
            }
        }
        (Ok(_), Err(driver)) => Err(driver),
        (Err(worker), Ok(())) => Err(worker),
    }
}

/// Fetch a container image and import its embedded OSTree commit.
#[context("Importing {}", imgref)]
#[instrument(level = "debug", skip(repo))]
pub async fn unencapsulate(repo: &ostree::Repo, imgref: &OstreeImageReference) -> Result<Import> {
    let importer = super::store::ImageImporter::new(repo, imgref, Default::default()).await?;
    importer.unencapsulate().await
}

/// Try to get the diff path for a layer in containers-storage.
/// Returns Some(path) if the layer diff directory is available, None to use blob access.
///
/// The `storage_root` parameter specifies the containers-storage root directory.
/// If None, direct filesystem access is not attempted.
pub(crate) fn try_get_layer_diff_path(
    storage_root: Option<&Utf8Path>,
    layer_info: Option<&Vec<containers_image_proxy::ConvertedLayerInfo>>,
    layer_index: usize,
    transport_src: Transport,
) -> Result<Option<Utf8PathBuf>> {
    match (transport_src, storage_root) {
        (Transport::ContainerStorage, Some(storage_root)) => {
            get_layer_diff_path(storage_root, layer_info, layer_index)
        }
        _ => Ok(None),
    }
}

/// Entry in the overlay-layers/layers.json file
#[derive(serde::Deserialize, Debug)]
struct OverlayLayerEntry {
    /// The directory name under overlay/
    id: String,
    /// Uncompressed diff digest (e.g., "sha256:...")
    #[serde(rename = "diff-digest")]
    diff_digest: Option<String>,
    /// Compressed diff digest (e.g., "sha256:...")
    #[serde(rename = "compressed-diff-digest")]
    compressed_diff_digest: Option<String>,
}

/// Look up the overlay directory ID from layers.json given a digest
fn lookup_layer_id_from_digest(storage_root: &Utf8Path, digest: &str) -> Result<Option<String>> {
    let layers_json_path = storage_root.join("overlay-layers/layers.json");

    let file = match std::fs::File::open(&layers_json_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(e) => return Err(anyhow::Error::new(e).context("Failed to open layers.json")),
    };

    let reader = std::io::BufReader::new(file);
    let layers: Vec<OverlayLayerEntry> =
        serde_json::from_reader(reader).context("Failed to parse layers.json")?;

    // Search for matching digest in both diff-digest and compressed-diff-digest
    for layer in &layers {
        let matches = layer.diff_digest.as_deref() == Some(digest)
            || layer.compressed_diff_digest.as_deref() == Some(digest);
        if matches {
            return Ok(Some(layer.id.clone()));
        }
    }

    Ok(None)
}

/// Get the diff directory path for a layer in containers-storage
fn get_layer_diff_path(
    storage_root: &Utf8Path,
    layer_info: Option<&Vec<containers_image_proxy::ConvertedLayerInfo>>,
    layer_index: usize,
) -> Result<Option<Utf8PathBuf>> {
    let Some(info) = layer_info else {
        return Ok(None);
    };

    let Some(layer) = info.get(layer_index) else {
        return Ok(None);
    };

    // Get the digest string (includes "sha256:" prefix)
    let digest_str = layer.digest.to_string();

    // Look up the layer ID from layers.json
    let Some(layer_id) = lookup_layer_id_from_digest(storage_root, &digest_str)? else {
        return Ok(None);
    };

    // Check if this is a composefs layer (not supported yet)
    let composefs_blob_path = storage_root.join(format!(
        "overlay/{}/composefs-data/composefs.blob",
        layer_id
    ));
    if composefs_blob_path.exists() {
        return Ok(None);
    }

    // Construct the layer diff path: $STORAGE/overlay/$LAYER_ID/diff
    let layer_diff_path = storage_root.join(format!("overlay/{}/diff", layer_id));

    // Check if the layer diff directory exists and is a directory
    if !layer_diff_path.is_dir() {
        return Ok(None);
    }

    Ok(Some(layer_diff_path))
}

/// A wrapper for [`get_blob`] which fetches a layer and decompresses it.
pub(crate) async fn fetch_layer<'a>(
    proxy: &'a ImageProxy,
    img: &OpenedImage,
    manifest: &oci_image::ImageManifest,
    layer: &'a oci_image::Descriptor,
    progress: Option<&'a Sender<Option<store::LayerProgress>>>,
    layer_info: Option<&Vec<containers_image_proxy::ConvertedLayerInfo>>,
    transport_src: Transport,
) -> Result<(
    Box<dyn AsyncBufRead + Send + Unpin>,
    impl Future<Output = Result<()>> + 'a,
    oci_image::MediaType,
)> {
    use futures_util::future::Either;
    tracing::debug!("fetching {}", layer.digest());
    let layer_index = manifest.layers().iter().position(|x| x == layer).unwrap();
    let (blob, driver, size);
    let mut media_type: oci_image::MediaType;
    match transport_src {
        // Both containers-storage and docker-daemon store layers uncompressed in their
        // local storage, even though the manifest may indicate they are compressed.
        // We need to use the actual media type from layer_info to avoid decompression errors.
        Transport::ContainerStorage | Transport::DockerDaemon => {
            let layer_info = layer_info.ok_or_else(|| {
                anyhow!("skopeo too old to pull from containers-storage or docker-daemon")
            })?;
            let n_layers = layer_info.len();
            let layer_blob = layer_info.get(layer_index).ok_or_else(|| {
                anyhow!("blobid position {layer_index} exceeds diffid count {n_layers}")
            })?;
            size = layer_blob.size;
            media_type = layer_blob.media_type.clone();

            // docker-daemon stores layers uncompressed even when the media type
            // indicates gzip compression. Translate to the uncompressed variant.
            if transport_src == Transport::DockerDaemon {
                if let oci_image::MediaType::Other(t) = &media_type {
                    if t.as_str() == "application/vnd.docker.image.rootfs.diff.tar.gzip" {
                        media_type = oci_image::MediaType::Other(
                            "application/vnd.docker.image.rootfs.diff.tar".to_string(),
                        );
                    }
                }
            }

            (blob, driver) = proxy.get_blob(img, &layer_blob.digest, size).await?;
        }
        _ => {
            size = layer.size();
            media_type = layer.media_type().clone();
            (blob, driver) = proxy.get_blob(img, layer.digest(), size).await?;
        }
    };

    let driver = async { driver.await.map_err(Into::into) };

    if let Some(progress) = progress {
        let (readprogress, mut readwatch) = ProgressReader::new(blob);
        let readprogress = tokio::io::BufReader::new(readprogress);
        let readproxy = async move {
            while let Ok(()) = readwatch.changed().await {
                let fetched = readwatch.borrow_and_update();
                let status = LayerProgress {
                    layer_index,
                    fetched: *fetched,
                    total: size,
                };
                progress.send_replace(Some(status));
            }
        };
        let reader = Box::new(readprogress);
        let driver = futures_util::future::join(readproxy, driver).map(|r| r.1);
        Ok((reader, Either::Left(driver), media_type))
    } else {
        Ok((Box::new(blob), Either::Right(driver), media_type))
    }
}
