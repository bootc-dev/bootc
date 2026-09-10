//! Applying an oci-delta with the ostree backend.
//!
//! A tar-diff patch reads the source image by *path*, so the source does not
//! have to be a container layer at all - an ostree commit holding the same
//! filesystem works just as well. [`OstreeDataSource`] serves file content out
//! of a commit, and [`DeltaLayerSource`] plugs that into the container importer
//! in place of the image proxy.
//!
//! The one wrinkle is that ostree does not store an image's root filesystem
//! verbatim: the tar importer moves `/etc` to `/usr/etc`, moves `/var` to
//! `/usr/share/factory/var` on ostree older than v2024.3, and drops anything
//! outside those unless the image was imported with `allow_nonusr`. See
//! [`source_path_candidates`].
//!
//! An ostree-native (chunked) image additionally has its layers made of repo
//! objects under `sysroot/ostree/`, which are nowhere to be found in the
//! commit's own file tree. That is not a problem here only because oci-delta
//! passes `IgnoreSourcePrefixes=["sysroot/ostree/"]` when building a delta, so
//! no patch ever asks for one.

use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow, bail, ensure};
use cap_std_ext::cap_std::fs::Dir;
use fn_error_context::context;
use futures_util::future::BoxFuture;
use ostree_ext::container as ostree_container;
use ostree_ext::oci_spec::image as oci_image;
use ostree_ext::prelude::*;
use ostree_ext::{gio, ostree};
use tokio::io::AsyncBufRead;
use tokio::sync::OnceCell;
use tokio_util::io::SyncIoBridge;

use oci_delta::BlobStream;
use oci_delta::{DeltaDataSource, reconstruct_layer_to};
use ostree_container::{FetchedLayer, LayerSource};

use crate::delta::Delta;

/// How much reconstructed layer data may sit between the worker and the
/// importer before the worker blocks.
const PIPE_BUFFER: usize = 128 * 1024;

/// Where in an ostree commit the content for a source image path may be found.
///
/// The first hit wins, and only the remaps the tar importer performs are tried.
/// For `etc` that is unambiguous - an image cannot have both `/etc/passwd` and
/// a distinct `/usr/etc/passwd` once imported, because the first becomes the
/// second. For `var` it is merely very unlikely: on ostree v2024.3 and newer
/// `/var` is kept as-is, so an image shipping both `/var/lib/x` and
/// `/usr/share/factory/var/lib/x` would have the fallback read the wrong one if
/// the former had been filtered out. A wrong read is caught by the diff_id
/// check on the reconstructed layer.
fn source_path_candidates(path: &str) -> Vec<String> {
    let mut candidates = vec![path.to_owned()];
    if let Some(rest) = path.strip_prefix("etc/") {
        candidates.push(format!("usr/etc/{rest}"));
    } else if let Some(rest) = path.strip_prefix("var/") {
        candidates.push(format!("usr/share/factory/var/{rest}"));
    }
    candidates
}

trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}

/// Serves file content from an ostree commit to a tar-diff patch.
struct OstreeDataSource {
    root: ostree::RepoFile,
    objects: Dir,
    current: Option<Box<dyn ReadSeek>>,
}

impl OstreeDataSource {
    #[context("Opening delta source commit {commit}")]
    fn new(repo: ostree::Repo, commit: &str) -> Result<Self> {
        let (root, _) = repo.read_commit(commit, gio::Cancellable::NONE)?;
        let root = root.downcast::<ostree::RepoFile>().expect("downcast");
        let objects = Dir::reopen_dir(&repo.dfd_borrow())?
            .open_dir("objects")
            .context("Opening repo objects directory")?;
        ensure!(
            repo.mode() != ostree::RepoMode::Archive,
            "OSTree archive repo mode is not supported"
        );
        Ok(Self {
            root,
            objects,
            current: None,
        })
    }

    fn open_object(&self, checksum: &str) -> Result<Box<dyn ReadSeek>> {
        let (prefix, rest) = checksum.split_at(2);
        let f = self.objects.open(format!("{prefix}/{rest}.file"))?;
        return Ok(Box::new(f.into_std()));
    }

    fn current(&mut self) -> Result<&mut Box<dyn ReadSeek>> {
        self.current
            .as_mut()
            .context("No current file set in data source")
    }
}

impl DeltaDataSource for OstreeDataSource {
    fn set_current_file(&mut self, path: &str) -> Result<()> {
        self.current = None;
        let path = path.trim_start_matches("./").trim_start_matches('/');
        let cancellable = gio::Cancellable::NONE;
        for candidate in source_path_candidates(path) {
            let f = self.root.resolve_relative_path(&candidate);
            let f = f.downcast::<ostree::RepoFile>().expect("downcast");
            if f.query_file_type(gio::FileQueryInfoFlags::NOFOLLOW_SYMLINKS, cancellable)
                != gio::FileType::Regular
            {
                continue;
            }
            f.ensure_resolved()?;
            self.current = Some(
                self.open_object(f.checksum().as_str())
                    .with_context(|| format!("Opening delta source file {candidate}"))?,
            );
            return Ok(());
        }
        bail!("Delta source file not found in source commit: {path}");
    }

    fn read_exact_current(&mut self, buf: &mut [u8]) -> Result<()> {
        Ok(self.current()?.read_exact(buf)?)
    }

    fn seek_current(&mut self, offset: u64) -> Result<u64> {
        Ok(self.current()?.seek(SeekFrom::Start(offset))?)
    }

    fn read_current_to_end(&mut self, max_size: u64) -> Result<Vec<u8>> {
        let current = self.current()?;
        let size = current.seek(SeekFrom::End(0))?;
        ensure!(
            size <= max_size,
            "Source file too large: {size} > {max_size}"
        );
        current.seek(SeekFrom::Start(0))?;
        let mut data = Vec::with_capacity(size as usize);
        current.read_to_end(&mut data)?;
        Ok(data)
    }

    fn copy_to(&mut self, dst: &mut dyn Write, n: u64) -> Result<()> {
        let current = self.current()?;
        let copied = std::io::copy(&mut Read::by_ref(current).take(n), dst)?;
        if copied != n {
            bail!("Short read from delta source: expected {n}, got {copied}");
        }
        Ok(())
    }
}

/// Produces the target image's layers from an oci-delta and a source commit
/// already in the repository, without any network access.
#[derive(Debug)]
pub(crate) struct DeltaLayerSource {
    delta: Arc<Delta>,
    /// `ostree::Repo` is `Send` but not `Sync`, and [`LayerSource`] is both.
    repo: Mutex<ostree::Repo>,
    source_commit: OnceCell<String>,
}

impl DeltaLayerSource {
    pub(crate) fn new(delta: Arc<Delta>, repo: &ostree::Repo) -> Self {
        Self {
            delta,
            repo: Mutex::new(repo.clone()),
            source_commit: OnceCell::new(),
        }
    }

    fn repo(&self) -> ostree::Repo {
        self.repo.lock().unwrap().clone()
    }

    /// The commit to read source content from.
    ///
    /// Resolved on first use rather than up front: an import that turns out to
    /// need no layers at all needs no source either, and this still runs before
    /// anything is written.
    async fn source_commit(&self) -> Result<&str> {
        self.source_commit
            .get_or_try_init(|| async { find_source_commit(&self.repo(), &self.delta) })
            .await
            .map(|s| s.as_str())
    }

    /// The patch for `layer`, its media type, and the diff_id the reconstructed
    /// content must hash to.
    fn open_patch(
        &self,
        manifest: &oci_image::ImageManifest,
        layer: &oci_image::Descriptor,
    ) -> Result<(Box<dyn BlobStream>, oci_image::MediaType, oci_image::Digest)> {
        let Some(patch) = self.delta.parsed.delta_layer_by_to.get(layer.digest()) else {
            bail!(
                "Delta {} carries no patch for layer {}, and it is not present locally; \
                 there is nothing to reconstruct it from",
                self.delta.path,
                layer.digest(),
            );
        };
        let index = manifest
            .layers()
            .iter()
            .position(|l| l == layer)
            .ok_or_else(|| anyhow!("Layer {} is not part of the target image", layer.digest()))?;
        let diff_id = self
            .delta
            .target_config()
            .rootfs()
            .diff_ids()
            .get(index)
            .ok_or_else(|| anyhow!("Target image has no diff_id for layer {index}"))?;
        let diff_id = oci_image::Digest::from_str(diff_id)
            .with_context(|| format!("Parsing diff_id for layer {index}"))?;
        Ok((
            self.delta.read_patch(patch)?,
            patch.media_type().clone(),
            diff_id,
        ))
    }
}

impl LayerSource for DeltaLayerSource {
    fn fetch_layer<'a>(
        &'a self,
        manifest: &'a oci_image::ImageManifest,
        layer: &'a oci_image::Descriptor,
        // The reconstructed bytes are uncompressed, so counting them against
        // the descriptor's compressed size would overshoot; the importer still
        // reports per-layer start and completion.
        _progress: Option<
            &'a tokio::sync::watch::Sender<Option<ostree_container::store::LayerProgress>>,
        >,
    ) -> BoxFuture<'a, Result<FetchedLayer<'a>>> {
        Box::pin(async move {
            let (blob, media_type, diff_id) = self.open_patch(manifest, layer)?;
            let source_commit = self.source_commit().await?.to_owned();
            let repo = self.repo();
            let (writer, reader) = tokio::io::duplex(PIPE_BUFFER);

            let worker = tokio::task::spawn_blocking(move || -> Result<()> {
                let mut source = OstreeDataSource::new(repo, &source_commit)?;
                let mut dst = BufWriter::with_capacity(PIPE_BUFFER, SyncIoBridge::new(writer));
                reconstruct_layer_to(blob, &media_type, &mut source, &diff_id, &mut dst)?;
                dst.into_inner()
                    .map_err(|e| anyhow!("Flushing reconstructed layer: {e}"))?
                    .shutdown()?;
                Ok(())
            });
            let driver = async move { worker.await.context("Delta worker")? };

            Ok((
                Box::new(tokio::io::BufReader::new(reader)) as Box<dyn AsyncBufRead + Send + Unpin>,
                Box::pin(driver) as BoxFuture<'a, _>,
                oci_image::MediaType::ImageLayer,
            ))
        })
    }

    fn finish(self: Box<Self>) -> BoxFuture<'static, Result<()>> {
        Box::pin(std::future::ready(Ok(())))
    }
}

/// Find the ostree commit holding the image this delta was built against.
///
/// Deltas are applied offline, so an absent source is fatal rather than a
/// reason to go to the registry.
#[context("Finding delta source image")]
pub(crate) fn find_source_commit(repo: &ostree::Repo, delta: &Delta) -> Result<String> {
    let wanted = delta.source_config_digest();
    for image in ostree_container::store::list_images(repo)? {
        let imgref = ostree_container::ImageReference::try_from(image.as_str())
            .with_context(|| format!("Parsing stored image reference {image}"))?;
        let Some(state) = ostree_container::store::query_image(repo, &imgref)? else {
            continue;
        };
        if state.manifest.config().digest() == wanted {
            tracing::debug!("Delta source {wanted} is {imgref} ({})", state.merge_commit);
            return Ok(state.merge_commit);
        }
    }
    for commit in
        ostree_container::store::list_container_deployment_commits(repo, gio::Cancellable::NONE)?
    {
        let state = ostree_container::store::query_image_commit(repo, &commit)?;
        if state.manifest.config().digest() == wanted {
            return Ok(commit);
        }
    }
    bail!(
        "Delta {} was built against the image with config {wanted}, which is not present in this \
         system's ostree repository. A delta can only be applied on top of its source image.",
        delta.path,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std_ext::cap_std::ambient_authority;
    use std::os::fd::{AsFd, AsRawFd};

    #[test]
    fn test_source_path_candidates() {
        assert_eq!(source_path_candidates("usr/bin/ls"), ["usr/bin/ls"]);
        assert_eq!(
            source_path_candidates("etc/passwd"),
            ["etc/passwd", "usr/etc/passwd"]
        );
        assert_eq!(
            source_path_candidates("var/lib/foo"),
            ["var/lib/foo", "usr/share/factory/var/lib/foo"]
        );
        // Only the first component is remapped.
        assert_eq!(
            source_path_candidates("usr/share/etc/x"),
            ["usr/share/etc/x"]
        );
    }

    /// Commit `dir` as `testref` and return an [`OstreeDataSource`] for it.
    fn data_source_for(repo: &ostree::Repo, dir: &Dir) -> Result<OstreeDataSource> {
        let cancellable = gio::Cancellable::NONE;
        let txn = repo.auto_transaction(cancellable)?;
        let mt = ostree::MutableTree::new();
        let modifier =
            ostree::RepoCommitModifier::new(ostree::RepoCommitModifierFlags::SKIP_XATTRS, None);
        repo.write_dfd_to_mtree(
            dir.as_fd().as_raw_fd(),
            ".",
            &mt,
            Some(&modifier),
            cancellable,
        )?;
        let root = repo.write_mtree(&mt, cancellable)?;
        let root = root.downcast::<ostree::RepoFile>().unwrap();
        let commit = repo.write_commit(None, None, None, None, &root, cancellable)?;
        txn.commit(cancellable)?;

        OstreeDataSource::new(repo.clone(), commit.as_str())
    }

    fn read_all(source: &mut OstreeDataSource, path: &str) -> Result<Vec<u8>> {
        source.set_current_file(path)?;
        let mut out = Vec::new();
        source.current()?.read_to_end(&mut out)?;
        Ok(out)
    }

    #[test]
    fn test_ostree_data_source() -> Result<()> {
        let td = cap_std_ext::cap_tempfile::TempDir::new(ambient_authority())?;
        td.create_dir("repo")?;
        let repo = ostree::Repo::create_at(
            td.as_fd().as_raw_fd(),
            "repo",
            ostree::RepoMode::BareUser,
            None,
            gio::Cancellable::NONE,
        )?;

        td.create_dir_all("rootfs/usr/bin")?;
        td.create_dir_all("rootfs/usr/etc")?;
        td.create_dir_all("rootfs/usr/share/factory/var/lib")?;
        td.write("rootfs/usr/bin/ls", b"binary")?;
        td.write("rootfs/usr/etc/passwd", b"root:x:0:0")?;
        td.write("rootfs/usr/share/factory/var/lib/state", b"stateful")?;
        let rootfs = td.open_dir("rootfs")?;

        let mut source = data_source_for(&repo, &rootfs)?;

        assert_eq!(read_all(&mut source, "usr/bin/ls")?, b"binary");
        // The remapped locations are found under their pre-import paths.
        assert_eq!(read_all(&mut source, "etc/passwd")?, b"root:x:0:0");
        assert_eq!(read_all(&mut source, "var/lib/state")?, b"stateful");
        // As are leading-`./` forms, which is how tar names entries.
        assert_eq!(read_all(&mut source, "./etc/passwd")?, b"root:x:0:0");

        // Partial reads from an offset, which is what a tar-diff mostly does.
        source.set_current_file("usr/etc/passwd")?;
        source.seek_current(5)?;
        let mut buf = [0u8; 3];
        source.read_exact_current(&mut buf)?;
        assert_eq!(&buf, b"x:0");

        // A directory is not content, and neither is an absent path.
        for missing in ["usr/bin", "usr/bin/nope", "etc/nope"] {
            let err = source.set_current_file(missing).unwrap_err();
            assert!(
                format!("{err:#}").contains("not found in source commit"),
                "{missing}: unexpected error: {err:#}"
            );
        }

        // A short read is an error rather than a silent truncation.
        source.set_current_file("usr/bin/ls")?;
        let err = source.copy_to(&mut Vec::new(), 100).unwrap_err();
        assert!(format!("{err:#}").contains("Short read"), "{err:#}");

        Ok(())
    }

    /// A delta whose source image is not in the repository must fail, not fall
    /// back to fetching it: there may well be no network at this point.
    #[tokio::test]
    async fn test_find_source_commit_absent() -> Result<()> {
        let t = crate::delta::tests::TestDelta::new();
        t.finish_default();
        let delta = crate::delta::Delta::open(t.path()).await?;

        let td = cap_std_ext::cap_tempfile::TempDir::new(ambient_authority())?;
        td.create_dir("repo")?;
        let repo = ostree::Repo::create_at(
            td.as_fd().as_raw_fd(),
            "repo",
            ostree::RepoMode::BareUser,
            None,
            gio::Cancellable::NONE,
        )?;

        let err = find_source_commit(&repo, &delta).unwrap_err();
        assert!(
            format!("{err:#}").contains("not present in this system's ostree repository"),
            "{err:#}"
        );
        Ok(())
    }
}
