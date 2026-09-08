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
    use anyhow::ensure;
    use camino::{Utf8Path, Utf8PathBuf};
    use cap_std_ext::cap_std::ambient_authority;
    use oci_delta::MEDIA_TYPE_DELTA;
    use ocidir::OciDir;
    use ocidir::prelude::*;
    use ostree_ext::fixture::{FileDef, Fixture};
    use std::collections::HashSet;
    use std::os::fd::{AsFd, AsRawFd};
    use std::process::{Command, Stdio};

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

    fn have_tool(name: &str) -> bool {
        Command::new(name)
            .arg("--help")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
    }

    fn copy_dir(src: &Utf8Path, dst: &Utf8Path) -> Result<()> {
        let st = Command::new("cp")
            .args(["-a", src.as_str(), dst.as_str()])
            .status()?;
        ensure!(st.success(), "cp -a {src} {dst} failed: {st}");
        Ok(())
    }

    fn open_oci(path: &Utf8Path) -> Result<OciDir> {
        Ok(OciDir::open(Dir::open_ambient_dir(
            path,
            ambient_authority(),
        )?)?)
    }

    fn single_manifest(oci: &OciDir) -> Result<(oci_image::Descriptor, oci_image::ImageManifest)> {
        let index = oci.read_index()?;
        let desc = index
            .manifests()
            .first()
            .cloned()
            .context("Layout has no manifest")?;
        let manifest = oci.read_json_blob(&desc)?;
        Ok((desc, manifest))
    }

    fn read_blob(oci: &OciDir, desc: &oci_image::Descriptor) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        oci.read_blob(desc)?.read_to_end(&mut buf)?;
        Ok(buf)
    }

    /// Import `path` as the image a delta will be applied on top of.
    async fn import_source(fixture: &Fixture, path: &Utf8Path) -> Result<()> {
        fixture
            .must_import(&ostree_container::ImageReference {
                transport: ostree_container::Transport::OciDir,
                name: path.to_string(),
            })
            .await?;
        Ok(())
    }

    /// Apply the delta at `delta_path` as an update to `target_path`.
    async fn apply_delta(
        fixture: &Fixture,
        target_path: &Utf8Path,
        delta_path: &Utf8Path,
    ) -> Result<(Arc<crate::delta::Delta>, Box<crate::deploy::ImageState>)> {
        let delta = Arc::new(crate::delta::Delta::open(delta_path).await?);
        let imgref = crate::spec::ImageReference {
            image: target_path.to_string(),
            transport: "oci".into(),
            signature: None,
        };
        let state = crate::deploy::pull_delta(
            fixture.destrepo(),
            &imgref,
            Arc::clone(&delta),
            true,
            Default::default(),
            None,
        )
        .await?;
        Ok((delta, state))
    }

    /// The delta reconstructed the target image exactly: the same content as
    /// the fixture's own commit, recorded under the target's real digest.
    fn assert_applied(
        fixture: &Fixture,
        state: &crate::deploy::ImageState,
        target: &oci_image::Digest,
    ) {
        assert_eq!(&state.manifest_digest, target);
        let expected = fixture.srcrepo().require_rev(fixture.testref()).unwrap();
        let layered =
            ostree_container::store::query_image_commit(fixture.destrepo(), &state.ostree_commit)
                .unwrap();
        ostree_ext::fixture::assert_commits_content_equal(
            fixture.destrepo(),
            &layered.base_commit,
            fixture.srcrepo(),
            &expected,
        );
    }

    /// Export the fixture as a container, change it, and export it again: a
    /// pair of ostree-native (chunked) images, as a bootc base image update
    /// looks. The source is imported into the destination repo.
    async fn chunked_source_and_target()
    -> Result<(Fixture, Utf8PathBuf, Utf8PathBuf, oci_image::Digest)> {
        let mut fixture = Fixture::new_v1()?;
        let (exported, _) = fixture.export_container().await?;
        let source = fixture.path.join("source-oci");
        copy_dir(Utf8Path::new(&exported.name), &source)?;

        fixture.update(
            // Both of these are paths the fixture has an owning "package" for,
            // which its chunked export requires.
            FileDef::iter_from(
                "r usr/bin/bash the-bash-shell-v2\nr usr/etc/someconfig.conf someconfig-v2\n",
            ),
            std::iter::empty(),
        )?;
        let (exported, digest) = fixture.export_container().await?;
        let target = Utf8PathBuf::from(exported.name);

        import_source(&fixture, &source).await?;
        Ok((fixture, source, target, digest))
    }

    /// 64 KiB of incompressible but deterministic data. `v2` differs from `v1`
    /// in eight bytes, so a binary diff of the two is tiny - which is how the
    /// tests tell whether the patch really read from the source.
    fn big_file(v2: bool) -> Vec<u8> {
        let mut state = 0x1234_5678u32;
        let mut data: Vec<u8> = std::iter::repeat_with(|| {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            (state >> 24) as u8
        })
        .take(64 * 1024)
        .collect();
        if v2 {
            data[32 * 1024..32 * 1024 + 8].fill(0xff);
        }
        data
    }

    /// Append a derived layer holding [`big_file`] at `/etc/bigconf`, i.e. at a
    /// path the ostree importer relocates.
    fn derive(oci: &Utf8Path, v2: bool) -> Result<()> {
        let content = big_file(v2);
        ostree_ext::integrationtest::generate_derived_oci_from_tar(
            oci,
            move |w| {
                let mut tar = tar::Builder::new(w);
                let mut dir = tar::Header::new_gnu();
                dir.set_entry_type(tar::EntryType::Directory);
                dir.set_mode(0o755);
                dir.set_size(0);
                tar.append_data(&mut dir, "etc/", std::io::empty())?;
                let mut file = tar::Header::new_gnu();
                file.set_mode(0o644);
                file.set_size(content.len() as u64);
                tar.append_data(&mut file, "etc/bigconf", content.as_slice())?;
                tar.finish()?;
                Ok(())
            },
            None,
            None,
        )
    }

    /// A pair of images that share a base and differ only in one derived layer,
    /// as a bootc image built from a Containerfile does. The source is imported
    /// into the destination repo.
    async fn derived_source_and_target()
    -> Result<(Fixture, Utf8PathBuf, Utf8PathBuf, oci_image::Digest)> {
        let fixture = Fixture::new_v1()?;
        let (exported, _) = fixture.export_container().await?;
        let source = fixture.path.join("source-oci");
        let target = fixture.path.join("target-oci");
        copy_dir(Utf8Path::new(&exported.name), &source)?;
        copy_dir(Utf8Path::new(&exported.name), &target)?;
        derive(&source, false)?;
        derive(&target, true)?;
        let digest = single_manifest(&open_oci(&target)?)?.0.digest().clone();

        import_source(&fixture, &source).await?;
        Ok((fixture, source, target, digest))
    }

    /// Write a delta from `source` to `target` that carries each changed layer
    /// whole rather than as a tar-diff.
    ///
    /// The format permits either, so this covers everything but the patch
    /// application itself while needing no external tooling; the tests below
    /// that use the real `oci-delta` skip themselves when it is absent.
    fn build_whole_layer_delta(source: &Utf8Path, target: &Utf8Path, out: &Utf8Path) -> Result<()> {
        use crate::delta::tests::{DELTA_CONTENT, DELTA_SOURCE_CONFIG, DELTA_TO, annotate, blob};

        let source = open_oci(source)?;
        let target = open_oci(target)?;
        let (_, source_manifest) = single_manifest(&source)?;
        let (target_manifest_desc, target_manifest) = single_manifest(&target)?;

        std::fs::create_dir_all(out)?;
        let out = OciDir::ensure(Dir::open_ambient_dir(out, ambient_authority())?)?;

        let mut layers = vec![
            annotate(
                blob(
                    &out,
                    &read_blob(&target, &target_manifest_desc)?,
                    oci_image::MediaType::ImageManifest,
                ),
                &[(DELTA_CONTENT, "image-manifest")],
            ),
            annotate(
                blob(
                    &out,
                    &read_blob(&target, target_manifest.config())?,
                    oci_image::MediaType::ImageConfig,
                ),
                &[(DELTA_CONTENT, "image-config")],
            ),
        ];
        let shared: HashSet<_> = source_manifest
            .layers()
            .iter()
            .map(|l| l.digest())
            .collect();
        for layer in target_manifest.layers() {
            if shared.contains(layer.digest()) {
                continue;
            }
            let patch = blob(
                &out,
                &read_blob(&target, layer)?,
                layer.media_type().clone(),
            );
            let to = layer.digest().to_string();
            layers.push(annotate(
                patch,
                &[(DELTA_CONTENT, "image-layer"), (DELTA_TO, to.as_str())],
            ));
        }
        ensure!(
            layers.len() > 2,
            "Source and target images share every layer"
        );

        let empty = blob(&out, b"{}", oci_image::MediaType::EmptyJSON);
        let manifest = oci_image::ImageManifestBuilder::default()
            .schema_version(2u32)
            .media_type(oci_image::MediaType::ImageManifest)
            .artifact_type(oci_image::MediaType::Other(MEDIA_TYPE_DELTA.to_string()))
            .config(empty)
            .layers(layers)
            .annotations(std::collections::HashMap::from([(
                DELTA_SOURCE_CONFIG.to_string(),
                source_manifest.config().digest().to_string(),
            )]))
            .build()?;
        out.replace_with_single_manifest(manifest, Default::default())?;
        Ok(())
    }

    fn create_delta(source: &Utf8Path, target: &Utf8Path, out: &Utf8Path) -> Result<()> {
        let out = Command::new("oci-delta")
            .arg("create")
            .arg(format!("oci:{source}"))
            .arg(format!("oci:{target}"))
            .arg(format!("oci:{out}"))
            .output()?;
        ensure!(
            out.status.success(),
            "oci-delta create failed: {}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr),
        );
        Ok(())
    }

    /// The whole pipeline - parse and validate the delta, find the source image
    /// in the repository, reconstruct the changed layers, import - with the
    /// patches degenerate so that no external tooling is needed.
    #[tokio::test]
    async fn test_apply_delta_whole_layers() -> Result<()> {
        let (fixture, source, target, digest) = chunked_source_and_target().await?;
        let delta_path = fixture.path.join("delta");
        build_whole_layer_delta(&source, &target, &delta_path)?;

        let (_, state) = apply_delta(&fixture, &target, &delta_path).await?;
        assert_applied(&fixture, &state, &digest);
        Ok(())
    }

    /// Construct and apply a real delta between two ostree-native (chunked) images.
    #[tokio::test]
    async fn test_apply_delta_chunked() -> Result<()> {
        if !have_tool("oci-delta") {
            eprintln!("skipping: oci-delta not found in PATH");
            return Ok(());
        }
        let (fixture, source, target, digest) = chunked_source_and_target().await?;
        let delta_path = fixture.path.join("delta");
        create_delta(&source, &target, &delta_path)?;

        let (_, state) = apply_delta(&fixture, &target, &delta_path).await?;
        assert_applied(&fixture, &state, &digest);
        Ok(())
    }

    /// A real delta over a derived layer, which unlike a chunked one is an
    /// ordinary root filesystem tar. This is the case that actually drives
    /// [`OstreeDataSource`], and the file it patches is one the importer
    /// relocated from `/etc` to `/usr/etc`.
    #[tokio::test]
    async fn test_apply_delta_derived() -> Result<()> {
        if !have_tool("oci-delta") {
            eprintln!("skipping: oci-delta not found in PATH");
            return Ok(());
        }
        let (fixture, source, target, digest) = derived_source_and_target().await?;
        let delta_path = fixture.path.join("delta");
        create_delta(&source, &target, &delta_path)?;

        let (delta, state) = apply_delta(&fixture, &target, &delta_path).await?;
        assert_eq!(&state.manifest_digest, &digest);

        // Only the derived layer changed, and the patch for it is a fraction of
        // its size - which it can only be if the reconstruction read the bulk
        // of the content back out of the source commit.
        let patched = delta.parsed.delta_layer_by_to.iter().collect::<Vec<_>>();
        let [(to, patch)] = patched.as_slice() else {
            panic!("expected one patched layer, got {}", patched.len());
        };
        let layer = delta
            .target_manifest()
            .layers()
            .iter()
            .find(|l| l.digest() == *to)
            .unwrap();
        assert!(
            patch.size() * 4 < layer.size(),
            "patch is {} bytes against a {} byte layer, so nothing was reused from the source",
            patch.size(),
            layer.size(),
        );

        let root = ostree_ext::fixture::ostree_ls(fixture.destrepo(), &state.ostree_commit)?;
        assert!(
            root.contains(&format!("r /usr/etc/bigconf {}\n", 64 * 1024)),
            "/usr/etc/bigconf is missing from the applied image:\n{root}"
        );
        Ok(())
    }

    /// A deployed source remains usable after staging advances to its image ref.
    #[tokio::test]
    async fn test_delta_source_retained_by_deployment() -> Result<()> {
        let (mut fixture, source, target, _) = chunked_source_and_target().await?;
        let repo = fixture.destrepo().clone();
        let source_ref = ostree_container::ImageReference {
            transport: ostree_container::Transport::OciDir,
            name: source.to_string(),
        };
        let original = ostree_container::store::query_image(&repo, &source_ref)?.unwrap();
        let newer = fixture
            .must_import(&ostree_container::ImageReference {
                transport: ostree_container::Transport::OciDir,
                name: target.to_string(),
            })
            .await?;
        // Model staging B over A under the same image reference.
        for (name, commit) in repo.list_refs_ext(
            Some("ostree/container/image"),
            ostree::RepoListRefsExtFlags::empty(),
            gio::Cancellable::NONE,
        )? {
            if commit.as_str() == original.merge_commit {
                repo.set_ref_immediate(
                    None,
                    &name,
                    Some(&newer.merge_commit),
                    gio::Cancellable::NONE,
                )?;
            }
        }

        // Build A→C; no image ref now identifies A.
        fixture.update(
            FileDef::iter_from("r usr/bin/bash the-bash-shell-v3\n"),
            std::iter::empty(),
        )?;
        let (_, digest) = fixture.export_container().await?;
        let delta_path = fixture.path.join("delta-retained-source");
        build_whole_layer_delta(&source, &target, &delta_path)?;
        let delta = Delta::open(&delta_path).await?;
        assert!(find_source_commit(&repo, &delta).is_err());

        // Ordinary ostree deployments have no container metadata.
        repo.set_ref_immediate(
            None,
            "ostree/0/0/1",
            Some(&original.base_commit),
            gio::Cancellable::NONE,
        )?;
        // Each supported deployment/base-image ref can retain A independently.
        for name in [
            "ostree/0/0/0",
            "ostree/1/0/0",
            "rpmostree/base/test",
            "ostree/container/baseimage/test",
        ] {
            repo.set_ref_immediate(
                None,
                name,
                Some(&original.merge_commit),
                gio::Cancellable::NONE,
            )?;
            assert_eq!(find_source_commit(&repo, &delta)?, original.merge_commit);
            repo.set_ref_immediate(None, name, None, gio::Cancellable::NONE)?;
        }
        repo.set_ref_immediate(
            None,
            "ostree/0/0/0",
            Some(&original.merge_commit),
            gio::Cancellable::NONE,
        )?;
        // Apply A→C using A retained solely by its deployment ref.
        let (_, state) = apply_delta(&fixture, &target, &delta_path).await?;
        assert_applied(&fixture, &state, &digest);
        Ok(())
    }
}
