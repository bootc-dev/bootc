//! Support for oci-delta artifacts (`--from-delta`).
//!
//! An oci-delta is an OCI layout (normally packed as an uncompressed tar)
//! whose single manifest is an artifact rather than an image. It carries the
//! target image manifest and config verbatim, plus binary patches for the
//! layers that changed relative to a source image. Layers that did not change
//! are omitted entirely and are expected to already be present locally.
//!
//! See <https://github.com/containers/oci-delta> for the format.
//!
//! # Trust model
//!
//! Everything in a delta is verified against a single value, the target
//! manifest digest: the embedded manifest and config must hash to the digests
//! the delta records, the config must be the one the manifest references, and
//! each reconstructed layer is checked against the corresponding diff_id in
//! that config.
//!
//! What is not currently established is that the digest is the one you meant to
//! deploy: it comes from the file rather than from a registry, and nothing
//! signs it. Future work may use signatures to complete this.

use std::collections::HashSet;

use anyhow::{Context, Result, bail, ensure};
use camino::{Utf8Path, Utf8PathBuf};
use cap_std_ext::cap_std;
use fn_error_context::context;
use ocidir::oci_spec::image::{
    Descriptor, Digest, DigestAlgorithm, ImageConfiguration, ImageManifest, MediaType,
};
use ocidir::prelude::*;
use ocidir::{OciArchive, OciDir};
use ostree_ext::containers_image_proxy;

use oci_delta::BlobStream;
use oci_delta::{
    BlobStreamFuture, DeltaBlobReader, MEDIA_TYPE_DELTA, ParsedDelta, is_delta_artifact,
    parse_delta_manifest,
};

/// The OCI layout a delta was read from.
///
/// Kept open for the lifetime of the [`Delta`] so that patch blobs can be read
/// back when the layers are applied, without parsing the layout again.
#[derive(Debug)]
enum Layout {
    Dir(OciDir),
    Archive(OciArchive),
}

impl Layout {
    fn open(path: &Utf8Path) -> Result<Self> {
        if path.is_dir() {
            let dir = cap_std::fs::Dir::open_ambient_dir(path, cap_std::ambient_authority())
                .context("Opening OCI layout directory")?;
            Ok(Self::Dir(
                OciDir::open(dir).context("Reading OCI layout directory")?,
            ))
        } else {
            Ok(Self::Archive(
                OciArchive::open(path).context("Reading OCI archive")?,
            ))
        }
    }

    fn read_index(&self) -> Result<ocidir::oci_spec::image::ImageIndex> {
        match self {
            Self::Dir(o) => o.read_index(),
            Self::Archive(o) => o.read_index(),
        }
        .map_err(Into::into)
    }

    fn read_blob(&self, desc: &Descriptor) -> Result<Box<dyn BlobStream>> {
        let blob: Box<dyn BlobStream> = match self {
            Self::Dir(o) => Box::new(o.read_blob(desc)?),
            Self::Archive(o) => Box::new(o.read_blob(desc)?),
        };
        Ok(blob)
    }
}

impl DeltaBlobReader for Layout {
    fn open_blob(&self, desc: &Descriptor) -> BlobStreamFuture<'_> {
        let result = self
            .read_blob(desc)
            .with_context(|| format!("Reading blob {}", desc.digest()));
        Box::pin(std::future::ready(result))
    }
}

/// A validated oci-delta artifact, ready to be applied.
#[derive(Debug)]
pub(crate) struct Delta {
    /// Where this was loaded from; used in diagnostics.
    pub(crate) path: Utf8PathBuf,
    /// Parsed information about the delta.
    pub(crate) parsed: ParsedDelta,
    config: ImageConfiguration,
    layout: Layout,
}

impl Delta {
    /// Open and validate the delta at `path`, which may be an OCI layout
    /// directory or (usually) an uncompressed tar of one.
    #[context("Opening delta {path}")]
    pub(crate) async fn open(path: &Utf8Path) -> Result<Self> {
        let layout = Layout::open(path)?;
        let parsed = parse(&layout).await?;

        let config = validate(&parsed)?;
        Ok(Self {
            path: path.to_owned(),
            parsed,
            config,
            layout,
        })
    }

    /// Open the patch blob `desc`
    pub(crate) fn read_patch(&self, desc: &Descriptor) -> Result<Box<dyn BlobStream>> {
        self.layout
            .read_blob(desc)
            .with_context(|| format!("Reading delta patch {}", desc.digest()))
    }

    /// The digest of the target image's manifest, as recorded in the delta.
    pub(crate) fn target_manifest_digest(&self) -> &Digest {
        self.parsed.target_manifest_descriptor.digest()
    }

    pub(crate) fn validate_image_reference(
        &self,
        imgref: &crate::spec::ImageReference,
    ) -> Result<()> {
        if imgref.transport()? != containers_image_proxy::Transport::Registry {
            return Ok(());
        }
        let reference: ocidir::oci_spec::distribution::Reference = imgref
            .image
            .parse()
            .with_context(|| format!("Parsing image reference {}", imgref.image))?;
        if let Some(digest) = reference.digest() {
            let digest: Digest = digest.parse()?;
            ensure!(
                &digest == self.target_manifest_digest(),
                "Image reference {} names digest {digest}, but delta {} targets {}",
                imgref.image,
                self.path,
                self.target_manifest_digest(),
            );
        }
        Ok(())
    }

    /// The target image's manifest.
    pub(crate) fn target_manifest(&self) -> &ImageManifest {
        &self.parsed.target_manifest
    }

    /// The target image's config.
    pub(crate) fn target_config(&self) -> &ImageConfiguration {
        &self.config
    }

    /// The config digest of the image this delta was built against.
    pub(crate) fn source_config_digest(&self) -> &Digest {
        &self.parsed.source_config_digest
    }

    /// An image reference naming this delta as a local OCI layout, for handing
    /// to the image import machinery.
    pub(crate) fn pull_ref(&self) -> Result<containers_image_proxy::ImageReference> {
        // An `oci:` reference is `path[:tag]`, so a colon in the path would be
        // taken as a tag separator.
        ensure!(
            !self.path.as_str().contains(':'),
            "Delta path {} contains a colon, which cannot be expressed as an image reference",
            self.path,
        );
        let transport = if self.path.is_dir() {
            "oci"
        } else {
            "oci-archive"
        };
        format!("{transport}:{}", self.path)
            .as_str()
            .try_into()
            .map_err(|e| anyhow::anyhow!("Building image reference for {}: {e}", self.path))
    }

    /// A one-line description of what applying this delta would do.
    pub(crate) fn describe(&self) -> String {
        let total = self.parsed.target_manifest.layers().len();
        let patched = self.parsed.delta_layer_by_to.len();
        format!(
            "{}: target manifest {}, {total} layers ({patched} patched, {} reused from source config {})",
            self.path,
            self.target_manifest_digest(),
            total - patched,
            self.parsed.source_config_digest,
        )
    }
}

/// Open the delta named by a `--from-delta` argument, if there is one.
pub(crate) async fn open_opt(path: Option<&Utf8Path>) -> Result<Option<Delta>> {
    match path {
        Some(path) => Ok(Some(Delta::open(path).await?)),
        None => Ok(None),
    }
}

/// Reject `--from-delta` for an image that also has to be in containers-storage.
pub(crate) fn reject_unified_storage(delta: &Delta, use_unified: bool) -> Result<()> {
    ensure!(
        !use_unified,
        "Cannot apply delta {}: deltas with unified storage not supported.",
        delta.path,
    );
    Ok(())
}

/// Check the delta's internal consistency, to fail early
fn validate(p: &ParsedDelta) -> Result<ImageConfiguration> {
    verify_digest(
        "Embedded target manifest",
        &p.target_manifest_raw,
        p.target_manifest_descriptor.digest(),
    )?;
    verify_digest(
        "Embedded target config",
        &p.target_config_raw,
        p.target_config_descriptor.digest(),
    )?;

    ensure!(
        p.target_manifest.config().digest() == p.target_config_descriptor.digest(),
        "Delta target manifest references config {}, but the embedded config is {}",
        p.target_manifest.config().digest(),
        p.target_config_descriptor.digest(),
    );

    let config = ImageConfiguration::from_reader(&p.target_config_raw[..])
        .context("Parsing embedded target config")?;
    let layers = p.target_manifest.layers();
    ensure!(!layers.is_empty(), "Delta target image has no layers");
    ensure!(
        config.rootfs().diff_ids().len() == layers.len(),
        "Delta target image has {} diff_ids but {} layers",
        config.rootfs().diff_ids().len(),
        layers.len(),
    );

    let target_layers: HashSet<&Digest> = layers.iter().map(|l| l.digest()).collect();
    for to in p.delta_layer_by_to.keys() {
        ensure!(
            target_layers.contains(to),
            "Delta contains a patch for layer {to}, which is not part of the target image",
        );
    }

    Ok(config)
}

/// Read the single manifest out of an OCI layout and parse it as a delta.
async fn parse(oci: &Layout) -> Result<ParsedDelta> {
    let index = oci.read_index().context("Reading index")?;
    let [desc] = index.manifests().as_slice() else {
        bail!(
            "Expected an OCI layout with a single manifest, found {}; this is not a delta",
            index.manifests().len()
        );
    };
    ensure!(
        desc.media_type() == &MediaType::ImageManifest,
        "Expected an image manifest, found {}; this is not a delta",
        desc.media_type(),
    );

    let mut raw = Vec::new();
    std::io::Read::read_to_end(
        &mut oci.read_blob(desc).context("Reading delta manifest")?,
        &mut raw,
    )
    .context("Reading delta manifest")?;
    verify_digest("Delta manifest", &raw, desc.digest())?;
    let manifest: ImageManifest = serde_json::from_slice(&raw).context("Parsing delta manifest")?;

    ensure!(
        is_delta_artifact(&manifest),
        "Not a delta: expected artifactType {MEDIA_TYPE_DELTA}, found {}.",
        manifest
            .artifact_type()
            .as_ref()
            .map(|t| t.to_string())
            .unwrap_or_else(|| "none".into()),
    );

    parse_delta_manifest(&manifest, oci).await
}

/// Verify that `data` hashes to `expected`.
fn verify_digest(what: &str, data: &[u8], expected: &Digest) -> Result<()> {
    let algorithm = match expected.algorithm() {
        DigestAlgorithm::Sha256 => openssl::hash::MessageDigest::sha256(),
        DigestAlgorithm::Sha384 => openssl::hash::MessageDigest::sha384(),
        DigestAlgorithm::Sha512 => openssl::hash::MessageDigest::sha512(),
        other => bail!("{what} uses unsupported digest algorithm {other}"),
    };
    let found = hex::encode(openssl::hash::hash(algorithm, data)?);
    ensure!(
        found == expected.digest(),
        "{what} does not match its digest: expected {expected}, got {found}",
    );
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ocidir::oci_spec::image::{ImageConfigurationBuilder, ImageManifestBuilder, RootFsBuilder};
    use std::collections::HashMap;

    pub(crate) const DELTA_CONTENT: &str = "io.github.containers.delta.content";
    pub(crate) const DELTA_TO: &str = "io.github.containers.delta.to";
    pub(crate) const DELTA_SOURCE_CONFIG: &str = "io.github.containers.delta.source-config";
    const TAR_DIFF: &str = "application/vnd.tar-diff";
    const ZERO_DIGEST: &str =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    pub(crate) fn blob(oci: &OciDir, data: &[u8], media_type: MediaType) -> Descriptor {
        let mut w = oci.create_blob().unwrap();
        std::io::Write::write_all(&mut w, data).unwrap();
        w.complete()
            .unwrap()
            .descriptor()
            .media_type(media_type)
            .build()
            .unwrap()
    }

    fn image_config(diff_ids: &[&str]) -> ImageConfiguration {
        ImageConfigurationBuilder::default()
            .rootfs(
                RootFsBuilder::default()
                    .typ("layers")
                    .diff_ids(diff_ids.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap()
    }

    pub(crate) fn annotate(mut desc: Descriptor, annotations: &[(&str, &str)]) -> Descriptor {
        desc.set_annotations(Some(
            annotations
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<HashMap<_, _>>(),
        ));
        desc
    }

    /// A minimal but structurally valid target image, of which the last layer
    /// is the one the delta patches.
    pub(crate) struct TestDelta {
        oci: OciDir,
        tmp: tempfile::TempDir,
        manifest_desc: Descriptor,
        config_desc: Descriptor,
        layer_descs: Vec<Descriptor>,
    }

    impl TestDelta {
        pub(crate) fn new() -> Self {
            Self::with_diff_ids(2)
        }

        /// Two layers, but `n_diff_ids` diff_ids, to check invalid combinations
        fn with_diff_ids(n_diff_ids: usize) -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let dir = cap_std::fs::Dir::open_ambient_dir(tmp.path(), cap_std::ambient_authority())
                .unwrap();
            let oci = OciDir::ensure(dir).unwrap();

            let layer_descs: Vec<Descriptor> = ["layer-one", "layer-two"]
                .iter()
                .map(|d| blob(&oci, d.as_bytes(), MediaType::ImageLayerGzip))
                .collect();
            let diff_ids = (0..n_diff_ids)
                .map(|i| format!("sha256:{}", i.to_string().repeat(64)))
                .collect::<Vec<_>>();
            let config = image_config(&diff_ids.iter().map(|s| s.as_str()).collect::<Vec<_>>());
            let config_desc = blob(
                &oci,
                serde_json::to_vec(&config).unwrap().as_slice(),
                MediaType::ImageConfig,
            );

            let manifest = ImageManifestBuilder::default()
                .schema_version(2u32)
                .media_type(MediaType::ImageManifest)
                .config(config_desc.clone())
                .layers(layer_descs.clone())
                .build()
                .unwrap();
            let manifest_desc = blob(
                &oci,
                serde_json::to_vec(&manifest).unwrap().as_slice(),
                MediaType::ImageManifest,
            );

            Self {
                oci,
                tmp,
                manifest_desc,
                config_desc,
                layer_descs,
            }
        }

        pub(crate) fn path(&self) -> &Utf8Path {
            Utf8Path::from_path(self.tmp.path()).unwrap()
        }

        /// Write out the delta manifest with the given layers and artifactType.
        fn finish(&self, artifact_type: Option<&str>, layers: Vec<Descriptor>) {
            let empty = blob(&self.oci, b"{}", MediaType::EmptyJSON);
            let mut b = ImageManifestBuilder::default()
                .schema_version(2u32)
                .media_type(MediaType::ImageManifest)
                .config(empty)
                .layers(layers)
                .annotations(HashMap::from([(
                    DELTA_SOURCE_CONFIG.to_string(),
                    ZERO_DIGEST.to_string(),
                )]));
            if let Some(t) = artifact_type {
                b = b.artifact_type(MediaType::Other(t.to_string()));
            }
            self.oci
                .replace_with_single_manifest(b.build().unwrap(), Default::default())
                .unwrap();
        }

        /// Write out the standard delta: the embedded manifest, the embedded
        /// config, and a patch for the last image layer.
        pub(crate) fn finish_default(&self) {
            self.finish(Some(MEDIA_TYPE_DELTA), self.default_layers());
        }

        fn patch_for(&self, to: &str) -> Descriptor {
            let patch = blob(
                &self.oci,
                b"patch-data",
                MediaType::Other(TAR_DIFF.to_string()),
            );
            annotate(patch, &[(DELTA_CONTENT, "image-layer"), (DELTA_TO, to)])
        }

        fn default_layers(&self) -> Vec<Descriptor> {
            vec![
                annotate(
                    self.manifest_desc.clone(),
                    &[(DELTA_CONTENT, "image-manifest")],
                ),
                annotate(self.config_desc.clone(), &[(DELTA_CONTENT, "image-config")]),
                self.patch_for(self.layer_descs.last().unwrap().digest().as_ref()),
            ]
        }

        /// Rewrite a blob in place, keeping its size so that ocidir's own size
        /// check isn't what catches the alteration.
        fn corrupt_blob(&self, desc: &Descriptor) {
            let name = desc.digest().digest();
            let mut content = Vec::new();
            std::io::Read::read_to_end(&mut self.oci.blobs_dir().open(name).unwrap(), &mut content)
                .unwrap();
            // Flip the last hex character of the first digest, which keeps the
            // bytes both the same length and valid JSON.
            let pos = content
                .windows(7)
                .position(|w| w == b"sha256:")
                .expect("no digest in blob")
                + 7
                + 63;
            content[pos] = if content[pos] == b'0' { b'1' } else { b'0' };
            self.oci.blobs_dir().write(name, &content).unwrap();
        }
    }

    #[tokio::test]
    async fn test_valid_delta() {
        let t = TestDelta::new();
        t.finish_default();

        let delta = Delta::open(t.path()).await.unwrap();
        assert_eq!(delta.target_manifest_digest(), t.manifest_desc.digest());
        assert_eq!(delta.parsed.target_manifest.layers().len(), 2);
        assert_eq!(delta.parsed.delta_layer_by_to.len(), 1);
        assert!(delta.describe().contains("1 patched, 1 reused"));

        let pull_ref = delta.pull_ref().unwrap();
        assert_eq!(
            pull_ref.transport,
            ostree_ext::containers_image_proxy::Transport::OciDir
        );
        assert_eq!(pull_ref.name, t.path().as_str());
    }

    #[tokio::test]
    async fn test_rejects_invalid() {
        struct Case {
            name: &'static str,
            prepare: fn(&TestDelta),
            expected: &'static str,
        }
        let cases = [
            Case {
                name: "plain image, no artifactType",
                prepare: |t| t.finish(None, t.layer_descs.clone()),
                expected: "Not a delta",
            },
            Case {
                name: "patch for a layer not in the target image",
                prepare: |t| {
                    let mut layers = t.default_layers();
                    layers.pop();
                    layers.push(t.patch_for(ZERO_DIGEST));
                    t.finish(Some(MEDIA_TYPE_DELTA), layers);
                },
                expected: "not part of the target image",
            },
            Case {
                name: "embedded manifest altered after the fact",
                prepare: |t| {
                    t.finish_default();
                    t.corrupt_blob(&t.manifest_desc);
                },
                expected: "does not match its digest",
            },
            Case {
                name: "delta manifest altered after the fact",
                prepare: |t| {
                    t.finish_default();
                    let index = t.oci.read_index().unwrap();
                    t.corrupt_blob(&index.manifests()[0]);
                },
                expected: "does not match its digest",
            },
            Case {
                name: "embedded config is not the one the manifest references",
                prepare: |t| {
                    let other = blob(
                        &t.oci,
                        &serde_json::to_vec(&image_config(&["sha256:aa", "sha256:bb"])).unwrap(),
                        MediaType::ImageConfig,
                    );
                    let mut layers = t.default_layers();
                    layers[1] = annotate(other, &[(DELTA_CONTENT, "image-config")]);
                    t.finish(Some(MEDIA_TYPE_DELTA), layers);
                },
                expected: "references config",
            },
        ];
        for case in cases {
            let t = TestDelta::new();
            (case.prepare)(&t);
            let err = Delta::open(t.path())
                .await
                .err()
                .unwrap_or_else(|| panic!("{}: expected failure", case.name));
            assert!(
                format!("{err:#}").contains(case.expected),
                "{}: unexpected error: {err:#}",
                case.name
            );
        }
    }

    #[tokio::test]
    async fn test_rejects_diff_id_mismatch() {
        let t = TestDelta::with_diff_ids(1);
        t.finish_default();

        let err = Delta::open(t.path()).await.unwrap_err();
        assert!(
            format!("{err:#}").contains("1 diff_ids but 2 layers"),
            "unexpected error: {err:#}"
        );
    }

    #[tokio::test]
    async fn test_pull_ref() {
        let t = TestDelta::new();
        t.finish_default();
        let mut delta = Delta::open(t.path()).await.unwrap();

        // A path that is not a directory is taken to be an archive.
        delta.path = "/var/tmp/update.oci-delta".into();
        let pull_ref = delta.pull_ref().unwrap();
        assert_eq!(
            pull_ref.transport,
            ostree_ext::containers_image_proxy::Transport::OciArchive
        );
        assert_eq!(pull_ref.name, "/var/tmp/update.oci-delta");

        delta.path = "/var/tmp/a:b.oci-delta".into();
        let err = delta.pull_ref().unwrap_err();
        assert!(
            format!("{err:#}").contains("contains a colon"),
            "unexpected error: {err:#}"
        );
    }

    #[tokio::test]
    async fn test_validate_image_reference() {
        let t = TestDelta::new();
        t.finish_default();
        let delta = Delta::open(t.path()).await.unwrap();
        let target = delta.target_manifest_digest();
        for (image, valid) in [
            ("quay.io/example/os:latest".to_owned(), true),
            (format!("quay.io/example/os@{target}"), true),
            (format!("quay.io/example/os:latest@{target}"), true),
            (format!("quay.io/example/os@{ZERO_DIGEST}"), false),
            (format!("quay.io/example/os:latest@{ZERO_DIGEST}"), false),
        ] {
            let imgref = crate::spec::ImageReference {
                image,
                transport: "registry".into(),
                signature: None,
            };
            let result = delta.validate_image_reference(&imgref);
            if valid {
                result.unwrap();
            } else {
                let error = result.unwrap_err().to_string();
                assert!(error.contains(ZERO_DIGEST), "{error}");
                assert!(error.contains(&target.to_string()), "{error}");
            }
        }
    }

    #[test]
    fn test_verify_digest() {
        let expected: Digest =
            "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
                .parse()
                .unwrap();
        verify_digest("test", b"hello", &expected).unwrap();
        let err = verify_digest("test", b"goodbye", &expected).unwrap_err();
        assert!(format!("{err:#}").contains("does not match its digest"));
    }
}
