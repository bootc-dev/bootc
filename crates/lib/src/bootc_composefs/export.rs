//! Export composefs-repo images to OCI layout or remote registries.
//!
//! ## `export_composefs_to_oci_dir`
//!
//! The primary export function used by the unified-storage reconcile pass.
//! Given a manifest digest for an image in the composefs repo, it produces a
//! self-contained OCI image directory that preserves the **original config
//! digest** of the source image.
//!
//! This guarantee matters because containers-storage uses the config digest
//! as its image ID; only by preserving it can a reconciled image be found
//! again by the unified-storage consistency check (`inspect_unified_storage`
//! in [`crate::image`]).
//!
//! Two invariants are enforced with hard failures:
//! - Each layer's uncompressed bytes are replayed from the composefs
//!   splitstream via `SplitStreamReader::cat()` — a byte-exact roundtrip that
//!   preserves the `diff_ids` recorded in the config.  A mismatch causes the
//!   export to abort.
//! - The original config JSON is written verbatim via `OciImage::read_config_json`,
//!   so the config blob's digest (and therefore the containers-storage ID) is
//!   unchanged.  A mismatch causes the export to abort.
//!
//! Layer blobs are freshly gzip-compressed, so their compressed digests (and
//! therefore the manifest digest) will differ from the original.  This is
//! expected and harmless — only the config digest matters for identity.
//!
//! ## `export_composefs_to_dest`
//!
//! Thin wrapper around `export_composefs_to_oci_dir` for push-to-registry
//! callers.  Uses skopeo to copy from the temporary OCI dir to the target
//! `ImageReference`.

use std::io::Write;

use anyhow::{Context, Result};
use camino::Utf8Path;
use cap_std_ext::cap_std::{self, fs::Dir};
use composefs_ctl::composefs::fsverity::Sha512HashValue;
use composefs_ctl::composefs_oci;
use composefs_oci::OciImage;
use ocidir::{OciDir, oci_spec::image::MediaType, oci_spec::image::Platform};
use ostree_ext::container::ImageReference;
use ostree_ext::container::Transport;
use ostree_ext::container::skopeo;

use crate::image::get_imgrefs_for_copy;
use crate::{
    bootc_composefs::status::get_composefs_status,
    store::{BootedComposefs, ComposefsRepository, Storage},
};

/// Assembles a composefs OCI image into an existing [`OciDir`] in a
/// config-digest-preserving way.
///
/// Reads layer data from the composefs splitstreams, re-emits each layer as a
/// fresh gzip blob, writes the original config JSON verbatim (so the config
/// digest is preserved), and inserts the assembled manifest into `oci_dir`.
///
/// This is the inner, store-agnostic half of the export pipeline.  Callers are
/// responsible for creating `oci_dir` and for routing the resulting OCI layout
/// to its destination (either via `skopeo copy` for the host-storage path, or
/// via [`crate::podstorage::CStorage::import_from_oci_dir`] for the bootc
/// private store path).
pub(crate) async fn export_composefs_to_oci_dir(
    composefs_repo: &ComposefsRepository,
    manifest_digest: &composefs_oci::OciDigest,
    oci_dir: &OciDir,
) -> Result<()> {
    // Open the composefs OCI image to get the manifest, config, and layer map.
    let oci_image = OciImage::<Sha512HashValue>::open(composefs_repo, manifest_digest, None)
        .with_context(|| {
            format!("Opening OCI image for manifest digest {manifest_digest} from composefs")
        })?;

    // Read the original config JSON verbatim.  This is the critical step that
    // preserves the config digest: we write these bytes as-is rather than
    // re-serializing the parsed ImageConfiguration, which would produce a
    // different byte sequence and therefore a different digest.
    let config_bytes = oci_image
        .read_config_json(composefs_repo)
        .context("Reading config JSON from composefs")?;

    // Verify the config is parseable (we need diff_ids for per-layer assertions).
    let config = oci_image
        .config()
        .ok_or_else(|| anyhow::anyhow!("OCI image {manifest_digest} has no config (artifact?)"))?;

    let layer_refs = oci_image.layer_refs();
    let diff_ids = config.rootfs().diff_ids();
    let total_layers = diff_ids.len();

    let mut new_manifest = oci_image.manifest().clone();
    new_manifest.layers_mut().clear();

    for (idx, old_diff_id) in diff_ids.iter().enumerate() {
        // Look up the layer's fs-verity ID from the composefs layer map.
        let layer_verity = layer_refs
            .get(old_diff_id.as_str())
            .ok_or_else(|| anyhow::anyhow!("Layer {old_diff_id} not found in layer_refs"))?;

        // Open the splitstream for this layer and re-emit the byte-exact
        // uncompressed tar through a fresh gzip layer writer.
        let mut layer_stream = composefs_repo
            .open_stream("", Some(layer_verity), None)
            .with_context(|| format!("Opening splitstream for layer {idx} ({old_diff_id})"))?;

        let mut layer_writer = oci_dir
            .create_gzip_layer(None)
            .context("Creating gzip layer writer")?;

        layer_stream
            .cat(composefs_repo, &mut layer_writer)
            .with_context(|| format!("Replaying layer {idx} via splitstream cat"))?;

        let layer = layer_writer
            .complete()
            .with_context(|| format!("Completing layer {idx}"))?;

        // Assert that cat() reproduced the correct uncompressed content:
        // the diff_id of the re-archived layer must match the original.
        let got_diff_id = layer.uncompressed_sha256_as_digest().to_string();
        if got_diff_id != old_diff_id.as_str() {
            anyhow::bail!(
                "Layer {idx} diff_id mismatch after cat: expected {old_diff_id}, got {got_diff_id}. \
                 The splitstream did not reproduce the original tar byte-exactly."
            );
        }

        tracing::debug!(
            "Wrote layer: {layer_sha} #{layer_num}/{total_layers}",
            layer_sha = got_diff_id,
            layer_num = idx + 1,
        );

        // Preserve per-layer annotations from the original manifest.
        let previous_annotations = oci_image
            .manifest()
            .layers()
            .get(idx)
            .and_then(|l| l.annotations().as_ref())
            .cloned();

        let mut layer_desc = layer.descriptor();
        if let Some(ann) = previous_annotations {
            layer_desc = layer_desc.annotations(ann);
        }
        new_manifest
            .layers_mut()
            .push(layer_desc.build().context("Building layer descriptor")?);
    }

    // Write the original config JSON verbatim as a blob.  Because we write the
    // exact same bytes that are stored in composefs, the resulting blob digest
    // equals the config digest in the composefs image, which is the key used
    // by containers-storage for image ID matching.
    let mut config_blob_writer = oci_dir
        .create_blob()
        .context("Creating config blob writer")?;
    config_blob_writer
        .write_all(&config_bytes)
        .context("Writing config bytes")?;
    let config_blob = config_blob_writer
        .complete()
        .context("Completing config blob")?;

    let config_descriptor = config_blob
        .descriptor()
        .media_type(MediaType::ImageConfig)
        .build()
        .context("Building config descriptor")?;

    // Invariant check: the digest of the verbatim config blob must match what
    // the composefs image recorded as its config digest.
    let expected_config_digest = oci_image.config_digest().to_string();
    let got_config_digest = config_descriptor.digest().to_string();
    if got_config_digest != expected_config_digest {
        anyhow::bail!(
            "Config digest mismatch: expected {expected_config_digest}, \
             got {got_config_digest}. The verbatim config bytes don't match \
             the composefs config digest."
        );
    }

    new_manifest.set_config(config_descriptor);
    oci_dir
        .insert_manifest(new_manifest, None, Platform::default())
        .context("Writing manifest")?;

    Ok(())
}

/// Streams a composefs OCI image out to a destination image reference.
///
/// Given a composefs repository handle and a manifest digest, reconstructs
/// the container image by reading layer data from the composefs splitstreams
/// and copies the assembled OCI image to `dest_imgref` via skopeo.
///
/// The original config JSON is written verbatim (not re-serialized), so the
/// exported config digest equals the composefs config digest. Each layer's
/// uncompressed tar is reproduced byte-exactly via `SplitStreamReader::cat()`
/// (which is a tested byte-exact roundtrip preserving diff_ids). Layer blobs
/// are fresh gzip recompressions, so layer blob digests differ; the manifest
/// digest therefore also differs. This is fine — fsck matches images by config
/// digest (image ID), not manifest digest.
///
/// TODO(unified-storage): This path re-encodes layers (no reflink sharing).
/// Once composefs-rs lands splitfdstream support, replace this with a direct,
/// reflink-aware writer. See `image.rs::repair_image_to_containers_storage`
/// which calls this function and carries the authoritative TODO comment.
pub(crate) async fn export_composefs_to_dest(
    storage: &Storage,
    composefs_repo: &ComposefsRepository,
    manifest_digest: &composefs_oci::OciDigest,
    dest_imgref: &ImageReference,
) -> Result<()> {
    // Use a scratch directory on the persistent sysroot filesystem rather than
    // `/var/tmp`, which may be a small tmpfs (e.g. a volatile `/var`) and would
    // overflow when reassembling the image's freshly-compressed layer blobs.
    let scratch = storage.oci_scratch_dir()?;
    let tmpdir = tempfile::Builder::new()
        .prefix("oci-")
        .tempdir_in(&scratch)
        .context("Creating temporary OCI dir in bootc storage scratch")?;
    let oci_abs = Utf8Path::from_path(tmpdir.path())
        .ok_or_else(|| anyhow::anyhow!("Temp OCI dir path is not valid UTF-8"))?;
    let oci_cap_dir = Dir::open_ambient_dir(tmpdir.path(), cap_std::ambient_authority())
        .context("Opening temp OCI dir")?;
    let oci_dir = OciDir::ensure(oci_cap_dir).context("Opening OCI")?;

    export_composefs_to_oci_dir(composefs_repo, manifest_digest, &oci_dir).await?;

    // Hand skopeo the real absolute path; it (and its forked helpers) resolve
    // it in bootc's mount namespace.
    let tempoci = ostree_ext::container::ImageReference {
        transport: Transport::OciDir,
        name: oci_abs.to_string(),
    };

    skopeo::copy(&tempoci, dest_imgref, None, None, true).await?;

    // Keep the temp dir alive until the copy has finished reading from it.
    drop(tmpdir);
    Ok(())
}

/// Exports a composefs repository to a container image in containers-storage:
pub async fn export_repo_to_image(
    storage: &Storage,
    booted_cfs: &BootedComposefs,
    source: Option<&str>,
    target: Option<&str>,
) -> Result<()> {
    use crate::bootc_composefs::state::read_origin;
    use crate::composefs_consts::{ORIGIN_KEY_IMAGE, ORIGIN_KEY_MANIFEST_DIGEST};

    let host = get_composefs_status(storage, booted_cfs).await?;

    let (source, dest_imgref) = get_imgrefs_for_copy(&host, source, target).await?;

    let mut depl_verity = None;

    for depl in host.list_deployments() {
        let img = &depl.image.as_ref().unwrap().image;

        // Not checking transport here as we'll be pulling from the repo anyway
        // So, image name is all we need
        if img.image == source.name {
            depl_verity = Some(depl.require_composefs()?.verity.clone());
            break;
        }
    }

    let depl_verity = depl_verity.ok_or_else(|| anyhow::anyhow!("Image {source} not found"))?;

    // Read the manifest digest from the deployment origin file so we can open
    // OciImage and preserve the config digest on export.
    let origin = read_origin(&storage.physical_root, &depl_verity)
        .with_context(|| format!("Reading origin for deployment {depl_verity}"))?
        .ok_or_else(|| anyhow::anyhow!("No origin file for deployment {depl_verity}"))?;

    let manifest_digest_str = origin
        .get::<String>(ORIGIN_KEY_IMAGE, ORIGIN_KEY_MANIFEST_DIGEST)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Deployment {depl_verity} has no manifest_digest in origin \
                 (legacy deployment not supported by this export path)"
            )
        })?;

    let manifest_digest: composefs_oci::OciDigest = manifest_digest_str
        .parse()
        .with_context(|| format!("Parsing manifest digest {manifest_digest_str}"))?;

    println!("Copying local image {source} to {dest_imgref} ...");
    export_composefs_to_dest(storage, &booted_cfs.repo, &manifest_digest, &dest_imgref).await?;
    println!("Pushed: {dest_imgref}");
    Ok(())
}
