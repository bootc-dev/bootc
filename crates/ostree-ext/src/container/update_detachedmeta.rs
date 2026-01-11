use super::ImageReference;
use crate::container::{DIFFID_LABEL, skopeo};
use crate::container::{Transport, store as container_store};
use anyhow::{Context, Result, anyhow};
use camino::Utf8Path;
use cap_std::fs::Dir;
use cap_std_ext::cap_std;
use containers_image_proxy::oci_spec::image as oci_image;
use std::io::{BufReader, BufWriter};

/// Given an OSTree container image reference, update the detached metadata (e.g. GPG signature)
/// while preserving all other container image metadata.
///
/// The return value is the manifest digest of (e.g. `@sha256:`) the image.
pub async fn update_detached_metadata(
    src: &ImageReference,
    dest: &ImageReference,
    detached_buf: Option<&[u8]>,
) -> Result<oci_image::Digest> {
    // For now, convert the source to a temporary OCI directory, so we can directly
    // parse and manipulate it.  In the future this will be replaced by https://github.com/ostreedev/ostree-rs-ext/issues/153
    // and other work to directly use the containers/image API via containers-image-proxy.
    let tempdir = tempfile::tempdir_in("/var/tmp")?;
    let tempsrc = tempdir.path().join("src");
    let tempsrc_utf8 = Utf8Path::from_path(&tempsrc).ok_or_else(|| anyhow!("Invalid tempdir"))?;
    let tempsrc_ref = ImageReference {
        transport: Transport::OciDir,
        name: tempsrc_utf8.to_string(),
    };

    // Full copy of the source image
    let pulled_digest = skopeo::copy(src, &tempsrc_ref, None, None, false)
        .await
        .context("Creating temporary copy to OCI dir")?;

    // Copy to the thread
    let detached_buf = detached_buf.map(Vec::from);
    let tempsrc_ref_path = tempsrc_ref.name.clone();
    // Fork a thread to do the heavy lifting of filtering the tar stream, rewriting the manifest/config.
    crate::tokio_util::spawn_blocking_cancellable_flatten(move |cancellable| {
        // Open the temporary OCI directory.
        let tempsrc = Dir::open_ambient_dir(tempsrc_ref_path, cap_std::ambient_authority())
            .context("Opening src")?;
        let tempsrc = ocidir::OciDir::open(tempsrc)?;

        // Load the manifest, platform, and config
        let idx = tempsrc.read_index()?;
        let manifest_descriptor = idx
            .manifests()
            .first()
            .ok_or(anyhow!("No manifests in index"))?;
        let mut manifest: oci_image::ImageManifest = tempsrc
            .read_json_blob(manifest_descriptor)
            .context("Reading manifest json blob")?;

        anyhow::ensure!(manifest_descriptor.digest() == &pulled_digest);
        let platform = manifest_descriptor
            .platform()
            .as_ref()
            .cloned()
            .unwrap_or_default();
        let mut config: oci_image::ImageConfiguration =
            tempsrc.read_json_blob(manifest.config())?;
        let mut ctrcfg = config
            .config()
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow!("Image is missing container configuration"))?;

        // Find the OSTree commit layer we want to replace
        let (commit_layer, _, _) =
            container_store::parse_ostree_manifest_layout(&manifest, &config)?;
        let commit_layer_idx = manifest
            .layers()
            .iter()
            .position(|x| x == commit_layer)
            .unwrap();

        // Create a new layer
        let out_layer = {
            // Create tar streams for source and destination
            let src_layer = BufReader::new(tempsrc.read_blob(commit_layer)?);
            let mut src_layer = flate2::read::GzDecoder::new(src_layer);
            let mut out_layer = BufWriter::new(tempsrc.create_gzip_layer(None)?);

            // Process the tar stream and inject our new detached metadata
            crate::tar::update_detached_metadata(
                &mut src_layer,
                &mut out_layer,
                detached_buf.as_deref(),
                Some(cancellable),
            )?;

            // Flush all wrappers, and finalize the layer
            out_layer
                .into_inner()
                .map_err(|_| anyhow!("Failed to flush buffer"))?
                .complete()?
        };
        // Get the diffid and descriptor for our new tar layer
        let out_layer_diffid = format!("sha256:{}", out_layer.uncompressed_sha256.digest());
        let out_layer_descriptor = out_layer
            .descriptor()
            .media_type(oci_image::MediaType::ImageLayerGzip)
            .build()
            .unwrap(); // SAFETY: We pass all required fields

        // Splice it into both the manifest and config
        manifest.layers_mut()[commit_layer_idx] = out_layer_descriptor;
        config.rootfs_mut().diff_ids_mut()[commit_layer_idx].clone_from(&out_layer_diffid);

        let labels = ctrcfg.labels_mut().get_or_insert_with(Default::default);
        // Nothing to do except in the special case where there's somehow only one
        // chunked layer.
        if manifest.layers().len() == 1 {
            labels.insert(DIFFID_LABEL.into(), out_layer_diffid);
        }
        config.set_config(Some(ctrcfg));

        // Write the config and manifest
        let new_config_descriptor = tempsrc.write_config(config)?;
        manifest.set_config(new_config_descriptor);
        // This entirely replaces the single entry in the OCI directory, which skopeo will find by default.
        tempsrc
            .replace_with_single_manifest(manifest, platform)
            .context("Writing manifest")?;
        Ok(())
    })
    .await
    .context("Regenerating commit layer")?;

    // Finally, copy the mutated image back to the target.  For chunked images,
    // because we only changed one layer, skopeo should know not to re-upload shared blobs.
    crate::container::skopeo::copy(&tempsrc_ref, dest, None, None, false)
        .await
        .context("Copying to destination")
}
