use std::{fs::File, os::fd::AsRawFd};

use anyhow::{Context, Result};
use cap_std_ext::cap_std::{ambient_authority, fs::Dir};
use composefs::splitstream::SplitStreamData;
use composefs_oci::open_config;
use ocidir::{OciDir, oci_spec::image::Platform};
use ostree_ext::container::Transport;
use ostree_ext::container::skopeo;
use tar::EntryType;

use crate::image::get_imgrefs_for_copy;
use crate::{
    bootc_composefs::status::{get_composefs_status, get_imginfo},
    store::{BootedComposefs, Storage},
};

/// Exports a composefs repository to a container image in containers-storage:
pub async fn export_repo_to_image(
    storage: &Storage,
    booted_cfs: &BootedComposefs,
    source: Option<&str>,
    target: Option<&str>,
) -> Result<()> {
    let host = get_composefs_status(storage, booted_cfs).await?;

    let (source, dest_imgref) = get_imgrefs_for_copy(&host, source, target).await?;

    let mut depl_verity = None;

    for depl in host
        .status
        .booted
        .iter()
        .chain(host.status.staged.iter())
        .chain(host.status.rollback.iter())
        .chain(host.status.other_deployments.iter())
    {
        let img = &depl.image.as_ref().unwrap().image;

        // Not checking transport here as we'll be pulling from the repo anyway
        // So, image name is all we need
        if img.image == source.name {
            depl_verity = Some(depl.require_composefs()?.verity.clone());
            break;
        }
    }

    let depl_verity = depl_verity.ok_or_else(|| anyhow::anyhow!("Image {source} not found"))?;

    let imginfo = get_imginfo(storage, &depl_verity, None).await?;

    let config_digest = imginfo.manifest.config().digest().digest();

    let var_tmp =
        Dir::open_ambient_dir("/var/tmp", ambient_authority()).context("Opening /var/tmp")?;

    let tmpdir = cap_std_ext::cap_tempfile::tempdir_in(&var_tmp)?;
    let oci_dir = OciDir::ensure(tmpdir.try_clone()?).context("Opening OCI")?;

    // Use composefs_oci::open_config to get the config and layer map
    let (config, layer_map) =
        open_config(&*booted_cfs.repo, config_digest, None).context("Opening config")?;

    // We can't guarantee that we'll get the same tar stream as the container image
    // So we create new config and manifest
    let mut new_config = config.clone();
    if let Some(history) = new_config.history_mut() {
        history.clear();
    }
    new_config.rootfs_mut().diff_ids_mut().clear();

    let mut new_manifest = imginfo.manifest.clone();
    new_manifest.layers_mut().clear();

    let total_layers = config.rootfs().diff_ids().len();

    for (idx, old_diff_id) in config.rootfs().diff_ids().iter().enumerate() {
        // Look up the layer verity from the map
        let layer_verity = layer_map
            .get(old_diff_id.as_str())
            .ok_or_else(|| anyhow::anyhow!("Layer {old_diff_id} not found in config"))?;

        let mut layer_stream = booted_cfs.repo.open_stream("", Some(layer_verity), None)?;

        let mut layer_writer = oci_dir.create_layer(None)?;
        layer_writer.follow_symlinks(false);

        let mut got_zero_block = false;

        loop {
            let mut buf = [0u8; 512];

            if !layer_stream
                .read_inline_exact(&mut buf)
                .context("Reading into buffer")?
            {
                break;
            }

            let all_zeroes = buf.iter().all(|x| *x == 0);

            // EOF for tar
            if all_zeroes && got_zero_block {
                break;
            } else if all_zeroes {
                got_zero_block = true;
                continue;
            }

            got_zero_block = false;

            let header = tar::Header::from_byte_slice(&buf);

            let size = header.entry_size()?;

            match layer_stream.read_exact(size as usize, ((size as usize) + 511) & !511)? {
                SplitStreamData::External(obj_id) => match header.entry_type() {
                    EntryType::Regular | EntryType::Continuous => {
                        let file = File::from(booted_cfs.repo.open_object(&obj_id)?);

                        layer_writer
                            .append(&header, file)
                            .context("Failed to write external entry")?;
                    }

                    _ => anyhow::bail!("Unsupported external-chunked entry {header:?} {obj_id:?}"),
                },

                SplitStreamData::Inline(content) => match header.entry_type() {
                    EntryType::Directory => {
                        layer_writer.append(&header, std::io::empty())?;
                    }

                    // We do not care what the content is as we're re-archiving it anyway
                    _ => {
                        layer_writer
                            .append(&header, &*content)
                            .context("Failed to write inline entry")?;
                    }
                },
            };
        }

        layer_writer.finish()?;

        let layer = layer_writer
            .into_inner()
            .context("Getting inner layer writer")?
            .complete()
            .context("Writing layer to disk")?;

        tracing::debug!(
            "Wrote layer: {layer_sha} #{layer_num}/{total_layers}",
            layer_sha = layer.uncompressed_sha256_as_digest(),
            layer_num = idx + 1,
        );

        let previous_annotations = imginfo
            .manifest
            .layers()
            .get(idx)
            .and_then(|l| l.annotations().as_ref())
            .cloned();

        let history = imginfo.config.history().as_ref();
        let history_entry = history.and_then(|v| v.get(idx));
        let previous_description = history_entry
            .clone()
            .and_then(|h| h.comment().as_deref())
            .unwrap_or_default();

        let previous_created = history_entry
            .and_then(|h| h.created().as_deref())
            .and_then(bootc_utils::try_deserialize_timestamp)
            .unwrap_or_default();

        oci_dir.push_layer_full(
            &mut new_manifest,
            &mut new_config,
            layer,
            previous_annotations,
            previous_description,
            previous_created,
        );
    }

    let descriptor = oci_dir.write_config(new_config).context("Writing config")?;

    new_manifest.set_config(descriptor);
    oci_dir
        .insert_manifest(new_manifest, None, Platform::default())
        .context("Writing manifest")?;

    // Pass the temporary oci directory as the current working directory for the skopeo process
    let tempoci = ostree_ext::container::ImageReference {
        transport: Transport::OciDir,
        name: format!("/proc/self/fd/{}", tmpdir.as_raw_fd()),
    };

    skopeo::copy(
        &tempoci,
        &dest_imgref,
        None,
        Some((
            std::sync::Arc::new(tmpdir.try_clone()?.into()),
            tmpdir.as_raw_fd(),
        )),
        true,
    )
    .await?;

    Ok(())
}
