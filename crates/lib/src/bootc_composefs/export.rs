use std::{fs::File, io::Read, os::fd::AsRawFd};

use anyhow::{Context, Result};
use cap_std_ext::cap_std::{ambient_authority, fs::Dir};
use composefs::{
    fsverity::FsVerityHashValue,
    splitstream::{SplitStreamData, SplitStreamReader},
    tree::{LeafContent, RegularFile},
};
use composefs_oci::tar::TarItem;
use ocidir::{oci_spec::image::Platform, OciDir};
use ostree_ext::container::skopeo;
use ostree_ext::{container::Transport, oci_spec::image::ImageConfiguration};
use tar::{EntryType, Header};

use crate::{
    bootc_composefs::{
        status::{get_composefs_status, get_imginfo},
        update::str_to_sha256digest,
    },
    image::IMAGE_DEFAULT,
    store::{BootedComposefs, Storage},
};

fn get_entry_with_header<R: Read, ObjectID: FsVerityHashValue>(
    reader: &mut SplitStreamReader<R, ObjectID>,
) -> anyhow::Result<Option<(Header, TarItem<ObjectID>)>> {
    let mut buf = [0u8; 512];
    if !reader.read_inline_exact(&mut buf)? || buf == [0u8; 512] {
        return Ok(None);
    }

    let header = tar::Header::from_byte_slice(&buf);

    let size = header.entry_size()?;

    let item = match reader.read_exact(size as usize, ((size + 511) & !511) as usize)? {
        SplitStreamData::External(id) => match header.entry_type() {
            EntryType::Regular | EntryType::Continuous => {
                TarItem::Leaf(LeafContent::Regular(RegularFile::External(id, size)))
            }
            _ => anyhow::bail!("Unsupported external-chunked entry {header:?} {id:?}"),
        },

        SplitStreamData::Inline(content) => match header.entry_type() {
            EntryType::Directory => TarItem::Directory,
            // We do not care what the content is as we're re-archiving it anyway
            _ => TarItem::Leaf(LeafContent::Regular(RegularFile::Inline(content))),
        },
    };

    return Ok(Some((header.clone(), item)));
}

/// Exports a composefs repository to a container image in containers-storage:
pub async fn export_repo_to_image(
    storage: &Storage,
    booted_cfs: &BootedComposefs,
    source: Option<&str>,
    target: Option<&str>,
) -> Result<()> {
    let host = get_composefs_status(storage, booted_cfs).await?;

    let booted_image = host
        .status
        .booted
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Booted deployment not found"))?
        .image
        .as_ref()
        .unwrap();

    // If the target isn't specified, push to containers-storage + our default image
    let dest_imgref = match target {
        Some(target) => ostree_ext::container::ImageReference {
            transport: Transport::ContainerStorage,
            name: target.to_owned(),
        },
        None => ostree_ext::container::ImageReference {
            transport: Transport::ContainerStorage,
            name: IMAGE_DEFAULT.into(),
        },
    };

    // If the source isn't specified, we use the booted image
    let source = match source {
        Some(source) => ostree_ext::container::ImageReference::try_from(source)
            .context("Parsing source image")?,

        None => ostree_ext::container::ImageReference {
            transport: Transport::try_from(booted_image.image.transport.as_str()).unwrap(),
            name: booted_image.image.image.clone(),
        },
    };

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

    let config_name = &imginfo.manifest.config().digest().digest();
    let config_name = str_to_sha256digest(config_name)?;

    let var_tmp =
        Dir::open_ambient_dir("/var/tmp", ambient_authority()).context("Opening /var/tmp")?;

    let tmpdir = cap_std_ext::cap_tempfile::tempdir_in(&var_tmp)?;
    let oci_dir = OciDir::ensure(tmpdir.try_clone()?).context("Opening OCI")?;

    let mut config_stream = booted_cfs
        .repo
        .open_stream(&hex::encode(config_name), None)
        .context("Opening config stream")?;

    let config = ImageConfiguration::from_reader(&mut config_stream)?;

    // We can't guarantee that we'll get the same tar stream as the container image
    // So we create new config and manifest
    let mut new_config = config.clone();
    if let Some(history) = new_config.history_mut() {
        history.clear();
    }
    new_config.rootfs_mut().diff_ids_mut().clear();

    let mut new_manifest = imginfo.manifest.clone();
    new_manifest.layers_mut().clear();

    for (idx, old_diff_id) in config.rootfs().diff_ids().iter().enumerate() {
        let layer_sha256 = str_to_sha256digest(old_diff_id)?;
        let layer_verity = config_stream.lookup(&layer_sha256)?;

        let mut layer_stream = booted_cfs
            .repo
            .open_stream(&hex::encode(layer_sha256), Some(layer_verity))?;

        let mut layer_writer = oci_dir.create_layer(None)?;
        layer_writer.follow_symlinks(false);

        while let Some((header, entry)) = get_entry_with_header(&mut layer_stream)? {
            let hsize = header.size()? as usize;
            let mut v = vec![0; hsize];

            match &entry {
                TarItem::Leaf(leaf_content) => {
                    match &leaf_content {
                        LeafContent::Regular(reg) => match reg {
                            RegularFile::Inline(items) => {
                                v[..hsize].copy_from_slice(items);
                            }

                            RegularFile::External(obj_id, ..) => {
                                let mut file = File::from(booted_cfs.repo.open_object(obj_id)?);
                                file.read_exact(&mut v)?;
                            }
                        },

                        // we don't need to write the data for symlinks.
                        // Same goes for devices, fifos and sockets
                        _ => {}
                    }
                }

                // we don't need to write the data for hardlinks/dirs
                TarItem::Directory | TarItem::Hardlink(..) => {}
            };

            layer_writer
                .append(&header, v.as_slice())
                .context("Failed to write entry")?;
        }

        layer_writer.finish()?;

        let layer = layer_writer
            .into_inner()
            .context("Getting inner layer writer")?
            .complete()
            .context("Writing layer to disk")?;

        tracing::debug!("Wrote layer: {}", layer.uncompressed_sha256_as_digest());

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
