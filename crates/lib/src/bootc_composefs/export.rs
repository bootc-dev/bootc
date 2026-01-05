#![allow(dead_code, unused_variables)]

use std::io::{Read, Seek, Write};

use anyhow::{Context, Result};
use canon_json::CanonJsonSerialize;
use cap_std_ext::cap_std::{
    ambient_authority,
    fs::{Dir, MetadataExt, OpenOptions},
};
use composefs::{
    fsverity::FsVerityHashValue,
    splitstream::{SplitStreamData, SplitStreamReader},
    tree::{LeafContent, RegularFile},
};
use composefs_oci::tar::TarItem;
use openssl::sha::Sha256;
use ostree_ext::oci_spec::image::{Descriptor, Digest, ImageConfiguration, MediaType};
use tar::{EntryType, Header};

use crate::{
    bootc_composefs::{
        status::{get_composefs_status, get_imginfo},
        update::str_to_sha256digest,
    },
    store::{BootedComposefs, Storage},
};

fn get_entry_with_header<R: Read, ObjectID: FsVerityHashValue>(
    reader: &mut SplitStreamReader<R, ObjectID>,
) -> anyhow::Result<Option<(Header, TarItem<ObjectID>)>> {
    loop {
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
}

pub async fn export_repo_to_oci(storage: &Storage, booted_cfs: &BootedComposefs) -> Result<()> {
    let host = get_composefs_status(storage, booted_cfs).await?;

    let image = host
        .status
        .booted
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Booted deployment not found"))?
        .image
        .as_ref()
        .unwrap();

    let imginfo = get_imginfo(
        storage,
        &booted_cfs.cmdline.digest,
        // TODO: Make this optional
        &image.image,
    )
    .await?;

    let config_name = &image.image_digest;
    let config_name = str_to_sha256digest(&config_name)?;

    let var_tmp =
        Dir::open_ambient_dir("/var/tmp", ambient_authority()).context("Opening /var/tmp")?;

    var_tmp
        .create_dir_all(&*booted_cfs.cmdline.digest)
        .context("Creating image dir")?;

    let image_dir = var_tmp
        .open_dir(&*booted_cfs.cmdline.digest)
        .context("Opening image dir")?;

    let mut config_stream = booted_cfs
        .repo
        .open_stream(&hex::encode(config_name), None)
        .context("Opening config stream")?;

    let config = ImageConfiguration::from_reader(&mut config_stream)?;

    // We can't guarantee that we'll get the same tar as the container image
    let mut new_config = config.clone();
    if let Some(history) = new_config.history_mut() {
        history.clear();
    }
    new_config.rootfs_mut().diff_ids_mut().clear();

    let mut new_manifest = imginfo.manifest.clone();
    new_manifest.layers_mut().clear();

    let mut file_open_opts = OpenOptions::new();
    file_open_opts.write(true).create(true);

    for (idx, diff_id) in config.rootfs().diff_ids().iter().enumerate() {
        let layer_sha256 = str_to_sha256digest(diff_id)?;
        let layer_verity = config_stream.lookup(&layer_sha256)?;

        let mut layer_stream = booted_cfs
            .repo
            .open_stream(&hex::encode(layer_sha256), Some(layer_verity))?;

        let mut file = image_dir.open_with(hex::encode(layer_sha256), &file_open_opts)?;

        let mut builder = tar::Builder::new(&mut file);

        while let Some((header, entry)) = get_entry_with_header(&mut layer_stream)? {
            let hsize = header.size()? as usize;
            let mut v = vec![0; hsize];

            match &entry {
                TarItem::Directory => {
                    assert_eq!(hsize, 0);
                }

                TarItem::Leaf(leaf_content) => {
                    match &leaf_content {
                        LeafContent::Regular(reg) => match reg {
                            RegularFile::Inline(items) => {
                                assert_eq!(hsize, items.len());
                                v[..hsize].copy_from_slice(items);
                            }

                            RegularFile::External(obj_id, size) => {
                                assert_eq!(*size as usize, hsize);

                                let mut file =
                                    std::fs::File::from(booted_cfs.repo.open_object(obj_id)?);

                                file.read_exact(&mut v)?;
                            }
                        },

                        LeafContent::BlockDevice(_) => todo!(),
                        LeafContent::CharacterDevice(_) => {
                            todo!()
                        }
                        LeafContent::Fifo => todo!(),
                        LeafContent::Socket => todo!(),

                        LeafContent::Symlink(..) => {
                            // we don't need to write the data for symlinks as the
                            // target will be in the header itself
                            assert_eq!(hsize, 0);
                        }
                    }
                }

                TarItem::Hardlink(..) => {
                    // we don't need to write the data for hardlinks as the
                    // target will be in the header itself
                    assert_eq!(hsize, 0);
                }
            };

            builder
                .append(&header, v.as_slice())
                .context("Failed to write entry")?;
        }

        builder.finish().context("Finishing builder")?;
        drop(builder);

        let mut new_diff_id = openssl::hash::Hasher::new(openssl::hash::MessageDigest::sha256())?;

        file.seek(std::io::SeekFrom::Start(0))
            .context("Seek failed")?;
        std::io::copy(&mut file, &mut new_diff_id).context("Failed to compute hash")?;

        let final_sha = new_diff_id.finish()?;
        let final_sha_str = hex::encode(final_sha);

        rustix::fs::renameat(&image_dir, hex::encode(layer_sha256), &image_dir, &final_sha_str)
            .context("Renameat")?;

        let digest = format!("sha256:{}", hex::encode(final_sha));

        new_config.rootfs_mut().diff_ids_mut().push(digest.clone());

        // TODO: Gzip this for manifest
        new_manifest.layers_mut().push(Descriptor::new(
            MediaType::ImageLayer,
            file.metadata()?.size(),
            Digest::try_from(digest)?,
        ));

        if let Some(old_history) = &config.history() {
            if idx >= old_history.len() {
                anyhow::bail!("Found more layers than history");
            }

            let old_history = &old_history[idx];

            let mut history = ostree_ext::oci_spec::image::HistoryBuilder::default();

            if let Some(old_created) = old_history.created() {
                history = history.created(old_created);
            }

            if let Some(old_created_by) = old_history.created_by() {
                history = history.created_by(old_created_by);
            }

            if let Some(comment) = old_history.comment() {
                history = history.comment(comment);
            }

            new_config
                .history_mut()
                .get_or_insert(Vec::new())
                .push(history.build().unwrap());
        }

        // TODO: Fsync
    }

    let config_json = new_config.to_canon_json_vec()?;

    // Hash the new config
    let mut config_hash = Sha256::new();
    config_hash.update(&config_json);
    let config_hash = hex::encode(config_hash.finish());

    // Write the config to Directory
    let mut cfg_file = image_dir
        .open_with(&config_hash, &file_open_opts)
        .context("Opening config file")?;

    cfg_file
        .write_all(&config_json)
        .context("Failed to write config")?;

    // Write the manifest
    let mut manifest_file = image_dir
        .open_with("manifest.json", &file_open_opts)
        .context("Opening manifest file")?;

    new_manifest.set_config(Descriptor::new(
        MediaType::ImageConfig,
        config_json.len() as u64,
        Digest::try_from(format!("sha256:{config_hash}"))?,
    ));

    manifest_file
        .write_all(&new_manifest.to_canon_json_vec()?)
        .context("Failed to write manifest")?;

    println!("Image: {config_hash}");

    Ok(())
}
