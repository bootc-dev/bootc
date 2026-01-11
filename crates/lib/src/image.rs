//! # Controlling bootc-managed images
//!
//! APIs for operating on container images in the bootc storage.

use anyhow::{Context, Result, bail};
use bootc_utils::CommandRunExt;
use cap_std_ext::cap_std::{self, fs::Dir};
use clap::ValueEnum;
use comfy_table::{Table, presets::NOTHING};
use fn_error_context::context;
use ostree_ext::container::{ImageReference, Transport};
use serde::Serialize;

use crate::{
    boundimage::query_bound_images,
    cli::{ImageListFormat, ImageListType},
    podstorage::CStorage,
    spec::Host,
    store::Storage,
    utils::async_task_with_spinner,
};

/// The name of the image we push to containers-storage if nothing is specified.
pub(crate) const IMAGE_DEFAULT: &str = "localhost/bootc";

/// Check if an image exists in the default containers-storage (podman storage).
///
/// TODO: Using exit codes to check image existence is not ideal. We should use
/// the podman HTTP API via bollard (<https://lib.rs/crates/bollard>) or similar
/// to properly communicate with podman and get structured responses. This would
/// also enable proper progress monitoring during pull operations.
async fn image_exists_in_host_storage(image: &str) -> Result<bool> {
    use tokio::process::Command as AsyncCommand;
    let mut cmd = AsyncCommand::new("podman");
    cmd.args(["image", "exists", image]);
    Ok(cmd.status().await?.success())
}

#[derive(Clone, Serialize, ValueEnum)]
enum ImageListTypeColumn {
    Host,
    Logical,
}

impl std::fmt::Display for ImageListTypeColumn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_possible_value().unwrap().get_name().fmt(f)
    }
}

#[derive(Serialize)]
struct ImageOutput {
    image_type: ImageListTypeColumn,
    image: String,
    // TODO: Add hash, size, etc? Difficult because [`ostree_ext::container::store::list_images`]
    // only gives us the pullspec.
}

#[context("Listing host images")]
fn list_host_images(sysroot: &crate::store::Storage) -> Result<Vec<ImageOutput>> {
    let ostree = sysroot.get_ostree()?;
    let repo = ostree.repo();
    let images = ostree_ext::container::store::list_images(&repo).context("Querying images")?;

    Ok(images
        .into_iter()
        .map(|image| ImageOutput {
            image,
            image_type: ImageListTypeColumn::Host,
        })
        .collect())
}

#[context("Listing logical images")]
fn list_logical_images(root: &Dir) -> Result<Vec<ImageOutput>> {
    let bound = query_bound_images(root)?;

    Ok(bound
        .into_iter()
        .map(|image| ImageOutput {
            image: image.image,
            image_type: ImageListTypeColumn::Logical,
        })
        .collect())
}

async fn list_images(list_type: ImageListType) -> Result<Vec<ImageOutput>> {
    let rootfs = cap_std::fs::Dir::open_ambient_dir("/", cap_std::ambient_authority())
        .context("Opening /")?;

    let sysroot: Option<crate::store::BootedStorage> =
        if ostree_ext::container_utils::running_in_container() {
            None
        } else {
            Some(crate::cli::get_storage().await?)
        };

    Ok(match (list_type, sysroot) {
        // TODO: Should we list just logical images silently here, or error?
        (ImageListType::All, None) => list_logical_images(&rootfs)?,
        (ImageListType::All, Some(sysroot)) => list_host_images(&sysroot)?
            .into_iter()
            .chain(list_logical_images(&rootfs)?)
            .collect(),
        (ImageListType::Logical, _) => list_logical_images(&rootfs)?,
        (ImageListType::Host, None) => {
            bail!("Listing host images requires a booted bootc system")
        }
        (ImageListType::Host, Some(sysroot)) => list_host_images(&sysroot)?,
    })
}

#[context("Listing images")]
pub(crate) async fn list_entrypoint(
    list_type: ImageListType,
    list_format: ImageListFormat,
) -> Result<()> {
    let images = list_images(list_type).await?;

    match list_format {
        ImageListFormat::Table => {
            let mut table = Table::new();

            table
                .load_preset(NOTHING)
                .set_content_arrangement(comfy_table::ContentArrangement::Dynamic)
                .set_header(["REPOSITORY", "TYPE"]);

            for image in images {
                table.add_row([image.image, image.image_type.to_string()]);
            }

            println!("{table}");
        }
        ImageListFormat::Json => {
            let mut stdout = std::io::stdout();
            serde_json::to_writer_pretty(&mut stdout, &images)?;
        }
    }

    Ok(())
}

/// Returns the source and target ImageReference
/// If the source isn't specified, we use booted image
/// If the target isn't specified, we push to containers-storage with our default image
pub(crate) async fn get_imgrefs_for_copy(
    host: &Host,
    source: Option<&str>,
    target: Option<&str>,
) -> Result<(ImageReference, ImageReference)> {
    // Initialize floating c_storage early - needed for container operations
    crate::podstorage::ensure_floating_c_storage_initialized();

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
    let src_imgref = match source {
        Some(source) => ostree_ext::container::ImageReference::try_from(source)
            .context("Parsing source image")?,

        None => {
            let booted = host
                .status
                .booted
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Booted deployment not found"))?;

            let booted_image = &booted.image.as_ref().unwrap().image;

            ImageReference {
                transport: Transport::try_from(booted_image.transport.as_str()).unwrap(),
                name: booted_image.image.clone(),
            }
        }
    };

    return Ok((src_imgref, dest_imgref));
}

/// Implementation of `bootc image push-to-storage`.
#[context("Pushing image")]
pub(crate) async fn push_entrypoint(
    storage: &Storage,
    host: &Host,
    source: Option<&str>,
    target: Option<&str>,
) -> Result<()> {
    let (source, target) = get_imgrefs_for_copy(host, source, target).await?;

    let ostree = storage.get_ostree()?;
    let repo = &ostree.repo();

    let mut opts = ostree_ext::container::store::ExportToOCIOpts::default();
    opts.progress_to_stdout = true;
    println!("Copying local image {source} to {target} ...");
    let r = ostree_ext::container::store::export(repo, &source, &target, Some(opts)).await?;

    println!("Pushed: {target} {r}");
    Ok(())
}

/// Thin wrapper for invoking `podman image <X>` but set up for our internal
/// image store (as distinct from /var/lib/containers default).
pub(crate) async fn imgcmd_entrypoint(
    storage: &CStorage,
    arg: &str,
    args: &[std::ffi::OsString],
) -> std::result::Result<(), anyhow::Error> {
    let mut cmd = storage.new_image_cmd()?;
    cmd.arg(arg);
    cmd.args(args);
    cmd.run_capture_stderr()
}

/// Re-pull the currently booted image into the bootc-owned container storage.
///
/// This onboards the system to unified storage for host images so that
/// upgrade/switch can use the unified path automatically when the image is present.
#[context("Setting unified storage for booted image")]
pub(crate) async fn set_unified_entrypoint() -> Result<()> {
    // Initialize floating c_storage early - needed for container operations
    crate::podstorage::ensure_floating_c_storage_initialized();

    let sysroot = crate::cli::get_storage().await?;
    set_unified(&sysroot).await
}

/// Inner implementation of set_unified that accepts a storage reference.
#[context("Setting unified storage for booted image")]
pub(crate) async fn set_unified(sysroot: &crate::store::Storage) -> Result<()> {
    let ostree = sysroot.get_ostree()?;
    let repo = &ostree.repo();

    // Discover the currently booted image reference.
    // get_status_require_booted validates that we have a booted deployment with an image.
    let (_booted_ostree, _deployments, host) = crate::status::get_status_require_booted(ostree)?;

    // Use the booted deployment's image from the status we just retrieved.
    // get_status_require_booted guarantees host.status.booted is Some.
    let booted_entry = host
        .status
        .booted
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No booted deployment found"))?;
    let image_status = booted_entry
        .image
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Booted deployment is not from a container image"))?;

    // Extract the ImageReference from the ImageStatus
    let imgref = &image_status.image;

    // Canonicalize for pull display only, but we want to preserve original pullspec
    let imgref_display = imgref.clone().canonicalize()?;

    // Pull the image from its original source into bootc storage using LBI machinery
    let imgstore = sysroot.get_ensure_imgstore()?;

    const SET_UNIFIED_JOURNAL_ID: &str = "1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d";
    tracing::info!(
        message_id = SET_UNIFIED_JOURNAL_ID,
        bootc.image.reference = &imgref_display.image,
        bootc.image.transport = &imgref_display.transport,
        "Re-pulling booted image into bootc storage via unified path: {}",
        imgref_display
    );

    // Determine the appropriate source for pulling the image into bootc storage.
    //
    // Case 1: If source transport is containers-storage, the image was installed from
    //         local container storage. Copy it from the default containers-storage to
    //         the bootc storage if it exists there, if not pull from ostree store.
    // Case 2: Otherwise, pull from the specified transport (usually a remote registry).
    let is_containers_storage = imgref.transport()? == Transport::ContainerStorage;

    if is_containers_storage {
        tracing::info!(
            "Source transport is containers-storage; checking if image exists in host storage"
        );

        // Check if the image already exists in the default containers-storage.
        // This can happen if someone did a local build (e.g., podman build) and
        // we don't want to overwrite it with an export from ostree.
        let image_exists = image_exists_in_host_storage(&imgref.image).await?;

        if image_exists {
            tracing::info!(
                "Image {} already exists in containers-storage, skipping ostree export",
                &imgref.image
            );
        } else {
            // The image was installed from containers-storage and now only exists in ostree.
            // We need to export from ostree to default containers-storage (/var/lib/containers)
            tracing::info!("Image not found in containers-storage; exporting from ostree");
            // Use image_status we already obtained above (no additional unwraps needed)
            let source = ImageReference {
                transport: Transport::try_from(imgref.transport.as_str())?,
                name: imgref.image.clone(),
            };
            let target = ImageReference {
                transport: Transport::ContainerStorage,
                name: imgref.image.clone(),
            };

            let mut opts = ostree_ext::container::store::ExportToOCIOpts::default();
            // TODO: bridge to progress API
            opts.progress_to_stdout = true;
            tracing::info!(
                "Exporting ostree deployment to default containers-storage: {}",
                &imgref.image
            );
            ostree_ext::container::store::export(repo, &source, &target, Some(opts)).await?;
        }

        // Now copy from default containers-storage to bootc storage
        tracing::info!(
            "Copying from default containers-storage to bootc storage: {}",
            &imgref.image
        );
        let image_name = imgref.image.clone();
        let copy_msg = format!("Copying {} to bootc storage", &image_name);
        async_task_with_spinner(&copy_msg, async move {
            imgstore.pull_from_host_storage(&image_name).await
        })
        .await?;
    } else {
        // For registry and other transports, check if the image already exists in
        // the host's default container storage (/var/lib/containers/storage).
        // If so, we can copy from there instead of pulling from the network,
        // which is faster (especially after https://github.com/containers/container-libs/issues/144
        // enables reflinks between container storages).
        let image_in_host = image_exists_in_host_storage(&imgref.image).await?;

        if image_in_host {
            tracing::info!(
                "Image {} found in host container storage; copying to bootc storage",
                &imgref.image
            );
            let image_name = imgref.image.clone();
            let copy_msg = format!("Copying {} to bootc storage", &image_name);
            async_task_with_spinner(&copy_msg, async move {
                imgstore.pull_from_host_storage(&image_name).await
            })
            .await?;
        } else {
            let img_string = imgref.to_transport_image()?;
            let pull_msg = format!("Pulling {} to bootc storage", &img_string);
            async_task_with_spinner(&pull_msg, async move {
                imgstore
                    .pull(&img_string, crate::podstorage::PullMode::Always)
                    .await
            })
            .await?;
        }
    }

    // Verify the image is now in bootc storage
    let imgstore = sysroot.get_ensure_imgstore()?;
    if !imgstore.exists(&imgref.image).await? {
        anyhow::bail!(
            "Image was pushed to bootc storage but not found: {}. \
             This may indicate a storage configuration issue.",
            &imgref.image
        );
    }
    tracing::info!("Image verified in bootc storage: {}", &imgref.image);

    // Optionally verify we can import from containers-storage by preparing in a temp importer
    // without actually importing into the main repo; this is a lightweight validation.
    let containers_storage_imgref = crate::spec::ImageReference {
        transport: "containers-storage".to_string(),
        image: imgref.image.clone(),
        signature: imgref.signature.clone(),
    };
    let ostree_imgref =
        ostree_ext::container::OstreeImageReference::from(containers_storage_imgref);
    let _ =
        ostree_ext::container::store::ImageImporter::new(repo, &ostree_imgref, Default::default())
            .await?;

    tracing::info!(
        message_id = SET_UNIFIED_JOURNAL_ID,
        bootc.status = "set_unified_complete",
        "Unified storage set for current image. Future upgrade/switch will use it automatically."
    );
    Ok(())
}
