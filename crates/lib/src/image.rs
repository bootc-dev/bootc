//! # Controlling bootc-managed images
//!
//! APIs for operating on container images in the bootc storage.

use anyhow::{bail, Context, Result};
use bootc_utils::CommandRunExt;
use cap_std_ext::cap_std::{self, fs::Dir};
use clap::ValueEnum;
use comfy_table::{presets::NOTHING, Table};
use fn_error_context::context;
use ostree_ext::container::{ImageReference, Transport};
use serde::Serialize;

use crate::{
    boundimage::query_bound_images,
    cli::{ImageListFormat, ImageListType},
    podstorage::{ensure_floating_c_storage_initialized, CStorage},
};

/// The name of the image we push to containers-storage if nothing is specified.
const IMAGE_DEFAULT: &str = "localhost/bootc";

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

/// Implementation of `bootc image push-to-storage`.
#[context("Pushing image")]
pub(crate) async fn push_entrypoint(source: Option<&str>, target: Option<&str>) -> Result<()> {
    let transport = Transport::ContainerStorage;
    let sysroot = crate::cli::get_storage().await?;
    let ostree = sysroot.get_ostree()?;
    let repo = &ostree.repo();

    // If the target isn't specified, push to containers-storage + our default image
    let target = if let Some(target) = target {
        ImageReference {
            transport,
            name: target.to_owned(),
        }
    } else {
        ensure_floating_c_storage_initialized();
        ImageReference {
            transport: Transport::ContainerStorage,
            name: IMAGE_DEFAULT.to_string(),
        }
    };

    // If the source isn't specified, we use the booted image
    let source = if let Some(source) = source {
        ImageReference::try_from(source).context("Parsing source image")?
    } else {
        let status = crate::status::get_status_require_booted(&ostree)?;
        // SAFETY: We know it's booted
        let booted = status.2.status.booted.unwrap();
        let booted_image = booted.image.unwrap().image;
        ImageReference {
            transport: Transport::try_from(booted_image.transport.as_str()).unwrap(),
            name: booted_image.image,
        }
    };
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
    let sysroot = crate::cli::get_storage().await?;
    let ostree = sysroot.get_ostree()?;
    let repo = &ostree.repo();

    // Discover the currently booted image reference
    let (_booted_deployment, _deployments, host) =
        crate::status::get_status_require_booted(ostree)?;
    let imgref = host
        .spec
        .image
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No image source specified in host spec"))?;

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

    // Check if this is a localhost image with registry transport - these images
    // were built locally and don't exist in any remote registry. We need to
    // export from the current ostree deployment to container storage first.
    let is_localhost_image =
        imgref.transport == "registry" && imgref.image.starts_with("localhost/");

    if is_localhost_image {
        tracing::info!(
            "Detected localhost image; exporting from ostree to container storage first"
        );

        // First, export from ostree to the default container storage (like copy-to-storage)
        let booted = host.status.booted.as_ref().unwrap();
        let booted_image = booted.image.as_ref().unwrap();
        let source = ImageReference {
            transport: Transport::try_from(booted_image.image.transport.as_str()).unwrap(),
            name: booted_image.image.image.clone(),
        };
        let target = ImageReference {
            transport: Transport::ContainerStorage,
            name: imgref.image.clone(),
        };

        ensure_floating_c_storage_initialized();
        let mut opts = ostree_ext::container::store::ExportToOCIOpts::default();
        opts.progress_to_stdout = true;
        tracing::info!(
            "Exporting ostree deployment to containers-storage: {}",
            &imgref.image
        );
        ostree_ext::container::store::export(repo, &source, &target, Some(opts)).await?;

        // Now copy from the default container storage (/var/lib/containers) into bootc storage.
        // We need to explicitly specify the source storage path because imgstore's pull
        // function operates with bootc storage as its primary root.
        tracing::info!(
            "Copying from default container storage to bootc storage: {}",
            &imgref.image
        );
        // Use explicit path to the default container storage
        let source_ref = format!(
            "containers-storage:[overlay@/var/lib/containers/storage]{}",
            &imgref.image
        );
        imgstore
            .pull(&source_ref, crate::podstorage::PullMode::Always)
            .await?;

        // Verify the image is now in bootc storage and findable by upgrade/switch
        if !imgstore.exists(&imgref.image).await? {
            anyhow::bail!(
                "Image was pushed to bootc storage but not found: {}. \
                 This may indicate a storage configuration issue.",
                &imgref.image
            );
        }
        tracing::info!("Image verified in bootc storage: {}", &imgref.image);
    } else {
        let img_string = crate::utils::imageref_to_container_ref(imgref);
        imgstore
            .pull(&img_string, crate::podstorage::PullMode::Always)
            .await?;
    }

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
