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

    let sysroot: Option<crate::store::Storage> =
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

/// Implementation of `bootc image copy-to-bootc-storage`.
#[context("Copying image to bootc storage")]
pub(crate) async fn copy_to_bootc_storage_entrypoint(source: &str) -> Result<()> {
    let sysroot = crate::cli::get_storage().await?;
    sysroot.get_ensure_imgstore()?.copy_to_storage(source).await
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
