use fn_error_context::context;
use std::sync::Arc;

use anyhow::{Context, Result};

use ostree_ext::composefs::{
    fsverity::{FsVerityHashValue, Sha256HashValue},
    repository::Repository as ComposefsRepository,
    tree::FileSystem,
    util::Sha256Digest,
};
use ostree_ext::composefs_boot::{bootloader::BootEntry as ComposefsBootEntry, BootOps};
use ostree_ext::composefs_oci::{
    image::create_filesystem as create_composefs_filesystem, pull as composefs_oci_pull,
};

use ostree_ext::container::ImageReference as OstreeExtImgRef;

use cap_std_ext::cap_std::{ambient_authority, fs::Dir};

use crate::install::{RootSetup, State};

pub(crate) fn open_composefs_repo(
    rootfs_dir: &Dir,
) -> Result<ComposefsRepository<Sha256HashValue>> {
    ComposefsRepository::open_path(rootfs_dir, "composefs")
        .context("Failed to open composefs repository")
}

pub(crate) async fn initialize_composefs_repository(
    state: &State,
    root_setup: &RootSetup,
) -> Result<(Sha256Digest, impl FsVerityHashValue)> {
    let rootfs_dir = &root_setup.physical_root;

    rootfs_dir
        .create_dir_all("composefs")
        .context("Creating dir composefs")?;

    let repo = open_composefs_repo(rootfs_dir)?;

    let OstreeExtImgRef {
        name: image_name,
        transport,
    } = &state.source.imageref;

    // transport's display is already of type "<transport_type>:"
    composefs_oci_pull(
        &Arc::new(repo),
        &format!("{transport}{image_name}"),
        None,
        Some(ostree_ext::containers_image_proxy::ImageProxyConfig {
            insecure_skip_tls_verification: Some(true),
            ..Default::default()
        }),
    )
    .await
}

/// skopeo (in composefs-rs) doesn't understand "registry:"
/// This function will convert it to "docker://" and return the image ref
///
/// Ex
/// docker://quay.io/some-image
/// containers-storage:some-image
pub(crate) fn get_imgref(transport: &String, image: &String) -> String {
    let img = image.strip_prefix(":").unwrap_or(&image);

    let final_imgref = if transport == "registry" {
        format!("docker://{img}")
    } else {
        format!("{transport}:{img}")
    };

    final_imgref
}

/// Pulls the `image` from `transport` into a composefs repository at /sysroot
/// Checks for boot entries in the image and returns them
#[context("Pulling composefs repository")]
pub(crate) async fn pull_composefs_repo(
    transport: &String,
    image: &String,
) -> Result<(
    ComposefsRepository<Sha256HashValue>,
    Vec<ComposefsBootEntry<Sha256HashValue>>,
    Sha256HashValue,
    FileSystem<Sha256HashValue>,
)> {
    let rootfs_dir = Dir::open_ambient_dir("/sysroot", ambient_authority())?;

    let repo = open_composefs_repo(&rootfs_dir).context("Opening compoesfs repo")?;

    let final_imgref = get_imgref(transport, image);

    tracing::debug!("Image to pull {final_imgref}");

    let (id, verity) = composefs_oci_pull(&Arc::new(repo), &final_imgref, None, None)
        .await
        .context("Pulling composefs repo")?;

    tracing::info!("id: {}, verity: {}", hex::encode(id), verity.to_hex());

    let repo = open_composefs_repo(&rootfs_dir)?;
    let mut fs = create_composefs_filesystem(&repo, &hex::encode(id), None)
        .context("Failed to create composefs filesystem")?;

    let entries = fs.transform_for_boot(&repo)?;
    let id = fs.commit_image(&repo, None)?;

    Ok((repo, entries, id, fs))
}
