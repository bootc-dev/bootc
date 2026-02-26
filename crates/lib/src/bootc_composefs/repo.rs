use fn_error_context::context;
use std::sync::Arc;

use anyhow::{Context, Result};

use ostree_ext::composefs::fsverity::{FsVerityHashValue, Sha512HashValue};
use ostree_ext::composefs_boot::{BootOps, bootloader::BootEntry as ComposefsBootEntry};
use ostree_ext::composefs_oci::{
    image::create_filesystem as create_composefs_filesystem, pull as composefs_oci_pull,
};

use ostree_ext::container::ImageReference as OstreeExtImgRef;

use cap_std_ext::cap_std::{ambient_authority, fs::Dir};

use crate::install::{RootSetup, State};

pub(crate) fn open_composefs_repo(rootfs_dir: &Dir) -> Result<crate::store::ComposefsRepository> {
    crate::store::ComposefsRepository::open_path(rootfs_dir, "composefs")
        .context("Failed to open composefs repository")
}

pub(crate) async fn initialize_composefs_repository(
    state: &State,
    root_setup: &RootSetup,
    allow_missing_fsverity: bool,
) -> Result<(String, impl FsVerityHashValue)> {
    const COMPOSEFS_REPO_INIT_JOURNAL_ID: &str = "5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9";

    let rootfs_dir = &root_setup.physical_root;
    let image_name = &state.source.imageref.name;
    let transport = &state.source.imageref.transport;

    tracing::info!(
        message_id = COMPOSEFS_REPO_INIT_JOURNAL_ID,
        bootc.operation = "repository_init",
        bootc.source_image = %image_name,
        bootc.transport = %transport,
        bootc.allow_missing_fsverity = allow_missing_fsverity,
        "Initializing composefs repository for image {}:{}",
        transport,
        image_name
    );

    crate::store::ensure_composefs_dir(rootfs_dir)?;

    let mut repo = open_composefs_repo(rootfs_dir)?;
    repo.set_insecure(allow_missing_fsverity);

    let OstreeExtImgRef {
        name: image_name,
        transport,
    } = &state.source.imageref;

    // transport's display is already of type "<transport_type>:"
    composefs_oci_pull(
        &Arc::new(repo),
        &format!("{transport}{image_name}"),
        None,
        None,
    )
    .await
}

/// skopeo (in composefs-rs) doesn't understand "registry:"
/// This function will convert it to "docker://" and return the image ref
///
/// Ex
/// docker://quay.io/some-image
/// containers-storage:some-image
/// docker-daemon:some-image-id
pub(crate) fn get_imgref(transport: &str, image: &str) -> String {
    let img = image.strip_prefix(":").unwrap_or(&image);
    let transport = transport.strip_suffix(":").unwrap_or(&transport);

    if transport == "registry" || transport == "docker://" {
        format!("docker://{img}")
    } else if transport == "docker-daemon" {
        format!("docker-daemon:{img}")
    } else {
        format!("{transport}:{img}")
    }
}

/// Pulls the `image` from `transport` into a composefs repository at /sysroot
/// Checks for boot entries in the image and returns them
#[context("Pulling composefs repository")]
pub(crate) async fn pull_composefs_repo(
    transport: &String,
    image: &String,
    allow_missing_fsverity: bool,
) -> Result<(
    crate::store::ComposefsRepository,
    Vec<ComposefsBootEntry<Sha512HashValue>>,
    Sha512HashValue,
    crate::store::ComposefsFilesystem,
)> {
    const COMPOSEFS_PULL_JOURNAL_ID: &str = "4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8";

    tracing::info!(
        message_id = COMPOSEFS_PULL_JOURNAL_ID,
        bootc.operation = "pull",
        bootc.source_image = image,
        bootc.transport = transport,
        bootc.allow_missing_fsverity = allow_missing_fsverity,
        "Pulling composefs image {}:{}",
        transport,
        image
    );

    let rootfs_dir = Dir::open_ambient_dir("/sysroot", ambient_authority())?;

    let mut repo = open_composefs_repo(&rootfs_dir).context("Opening composefs repo")?;
    repo.set_insecure(allow_missing_fsverity);

    let final_imgref = get_imgref(transport, image);

    tracing::debug!("Image to pull {final_imgref}");

    let (id, verity) = composefs_oci_pull(&Arc::new(repo), &final_imgref, None, None)
        .await
        .context("Pulling composefs repo")?;

    tracing::info!(
        message_id = COMPOSEFS_PULL_JOURNAL_ID,
        id = id,
        verity = verity.to_hex(),
        "Pulled image into repository"
    );

    let mut repo = open_composefs_repo(&rootfs_dir)?;
    repo.set_insecure(allow_missing_fsverity);

    let mut fs: crate::store::ComposefsFilesystem =
        create_composefs_filesystem(&repo, &id, None)
            .context("Failed to create composefs filesystem")?;

    let entries = fs.transform_for_boot(&repo)?;
    let id = fs.commit_image(&repo, None)?;

    Ok((repo, entries, id, fs))
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMAGE_NAME: &str = "quay.io/example/image:latest";

    #[test]
    fn test_get_imgref_registry_transport() {
        assert_eq!(
            get_imgref("registry:", IMAGE_NAME),
            format!("docker://{IMAGE_NAME}")
        );
    }

    #[test]
    fn test_get_imgref_containers_storage() {
        assert_eq!(
            get_imgref("containers-storage", IMAGE_NAME),
            format!("containers-storage:{IMAGE_NAME}")
        );

        assert_eq!(
            get_imgref("containers-storage:", IMAGE_NAME),
            format!("containers-storage:{IMAGE_NAME}")
        );
    }

    #[test]
    fn test_get_imgref_edge_cases() {
        assert_eq!(
            get_imgref("registry", IMAGE_NAME),
            format!("docker://{IMAGE_NAME}")
        );
    }

    #[test]
    fn test_get_imgref_docker_daemon_transport() {
        assert_eq!(
            get_imgref("docker-daemon", IMAGE_NAME),
            format!("docker-daemon:{IMAGE_NAME}")
        );
    }
}
