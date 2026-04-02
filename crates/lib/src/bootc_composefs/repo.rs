use fn_error_context::context;
use std::sync::Arc;

use anyhow::{Context, Result};

use cfsctl::composefs;
use cfsctl::composefs_boot;
use cfsctl::composefs_oci;
use composefs::fsverity::{FsVerityHashValue, Sha512HashValue};
use composefs_boot::bootloader::{BootEntry as ComposefsBootEntry, get_boot_resources};
use composefs_oci::{
    image::create_filesystem as create_composefs_filesystem,
    pull_image as composefs_oci_pull_image, skopeo::PullResult, tag_image,
};

use ostree_ext::container::ImageReference as OstreeExtImgRef;

use cap_std_ext::cap_std::{ambient_authority, fs::Dir};

use crate::composefs_consts::BOOTC_TAG_PREFIX;
use crate::install::{RootSetup, State};

/// Create a composefs OCI tag name for the given manifest digest.
///
/// Returns a tag like `localhost/bootc-sha256:abc...` which acts as a GC root
/// in the composefs repository, keeping the manifest, config, and all layer
/// splitstreams alive.
pub(crate) fn bootc_tag_for_manifest(manifest_digest: &str) -> String {
    format!("{BOOTC_TAG_PREFIX}{manifest_digest}")
}

pub(crate) fn open_composefs_repo(rootfs_dir: &Dir) -> Result<crate::store::ComposefsRepository> {
    crate::store::ComposefsRepository::open_path(rootfs_dir, "composefs")
        .context("Failed to open composefs repository")
}

pub(crate) async fn initialize_composefs_repository(
    state: &State,
    root_setup: &RootSetup,
    allow_missing_fsverity: bool,
) -> Result<PullResult<Sha512HashValue>> {
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

    let (mut repo, _created) = crate::store::ComposefsRepository::init_path(
        rootfs_dir,
        "composefs",
        composefs::fsverity::Algorithm::SHA512,
        !allow_missing_fsverity,
    )
    .context("Failed to initialize composefs repository")?;
    if allow_missing_fsverity {
        repo.set_insecure();
    }

    let OstreeExtImgRef {
        name: image_name,
        transport,
    } = &state.source.imageref;

    let mut config = crate::deploy::new_proxy_config();
    ostree_ext::container::merge_default_container_proxy_opts(&mut config)?;

    // Pull without a reference tag; we tag explicitly afterward so we
    // control the tag name format.
    let repo = Arc::new(repo);
    let (pull_result, _stats) = composefs_oci_pull_image(
        &repo,
        &format!("{transport}{image_name}"),
        None,
        Some(config),
    )
    .await?;

    // Tag the manifest as a bootc-owned GC root.
    let tag = bootc_tag_for_manifest(&pull_result.manifest_digest.to_string());
    tag_image(&*repo, &pull_result.manifest_digest, &tag)
        .context("Tagging pulled image as bootc GC root")?;

    tracing::info!(
        message_id = COMPOSEFS_REPO_INIT_JOURNAL_ID,
        bootc.operation = "repository_init",
        bootc.manifest_digest = %pull_result.manifest_digest,
        bootc.manifest_verity = pull_result.manifest_verity.to_hex(),
        bootc.config_digest = %pull_result.config_digest,
        bootc.config_verity = pull_result.config_verity.to_hex(),
        bootc.tag = tag,
        "Pulled image into composefs repository",
    );

    Ok(pull_result)
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

/// Result of pulling a composefs repository, including the OCI manifest digest
/// needed to reconstruct image metadata from the local composefs repo.
pub(crate) struct PullRepoResult {
    pub(crate) repo: crate::store::ComposefsRepository,
    pub(crate) entries: Vec<ComposefsBootEntry<Sha512HashValue>>,
    pub(crate) id: Sha512HashValue,
    /// The OCI manifest content digest (e.g. "sha256:abc...")
    pub(crate) manifest_digest: String,
}

/// Pulls the `image` from `transport` into a composefs repository at /sysroot
/// Checks for boot entries in the image and returns them
#[context("Pulling composefs repository")]
pub(crate) async fn pull_composefs_repo(
    transport: &String,
    image: &String,
    allow_missing_fsverity: bool,
) -> Result<PullRepoResult> {
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
    if allow_missing_fsverity {
        repo.set_insecure();
    }

    let final_imgref = get_imgref(transport, image);

    tracing::debug!("Image to pull {final_imgref}");

    let mut config = crate::deploy::new_proxy_config();
    ostree_ext::container::merge_default_container_proxy_opts(&mut config)?;

    let repo = Arc::new(repo);
    let (pull_result, _stats) = composefs_oci_pull_image(&repo, &final_imgref, None, Some(config))
        .await
        .context("Pulling composefs repo")?;

    // Tag the manifest as a bootc-owned GC root.
    let tag = bootc_tag_for_manifest(&pull_result.manifest_digest.to_string());
    tag_image(&*repo, &pull_result.manifest_digest, &tag)
        .context("Tagging pulled image as bootc GC root")?;

    tracing::info!(
        message_id = COMPOSEFS_PULL_JOURNAL_ID,
        bootc.operation = "pull",
        bootc.manifest_digest = %pull_result.manifest_digest,
        bootc.manifest_verity = pull_result.manifest_verity.to_hex(),
        bootc.config_digest = %pull_result.config_digest,
        bootc.config_verity = pull_result.config_verity.to_hex(),
        bootc.tag = tag,
        "Pulled image into composefs repository",
    );

    // Generate the bootable EROFS image (idempotent).
    let id = composefs_oci::generate_boot_image(&repo, &pull_result.manifest_digest)
        .context("Generating bootable EROFS image")?;

    // Get boot entries from the OCI filesystem (untransformed).
    let fs = create_composefs_filesystem(&*repo, &pull_result.config_digest, None)
        .context("Creating composefs filesystem for boot entry discovery")?;
    let entries =
        get_boot_resources(&fs, &*repo).context("Extracting boot entries from OCI image")?;

    // Unwrap the Arc to get the owned repo back.
    let mut repo = Arc::try_unwrap(repo).map_err(|_| {
        anyhow::anyhow!("BUG: Arc<Repository> still has other references after pull completed")
    })?;
    if allow_missing_fsverity {
        repo.set_insecure();
    }

    Ok(PullRepoResult {
        repo,
        entries,
        id,
        manifest_digest: pull_result.manifest_digest.to_string(),
    })
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

    #[test]
    fn test_bootc_tag_for_manifest() {
        let digest = "sha256:abc123def456";
        let tag = bootc_tag_for_manifest(digest);
        assert_eq!(tag, "localhost/bootc-sha256:abc123def456");
        assert!(tag.starts_with(BOOTC_TAG_PREFIX));
    }
}
