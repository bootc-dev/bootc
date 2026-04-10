use fn_error_context::context;
use std::sync::Arc;

use anyhow::{Context, Result};

use cfsctl::composefs;
use cfsctl::composefs_boot;
use cfsctl::composefs_oci;
use composefs::fsverity::{FsVerityHashValue, Sha512HashValue};
use composefs_boot::bootloader::{BootEntry as ComposefsBootEntry, get_boot_resources};
use composefs_oci::{
    PullOptions, PullResult, image::create_filesystem as create_composefs_filesystem, tag_image,
};

use ostree_ext::containers_image_proxy;

use cap_std_ext::cap_std::{ambient_authority, fs::Dir};

use crate::composefs_consts::BOOTC_TAG_PREFIX;
use crate::install::{RootSetup, State};
use crate::lsm;
use crate::podstorage::CStorage;

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

    let imgref = get_imgref(&transport.to_string(), image_name)?;

    // On a composefs install, containers-storage lives physically under
    // composefs/bootc/storage with a compatibility symlink at
    // ostree/bootc -> ../composefs/bootc so the existing /usr/lib/bootc/storage
    // symlink (and all runtime code using ostree/bootc/storage) keeps working.
    crate::store::ensure_composefs_bootc_link(rootfs_dir)?;

    // Use the unified path: first into containers-storage on the target
    // rootfs, then cstor zero-copy into composefs. This ensures the image
    // is available for `podman run` from first boot.
    let sepolicy = state.load_policy()?;
    let run = Dir::open_ambient_dir("/run", ambient_authority())?;
    let imgstore = CStorage::create(rootfs_dir, &run, sepolicy.as_ref())?;
    let storage_path = root_setup.physical_root_path.join(CStorage::subpath());

    let repo = Arc::new(repo);
    let pull_result =
        pull_composefs_unified(&imgstore, storage_path.as_str(), &repo, &imgref).await?;

    // SELinux-label the containers-storage now that all pulls are done.
    imgstore
        .ensure_labeled()
        .context("SELinux labeling of containers-storage")?;

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

/// Convert a transport string and image name into a `containers_image_proxy::ImageReference`.
///
/// The `spec::ImageReference` stores transport as a string (e.g. "registry:",
/// "containers-storage:"). This parses that into a proper typed reference
/// that renders correctly for skopeo (e.g. "docker://quay.io/some-image").
pub(crate) fn get_imgref(
    transport: &str,
    image: &str,
) -> Result<containers_image_proxy::ImageReference> {
    let img = image.strip_prefix(':').unwrap_or(image);
    // Normalize: strip trailing separator if present, then parse
    // via containers_image_proxy::Transport for proper typed handling.
    let transport_str = transport.strip_suffix(':').unwrap_or(transport);
    // Build a canonical imgref string so Transport::try_from can parse it.
    let imgref_str = format!("{transport_str}:{img}");
    let transport: containers_image_proxy::Transport = imgref_str
        .as_str()
        .try_into()
        .with_context(|| format!("Parsing transport from '{imgref_str}'"))?;
    Ok(containers_image_proxy::ImageReference::new(transport, img))
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

/// Pull an image via unified storage: first into bootc-owned containers-storage,
/// then from there into the composefs repository via cstor (zero-copy
/// reflink/hardlink).
///
/// The caller provides:
/// - `imgstore`: the bootc-owned `CStorage` instance (may be on an arbitrary
///   mount point during install, or under `/sysroot` during upgrade)
/// - `storage_path`: the absolute filesystem path to that containers-storage
///   directory, so cstor and skopeo can find it (e.g.
///   `/mnt/sysroot/ostree/bootc/storage` during install, or
///   `/sysroot/ostree/bootc/storage` during upgrade)
///
/// This ensures the image is available in containers-storage for `podman run`
/// while also populating the composefs repo for booting.
async fn pull_composefs_unified(
    imgstore: &CStorage,
    storage_path: &str,
    repo: &Arc<crate::store::ComposefsRepository>,
    imgref: &containers_image_proxy::ImageReference,
) -> Result<PullResult<Sha512HashValue>> {
    let image = &imgref.name;

    // Stage 1: get the image into bootc-owned containers-storage.
    if imgref.transport == containers_image_proxy::Transport::ContainerStorage {
        // The image is in the default containers-storage (/var/lib/containers/storage).
        // Copy it into bootc-owned storage.
        tracing::info!("Unified pull: copying {image} from host containers-storage");
        imgstore
            .pull_from_host_storage(image)
            .await
            .context("Copying image from host containers-storage into bootc storage")?;
    } else {
        // For registry (docker://), oci:, docker-daemon:, etc. — pull
        // via the native podman API with streaming progress display.
        let pull_ref = imgref.to_string();
        tracing::info!("Unified pull: fetching {pull_ref} into containers-storage");
        imgstore
            .pull_with_progress(&pull_ref)
            .await
            .context("Pulling image into bootc containers-storage")?;
    }

    // Stage 2: import full OCI structure (layers + config + manifest) from
    // containers-storage into composefs via cstor (zero-copy reflink/hardlink).
    let cstor_imgref_str = format!("containers-storage:{image}");
    tracing::info!("Unified pull: importing from {cstor_imgref_str} (zero-copy)");

    let storage = std::path::Path::new(storage_path);
    let pull_opts = PullOptions {
        additional_image_stores: &[storage],
        ..Default::default()
    };
    let pull_result = composefs_oci::pull(repo, &cstor_imgref_str, None, pull_opts)
        .await
        .context("Importing from containers-storage into composefs")?;

    Ok(pull_result)
}

/// Pulls the `image` from `transport` into a composefs repository at /sysroot.
///
/// For registry transports, this uses the unified storage path: the image is
/// first pulled into bootc-owned containers-storage (so it's available for
/// `podman run`), then imported from there into the composefs repo.
///
/// Checks for boot entries in the image and returns them.
#[context("Pulling composefs repository")]
pub(crate) async fn pull_composefs_repo(
    transport: &str,
    image: &str,
    allow_missing_fsverity: bool,
) -> Result<PullRepoResult> {
    const COMPOSEFS_PULL_JOURNAL_ID: &str = "4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8";

    let imgref = get_imgref(transport, image)?;

    tracing::info!(
        message_id = COMPOSEFS_PULL_JOURNAL_ID,
        bootc.operation = "pull",
        bootc.source_image = image,
        bootc.transport = %imgref.transport,
        bootc.allow_missing_fsverity = allow_missing_fsverity,
        "Pulling composefs image {imgref}",
    );

    let rootfs_dir = Dir::open_ambient_dir("/sysroot", ambient_authority())?;

    let mut repo = open_composefs_repo(&rootfs_dir).context("Opening composefs repo")?;
    if allow_missing_fsverity {
        repo.set_insecure();
    }

    let repo = Arc::new(repo);

    // Create bootc-owned containers-storage on the rootfs.
    // Load SELinux policy from the running system so newly pulled layers
    // get the correct container_var_lib_t labels.
    let root = Dir::open_ambient_dir("/", ambient_authority())?;
    let sepolicy = lsm::new_sepolicy_at(&root)?;
    let run = Dir::open_ambient_dir("/run", ambient_authority())?;
    let imgstore = CStorage::create(&rootfs_dir, &run, sepolicy.as_ref())?;
    let storage_path = format!("/sysroot/{}", CStorage::subpath());

    let pull_result = pull_composefs_unified(&imgstore, &storage_path, &repo, &imgref).await?;

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
        let r = get_imgref("registry:", IMAGE_NAME).unwrap();
        assert_eq!(r.transport, containers_image_proxy::Transport::Registry);
        assert_eq!(r.name, IMAGE_NAME);
        assert_eq!(r.to_string(), format!("docker://{IMAGE_NAME}"));
    }

    #[test]
    fn test_get_imgref_containers_storage() {
        let r = get_imgref("containers-storage", IMAGE_NAME).unwrap();
        assert_eq!(
            r.transport,
            containers_image_proxy::Transport::ContainerStorage
        );
        assert_eq!(r.name, IMAGE_NAME);

        let r = get_imgref("containers-storage:", IMAGE_NAME).unwrap();
        assert_eq!(
            r.transport,
            containers_image_proxy::Transport::ContainerStorage
        );
        assert_eq!(r.name, IMAGE_NAME);
    }

    #[test]
    fn test_get_imgref_edge_cases() {
        let r = get_imgref("registry", IMAGE_NAME).unwrap();
        assert_eq!(r.transport, containers_image_proxy::Transport::Registry);
        assert_eq!(r.to_string(), format!("docker://{IMAGE_NAME}"));
    }

    #[test]
    fn test_get_imgref_docker_daemon_transport() {
        let r = get_imgref("docker-daemon", IMAGE_NAME).unwrap();
        assert_eq!(r.transport, containers_image_proxy::Transport::DockerDaemon);
        assert_eq!(r.name, IMAGE_NAME);
    }

    #[test]
    fn test_bootc_tag_for_manifest() {
        let digest = "sha256:abc123def456";
        let tag = bootc_tag_for_manifest(digest);
        assert_eq!(tag, "localhost/bootc-sha256:abc123def456");
        assert!(tag.starts_with(BOOTC_TAG_PREFIX));
    }
}
