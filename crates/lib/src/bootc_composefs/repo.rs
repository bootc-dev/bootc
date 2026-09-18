//! Composefs repository lifecycle and OCI pull paths.
//!
//! This module owns how OCI images get into the composefs object store.
//! There are two pull paths, selected by the `use_unified` flag:
//!
//! ## Direct pull (`use_unified = false`)
//!
//! `pull_composefs_direct` fetches from the source transport (registry, OCI
//! dir, etc.) straight into the composefs repo via `composefs_oci::pull` with
//! default options. No containers-storage involvement.
//!
//! ## Unified pull (`use_unified = true`)
//!
//! `pull_composefs_unified` is the two-stage path that populates all three
//! stores (see [`crate::store`] for the architecture overview):
//!
//! **Stage 1** — Pull into bootc-owned containers-storage via
//! `CStorage::pull_with_progress` (or `pull_from_host_storage` if the image
//! already exists in the default podman store, saving a network round-trip).
//!
//! **Stage 2** — `composefs_oci::pull` with `LocalFetchOpt::ZeroCopy` and
//! `storage_root` pointing at the containers-storage directory. composefs-ctl
//! walks the overlay `diff/` directories and FICLONEs each file into the
//! composefs object store keyed by its SHA-512 fsverity digest. On a
//! reflink-capable filesystem this is near-instantaneous and consumes no
//! additional disk space.
//!
//! The caller provides `storage_path` as an absolute filesystem path string
//! (not a `Dir` fd) because composefs-ctl passes it to a child skopeo process.
//! It is derived from the physical root fd via `/proc/self/fd/{fd}` readlink.
//!
//! ## Entry points
//!
//! - [`pull_composefs_repo`] — upgrade/switch on a composefs-booted system.
//! - [`initialize_composefs_repository`] — `bootc install` with the composefs
//!   backend.

use fn_error_context::context;
use std::sync::Arc;

use anyhow::{Context, Result};

use composefs::fsverity::{FsVerityHashValue, Sha512HashValue};
use composefs::repository::RepositoryConfig;
use composefs::tree::FileSystem;
use composefs_boot::bootloader::{BootEntry as ComposefsBootEntry, get_boot_resources};
use composefs_ctl::composefs;
use composefs_ctl::composefs_boot;
use composefs_ctl::composefs_oci;
use composefs_oci::{
    LocalFetchOpt, PullOptions, PullResult,
    image::create_filesystem as create_composefs_filesystem, tag_image,
};

use ostree_ext::containers_image_proxy;

use cap_std_ext::cap_std::{ambient_authority, fs::Dir};
use rustix::fs::{FlockOperation, flock};

use crate::bootc_composefs::boot::{
    ensure_correct_composefs_digest, print_uki_dumpfile_diff_on_mismatch,
};
use crate::bootc_composefs::progress;
use crate::composefs_consts::BOOTC_TAG_PREFIX;
use crate::install::{RootSetup, State};
use crate::lsm;
use crate::podstorage::CStorage;
use crate::progress_jsonl::ProgressWriter;

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

/// Build the repository configuration used by every composefs initialization
/// path.  Keeping the fs-verity policy and the dual EROFS format policy here
/// prevents preflight initialization from silently creating a different
/// repository than the real pull path will use.
pub(crate) fn composefs_repository_config(allow_missing_fsverity: bool) -> RepositoryConfig {
    let mut config = RepositoryConfig::new(composefs::fsverity::Algorithm::SHA512);
    if allow_missing_fsverity {
        config = config.set_insecure();
    }
    crate::store::set_dual_erofs_formats(&mut config);
    config
}

pub(crate) struct InitializedComposefs {
    pub(crate) pull_result: PullResult<Sha512HashValue>,
    pub(crate) created: bool,
    pub(crate) repository_insecure: bool,
    pub(crate) uki_policy: Option<bool>,
}

pub(crate) fn final_repository_policy(uki_policy: Option<bool>, requested_relaxed: bool) -> bool {
    uki_policy == Some(true) || (uki_policy.is_none() && requested_relaxed)
}

/// Enforce the durable repository policy after inspecting the imported image.
/// Existing metadata is never rewritten: an explicit relaxation only applies
/// to the session that will install the boot artifacts.
pub(crate) fn validate_repository_policy(
    repository_insecure: bool,
    requested_relaxed: bool,
    allow_missing_verity_explicit: bool,
) -> Result<()> {
    if repository_insecure && !requested_relaxed {
        anyhow::bail!(
            "Existing composefs repository is insecure, but this install requires fs-verity; refusing to continue"
        );
    }
    if !repository_insecure && requested_relaxed && !allow_missing_verity_explicit {
        anyhow::bail!(
            "Initial insecure UKI conflicts with the existing strict composefs repository; explicitly pass --allow-missing-verity to permit this session"
        );
    }
    Ok(())
}

/// Replace only the metadata of a repository created by this install.  The
/// replacement is generated by composefs-rs itself, so format and feature
/// settings cannot drift from the normal initialization path.
pub(crate) fn finalize_fresh_repository_policy(
    rootfs: &std::path::Path,
    initial_config: RepositoryConfig,
) -> Result<()> {
    let repo_path = rootfs.join(crate::store::COMPOSEFS);
    let parent = repo_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("composefs repository has no parent"))?;
    let temp = tempfile::Builder::new()
        .prefix(".bootc-meta-")
        .tempdir_in(parent)
        .context("Creating temporary metadata directory")?;
    let temp_root = Dir::open_ambient_dir(temp.path(), ambient_authority())?;
    let relaxed = initial_config.set_insecure();
    let (temporary_repo, _) =
        crate::store::ComposefsRepository::init_path(&temp_root, ".", relaxed)?;
    let replacement_metadata = temporary_repo.metadata().clone();
    drop(temporary_repo);

    // Repository handles use LOCK_SH.  They must all be gone before this
    // short exclusive critical section, otherwise flock would self-deadlock.
    let lock = std::fs::File::open(&repo_path).context("Opening composefs repository lock")?;
    flock(&lock, FlockOperation::LockExclusive).context("Taking composefs repository lock")?;
    let target_meta = repo_path.join("meta.json");
    let target_metadata: composefs::repository::RepoMetadata =
        serde_json::from_slice(&std::fs::read(&target_meta)?)?;
    anyhow::ensure!(
        target_metadata == replacement_metadata,
        "composefs metadata generated for policy replacement does not match the repository"
    );

    let replacement_meta = temp.path().join("meta.json");
    std::fs::rename(&replacement_meta, &target_meta)
        .context("Atomically replacing composefs metadata")?;
    std::fs::File::open(&target_meta)?.sync_all()?;
    std::fs::File::open(&repo_path)?.sync_all()?;
    Ok(())
}

pub(crate) fn tag_pulled_image(
    rootfs_dir: &Dir,
    pull_result: &PullResult<Sha512HashValue>,
) -> Result<()> {
    let repo = crate::store::ComposefsRepository::open_path(rootfs_dir, "composefs")?;
    let tag = bootc_tag_for_manifest(&pull_result.manifest_digest.to_string());
    tag_image(&repo, &pull_result.manifest_digest, &tag)
        .context("Tagging pulled image as bootc GC root")?;
    Ok(())
}

pub(crate) async fn initialize_composefs_repository(
    state: &State,
    root_setup: &RootSetup,
    allow_missing_fsverity: bool,
    use_unified: bool,
    fetch_imgref: Option<&containers_image_proxy::ImageReference>,
    manifest: &ostree_ext::oci_spec::image::ImageManifest,
) -> Result<InitializedComposefs> {
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
        bootc.unified_storage = use_unified,
        "Initializing composefs repository for image {}:{}",
        transport,
        image_name
    );

    crate::store::ensure_composefs_dir(rootfs_dir)?;

    let config = composefs_repository_config(allow_missing_fsverity);
    let (mut repo, created) =
        crate::store::ComposefsRepository::init_path(rootfs_dir, "composefs", config)
            .context("Failed to initialize composefs repository")?;
    let repository_insecure = repo.is_insecure();
    // `set_insecure()` is an explicit per-handle relaxation.  It must also be
    // applied when init_path opened an existing strict repository; init_path
    // correctly derives the durable policy from meta.json and does not rewrite
    // it merely because this session permits missing fs-verity.
    if allow_missing_fsverity && (created || repository_insecure) {
        repo.set_insecure();
    }

    crate::deploy::check_disk_space_composefs(
        &repo,
        manifest,
        &crate::spec::ImageReference {
            image: fetch_imgref
                .map(|r| r.name.clone())
                .unwrap_or_else(|| state.source.composefs_fetch_reference().name),
            transport: fetch_imgref
                .map(|r| r.transport.to_string())
                .unwrap_or_else(|| {
                    state
                        .source
                        .composefs_fetch_reference()
                        .transport
                        .to_string()
                }),
            signature: None,
        },
    )?;

    let original_imgref: containers_image_proxy::ImageReference = state
        .source
        .imageref
        .to_string()
        .as_str()
        .try_into()
        .context("Parsing source image reference")?;
    let imgref = fetch_imgref.unwrap_or(&original_imgref);

    // Ensure the compatibility symlink ostree/bootc -> ../composefs/bootc
    // exists.  This is needed for LBI and (when unified storage is enabled)
    // for containers-storage under composefs/bootc/storage.  The existing
    // /usr/lib/bootc/storage symlink and all runtime code using
    // ostree/bootc/storage depend on this link.
    crate::store::ensure_composefs_bootc_link(rootfs_dir)?;

    let repo = Arc::new(repo);

    let pull_result = if use_unified {
        // Unified path: first into containers-storage on the target
        // rootfs, then cstor zero-copy into composefs. This ensures the image
        // is available for `podman run` from first boot.
        let sepolicy = state.load_policy()?;
        let run = Dir::open_ambient_dir("/run", ambient_authority())?;
        let imgstore = CStorage::create(rootfs_dir, &run, sepolicy.as_ref())?;
        let storage_path = root_setup.physical_root_path.join(CStorage::subpath());

        // `bootc install` does not yet plumb `--quiet`/`--progress-fd` down to
        // this path; use defaults for now (terminal progress still renders).
        let r = pull_composefs_unified(
            &imgstore,
            storage_path.as_str(),
            &repo,
            &imgref,
            false,
            ProgressWriter::default(),
        )
        .await?;

        // SELinux-label the containers-storage now that all pulls are done.
        imgstore
            .ensure_labeled()
            .context("SELinux labeling of containers-storage")?;
        r
    } else {
        // Direct path: pull directly into composefs via skopeo, without
        // containers-storage as intermediary.
        pull_composefs_direct(&repo, &imgref, false, ProgressWriter::default()).await?
    };

    let uki_policy = inspect_uki_policy(&repo, &pull_result)?;

    drop(repo);

    Ok(InitializedComposefs {
        pull_result,
        created,
        repository_insecure,
        uki_policy,
    })
}

/// Result of pulling a composefs repository, including the OCI manifest digest
/// needed to reconstruct image metadata from the local composefs repo.
pub(crate) struct PullRepoResult {
    pub(crate) repo: crate::store::ComposefsRepository,
    pub(crate) entries: Vec<ComposefsBootEntry<Sha512HashValue>>,
    pub(crate) id: Sha512HashValue,
    /// The OCI manifest content digest (e.g. "sha256:abc...")
    pub(crate) manifest_digest: String,
    /// The untransformed OCI filesystem (still has /boot, /sysroot, etc.)
    pub(crate) fs: FileSystem<Sha512HashValue>,
}

/// The boot-facing artifacts reconstructed from a pulled OCI image.
pub(crate) struct BootImage {
    pub(crate) id: Sha512HashValue,
    pub(crate) fs: FileSystem<Sha512HashValue>,
    pub(crate) entries: Vec<ComposefsBootEntry<Sha512HashValue>>,
}

/// Generate the boot image, reconstruct the untransformed filesystem for boot
/// entry discovery, and reconcile the generated digest with a UKI, if present.
///
/// Keeping this sequence next to the pull paths is important: install and
/// update must not independently generate images or recover a different digest.
pub(crate) fn prepare_boot_image(
    repo: &Arc<crate::store::ComposefsRepository>,
    pull_result: &PullResult<Sha512HashValue>,
) -> Result<BootImage> {
    let generated_id = composefs_oci::generate_boot_image(
        repo,
        &pull_result.manifest_digest,
        &composefs_oci::OciTransformOptions::default(),
    )
    .context("Generating bootable EROFS image")?;

    let fs = create_composefs_filesystem(
        &**repo,
        &pull_result.config_digest,
        Some(&pull_result.config_verity),
        &composefs_oci::OciTransformOptions::default(),
    )
    .context("Creating composefs filesystem for boot entry discovery")?;
    let entries =
        get_boot_resources(&fs, &**repo).context("Extracting boot entries from OCI image")?;
    let id = print_uki_dumpfile_diff_on_mismatch(
        ensure_correct_composefs_digest(repo, &pull_result.manifest_digest, generated_id, &entries),
        repo,
        &fs,
    )?;

    Ok(BootImage { id, fs, entries })
}

/// Inspect UKI policy without generating or recovering a boot image.  Boot
/// image generation is deferred until the durable repository policy has been
/// finalized and the normal boot setup path runs.
pub(crate) fn inspect_uki_policy(
    repo: &Arc<crate::store::ComposefsRepository>,
    pull_result: &PullResult<Sha512HashValue>,
) -> Result<Option<bool>> {
    let fs = create_composefs_filesystem(
        &**repo,
        &pull_result.config_digest,
        Some(&pull_result.config_verity),
        &composefs_oci::OciTransformOptions::default(),
    )
    .context("Creating composefs filesystem for UKI policy inspection")?;
    let entries = get_boot_resources(&fs, &**repo).context("Extracting boot entries")?;
    crate::bootc_composefs::boot::uki_fsverity_policy(repo, &entries)
}

/// Pull an image directly into the composefs repository via skopeo.
///
/// This is the default path: the image is fetched directly from the source
/// transport (registry, oci directory, etc.) into the composefs repo without
/// going through containers-storage first.
async fn pull_composefs_direct(
    repo: &Arc<crate::store::ComposefsRepository>,
    imgref: &containers_image_proxy::ImageReference,
    quiet: bool,
    prog: ProgressWriter,
) -> Result<PullResult<Sha512HashValue>> {
    let imgref_str = imgref.to_string();
    tracing::info!("Direct pull: fetching {imgref_str} into composefs repository");

    let mut config = crate::deploy::new_proxy_config();
    ostree_ext::container::merge_default_container_proxy_opts(&mut config)?;

    let (reporter, prog_task) = progress::spawn(quiet, prog);

    let pull_result = composefs_oci::pull(
        repo,
        &imgref_str,
        None,
        PullOptions {
            img_proxy_config: Some(config),
            progress: Some(reporter),
            ..Default::default()
        },
    )
    .await;

    // Awaiting the progress task after the pull future completes ensures the
    // reporter's `Arc` (and hence the channel it feeds) has been dropped, so
    // the background task drains its queue and exits rather than hanging.
    prog_task
        .await
        .context("Composefs progress task panicked")?;

    pull_result.context("Pulling image into composefs repository")
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
    quiet: bool,
    prog: ProgressWriter,
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
    let (reporter, prog_task) = progress::spawn(quiet, prog);
    let pull_opts = PullOptions {
        // The image is already in bootc-owned containers-storage at this point
        // (placed there by Stage 1 of the unified pull). Use ZeroCopy so we
        // actually import via reflink/hardlink and fail loudly if that isn't
        // possible — a plain copy fallback here would mean Stage 1 and Stage 2
        // are on different filesystems or the storage root is wrong.
        local_fetch: LocalFetchOpt::ZeroCopy,
        storage_root: Some(storage),
        progress: Some(reporter),
        ..Default::default()
    };
    let pull_result = composefs_oci::pull(repo, &cstor_imgref_str, None, pull_opts).await;

    prog_task
        .await
        .context("Composefs progress task panicked")?;

    let pull_result = pull_result.context("Importing from containers-storage into composefs")?;

    Ok(pull_result)
}

/// Pulls an image into a composefs repository at /sysroot.
///
/// When `use_unified` is true, the image is first pulled into bootc-owned
/// containers-storage (so it's available for `podman run`), then imported
/// from there into the composefs repo via zero-copy reflinks.
///
/// When `use_unified` is false (the default), the image is pulled directly
/// into the composefs repo via skopeo.
///
/// Checks for boot entries in the image and returns them.
#[context("Pulling composefs repository")]
pub(crate) async fn pull_composefs_repo(
    spec_imgref: &crate::spec::ImageReference,
    allow_missing_fsverity: bool,
    use_unified: bool,
    quiet: bool,
    prog: ProgressWriter,
) -> Result<PullRepoResult> {
    const COMPOSEFS_PULL_JOURNAL_ID: &str = "4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8";

    let imgref = spec_imgref.to_image_proxy_ref()?;

    tracing::info!(
        message_id = COMPOSEFS_PULL_JOURNAL_ID,
        bootc.operation = "pull",
        bootc.source_image = &spec_imgref.image,
        bootc.transport = %imgref.transport,
        bootc.allow_missing_fsverity = allow_missing_fsverity,
        bootc.unified_storage = use_unified,
        "Pulling composefs image {imgref}",
    );

    let rootfs_dir = Dir::open_ambient_dir("/sysroot", ambient_authority())?;

    let mut repo = open_composefs_repo(&rootfs_dir).context("Opening composefs repo")?;
    if allow_missing_fsverity {
        repo.set_insecure();
    }

    let repo = Arc::new(repo);

    // Upgrade any old-format OCI images before pulling.  Old bootc
    // (composefs-rs ≤ 2203e8f) did not add IMAGE_REF_KEY to config
    // splitstreams, so the new GC's tag-based stream walk cannot reach
    // their layer objects.  upgrade_repo() rewrites those config
    // splitstreams in place before we add a new deployment, ensuring all
    // existing deployments are GC-safe.  It is idempotent and fast when
    // images are already in the current format.
    let upgrade_result =
        composefs_oci::upgrade_repo(&repo).context("Upgrading old-format OCI images")?;
    if upgrade_result.upgraded > 0 {
        tracing::info!(
            "Upgraded {} old-format OCI image(s) to current format",
            upgrade_result.upgraded
        );
    }

    let pull_result = if use_unified {
        // Create bootc-owned containers-storage on the rootfs.
        // Load SELinux policy from the running system so newly pulled layers
        // get the correct container_var_lib_t labels.
        let root = Dir::open_ambient_dir("/", ambient_authority())?;
        let sepolicy = lsm::new_sepolicy_at(&root)?;
        let run = Dir::open_ambient_dir("/run", ambient_authority())?;
        let imgstore = CStorage::create(&rootfs_dir, &run, sepolicy.as_ref())?;
        let storage_path = format!("/sysroot/{}", CStorage::subpath());

        pull_composefs_unified(&imgstore, &storage_path, &repo, &imgref, quiet, prog).await?
    } else {
        pull_composefs_direct(&repo, &imgref, quiet, prog).await?
    };

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

    let BootImage { id, fs, entries } = prepare_boot_image(&repo, &pull_result)?;

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
        fs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn test_bootc_tag_for_manifest() {
        let digest = "sha256:abc123def456";
        let tag = bootc_tag_for_manifest(digest);
        assert_eq!(tag, "localhost/bootc-sha256:abc123def456");
        assert!(tag.starts_with(BOOTC_TAG_PREFIX));
    }

    #[test]
    fn test_repository_init_preserves_requested_verity_policy() {
        for allow_missing in [true, false] {
            let tempdir = tempfile::tempdir().unwrap();
            let root = Dir::open_ambient_dir(tempdir.path(), ambient_authority()).unwrap();
            let result = crate::store::ComposefsRepository::init_path(
                &root,
                ".",
                composefs_repository_config(allow_missing),
            );

            match result {
                Ok((repo, _)) => assert_eq!(repo.is_insecure(), allow_missing),
                Err(error) if !allow_missing => {
                    // A host without fs-verity support must fail strict
                    // initialization rather than silently creating insecure
                    // metadata.
                    let message = format!("{error:#}");
                    assert!(
                        message.to_ascii_lowercase().contains("verity"),
                        "strict initialization failed for an unrelated reason: {message}"
                    );
                }
                Err(error) => panic!("insecure initialization failed: {error:#}"),
            }
        }
    }

    #[test]
    fn test_existing_repository_policy_is_one_way() {
        let tempdir = tempfile::tempdir().unwrap();
        let root = Dir::open_ambient_dir(tempdir.path(), ambient_authority()).unwrap();
        let (strict_repo, _) = match crate::store::ComposefsRepository::init_path(
            &root,
            ".",
            composefs_repository_config(false),
        ) {
            Ok(result) => result,
            Err(error) if format!("{error:#}").to_ascii_lowercase().contains("verity") => {
                // The host test filesystem may not support fs-verity.  The
                // strict fresh-install behavior is covered by the same init
                // probe above and by the VM test environment.
                return;
            }
            Err(error) => panic!("strict initialization failed unexpectedly: {error:#}"),
        };
        assert!(!strict_repo.is_insecure());

        let metadata_before = std::fs::read(tempdir.path().join("meta.json")).unwrap();
        let metadata_inode = std::fs::metadata(tempdir.path().join("meta.json"))
            .unwrap()
            .ino();
        let (relaxed_repo, _) = crate::store::ComposefsRepository::init_path(
            &root,
            ".",
            composefs_repository_config(true),
        )
        .unwrap();
        assert!(!relaxed_repo.is_insecure());
        assert_eq!(
            metadata_before,
            std::fs::read(tempdir.path().join("meta.json")).unwrap()
        );
        assert_eq!(
            metadata_inode,
            std::fs::metadata(tempdir.path().join("meta.json"))
                .unwrap()
                .ino()
        );
        assert!(validate_repository_policy(false, true, true).is_ok());

        let insecure_tempdir = tempfile::tempdir().unwrap();
        let insecure_root =
            Dir::open_ambient_dir(insecure_tempdir.path(), ambient_authority()).unwrap();
        let (insecure_repo, _) = crate::store::ComposefsRepository::init_path(
            &insecure_root,
            ".",
            composefs_repository_config(true),
        )
        .unwrap();
        assert!(insecure_repo.is_insecure());
        assert!(validate_repository_policy(true, false, false).is_err());
    }

    #[test]
    fn test_final_repository_policy_matrix() {
        for (uki_policy, requested_relaxed, expected) in [
            (Some(false), false, false),
            (Some(false), true, false),
            (Some(true), false, true),
            (Some(true), true, true),
            (None, false, false),
            (None, true, true),
        ] {
            assert_eq!(
                final_repository_policy(uki_policy, requested_relaxed),
                expected
            );
        }
    }

    #[test]
    fn test_existing_repository_policy_matrix() {
        for (insecure, uki_policy, requested, explicit, expected) in [
            (false, Some(false), false, false, true),
            (false, Some(true), true, false, false),
            (false, Some(true), true, true, true),
            (false, None, false, false, true),
            (false, None, true, false, false),
            (false, None, true, true, true),
            (true, Some(false), false, false, false),
            (true, Some(true), true, false, true),
            (true, None, false, false, false),
            (true, None, true, false, true),
        ] {
            let requested_relaxed = final_repository_policy(uki_policy, requested);
            assert_eq!(
                validate_repository_policy(insecure, requested_relaxed, explicit).is_ok(),
                expected,
                "insecure={insecure} uki_policy={uki_policy:?} requested={requested} explicit={explicit}"
            );
        }
    }

    #[test]
    fn test_fresh_policy_replacement_preserves_objects() {
        let tempdir = tempfile::tempdir().unwrap();
        let root = Dir::open_ambient_dir(tempdir.path(), ambient_authority()).unwrap();
        crate::store::ensure_composefs_dir(&root).unwrap();
        let (repo, _) = match crate::store::ComposefsRepository::init_path(
            &root,
            crate::store::COMPOSEFS,
            composefs_repository_config(false),
        ) {
            Ok(repo) => repo,
            Err(error) if format!("{error:#}").to_ascii_lowercase().contains("verity") => return,
            Err(error) => panic!("strict repository initialization failed: {error:#}"),
        };
        let metadata_path = tempdir
            .path()
            .join(crate::store::COMPOSEFS)
            .join("meta.json");
        let metadata_inode = std::fs::metadata(&metadata_path).unwrap().ino();
        let object_path = tempdir
            .path()
            .join(crate::store::COMPOSEFS)
            .join("objects/sentinel");
        std::fs::write(&object_path, b"retained").unwrap();
        drop(repo);

        finalize_fresh_repository_policy(tempdir.path(), composefs_repository_config(false))
            .unwrap();

        let reopened =
            crate::store::ComposefsRepository::open_path(&root, crate::store::COMPOSEFS).unwrap();
        assert!(reopened.is_insecure());
        assert_ne!(
            metadata_inode,
            std::fs::metadata(&metadata_path).unwrap().ino()
        );
        assert_eq!(std::fs::read(object_path).unwrap(), b"retained");
    }

    #[test]
    fn test_fresh_policy_replacement_refuses_feature_mismatch() {
        let tempdir = tempfile::tempdir().unwrap();
        let root = Dir::open_ambient_dir(tempdir.path(), ambient_authority()).unwrap();
        crate::store::ensure_composefs_dir(&root).unwrap();
        let (repo, _) = crate::store::ComposefsRepository::init_path(
            &root,
            crate::store::COMPOSEFS,
            composefs_repository_config(true),
        )
        .unwrap();
        drop(repo);

        let metadata_path = tempdir
            .path()
            .join(crate::store::COMPOSEFS)
            .join("meta.json");
        let mut metadata: composefs::repository::RepoMetadata =
            serde_json::from_slice(&std::fs::read(&metadata_path).unwrap()).unwrap();
        metadata
            .features
            .compatible
            .push("review-only-feature".to_string());
        std::fs::write(&metadata_path, serde_json::to_vec(&metadata).unwrap()).unwrap();
        let metadata_inode = std::fs::metadata(&metadata_path).unwrap().ino();

        let error =
            finalize_fresh_repository_policy(tempdir.path(), composefs_repository_config(false))
                .unwrap_err();
        assert!(format!("{error:#}").contains("metadata"));
        assert_eq!(
            metadata_inode,
            std::fs::metadata(&metadata_path).unwrap().ino()
        );
        assert!(!std::fs::read_dir(tempdir.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".bootc-meta-")
        }));
    }
}
