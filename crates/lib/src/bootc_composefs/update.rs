use anyhow::{Context, Result};
use camino::Utf8PathBuf;
use cap_std_ext::{cap_std::fs::Dir, dirext::CapStdExtDirExt};
use composefs::fsverity::{FsVerityHashValue, Sha512HashValue};
use composefs_boot::BootOps;
use composefs_oci::image::create_filesystem;
use fn_error_context::context;
use ocidir::cap_std::ambient_authority;
use ostree_ext::container::ManifestDiff;

use crate::{
    bootc_composefs::{
        boot::{BootSetupType, BootType, setup_composefs_bls_boot, setup_composefs_uki_boot},
        repo::{get_imgref, pull_composefs_repo},
        service::start_finalize_stated_svc,
        soft_reboot::prepare_soft_reboot_composefs,
        state::write_composefs_state,
        status::{
            ImgConfigManifest, StagedDeployment, get_bootloader, get_composefs_status,
            get_container_manifest_and_config, get_imginfo,
        },
    },
    cli::{SoftRebootMode, UpgradeOpts},
    composefs_consts::{
        COMPOSEFS_STAGED_DEPLOYMENT_FNAME, COMPOSEFS_TRANSIENT_STATE_DIR, STATE_DIR_RELATIVE,
        TYPE1_ENT_PATH_STAGED, USER_CFG_STAGED,
    },
    spec::{Bootloader, Host, ImageReference},
    store::{BootedComposefs, ComposefsRepository, Storage},
};

/// Checks if a container image has been pulled to the local composefs repository.
///
/// This function verifies whether the specified container image exists in the local
/// composefs repository by checking if the image's configuration digest stream is
/// available. It retrieves the image manifest and configuration from the container
/// registry and uses the configuration digest to perform the local availability check.
///
/// # Arguments
///
/// * `repo` - The composefs repository
/// * `imgref` - Reference to the container image to check
///
/// # Returns
///
/// Returns a tuple containing:
/// * `Some<Sha512HashValue>` if the image is pulled/available locally, `None` otherwise
/// * The container image manifest
/// * The container image configuration
#[context("Checking if image {} is pulled", imgref.image)]
pub(crate) async fn is_image_pulled(
    repo: &ComposefsRepository,
    imgref: &ImageReference,
) -> Result<(Option<Sha512HashValue>, ImgConfigManifest)> {
    let imgref_repr = get_imgref(&imgref.transport, &imgref.image);
    let img_config_manifest = get_container_manifest_and_config(&imgref_repr).await?;

    let img_digest = img_config_manifest.manifest.config().digest().digest();

    // TODO: export config_identifier function from composefs-oci/src/lib.rs and use it here
    let img_id = format!("oci-config-sha256:{img_digest}");

    // NB: add deep checking?
    let container_pulled = repo.has_stream(&img_id).context("Checking stream")?;

    Ok((container_pulled, img_config_manifest))
}

fn rm_staged_type1_ent(boot_dir: &Dir) -> Result<()> {
    if boot_dir.exists(TYPE1_ENT_PATH_STAGED) {
        boot_dir
            .remove_dir_all(TYPE1_ENT_PATH_STAGED)
            .context("Removing staged bootloader entry")?;
    }

    Ok(())
}

#[derive(Debug)]
pub(crate) enum UpdateAction {
    /// Skip the update. We probably have the update in our deployments
    Skip,
    /// Proceed with the update
    Proceed,
    /// Only update the target imgref in the .origin file
    /// Will only be returned if the Operation is update and not switch
    UpdateOrigin,
}

/// Determines what action should be taken for the update
///
/// Cases:
///
/// - The verity is the same as that of the currently booted deployment
///
///    Nothing to do here as we're currently booted
///
/// - The verity is the same as that of the staged deployment
///
///    Nothing to do, as we only get a "staged" deployment if we have
///    /run/composefs/staged-deployment which is the last thing we create while upgrading
///
/// - The verity is the same as that of the rollback deployment
///
///    Nothing to do since this is a rollback deployment which means this was unstaged at some
///    point
///
/// - The verity is not found
///
///    The update/switch might've been canceled before /run/composefs/staged-deployment
///    was created, or at any other point in time, or it's a new one.
///    Any which way, we can overwrite everything
///
/// # Arguments
///
/// * `storage`       - The global storage object
/// * `booted_cfs`    - Reference to the booted composefs deployment
/// * `host`          - Object returned by `get_composefs_status`
/// * `img_digest`    - The SHA256 sum of the target image
/// * `config_verity` - The verity of the Image config splitstream
/// * `is_switch`     - Whether this is an update operation or a switch operation
///
/// # Returns
/// * UpdateAction::Skip         - Skip the update/switch as we have it as a deployment
/// * UpdateAction::UpdateOrigin - Just update the target imgref in the origin file
/// * UpdateAction::Proceed      - Proceed with the update
pub(crate) fn validate_update(
    storage: &Storage,
    booted_cfs: &BootedComposefs,
    host: &Host,
    img_digest: &str,
    config_verity: &Sha512HashValue,
    is_switch: bool,
) -> Result<UpdateAction> {
    let repo = &*booted_cfs.repo;

    let mut fs = create_filesystem(repo, img_digest, Some(config_verity))?;
    fs.transform_for_boot(&repo)?;

    let image_id = fs.compute_image_id();

    // Case1
    //
    // "update" image has the same verity as the one currently booted
    // This could be someone trying to `bootc switch <remote_image>` where
    // remote_image is the exact same image as the one currently booted, but
    // they are wanting to change the target
    // We just update the image origin file here
    //
    // If it's not a switch op, then we skip the update
    if image_id.to_hex() == *booted_cfs.cmdline.digest {
        let ret = if is_switch {
            UpdateAction::UpdateOrigin
        } else {
            UpdateAction::Skip
        };

        return Ok(ret);
    }

    let all_deployments = host.all_composefs_deployments()?;

    let found_depl = all_deployments
        .iter()
        .find(|d| d.deployment.verity == image_id.to_hex());

    // We have this in our deployments somewhere, i.e. Case 2 or 3
    if found_depl.is_some() {
        return Ok(UpdateAction::Skip);
    }

    let booted = host.require_composefs_booted()?;
    let boot_dir = storage.require_boot_dir()?;

    // Remove staged bootloader entries, if any
    // GC should take care of the UKI PEs and other binaries
    match get_bootloader()? {
        Bootloader::Grub => match booted.boot_type {
            BootType::Bls => rm_staged_type1_ent(boot_dir)?,

            BootType::Uki => {
                let grub = boot_dir.open_dir("grub2").context("Opening grub dir")?;

                if grub.exists(USER_CFG_STAGED) {
                    grub.remove_file(USER_CFG_STAGED)
                        .context("Removing staged grub user config")?;
                }
            }
        },

        Bootloader::Systemd => rm_staged_type1_ent(boot_dir)?,

        Bootloader::None => unreachable!("Checked at install time"),
    }

    // Remove state directory
    let state_dir = storage
        .physical_root
        .open_dir(STATE_DIR_RELATIVE)
        .context("Opening state dir")?;

    if state_dir.exists(image_id.to_hex()) {
        state_dir
            .remove_dir_all(image_id.to_hex())
            .context("Removing state")?;
    }

    Ok(UpdateAction::Proceed)
}

/// This is just an intersection of SwitchOpts and UpgradeOpts
pub(crate) struct DoUpgradeOpts {
    pub(crate) apply: bool,
    pub(crate) soft_reboot: Option<SoftRebootMode>,
    pub(crate) download_only: bool,
}

async fn apply_upgrade(
    storage: &Storage,
    booted_cfs: &BootedComposefs,
    depl_id: &String,
    opts: &DoUpgradeOpts,
) -> Result<()> {
    if let Some(soft_reboot_mode) = opts.soft_reboot {
        return prepare_soft_reboot_composefs(
            storage,
            booted_cfs,
            Some(depl_id),
            soft_reboot_mode,
            opts.apply,
        )
        .await;
    };

    if opts.apply {
        return crate::reboot::reboot();
    }

    Ok(())
}

/// Performs the Update or Switch operation
#[context("Performing Upgrade Operation")]
pub(crate) async fn do_upgrade(
    storage: &Storage,
    booted_cfs: &BootedComposefs,
    host: &Host,
    imgref: &ImageReference,
    img_manifest_config: &ImgConfigManifest,
    opts: &DoUpgradeOpts,
) -> Result<()> {
    start_finalize_stated_svc()?;

    let (repo, entries, id, fs) = pull_composefs_repo(&imgref.transport, &imgref.image).await?;

    let Some(entry) = entries.iter().next() else {
        anyhow::bail!("No boot entries!");
    };

    let mounted_fs = Dir::reopen_dir(
        &repo
            .mount(&id.to_hex())
            .context("Failed to mount composefs image")?,
    )?;

    let boot_type = BootType::from(entry);

    let boot_digest = match boot_type {
        BootType::Bls => setup_composefs_bls_boot(
            BootSetupType::Upgrade((storage, &fs, &host)),
            repo,
            &id,
            entry,
            &mounted_fs,
        )?,

        BootType::Uki => setup_composefs_uki_boot(
            BootSetupType::Upgrade((storage, &fs, &host)),
            repo,
            &id,
            entries,
        )?,
    };

    write_composefs_state(
        &Utf8PathBuf::from("/sysroot"),
        &id,
        imgref,
        Some(StagedDeployment {
            depl_id: id.to_hex(),
            finalization_locked: opts.download_only,
        }),
        boot_type,
        boot_digest,
        img_manifest_config,
    )
    .await?;

    apply_upgrade(storage, booted_cfs, &id.to_hex(), opts).await
}

#[context("Upgrading composefs")]
pub(crate) async fn upgrade_composefs(
    opts: UpgradeOpts,
    storage: &Storage,
    composefs: &BootedComposefs,
) -> Result<()> {
    let host = get_composefs_status(storage, composefs)
        .await
        .context("Getting composefs deployment status")?;

    let do_upgrade_opts = DoUpgradeOpts {
        soft_reboot: opts.soft_reboot,
        apply: opts.apply,
        download_only: opts.download_only,
    };

    if opts.from_downloaded {
        let staged = host
            .status
            .staged
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No staged deployment found"))?;

        // Staged deployment exists, but it will be finalized
        if !staged.download_only {
            println!("Staged deployment is present and not in download only mode.");
            println!("Use `bootc update --apply` to apply the update.");
            return Ok(());
        }

        start_finalize_stated_svc()?;

        // Make the staged deployment not download_only
        let new_staged = StagedDeployment {
            depl_id: staged.require_composefs()?.verity.clone(),
            finalization_locked: false,
        };

        let staged_depl_dir =
            Dir::open_ambient_dir(COMPOSEFS_TRANSIENT_STATE_DIR, ambient_authority())
                .context("Opening transient state directory")?;

        staged_depl_dir
            .atomic_replace_with(
                COMPOSEFS_STAGED_DEPLOYMENT_FNAME,
                |f| -> std::io::Result<()> {
                    serde_json::to_writer(f, &new_staged).map_err(std::io::Error::from)
                },
            )
            .context("Writing staged file")?;

        return apply_upgrade(
            storage,
            composefs,
            &staged.require_composefs()?.verity,
            &do_upgrade_opts,
        )
        .await;
    }

    let mut booted_imgref = host
        .spec
        .image
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No image source specified"))?;

    let repo = &*composefs.repo;

    let (img_pulled, mut img_config) = is_image_pulled(&repo, booted_imgref).await?;
    let booted_img_digest = img_config.manifest.config().digest().digest().to_owned();

    // Check if we already have this update staged
    // Or if we have another staged deployment with a different image
    let staged_image = host.status.staged.as_ref().and_then(|i| i.image.as_ref());

    if let Some(staged_image) = staged_image {
        // We have a staged image and it has the same digest as the currently booted image's latest
        // digest
        if staged_image.image_digest == booted_img_digest {
            if opts.apply {
                return crate::reboot::reboot();
            }

            println!("Update already staged. To apply update run `bootc update --apply`");

            return Ok(());
        }

        // We have a staged image but it's not the update image.
        // Maybe it's something we got by `bootc switch`
        // Switch takes precedence over update, so we change the imgref
        booted_imgref = &staged_image.image;

        let (img_pulled, staged_img_config) = is_image_pulled(&repo, booted_imgref).await?;
        img_config = staged_img_config;

        if let Some(cfg_verity) = img_pulled {
            let action = validate_update(
                storage,
                composefs,
                &host,
                img_config.manifest.config().digest().digest(),
                &cfg_verity,
                false,
            )?;

            match action {
                UpdateAction::Skip => {
                    println!("No changes in staged image: {booted_imgref:#}");
                    return Ok(());
                }

                UpdateAction::Proceed => {
                    return do_upgrade(
                        storage,
                        composefs,
                        &host,
                        booted_imgref,
                        &img_config,
                        &do_upgrade_opts,
                    )
                    .await;
                }

                UpdateAction::UpdateOrigin => {
                    anyhow::bail!("Updating origin not supported for update operation")
                }
            }
        }
    }

    // We already have this container config
    if let Some(cfg_verity) = img_pulled {
        let action = validate_update(
            storage,
            composefs,
            &host,
            &booted_img_digest,
            &cfg_verity,
            false,
        )?;

        match action {
            UpdateAction::Skip => {
                println!("No changes in: {booted_imgref:#}");
                return Ok(());
            }

            UpdateAction::Proceed => {
                return do_upgrade(
                    storage,
                    composefs,
                    &host,
                    booted_imgref,
                    &img_config,
                    &do_upgrade_opts,
                )
                .await;
            }

            UpdateAction::UpdateOrigin => {
                anyhow::bail!("Updating origin not supported for update operation")
            }
        }
    }

    if opts.check {
        let current_manifest =
            get_imginfo(storage, &*composefs.cmdline.digest, Some(booted_imgref)).await?;
        let diff = ManifestDiff::new(&current_manifest.manifest, &img_config.manifest);
        diff.print();
        return Ok(());
    }

    do_upgrade(
        storage,
        composefs,
        &host,
        booted_imgref,
        &img_config,
        &do_upgrade_opts,
    )
    .await?;

    Ok(())
}
