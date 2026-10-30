use anyhow::{Context, Result};
use fn_error_context::context;

use crate::{
    bootc_composefs::{
        status::get_composefs_status,
        update::{
            DoUpgradeOpts, UpdateAction, apply_upgrade_from_downloaded,
            discard_failed_aboot_update, do_upgrade, ensure_delta_source_present, is_image_pulled,
            lookup_config_splitstream, validate_update,
        },
    },
    cli::{
        SwitchOpts, handle_unchanged_switch, imgref_for_switch, switch_images_unchanged,
        target_imgref_for_switch,
    },
    progress_jsonl::ProgressWriter,
    store::{BootedComposefs, Storage},
};

#[context("Composefs Switching")]
pub(crate) async fn switch_composefs(
    opts: SwitchOpts,
    storage: &Storage,
    booted_cfs: &BootedComposefs,
) -> Result<()> {
    // TODO: Handle in-place
    let mut host = get_composefs_status(storage, booted_cfs)
        .await
        .context("Getting composefs deployment status")?;

    let delta = crate::delta::open_opt(opts.from_delta.as_deref()).await?;

    let prog: ProgressWriter = opts.progress.clone().try_into()?;

    let mut do_upgrade_opts = DoUpgradeOpts {
        soft_reboot: opts.soft_reboot,
        apply: opts.apply,
        download_only: opts.download_opts.download_only,
        use_unified: false,
        quiet: opts.quiet,
        prog,
        delta: delta.as_ref(),
        uki_addon_opts: opts.uki_addon_opts.clone(),
    };

    if opts.download_opts.from_downloaded {
        return apply_upgrade_from_downloaded(storage, booted_cfs, &host, &do_upgrade_opts).await;
    }

    if opts.target_imgref.is_some() && opts.enforce_container_sigpolicy {
        // Parsing a signed reference does not enforce its policy in the composefs pull path.
        anyhow::bail!(
            "--target-imgref with --enforce-container-sigpolicy is not supported by the composefs backend"
        );
    }

    let source = imgref_for_switch(&opts)?;
    let target = target_imgref_for_switch(&opts)?;
    let origin = target.as_ref().unwrap_or(&source);
    if let Some(delta) = delta.as_ref() {
        delta.validate_image_reference(&source)?;
    }

    // There may be an existing failed update with the same update origin, and
    // in that case we don't want the "nothing changed" check below to trigger.
    // Instead we want to discard the failed attempt and redo the update.
    let failed_target_matches = host
        .status
        .staged
        .as_ref()
        .and_then(|entry| entry.image.as_ref())
        .is_some_and(|image| &image.image == origin);
    let discarded_failed_update = discard_failed_aboot_update(storage, &host)?;
    if discarded_failed_update {
        // Refresh host to skip discarded update
        host = get_composefs_status(storage, booted_cfs).await?;
    }
    let retry_failed_target = discarded_failed_update && failed_target_matches;

    let current = host
        .status
        .staged
        .as_ref()
        .or(host.status.booted.as_ref())
        .context("No current deployment")?;
    let current_origin = host
        .spec
        .image
        .as_ref()
        .context("No image for current deployment")?;
    let current_delivery_source = if target.is_some() && origin == current_origin {
        let current_origin_file = super::state::read_origin(
            &storage.physical_root,
            &current.require_composefs()?.verity,
        )?
        .context("No origin for current deployment")?;
        current_origin_file
            .get::<String>(
                crate::deploy::ORIGIN_BOOTC,
                crate::deploy::ORIGIN_SOURCE_IMAGE,
            )
            .map(|source| {
                source
                    .parse::<ostree_ext::container::OstreeImageReference>()
                    .map(crate::spec::ImageReference::from)
            })
            .transpose()
            .context("Parsing current deployment's delivery source")?
    } else {
        None
    };
    if !retry_failed_target
        && switch_images_unchanged(
            &source,
            target.as_ref(),
            current_origin,
            current_delivery_source.as_ref(),
        )?
    {
        return handle_unchanged_switch(&opts, &host);
    }

    const COMPOSEFS_SWITCH_JOURNAL_ID: &str = "7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1";

    tracing::info!(
        message_id = COMPOSEFS_SWITCH_JOURNAL_ID,
        bootc.operation = "switch",
        bootc.target_image = origin.to_string(),
        bootc.source_image = source.to_string(),
        bootc.apply_mode = opts.apply,
        bootc.download_only = opts.download_opts.download_only,
        bootc.from_downloaded = opts.download_opts.from_downloaded,
        "Starting composefs switch operation",
    );

    let repo = &*booted_cfs.repo;

    // Use unified storage if explicitly requested, or auto-detect: either the
    // target image is already in bootc-owned containers-storage, OR the booted
    // image is — which means the user has opted into unified storage and all
    // subsequent operations (including switch to a new image) should use it.
    do_upgrade_opts.use_unified = if opts.unified_storage_exp {
        true
    } else {
        let booted_imgref = host.spec.image.as_ref();
        let booted_unified = if let Some(booted) = booted_imgref {
            crate::deploy::image_exists_in_unified_storage(storage, booted).await?
        } else {
            false
        };
        let target_unified =
            crate::deploy::image_exists_in_unified_storage(storage, &source).await?;
        booted_unified || target_unified
    };

    // With a delta the target is whatever the delta says it is, and we can look
    // it up locally; without one we have to ask the registry.
    let (image, manifest) = match &delta {
        Some(delta) => {
            crate::delta::reject_unified_storage(delta, do_upgrade_opts.use_unified)?;
            ensure_delta_source_present(repo, delta)?;
            (
                lookup_config_splitstream(repo, delta.target_manifest().config().digest())?,
                delta.target_manifest().clone(),
            )
        }
        None => {
            let (image, img_config, _) = is_image_pulled(repo, &source).await?;
            (image, img_config.manifest)
        }
    };

    if let Some(cfg_verity) = image {
        let action = validate_update(
            storage,
            booted_cfs,
            &host,
            manifest.config().digest().as_ref(),
            &cfg_verity,
            true,
        )?;

        match action {
            UpdateAction::Skip => {
                println!("No changes in image: {source:#}");
                return Ok(());
            }

            UpdateAction::Proceed => {
                return do_upgrade(
                    storage,
                    booted_cfs,
                    &host,
                    &source,
                    target.as_ref(),
                    &do_upgrade_opts,
                    &manifest,
                )
                .await;
            }
        }
    }

    do_upgrade(
        storage,
        booted_cfs,
        &host,
        &source,
        target.as_ref(),
        &do_upgrade_opts,
        &manifest,
    )
    .await?;

    Ok(())
}
