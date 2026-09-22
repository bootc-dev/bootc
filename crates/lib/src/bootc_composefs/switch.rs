use anyhow::{Context, Result};
use fn_error_context::context;

use crate::{
    bootc_composefs::{
        status::get_composefs_status,
        update::{
            DoUpgradeOpts, UpdateAction, apply_upgrade_from_downloaded, do_upgrade,
            ensure_delta_source_present, is_image_pulled, lookup_config_splitstream,
            validate_update,
        },
    },
    cli::{SwitchOpts, imgref_for_switch},
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
    let host = get_composefs_status(storage, booted_cfs)
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
    };

    if opts.download_opts.from_downloaded {
        return apply_upgrade_from_downloaded(storage, booted_cfs, &host, &do_upgrade_opts).await;
    }

    let target = imgref_for_switch(&opts)?;
    if let Some(delta) = delta.as_ref() {
        delta.validate_image_reference(&target)?;
    }

    let new_spec = {
        let mut new_spec = host.spec.clone();
        new_spec.image = Some(target.clone());
        new_spec
    };

    if new_spec == host.spec {
        println!("Image specification is unchanged.");
        if opts.apply && host.status.staged.is_some() {
            crate::reboot::reboot()?;
        }
        return Ok(());
    }

    let Some(target_imgref) = new_spec.image else {
        anyhow::bail!("Target image is undefined")
    };

    const COMPOSEFS_SWITCH_JOURNAL_ID: &str = "7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1";

    tracing::info!(
        message_id = COMPOSEFS_SWITCH_JOURNAL_ID,
        bootc.operation = "switch",
        bootc.target_image = target_imgref.to_string(),
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
            crate::deploy::image_exists_in_unified_storage(storage, &target_imgref).await?;
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
            let (image, img_config, _) = is_image_pulled(repo, &target_imgref).await?;
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
                println!("No changes in image: {target_imgref:#}");
                return Ok(());
            }

            UpdateAction::Proceed => {
                return do_upgrade(
                    storage,
                    booted_cfs,
                    &host,
                    &target_imgref,
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
        &target_imgref,
        &do_upgrade_opts,
        &manifest,
    )
    .await?;

    Ok(())
}
