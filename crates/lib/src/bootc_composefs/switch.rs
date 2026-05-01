use anyhow::{Context, Result};
use fn_error_context::context;

use crate::{
    bootc_composefs::{
        status::get_composefs_status,
        update::{DoUpgradeOpts, UpdateAction, do_upgrade, is_image_pulled, validate_update},
    },
    cli::{SwitchOpts, imgref_for_switch},
    store::{BootedComposefs, Storage},
};

#[context("Composefs Switching")]
pub(crate) async fn switch_composefs(
    opts: SwitchOpts,
    storage: &Storage,
    booted_cfs: &BootedComposefs,
) -> Result<()> {
    let target = imgref_for_switch(&opts)?;

    // TODO: Handle in-place
    let host = get_composefs_status(storage, booted_cfs)
        .await
        .context("Getting composefs deployment status")?;

    let new_spec = {
        let mut new_spec = host.spec.clone();
        new_spec.image = Some(target.clone());
        new_spec
    };

    if new_spec == host.spec {
        println!("Image specification is unchanged.");
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
        "Starting composefs switch operation",
    );

    let repo = &*booted_cfs.repo;
    let (image, img_config) = is_image_pulled(repo, &target_imgref).await?;

    // Use unified storage if explicitly requested, or auto-detect: either the
    // target image is already in bootc-owned containers-storage, OR the booted
    // image is — which means the user has opted into unified storage and all
    // subsequent operations (including switch to a new image) should use it.
    let use_unified = if opts.unified_storage_exp {
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

    let do_upgrade_opts = DoUpgradeOpts {
        soft_reboot: opts.soft_reboot,
        apply: opts.apply,
        download_only: false,
        use_unified,
    };

    if let Some(cfg_verity) = image {
        let action = validate_update(
            storage,
            booted_cfs,
            &host,
            img_config.manifest.config().digest().as_ref(),
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
                    &img_config.manifest,
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
        &img_config.manifest,
    )
    .await?;

    Ok(())
}
