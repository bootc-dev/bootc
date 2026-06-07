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

    const COMPOSEFS_SWITCH_JOURNAL_ID: &str = "087ccc03481a477b83c0f6ba62500724";

    tracing::info!(
        message_id = COMPOSEFS_SWITCH_JOURNAL_ID,
        bootc.operation = "switch",
        bootc.target_image = target_imgref.to_string(),
        bootc.apply_mode = opts.apply,
        "Starting composefs switch operation",
    );

    let repo = &*booted_cfs.repo;
    let (image, img_config) = is_image_pulled(repo, &target_imgref).await?;

    // Use unified storage if explicitly requested via flag, or if the
    // composefs/bootc.json marker says unified storage is enabled on this system.
    //
    // Note: the native composefs backend intentionally reads the containers-storage
    // participation signal (unified_storage_enabled) rather than binding_state().
    // On the native backend there is no ostree repo so binding_state() would always
    // return Disabled — we gate on cstorage participation, not the ostree binding.
    let use_unified = opts.unified_storage_exp
        || crate::deploy::unified_storage_enabled(storage)
            .context("Checking unified storage flag")?;

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
