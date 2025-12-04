use anyhow::{Context, Result};
use fn_error_context::context;

use crate::{
    bootc_composefs::{
        state::update_target_imgref_in_origin,
        status::get_composefs_status,
        update::{do_upgrade, is_image_pulled, validate_update, DoUpgradeOpts, UpdateAction},
    },
    cli::{imgref_for_switch, SwitchOpts},
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

    let repo = &*booted_cfs.repo;
    let (image, img_config) = is_image_pulled(repo, &target_imgref).await?;

    let do_upgrade_opts = DoUpgradeOpts {
        soft_reboot: opts.soft_reboot,
        apply: opts.apply,
    };

    if let Some(cfg_verity) = image {
        let action = validate_update(
            storage,
            booted_cfs,
            &host,
            img_config.manifest.config().digest().digest(),
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
                    &img_config,
                    &do_upgrade_opts,
                )
                .await;
            }

            UpdateAction::UpdateOrigin => {
                // The staged image will never be the current image's verity digest
                println!("Image already in composefs repository");
                println!("Updating target image reference");
                return update_target_imgref_in_origin(storage, booted_cfs, &target_imgref);
            }
        }
    }

    do_upgrade(
        storage,
        booted_cfs,
        &host,
        &target_imgref,
        &img_config,
        &do_upgrade_opts,
    )
    .await?;

    Ok(())
}
