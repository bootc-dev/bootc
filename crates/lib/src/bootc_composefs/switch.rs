use anyhow::{Context, Result};
use fn_error_context::context;

use crate::{
    bootc_composefs::{
        status::get_composefs_status,
        update::{
            DoUpgradeOpts, UpdateAction, apply_upgrade_from_downloaded, do_upgrade,
            is_image_pulled, validate_update,
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

    let prog: ProgressWriter = opts.progress.clone().try_into()?;

    let mut do_upgrade_opts = DoUpgradeOpts {
        soft_reboot: opts.soft_reboot,
        apply: opts.apply,
        download_only: opts.download_opts.download_only,
        use_unified: false,
        quiet: opts.quiet,
        prog,
        origin_override: None,
    };

    if opts.download_opts.from_downloaded {
        return apply_upgrade_from_downloaded(storage, booted_cfs, &host, &do_upgrade_opts).await;
    }

    // The source we fetch the image from now.
    let source = imgref_for_switch(&opts)?;
    // Optional decoupled reference to persist as the origin for future upgrades
    // (`--target-imgref`, issue #2464). `None` means source and origin coincide.
    let origin_override =
        crate::cli::target_imgref_for_switch(&opts)?.map(crate::spec::ImageReference::from);

    let new_spec = {
        let mut new_spec = host.spec.clone();
        new_spec.image = Some(origin_override.clone().unwrap_or_else(|| source.clone()));
        new_spec
    };

    // Only take the unchanged fast path when the pull source is also the origin.
    // With `--target-imgref` the source is decoupled from the persisted origin, so a
    // switch from a different source keeping the same origin (issue #2464) must still
    // run the pull even though `new_spec == host.spec`.
    if origin_override.is_none() && new_spec == host.spec {
        println!("Image specification is unchanged.");
        if opts.apply && host.status.staged.is_some() {
            crate::reboot::reboot()?;
        }
        return Ok(());
    }

    // Persist the decoupled origin (if any); everything below pulls and validates
    // against the source image.
    do_upgrade_opts.origin_override = origin_override;
    let target_imgref = source;

    const COMPOSEFS_SWITCH_JOURNAL_ID: &str = "7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1";

    // With `--target-imgref` the persisted origin is decoupled from the pull
    // source, so record both (mirroring the ostree path's journal fields).
    let origin_image = do_upgrade_opts
        .origin_override
        .as_ref()
        .unwrap_or(&target_imgref);

    tracing::info!(
        message_id = COMPOSEFS_SWITCH_JOURNAL_ID,
        bootc.operation = "switch",
        bootc.source_image = target_imgref.to_string(),
        bootc.target_image = origin_image.to_string(),
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

    let (image, img_config) = is_image_pulled(repo, &target_imgref).await?;

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
