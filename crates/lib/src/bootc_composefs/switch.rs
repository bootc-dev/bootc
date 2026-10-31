use anyhow::{Context, Result};
use fn_error_context::context;
use ostree_ext::oci_spec::image::Digest;

use crate::{
    bootc_composefs::{
        status::get_composefs_status,
        update::{
            DoUpgradeOpts, UpdateAction, apply_upgrade_from_downloaded, do_upgrade,
            ensure_delta_source_present, is_image_pulled, lookup_config_splitstream,
            validate_update,
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
        uki_addon_opts: opts.uki_addon_opts.clone(),
    };

    if opts.download_opts.from_downloaded {
        return apply_upgrade_from_downloaded(storage, booted_cfs, &host, &do_upgrade_opts).await;
    }

    anyhow::ensure!(
        opts.target_imgref.is_none() || !opts.enforce_container_sigpolicy,
        "--target-imgref with --enforce-container-sigpolicy is not supported by the composefs backend"
    );

    let source = imgref_for_switch(&opts)?;
    let final_target_imgref = target_imgref_for_switch(&opts)?;
    let origin = final_target_imgref.as_ref().unwrap_or(&source);
    if let Some(delta) = delta.as_ref() {
        delta.validate_image_reference(&source)?;
    }

    let current = host
        .status
        .staged
        .as_ref()
        .or(host.status.booted.as_ref())
        .context("No current deployment")?;
    let current_origin =
        super::state::read_origin(&storage.physical_root, &current.require_composefs()?.verity)?
            .context("No origin for current deployment")?;
    let pending = super::origin::OriginChange::read_active(&storage.physical_root, &host)?;
    let previous_source = pending.as_ref().map(|p| p.source.to_string()).or_else(|| {
        current_origin.get::<String>(
            crate::deploy::ORIGIN_BOOTC,
            crate::deploy::ORIGIN_SOURCE_IMAGE,
        )
    });
    if switch_images_unchanged(
        &source,
        final_target_imgref.as_ref(),
        host.spec.image.as_ref(),
        previous_source.as_deref(),
    )? {
        if let Some(pending) = pending {
            if super::origin::should_reboot(
                opts.soft_reboot,
                opts.apply,
                pending.finalization_locked,
            )? {
                crate::reboot::reboot()?;
            }
            println!("Image specification is unchanged.");
            return Ok(());
        }
        return handle_unchanged_switch(&opts, &host);
    }

    let target_imgref = &source;

    const COMPOSEFS_SWITCH_JOURNAL_ID: &str = "7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1";

    tracing::info!(
        message_id = COMPOSEFS_SWITCH_JOURNAL_ID,
        bootc.operation = "switch",
        bootc.target_image = origin.to_string(),
        bootc.source_image = target_imgref.to_string(),
        bootc.apply_mode = opts.apply,
        bootc.download_only = opts.download_opts.download_only,
        bootc.from_downloaded = opts.download_opts.from_downloaded,
        "Starting composefs switch operation",
    );

    let repo = &*booted_cfs.repo;

    // Preserve unified storage across switches, including when the current
    // deployment's origin differs from its name in containers-storage.
    do_upgrade_opts.use_unified = if opts.unified_storage_exp {
        true
    } else {
        let booted_unified = crate::deploy::deployment_uses_unified_storage(
            storage,
            host.status.staged.as_ref().or(host.status.booted.as_ref()),
        )
        .await?;
        let target_unified =
            crate::deploy::image_exists_in_unified_storage(storage, target_imgref).await?;
        booted_unified || target_unified
    };

    // With a delta the target is whatever the delta says it is, and we can look
    // it up locally; without one we have to ask the registry.
    let (image, manifest, manifest_digest) = match &delta {
        Some(delta) => {
            crate::delta::reject_unified_storage(delta, do_upgrade_opts.use_unified)?;
            ensure_delta_source_present(repo, delta)?;
            (
                lookup_config_splitstream(repo, delta.target_manifest().config().digest())?,
                delta.target_manifest().clone(),
                delta.target_manifest_digest().to_string(),
            )
        }
        None => {
            let (image, img_config, digest) = is_image_pulled(repo, target_imgref).await?;
            (image, img_config.manifest, digest)
        }
    };

    if final_target_imgref.is_some()
        && switch_origin(
            storage,
            &host,
            &source,
            origin,
            &manifest_digest.parse().context("Parsing manifest digest")?,
            &do_upgrade_opts,
        )?
    {
        return Ok(());
    }

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
                    target_imgref,
                    final_target_imgref.as_ref(),
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
        target_imgref,
        final_target_imgref.as_ref(),
        &do_upgrade_opts,
        &manifest,
    )
    .await?;

    Ok(())
}

/// Reuse only an identical OCI image, never just an identical composefs root.
/// Different manifests can share a root while providing different initial /etc
/// content; those still go through do_upgrade's collision check.
fn switch_origin(
    storage: &Storage,
    host: &crate::spec::Host,
    source: &crate::spec::ImageReference,
    target: &crate::spec::ImageReference,
    manifest_digest: &Digest,
    opts: &DoUpgradeOpts<'_>,
) -> Result<bool> {
    let same_image = |entry: &&crate::spec::BootEntry| {
        entry
            .image
            .as_ref()
            .is_some_and(|image| image.image_digest == manifest_digest.as_ref())
    };
    let entry = host
        .status
        .staged
        .as_ref()
        .filter(same_image)
        .or_else(|| host.status.booted.as_ref().filter(same_image));
    let Some(entry) = entry else { return Ok(false) };
    anyhow::ensure!(
        opts.uki_addon_opts.scoped.is_none() && opts.uki_addon_opts.global.is_none(),
        "Cannot install UKI addons with an origin-only change"
    );
    anyhow::ensure!(
        !host.status.rollback_queued,
        "Cannot change origin while rollback is queued"
    );
    let locked = entry.download_only || opts.download_only;
    let reboot = super::origin::should_reboot(opts.soft_reboot, opts.apply, locked)?;
    let deployment = &entry.require_composefs()?.verity;
    super::service::start_finalize_stated_svc()?;
    if deployment == &host.require_composefs_booted()?.verity {
        if host.require_composefs_booted()?.boot_type == super::boot::BootType::Aboot {
            super::update::ensure_no_aboot_attempt(storage)?;
        }
        let pending = super::origin::OriginChange::new(
            &storage.physical_root,
            host,
            manifest_digest,
            source,
            target,
            locked,
        )?;
        pending.write(&storage.physical_root)?;
    } else {
        // This is a genuine staged deployment. Do not rewrite state also used
        // by a rollback or pinned deployment.
        anyhow::ensure!(
            host.all_composefs_deployments()?.iter().all(|d| {
                d.deployment.verity != *deployment
                    || (matches!(d.ty, Some(crate::status::Slot::Staged)) && !d.pinned)
            }),
            "Origin change would modify another deployment"
        );
        super::update::set_staged_lock(storage, entry, locked)?;
        let old = super::state::read_origin(&storage.physical_root, deployment)?
            .context("No staged origin")?;
        let origin = super::state::with_image_references(old, Some(source), target)?;
        super::state::write_origin(&storage.physical_root, deployment, &origin)?;
    }
    println!("Staged update origin: {target}");
    if reboot {
        crate::reboot::reboot()?;
    }
    Ok(true)
}
