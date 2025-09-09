use anyhow::{Context, Result};
use camino::Utf8PathBuf;
use fn_error_context::context;

use crate::{
    bootc_composefs::{
        boot::{setup_composefs_bls_boot, setup_composefs_uki_boot, BootSetupType, BootType},
        repo::pull_composefs_repo,
        state::write_composefs_state,
        status::composefs_deployment_status,
    },
    cli::UpgradeOpts,
};

#[context("Upgrading composefs")]
pub(crate) async fn upgrade_composefs(_opts: UpgradeOpts) -> Result<()> {
    // TODO: IMPORTANT Have all the checks here that `bootc upgrade` has for an ostree booted system

    let host = composefs_deployment_status()
        .await
        .context("Getting composefs deployment status")?;

    // TODO: IMPORTANT We need to check if any deployment is staged and get the image from that
    let imgref = host
        .spec
        .image
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No image source specified"))?;

    let (repo, entries, id, fs) = pull_composefs_repo(&imgref.transport, &imgref.image).await?;

    let Some(entry) = entries.into_iter().next() else {
        anyhow::bail!("No boot entries!");
    };

    let boot_type = BootType::from(&entry);
    let mut boot_digest = None;

    match boot_type {
        BootType::Bls => {
            boot_digest = Some(setup_composefs_bls_boot(
                BootSetupType::Upgrade((&fs, &host)),
                repo,
                &id,
                entry,
            )?)
        }

        BootType::Uki => {
            setup_composefs_uki_boot(BootSetupType::Upgrade((&fs, &host)), repo, &id, entry)?
        }
    };

    write_composefs_state(
        &Utf8PathBuf::from("/sysroot"),
        id,
        imgref,
        true,
        boot_type,
        boot_digest,
    )?;

    Ok(())
}
