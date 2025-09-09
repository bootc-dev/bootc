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
    cli::{imgref_for_switch, SwitchOpts},
};

#[context("Composefs Switching")]
pub(crate) async fn switch_composefs(opts: SwitchOpts) -> Result<()> {
    let target = imgref_for_switch(&opts)?;
    // TODO: Handle in-place

    let host = composefs_deployment_status()
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

    let (repo, entries, id, fs) =
        pull_composefs_repo(&"docker".into(), &target_imgref.image).await?;

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
        &target_imgref,
        true,
        boot_type,
        boot_digest,
    )?;

    Ok(())
}
