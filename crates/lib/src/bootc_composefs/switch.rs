use anyhow::{Context, Result};
use camino::Utf8PathBuf;
use cap_std_ext::cap_std::fs::Dir;
use composefs::fsverity::FsVerityHashValue;
use fn_error_context::context;

use crate::{
    bootc_composefs::{
        boot::{setup_composefs_bls_boot, setup_composefs_uki_boot, BootSetupType, BootType},
        repo::pull_composefs_repo,
        service::start_finalize_stated_svc,
        state::write_composefs_state,
        status::get_composefs_status,
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

    start_finalize_stated_svc()?;

    let (repo, entries, id, fs) =
        pull_composefs_repo(&target_imgref.transport, &target_imgref.image).await?;

    let Some(entry) = entries.iter().next() else {
        anyhow::bail!("No boot entries!");
    };

    let boot_type = BootType::from(entry);
    let mut boot_digest = None;

    let mounted_fs = Dir::reopen_dir(
        &repo
            .mount(&id.to_hex())
            .context("Failed to mount composefs image")?,
    )?;

    match boot_type {
        BootType::Bls => {
            boot_digest = Some(setup_composefs_bls_boot(
                BootSetupType::Upgrade((storage, &fs, &host)),
                repo,
                &id,
                entry,
                &mounted_fs,
            )?)
        }
        BootType::Uki => setup_composefs_uki_boot(
            BootSetupType::Upgrade((storage, &fs, &host)),
            repo,
            &id,
            entries,
        )?,
    };

    // TODO: Remove this hardcoded path when write_composefs_state accepts a Dir
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
