use crate::{
    bootc_composefs::{
        boot::{SYSTEMD_UKI_DIR, compute_boot_digest_uki},
        state::update_boot_digest_in_origin,
    },
    store::Storage,
};
use anyhow::Result;
use bootc_kernel_cmdline::utf8::Cmdline;
use fn_error_context::context;

fn get_uki(storage: &Storage, deployment_verity: &str) -> Result<Vec<u8>> {
    let uki_dir = storage
        .esp
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("ESP not mounted"))?
        .fd
        .open_dir(SYSTEMD_UKI_DIR)?;

    let req_fname = format!("{deployment_verity}.efi");

    for entry in uki_dir.entries_utf8()? {
        let pe = entry?;

        let filename = pe.file_name()?;

        if filename != req_fname {
            continue;
        }

        return Ok(uki_dir.read(filename)?);
    }

    anyhow::bail!("UKI for deployment {deployment_verity} not found")
}

#[context("Computing and storing boot digest for UKI")]
pub(crate) fn compute_store_boot_digest_for_uki(
    storage: &Storage,
    deployment_verity: &str,
) -> Result<String> {
    let uki = get_uki(storage, deployment_verity)?;
    let digest = compute_boot_digest_uki(&uki)?;

    update_boot_digest_in_origin(storage, &deployment_verity, &digest)?;
    return Ok(digest);
}

#[context("Getting UKI cmdline")]
pub(crate) fn get_uki_cmdline(
    storage: &Storage,
    deployment_verity: &str,
) -> Result<Cmdline<'static>> {
    let uki = get_uki(storage, deployment_verity)?;
    let cmdline = composefs_boot::uki::get_cmdline(&uki)?;

    return Ok(Cmdline::from(cmdline.to_owned()));
}
