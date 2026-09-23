use crate::{
    bootc_composefs::{
        boot::{BOOTC_UKI_DIR, compute_boot_digest_uki, get_uki_name},
        state::update_boot_digest_in_origin,
    },
    composefs_consts::{BLS_ENTRY_PREFIX, TYPE1_ENT_PATH},
    store::Storage,
};
use anyhow::Result;
use cap_std_ext::cap_std::fs::Dir;
use composefs_ctl::composefs_boot;
use fn_error_context::context;
use linux_kernel_cmdline::utf8::Cmdline;

fn get_uki(storage: &Storage, deployment_verity: &str) -> Result<cap_std_ext::cap_std::fs::File> {
    let uki_dir = storage.require_esp()?.fd.open_dir(BOOTC_UKI_DIR)?;

    let req_fname = get_uki_name(deployment_verity);

    for entry in uki_dir.entries_utf8()? {
        let pe = entry?;

        let filename = pe.file_name()?;

        if filename != req_fname {
            continue;
        }

        return Ok(uki_dir.open(filename)?);
    }

    anyhow::bail!("UKI for deployment {deployment_verity} not found")
}

#[context("Computing and storing boot digest for UKI")]
pub(crate) fn compute_store_boot_digest_for_uki(
    storage: &Storage,
    deployment_verity: &str,
) -> Result<String> {
    let mut uki = get_uki(storage, deployment_verity)?;
    let digest = compute_boot_digest_uki(&mut uki)?;

    update_boot_digest_in_origin(storage, &deployment_verity, &digest)?;
    return Ok(digest);
}

#[context("Getting UKI cmdline")]
pub(crate) fn get_uki_cmdline(
    storage: &Storage,
    deployment_verity: &str,
) -> Result<Cmdline<'static>> {
    let mut uki = get_uki(storage, deployment_verity)?;
    let cmdline = composefs_boot::uki::get_cmdline_buffered(&mut uki)?;

    return Ok(Cmdline::from(cmdline.to_owned()));
}

#[context("Staging non-managed BLS entry")]
pub(crate) fn stage_non_manged_bls_entries(boot_dir: &Dir, staged_entries: &Dir) -> Result<()> {
    let original_entries = boot_dir.open_dir(TYPE1_ENT_PATH)?;
    for entry in original_entries.entries_utf8()? {
        let entry = entry?;
        let entry_name = entry.file_name()?;
        if entry.file_type()?.is_file() && !entry_name.starts_with(BLS_ENTRY_PREFIX) {
            original_entries.copy(entry_name.clone(), staged_entries, entry_name)?;
        }
    }
    Ok(())
}
