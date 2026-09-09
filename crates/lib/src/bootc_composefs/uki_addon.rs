#![allow(dead_code)]
use anyhow::{Context, Result};
use cap_std_ext::cap_std::fs::Dir;
use cap_std_ext::dirext::CapStdExtDirExt;
use fn_error_context::context;
use ostree_ext::composefs_boot::bootloader::{EFI_ADDON_DIR_EXT, EFI_ADDON_FILE_EXT};

use crate::{
    bootc_composefs::boot::{BOOTC_UKI_DIR, GLOBAL_UKI_ADDONS_DIR},
    composefs_consts::UKI_NAME_PREFIX,
    store::{BootedComposefs, Storage},
};

#[derive(Debug, Clone)]
pub enum UkiAddonType {
    Scoped { depl_id: String },
    Global,
}

#[derive(Debug, Clone)]
pub struct UkiAddonsList {
    pub name: String,
    pub addon_type: UkiAddonType,
}

fn gather_addons_from_dir(
    dir: &Dir,
    addons: &mut Vec<UkiAddonsList>,
    addon_type: UkiAddonType,
) -> Result<()> {
    for ent in dir.entries_utf8()? {
        let ent = ent?;
        let filename = ent.file_name()?;

        if let Some(addon_name) = filename.strip_suffix(EFI_ADDON_FILE_EXT) {
            addons.push(UkiAddonsList {
                name: addon_name.to_string(),
                addon_type: addon_type.clone(),
            });
        };
    }

    Ok(())
}

#[context("Listing UKI Addons")]
pub fn list_installed_uki_addons(
    storage: &Storage,
    booted_composefs: &BootedComposefs,
) -> Result<Vec<UkiAddonsList>> {
    let mut addons = vec![];

    let Ok(esp) = storage.require_esp() else {
        return Ok(addons);
    };

    if let Some(global_dir) = esp.fd.open_dir_optional(GLOBAL_UKI_ADDONS_DIR)? {
        gather_addons_from_dir(&global_dir, &mut addons, UkiAddonType::Global)?;
    };

    for ent in esp
        .fd
        .open_dir(BOOTC_UKI_DIR)
        .context("Opening UKI dir")?
        .entries_utf8()
        .context("Reading UKI dir entries")?
    {
        let ent = ent?;
        let filename = ent.file_name()?;

        if !ent.file_type()?.is_dir() {
            continue;
        }

        let Some(dir_name) = filename.strip_suffix(EFI_ADDON_DIR_EXT) else {
            continue;
        };

        let depl_id = dir_name.strip_prefix(UKI_NAME_PREFIX).unwrap_or(dir_name);

        let dir = esp
            .fd
            .open_dir(format!("{BOOTC_UKI_DIR}/{filename}"))
            .with_context(|| format!("Opening {filename}"))?;

        gather_addons_from_dir(
            &dir,
            &mut addons,
            UkiAddonType::Scoped {
                depl_id: depl_id.to_string(),
            },
        )?;
    }

    Ok(addons)
}
