#![allow(dead_code)]
use std::fmt;

use anyhow::{Context, Result};
use cap_std_ext::cap_std::fs::Dir;
use cap_std_ext::dirext::CapStdExtDirExt;
use fn_error_context::context;
use ostree_ext::composefs_boot::bootloader::{EFI_ADDON_DIR_EXT, EFI_ADDON_FILE_EXT};
use serde::Serialize;

use crate::{
    bootc_composefs::boot::{BOOTC_UKI_DIR, GLOBAL_UKI_ADDONS_DIR},
    composefs_consts::UKI_NAME_PREFIX,
    store::Storage,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum UkiAddonType {
    Scoped { depl_id: String },
    Global,
}

impl fmt::Display for UkiAddonType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UkiAddonType::Global => write!(f, "global"),
            UkiAddonType::Scoped { depl_id } => write!(f, "scoped (deployment {depl_id})"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct UkiAddonsList {
    pub name: String,
    pub addon_type: UkiAddonType,
}

impl fmt::Display for UkiAddonsList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.addon_type)
    }
}

fn gather_addons_from_dir(
    dir: &Dir,
    addons: &mut Vec<UkiAddonsList>,
    addon_type: UkiAddonType,
) -> Result<()> {
    for ent in dir.entries_utf8()? {
        let ent = ent?;
        let filename = ent.file_name()?;

        let Some(addon_name) = filename.strip_suffix(EFI_ADDON_FILE_EXT) else {
            continue;
        };

        match addon_name.strip_prefix(UKI_NAME_PREFIX) {
            Some(addon_name) => {
                addons.push(UkiAddonsList {
                    name: addon_name.to_string(),
                    addon_type: addon_type.clone(),
                });
            }
            None => match addon_type {
                UkiAddonType::Scoped { .. } => {
                    addons.push(UkiAddonsList {
                        name: addon_name.to_string(),
                        addon_type: addon_type.clone(),
                    });
                }
                // We only prefix global UKI Addons for identification
                UkiAddonType::Global => {
                    tracing::info!("Global UKI Addon not managed by bootc found: {addon_name}")
                }
            },
        }
    }

    Ok(())
}

#[context("Listing UKI Addons")]
pub fn list_installed_uki_addons(storage: &Storage) -> Result<Vec<UkiAddonsList>> {
    let mut addons = vec![];

    let Ok(esp) = storage.require_esp() else {
        return Ok(addons);
    };

    if let Some(global_dir) = esp.fd.open_dir_optional(GLOBAL_UKI_ADDONS_DIR)? {
        gather_addons_from_dir(&global_dir, &mut addons, UkiAddonType::Global)
            .context("Gathering global addons")?;
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
