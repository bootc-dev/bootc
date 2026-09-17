use std::fmt;

use anyhow::{Context, Result};
use bootc_mount::tempmount::TempMount;
use cap_std_ext::cap_std::fs::Dir;
use cap_std_ext::dirext::CapStdExtDirExt;
use fn_error_context::context;
use ostree_ext::{
    composefs::fsverity::{FsVerityHashValue, Sha512HashValue},
    composefs_boot::bootloader::{EFI_ADDON_DIR_EXT, EFI_ADDON_FILE_EXT},
    composefs_oci::linked_erofs_images,
};
use serde::Serialize;

use crate::{
    bootc_composefs::{
        boot::{BOOTC_UKI_DIR, EFI_LINUX, GLOBAL_UKI_ADDONS_DIR},
        status::BootloaderEntry,
    },
    composefs_consts::UKI_NAME_PREFIX,
    store::{BootedComposefs, Storage},
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

/// Gathers UKI Addons (Global + Scoped) from the ESP
#[context("Gathering addons from filesystem")]
pub fn gather_addons_from_filesystem(
    boot_dir: &Dir,
    depl_id: Option<&str>,
) -> Result<Vec<UkiAddonsList>> {
    let mut addons_list: Vec<UkiAddonsList> = vec![];

    if let Some(global_dir) = boot_dir.open_dir_optional(GLOBAL_UKI_ADDONS_DIR)? {
        for entry in global_dir.entries_utf8()? {
            let entry = entry?;
            let filename = entry.file_name()?;

            if let Some(name) = filename.strip_suffix(EFI_ADDON_FILE_EXT) {
                addons_list.push(UkiAddonsList {
                    name: name.to_string(),
                    addon_type: UkiAddonType::Global,
                });
            }
        }
    }

    let Some(efi_linux) = boot_dir.open_dir_optional(EFI_LINUX)? else {
        return Ok(addons_list);
    };

    for entry in efi_linux.entries_utf8()? {
        let entry = entry?;

        if !entry.file_type()?.is_dir() {
            continue;
        }

        let dirname = entry.file_name()?;

        // This will usually be the kernel version
        let Some(..) = dirname.strip_suffix(EFI_ADDON_DIR_EXT) else {
            continue;
        };

        let dir = efi_linux
            .open_dir(&dirname)
            .with_context(|| format!("Opening {dirname}"))?;

        for addon_ent in dir.entries_utf8()? {
            let addon_ent = addon_ent?;
            let filename = addon_ent.file_name()?;

            if let Some(name) = filename.strip_suffix(EFI_ADDON_FILE_EXT) {
                addons_list.push(UkiAddonsList {
                    name: name.to_string(),
                    addon_type: UkiAddonType::Scoped {
                        // We can't always have the deployment id with us
                        depl_id: depl_id.map(|x| x.to_string()).unwrap_or("".into()),
                    },
                });
            }
        }
    }

    Ok(addons_list)
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

    let Some(bootc_uki_dir) = esp
        .fd
        .open_dir_optional(BOOTC_UKI_DIR)
        .context("Opening UKI dir")?
    else {
        return Ok(addons);
    };

    for ent in bootc_uki_dir
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

/// Go through all the EROFS images and get all the referenced UKI Addons
///
/// Returns a list of tuple of (EROFS verity, List of referenced addons)
#[context("Getting all referenced UKI Addons")]
pub fn list_referenced_uki_addons(
    booted_cfs: &BootedComposefs,
    bootloader_entries: &Vec<BootloaderEntry>,
) -> Result<Vec<(String, Vec<UkiAddonsList>)>> {
    let mut all_referenced_addons: Vec<(String, Vec<UkiAddonsList>)> = vec![];

    for entry in bootloader_entries {
        let verity = Sha512HashValue::from_hex(&entry.fsverity);

        let verity = match verity {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    "Invalid fsverity found in bootloader entry {}: {e:?}",
                    entry.fsverity
                );
                continue;
            }
        };

        let linked_erofs = linked_erofs_images(&booted_cfs.repo, &verity)?;

        let Some(non_bootable) = linked_erofs.iter().find(|e| !e.bootable) else {
            tracing::debug!("No non-bootable EROFS found for {}", entry.fsverity);
            continue;
        };

        let composefs_mnt_fd = booted_cfs
            .repo
            .mount(&non_bootable.id.to_hex())
            .context("Failed to mount composefs image")?;

        let composefs = TempMount::mount_fd(composefs_mnt_fd)
            .context("Attaching composefs image to temporary directory")?;

        let cfs_boot_dir = composefs
            .fd
            .open_dir("boot")
            .context("Opening boot directory in composefs image")?;

        let addons_list = gather_addons_from_filesystem(&cfs_boot_dir, Some(&entry.fsverity))?;

        // We work with the bootable fsverity everywhere
        all_referenced_addons.push((entry.fsverity.clone(), addons_list));
    }

    Ok(all_referenced_addons)
}
