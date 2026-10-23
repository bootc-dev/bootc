use std::collections::HashSet;
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
        boot::{BOOTC_UKI_DIR, EFI_LINUX, GLOBAL_UKI_ADDONS_DIR, STAGED_GLOBAL_UKI_ADDONS_DIR},
        status::BootloaderEntry,
    },
    composefs_consts::UKI_NAME_PREFIX,
    spec::BootEntry,
    store::{BootedComposefs, Storage},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum UkiAddonType {
    Scoped { depl_id: String },
    Global,
}

#[derive(Debug, Clone, Serialize)]
pub struct UkiAddonsList {
    pub name: String,
    pub addon_type: UkiAddonType,
    /// Whether this addon is part of a staged deployment
    pub staged: bool,
}

impl fmt::Display for UkiAddonsList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let type_str = match &self.addon_type {
            UkiAddonType::Global => "global",
            UkiAddonType::Scoped { .. } => "scoped",
        };

        // (label, value) rows; the first is the bulleted header line.
        let mut rows: Vec<(&str, &str)> = vec![("Addon", self.name.as_str()), ("Type", type_str)];

        if let UkiAddonType::Scoped { depl_id } = &self.addon_type {
            rows.push(("Deployment", depl_id.as_str()));
        }

        rows.push(("Staged", if self.staged { "yes" } else { "no" }));

        // Left-align the labels and pad so every value starts in the same column.
        let max_label = rows
            .iter()
            .map(|(label, _)| label.chars().count())
            .max()
            .unwrap_or(0);

        // Width of the "<label>:" column, so values line up one space after it.
        let label_width = max_label + 1;
        let last = rows.len() - 1;

        for (i, (label, value)) in rows.iter().enumerate() {
            let label = format!("{label}:");

            if i == last {
                write!(f, "{label:<label_width$} {value}")?;
            } else {
                writeln!(f, "{label:<label_width$} {value}")?;
            }
        }

        Ok(())
    }
}

fn gather_addons_from_dir(
    dir: &Dir,
    addons: &mut Vec<UkiAddonsList>,
    addon_type: UkiAddonType,
    staged: bool,
) -> Result<()> {
    for ent in dir.entries_utf8()? {
        let ent = ent?;
        let filename = ent.file_name()?;

        let Some(addon_name) = filename.strip_suffix(EFI_ADDON_FILE_EXT) else {
            continue;
        };

        match addon_type {
            UkiAddonType::Global => {
                let Some(addon_name) = addon_name.strip_prefix(UKI_NAME_PREFIX) else {
                    tracing::info!("Global UKI Addon not managed by bootc found: {addon_name}");
                    continue;
                };

                addons.push(UkiAddonsList {
                    name: addon_name.to_string(),
                    addon_type: addon_type.clone(),
                    staged,
                });
            }
            UkiAddonType::Scoped { .. } => {
                addons.push(UkiAddonsList {
                    name: addon_name.to_string(),
                    addon_type: addon_type.clone(),
                    staged,
                });
            }
        }
    }

    Ok(())
}

/// Gathers UKI Addons (Global + Scoped) from the ESP
#[context("Gathering addons from filesystem")]
pub fn gather_addons_from_filesystem(
    boot_dir: &Dir,
    depl_id: Option<&str>,
    staged_deployment: &Option<BootEntry>,
) -> Result<Vec<UkiAddonsList>> {
    let mut addons_list: Vec<UkiAddonsList> = vec![];

    for dir in [GLOBAL_UKI_ADDONS_DIR, STAGED_GLOBAL_UKI_ADDONS_DIR] {
        if let Some(global_dir) = boot_dir.open_dir_optional(dir)? {
            for entry in global_dir.entries_utf8()? {
                let entry = entry?;
                let filename = entry.file_name()?;

                if let Some(name) = filename.strip_suffix(EFI_ADDON_FILE_EXT) {
                    addons_list.push(UkiAddonsList {
                        name: name.to_string(),
                        addon_type: UkiAddonType::Global,
                        staged: dir == STAGED_GLOBAL_UKI_ADDONS_DIR,
                    });
                }
            }
        }
    }

    let Some(efi_linux) = boot_dir.open_dir_optional(EFI_LINUX)? else {
        return Ok(addons_list);
    };

    let staged_deployment_id = match staged_deployment {
        Some(entry) => Some(entry.require_composefs()?.verity.as_str()),
        None => None,
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
                    staged: staged_deployment_id
                        .is_some_and(|staged_id| Some(staged_id) == depl_id),
                });
            }
        }
    }

    Ok(addons_list)
}

#[context("Listing UKI Addons")]
pub fn list_installed_uki_addons(
    storage: &Storage,
    staged_deployment: &Option<BootEntry>,
) -> Result<Vec<UkiAddonsList>> {
    let mut addons = vec![];

    let Ok(esp) = storage.require_esp() else {
        return Ok(addons);
    };

    if let Some(global_dir) = esp.fd.open_dir_optional(GLOBAL_UKI_ADDONS_DIR)? {
        gather_addons_from_dir(&global_dir, &mut addons, UkiAddonType::Global, false)
            .context("Gathering global addons")?;
    };

    if let Some(global_dir) = esp.fd.open_dir_optional(STAGED_GLOBAL_UKI_ADDONS_DIR)? {
        gather_addons_from_dir(&global_dir, &mut addons, UkiAddonType::Global, true)
            .context("Gathering staged global addons")?;
    };

    let Some(bootc_uki_dir) = esp
        .fd
        .open_dir_optional(BOOTC_UKI_DIR)
        .context("Opening UKI dir")?
    else {
        return Ok(addons);
    };

    let staged_deployment_id = match staged_deployment {
        Some(ent) => Some(ent.require_composefs()?.verity.as_str()),
        None => None,
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
            staged_deployment_id.is_some_and(|verity| verity == depl_id),
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
    staged_deployment: &Option<BootEntry>,
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

        let linked_erofs = match linked_erofs_images(&booted_cfs.repo, &verity) {
            Ok(v) => v,
            // Skip entries with no linked EROFS image, but propagate any other error
            // TODO: Update with proper error downcasted match once we have
            // https://github.com/composefs/composefs-rs/pull/400 released
            Err(e)
                if e.chain()
                    .any(|c| c.to_string().contains("No EROFS image found")) =>
            {
                tracing::debug!("No EROFS image found for {}", entry.fsverity);
                continue;
            }
            Err(e) => return Err(e),
        };

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

        let addons_list =
            gather_addons_from_filesystem(&cfs_boot_dir, Some(&entry.fsverity), staged_deployment)?;

        // We work with the bootable fsverity everywhere
        all_referenced_addons.push((entry.fsverity.clone(), addons_list));
    }

    Ok(all_referenced_addons)
}

/// Installed global UKI addons that will be garbage-collected on the next
/// update/switch.
///
/// A global addon is removed by GC once no deployment's image references it
/// This returns the installed global addons that survive the current update's
/// GC but are headed for removal on the next one unless they are re-referenced
///
/// We do this to show a notice/warning to the user that their global addon might
/// be removed unless re-referenced by another image
#[context("Finding global UKI addons pending removal")]
pub(crate) fn global_addons_pending_removal(
    storage: &Storage,
    booted_cfs: &BootedComposefs,
    staged_verity: &str,
    pinned_verities: &[String],
    bootloader_entries: &Vec<BootloaderEntry>,
) -> Result<Vec<String>> {
    // Global addons currently installed on the ESP.
    let installed: Vec<String> = list_installed_uki_addons(storage, &None)?
        .into_iter()
        .filter(|addon| addon.addon_type == UkiAddonType::Global)
        .map(|addon| addon.name)
        .collect();

    if installed.is_empty() {
        return Ok(vec![]);
    }

    // Per-deployment addon references, keyed by EROFS verity.
    let referenced = list_referenced_uki_addons(booted_cfs, bootloader_entries, &None)?;

    // The set of global addon names referenced by any of the given deployments.
    let global_refs_for = |verities: &HashSet<&str>| -> HashSet<String> {
        referenced
            .iter()
            .filter(|(verity, _)| verities.contains(verity.as_str()))
            .flat_map(|(_, addons)| addons.iter())
            .filter(|addon| addon.addon_type == UkiAddonType::Global)
            .map(|addon| addon.name.clone())
            .collect()
    };

    let ref_booted = global_refs_for(&HashSet::from([&*booted_cfs.cmdline.digest]));
    let ref_staged = global_refs_for(&HashSet::from([staged_verity]));
    let ref_pinned = global_refs_for(&pinned_verities.iter().map(|s| s.as_str()).collect());

    let pending = installed
        .into_iter()
        .filter(|name| {
            ref_booted.contains(name) && !ref_staged.contains(name) && !ref_pinned.contains(name)
        })
        .collect();

    Ok(pending)
}
