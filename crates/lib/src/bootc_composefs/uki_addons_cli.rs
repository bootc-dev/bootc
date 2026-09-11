use std::path::Path;

use anyhow::{Context, Result};
use bootc_mount::tempmount::TempMount;
use camino::Utf8PathBuf;
use cap_std_ext::cap_std::fs::Dir;
use fn_error_context::context;
use ostree_ext::{
    composefs::fsverity::{FsVerityHashValue, Sha512HashValue},
    composefs_boot::{
        bootloader::{EFI_ADDON_DIR_EXT, EFI_ADDON_FILE_EXT},
        cmdline::ComposefsCmdline as ComposefsBootCmdline,
        uki,
    },
    composefs_oci::linked_erofs_images,
};

use crate::{
    bootc_composefs::{
        boot::{
            BOOTC_UKI_DIR, EFI_LINUX, GLOBAL_UKI_ADDONS_DIR, get_global_uki_addon_name,
            get_scoped_uki_addon_name, get_uki_addon_dir_name,
        },
        uki_addon::{UkiAddonType, list_installed_uki_addons},
    },
    cli::{UkiAddonCliOpts, UkiAddonScope},
    store::{BootedComposefs, Storage},
};

#[context("Verifying {addon_type:?} {addon_name} addon exists")]
fn verify_addon_exists(
    boot_dir: &Dir,
    addon_name: &str,
    addon_type: UkiAddonScope,
) -> Result<Utf8PathBuf> {
    let mut path = Utf8PathBuf::from("boot");

    match addon_type {
        UkiAddonScope::Global => {
            let addons_dir = boot_dir.open_dir(GLOBAL_UKI_ADDONS_DIR)?;

            for entry in addons_dir.entries_utf8()? {
                let entry = entry?;
                let filename = entry.file_name()?;

                if let Some(name) = filename.strip_suffix(EFI_ADDON_FILE_EXT) {
                    if name == addon_name {
                        return Ok(path.join(GLOBAL_UKI_ADDONS_DIR).join(filename));
                    }
                };
            }
        }

        UkiAddonScope::Scoped => {
            path = path.join(EFI_LINUX);

            for entry in boot_dir
                .open_dir(EFI_LINUX)
                .context("Opening EFI/Linux")?
                .entries_utf8()?
            {
                let entry = entry?;

                if !entry.file_type()?.is_dir() {
                    continue;
                }

                let dirname = entry.file_name()?;

                if !dirname.ends_with(EFI_ADDON_DIR_EXT) {
                    continue;
                }

                path.push(&dirname);

                for addon_ent in entry.open_dir()?.entries()? {
                    let addon_ent = addon_ent?;
                    let filename = addon_ent.file_name()?;

                    if let Some(name) = filename.strip_suffix(EFI_ADDON_FILE_EXT) {
                        if name == addon_name {
                            return Ok(path.join(filename));
                        }
                    };
                }

                path.pop();
            }
        }
    };

    anyhow::bail!("{addon_name} not found");
}

pub(crate) fn handle_addon_cli_cmd(
    storage: &Storage,
    booted_cfs: &BootedComposefs,
    opts: &UkiAddonCliOpts,
) -> Result<()> {
    let Ok(esp) = storage.require_esp() else {
        anyhow::bail!("ESP not found");
    };

    match opts {
        UkiAddonCliOpts::List { json } => {
            let addons = list_installed_uki_addons(storage)?;

            if *json {
                return serde_json::to_writer(std::io::stdout(), &addons)
                    .context("Writing JSON output");
            }

            if addons.is_empty() {
                println!("No UKI addons installed");
                return Ok(());
            }

            for addon in &addons {
                println!("{addon}");
            }
        }
        UkiAddonCliOpts::Remove {
            name: addon_name,
            deployment_id,
        } => {
            let addons = list_installed_uki_addons(storage)?;

            match deployment_id {
                Some(depl_id) => {
                    let found = addons.iter().any(|addon| {
                        matches!(
                            &addon.addon_type,
                            UkiAddonType::Scoped { depl_id: id } if id == depl_id
                        ) && addon.name == *addon_name
                    });

                    if !found {
                        anyhow::bail!(
                            "No addon found with the name {addon_name} for deployment {depl_id}"
                        );
                    }

                    let addon_path = Path::new(BOOTC_UKI_DIR)
                        .join(get_uki_addon_dir_name(depl_id))
                        .join(get_scoped_uki_addon_name(addon_name));

                    // Absolutely make sure the addon doesn't contain `composefs=` cmdline
                    // if it does, we can't remove it
                    let mut addon_file = esp
                        .fd
                        .open(&addon_path)
                        .with_context(|| format!("Opening {}", addon_path.display()))?;

                    match uki::get_cmdline_buffered(&mut addon_file) {
                        Ok(cmdline_str) => {
                            let cfs_cmdline_info =
                                ComposefsBootCmdline::<Sha512HashValue>::from_cmdline(&cmdline_str)
                                    .context("Parsing composefs=")?;

                            if let Some(cmdline) = cfs_cmdline_info {
                                anyhow::bail!(
                                    "Composefs commandline {cmdline:?} found in addon {addon_name}, cannot remove"
                                );
                            };
                        }
                        Err(uki::UkiError::MissingSection(..)) => {
                            // All good, no cmdline section in this addon
                        }
                        Err(e) => Err(e).context("Reading cmdline section from addon")?,
                    };

                    esp.fd
                        .remove_file(&addon_path)
                        .with_context(|| format!("Failed to remove addon {addon_name}"))?;

                    println!("Removed addon {addon_name}");

                    let addons_dir = addon_path
                        .parent()
                        .expect("Expected addon path to have a parent");

                    let num_ents = esp
                        .fd
                        .open_dir(addons_dir)
                        .context("Opening addons dir")?
                        .entries()
                        .context("Getting addons dir entries")?
                        .count();

                    // Remove directory if empty
                    if num_ents == 0 {
                        esp.fd.remove_dir(&addons_dir).with_context(|| {
                            format!("Removing addons dir: {}", addons_dir.display())
                        })?;

                        println!("Removed empty directory {}", addons_dir.display());
                    }
                }

                // Removing a global addon
                None => {
                    let found = addons.iter().any(|addon| {
                        addon.addon_type == UkiAddonType::Global && addon.name == *addon_name
                    });

                    if !found {
                        anyhow::bail!("No Global addon found with the name {addon_name}");
                    }

                    let full_addon_name = get_global_uki_addon_name(addon_name);

                    tracing::debug!("Removing Global UKI Addon {full_addon_name}");

                    esp.fd
                        .remove_file(format!("{GLOBAL_UKI_ADDONS_DIR}/{full_addon_name}"))
                        .with_context(|| format!("Removing global addon {full_addon_name}"))?;

                    println!("Removed Global Addon {addon_name}");

                    let num_ents = esp
                        .fd
                        .open_dir(GLOBAL_UKI_ADDONS_DIR)
                        .context("Opening global addons dir")?
                        .entries()
                        .context("Getting global addons dir entries")?
                        .count();

                    // Remove directory if empty
                    if num_ents == 0 {
                        esp.fd
                            .remove_dir(GLOBAL_UKI_ADDONS_DIR)
                            .context("Removing global addons dir")?;

                        println!("Removed empty directory {GLOBAL_UKI_ADDONS_DIR}");
                    }
                }
            }
        }

        UkiAddonCliOpts::Add {
            name: addon_name,
            addon_type,
        } => {
            // This should never fail
            let booted_digest = Sha512HashValue::from_hex(booted_cfs.cmdline.digest.as_bytes())
                .context("Booted composefs has bad FSVerity")?;

            let addons = list_installed_uki_addons(storage)?;

            let already_present = addons.iter().any(|addon| match addon_type {
                UkiAddonScope::Global => {
                    addon.addon_type == UkiAddonType::Global && addon.name == *addon_name
                }
                UkiAddonScope::Scoped => {
                    matches!(
                        &addon.addon_type,
                        UkiAddonType::Scoped { depl_id: id } if *id == booted_digest.to_hex()
                    ) && addon.name == *addon_name
                }
            });

            if already_present {
                println!("Addon {addon_name} is already present. Nothing to do.");
                return Ok(());
            }

            let linked_images = linked_erofs_images(&booted_cfs.repo, &booted_digest)
                .context("Finding linked EROFS for booted deployment")?;

            let Some(non_bootable_img) = linked_images.iter().find(|img| !img.bootable) else {
                anyhow::bail!("No non-bootable image found. Cannot gather UKI Addons");
            };

            tracing::debug!("non_bootable_img: {non_bootable_img:#?}");

            // Now we mount the img, and copy from /boot
            let composefs_mnt_fd = booted_cfs
                .repo
                .mount(&non_bootable_img.id.to_hex())
                .context("Failed to mount composefs image")?;

            let composefs = TempMount::mount_fd(composefs_mnt_fd)
                .context("Attaching composefs image to temporary directory")?;

            let cfs_boot_dir = composefs
                .fd
                .open_dir("boot")
                .context("Opening boot directory in composefs image")?;

            // Make sure the addon actually exists in the image
            // before creating directories
            let addon_path = verify_addon_exists(&cfs_boot_dir, addon_name, *addon_type)?;

            match addon_type {
                UkiAddonScope::Global => {
                    esp.fd
                        .create_dir_all(GLOBAL_UKI_ADDONS_DIR)
                        .context("Creating global addons directory")?;

                    let global_addons_dir = esp
                        .fd
                        .open_dir(GLOBAL_UKI_ADDONS_DIR)
                        .context("Opening global addons dir")?;

                    composefs
                        .fd
                        .copy(
                            addon_path,
                            &global_addons_dir,
                            get_global_uki_addon_name(addon_name),
                        )
                        .context("Copying global addon")?;
                }
                UkiAddonScope::Scoped => {
                    let dir_path = Path::new(BOOTC_UKI_DIR)
                        .join(get_uki_addon_dir_name(&booted_digest.to_hex()));

                    esp.fd
                        .create_dir_all(&dir_path)
                        .context("Creating addons directory")?;

                    let to_dir = esp
                        .fd
                        .open_dir(&dir_path)
                        .context("Opening addons directory")?;

                    composefs
                        .fd
                        .copy(addon_path, &to_dir, get_scoped_uki_addon_name(addon_name))
                        .context("Copying addon")?;
                }
            }
        }
    }

    Ok(())
}
