use std::io::{Seek, SeekFrom};
use std::path::Path;

use anyhow::{Context, Result};
use bootc_mount::tempmount::TempMount;
use camino::Utf8PathBuf;
use cap_std_ext::{cap_std::fs::Dir, dirext::CapStdExtDirExt};
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

use crate::bootc_composefs::boot::STAGED_GLOBAL_UKI_ADDONS_DIR;
use crate::spec::Host;
use crate::{
    bootc_composefs::{
        boot::{
            BOOTC_UKI_DIR, EFI_LINUX, GLOBAL_UKI_ADDONS_DIR, get_global_uki_addon_name,
            get_scoped_uki_addon_name, get_uki_addon_dir_name,
        },
        status::list_bootloader_entries,
        uki_addon::{UkiAddonType, list_installed_uki_addons, list_referenced_uki_addons},
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
    host: &Host,
    opts: &UkiAddonCliOpts,
) -> Result<()> {
    let Ok(esp) = storage.require_esp() else {
        anyhow::bail!("ESP not found");
    };

    match opts {
        UkiAddonCliOpts::List { json } => {
            let addons = list_installed_uki_addons(storage, &host.status.staged)?;

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
            addon_type,
        } => {
            let addons = list_installed_uki_addons(storage, &host.status.staged)?;

            let is_staged = host.status.staged.is_some();

            match addon_type {
                UkiAddonScope::Scoped => {
                    // If we have a staged deployment, we'll operate on that
                    let depl_id = match &host.status.staged {
                        Some(staged) => staged.require_composefs()?.verity.as_str(),
                        None => &*booted_cfs.cmdline.digest,
                    };

                    let found = addons.iter().any(|addon| {
                        matches!(
                            &addon.addon_type,
                            UkiAddonType::Scoped { depl_id: id } if id == depl_id
                        ) && addon.name == *addon_name
                            && addon.staged == is_staged
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

                UkiAddonScope::Global => {
                    let found = addons.iter().any(|addon| {
                        addon.addon_type == UkiAddonType::Global
                            && addon.name == *addon_name
                            && addon.staged == is_staged
                    });

                    if !found {
                        anyhow::bail!("No Global addon found with the name {addon_name}");
                    }

                    let full_addon_name = get_global_uki_addon_name(addon_name);

                    tracing::debug!("Removing Global UKI Addon {full_addon_name}");

                    let global_addons_dir = if is_staged {
                        STAGED_GLOBAL_UKI_ADDONS_DIR
                    } else {
                        GLOBAL_UKI_ADDONS_DIR
                    };

                    esp.fd
                        .remove_file(format!("{global_addons_dir}/{full_addon_name}"))
                        .with_context(|| format!("Removing global addon {full_addon_name}"))?;

                    println!("Removed Global Addon {addon_name}");

                    let num_ents = esp
                        .fd
                        .open_dir(global_addons_dir)
                        .context("Opening global addons dir")?
                        .entries()
                        .context("Getting global addons dir entries")?
                        .count();

                    // Remove the directory if it's now empty.
                    if num_ents == 0 {
                        esp.fd
                            .remove_dir(global_addons_dir)
                            .context("Removing global addons dir")?;

                        println!("Removed empty directory {global_addons_dir}");

                        // The staged global addon set is a transient overlay that
                        // finalize exchanges with the live set on the next boot. An
                        // empty overlay is collapsed rather than applied, so removing
                        // the last staged global addon leaves the currently active
                        // global addons in effect after reboot.
                        if is_staged {
                            println!(
                                "Note: '{addon_name}' was the last staged global addon. \
                                 An empty staged global addon set is not applied on boot, so \
                                 the currently active global addons remain in effect after \
                                 reboot. To drop all global addons, remove them while no \
                                 deployment is staged."
                            );
                        }
                    }
                }
            }
        }

        UkiAddonCliOpts::Add {
            name: addon_name,
            addon_type,
        } => {
            // If we have a staged deployment, we'll operate on that
            let deployment_id = match &host.status.staged {
                Some(staged) => staged.require_composefs()?.verity.as_str(),
                None => &*booted_cfs.cmdline.digest,
            };

            let is_staged = host.status.staged.is_some();

            // This should never fail
            // This is either the staged/booted digest
            let deployment_digest = Sha512HashValue::from_hex(deployment_id.as_bytes())
                .with_context(|| {
                    format!("Composefs deployment has bad FSVerity: {deployment_id}")
                })?;

            let addons = list_installed_uki_addons(storage, &host.status.staged)?;

            let already_present = addons.iter().any(|addon| match addon_type {
                UkiAddonScope::Global => {
                    addon.addon_type == UkiAddonType::Global
                        && addon.name == *addon_name
                        && addon.staged == is_staged
                }
                UkiAddonScope::Scoped => {
                    matches!(
                        &addon.addon_type,
                        UkiAddonType::Scoped { depl_id: id } if *id == deployment_digest.to_hex()
                    ) && addon.name == *addon_name
                        && addon.staged == is_staged
                }
            });

            if already_present {
                println!("Addon {addon_name} is already present. Nothing to do.");
                return Ok(());
            }

            let linked_images = linked_erofs_images(&booted_cfs.repo, &deployment_digest)
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

            // Make sure this addon doesn't contain a composefs= or composefs.digest= cmdline
            let mut addon_file = composefs
                .fd
                .open(&addon_path)
                .with_context(|| format!("Opening UKI Addon at {addon_path}"))?;

            // UKI Addon might not even have a cmdline
            let cmdline = uki::get_cmdline_buffered(&mut addon_file);

            match cmdline {
                Ok(ref cmdline_str) => {
                    let cfs_cmdline_info =
                        ComposefsBootCmdline::<Sha512HashValue>::from_cmdline(cmdline_str)
                            .context("Parsing composefs=")?;

                    if let Some(cfs_cmdline) = cfs_cmdline_info {
                        anyhow::bail!(
                            "composefs cmdline {cfs_cmdline:?} found in UKI Addon {addon_name}. Refusing to add"
                        );
                    }
                }
                Err(uki::UkiError::MissingSection(..)) => {
                    // This is fine, no cmdline section
                    // so it's just a no op
                }
                Err(e) => {
                    return Err(e).context("Getting UKI cmdline");
                }
            };

            let (dest_dir, dest_name) = match addon_type {
                UkiAddonScope::Global => {
                    let global_addons_dir = if is_staged {
                        STAGED_GLOBAL_UKI_ADDONS_DIR
                    } else {
                        GLOBAL_UKI_ADDONS_DIR
                    };

                    esp.fd
                        .create_dir_all(global_addons_dir)
                        .context("Creating global addons directory")?;

                    let global_addons_dir = esp
                        .fd
                        .open_dir(global_addons_dir)
                        .context("Opening global addons dir")?;

                    (global_addons_dir, get_global_uki_addon_name(addon_name))
                }
                UkiAddonScope::Scoped => {
                    let dir_path = Path::new(BOOTC_UKI_DIR)
                        .join(get_uki_addon_dir_name(&deployment_digest.to_hex()));

                    esp.fd
                        .create_dir_all(&dir_path)
                        .context("Creating addons directory")?;

                    let to_dir = esp
                        .fd
                        .open_dir(&dir_path)
                        .context("Opening addons directory")?;

                    (to_dir, get_scoped_uki_addon_name(addon_name))
                }
            };

            addon_file
                .seek(SeekFrom::Start(0))
                .context("Seeking to start of addon")?;

            dest_dir
                .atomic_replace_with(&dest_name, |writer| std::io::copy(&mut addon_file, writer))
                .with_context(|| format!("Writing addon {dest_name}"))?;

            rustix::fs::fsync(
                dest_dir
                    .reopen_as_ownedfd()
                    .context("Reopening as owned fd")?,
            )
            .context("fsync")?;

            match addon_type {
                UkiAddonScope::Global => println!("Global UKI Addon {addon_name} added"),
                UkiAddonScope::Scoped => {
                    println!(
                        "UKI Addon {addon_name} added to {} deployment",
                        if host.status.staged.is_some() {
                            "staged"
                        } else {
                            "booted"
                        }
                    )
                }
            }
        }
        UkiAddonCliOpts::ListReferenced { json } => {
            let referenced = list_referenced_uki_addons(
                booted_cfs,
                &list_bootloader_entries(storage)?,
                &host.status.staged,
            )?;

            if *json {
                return serde_json::to_writer(std::io::stdout(), &referenced)
                    .context("Writing JSON output");
            }

            if referenced.is_empty() {
                println!("No referenced UKI addons found");
                return Ok(());
            }

            for (verity, addons) in &referenced {
                println!("Deployment {verity}:");
                if addons.is_empty() {
                    println!("  (none)");
                } else {
                    for addon in addons {
                        println!("  {addon}");
                    }
                }
            }
        }
    }

    Ok(())
}
