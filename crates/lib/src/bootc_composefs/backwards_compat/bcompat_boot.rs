use std::io::{Read, Write};

use crate::{
    bootc_composefs::{
        boot::{
            BOOTC_UKI_DIR, BootType, FILENAME_PRIORITY_PRIMARY, FILENAME_PRIORITY_SECONDARY,
            get_efi_uuid_source, get_uki_name, parse_os_release, type1_entry_conf_file_name,
        },
        rollback::{rename_exchange_bls_entries, rename_exchange_user_cfg},
        status::{get_bootloader, get_sorted_grub_uki_boot_entries, get_sorted_type1_boot_entries},
    },
    composefs_consts::{
        ORIGIN_KEY_BOOT, ORIGIN_KEY_BOOT_TYPE, STATE_DIR_RELATIVE, TYPE1_BOOT_DIR_PREFIX,
        TYPE1_ENT_PATH_STAGED, UKI_NAME_PREFIX, USER_CFG_STAGED,
    },
    parsers::bls_config::{BLSConfig, BLSConfigType},
    spec::Bootloader,
    store::{BootedComposefs, Storage},
};
use anyhow::{Context, Result};
use camino::Utf8PathBuf;
use cap_std_ext::{cap_std::fs::Dir, dirext::CapStdExtDirExt};
use cfsctl::composefs_boot::bootloader::{EFI_ADDON_DIR_EXT, EFI_EXT};
use fn_error_context::context;
use ocidir::cap_std::ambient_authority;
use rustix::fs::{RenameFlags, fsync, renameat_with};

/// Represents a pending rename operation to be executed atomically
#[derive(Debug)]
struct PendingRename {
    old_name: String,
    new_name: String,
}

/// Transaction context for managing atomic renames (both files and directories)
#[derive(Debug)]
struct RenameTransaction {
    operations: Vec<PendingRename>,
}

impl RenameTransaction {
    fn new() -> Self {
        Self {
            operations: Vec::new(),
        }
    }

    fn add_operation(&mut self, old_name: String, new_name: String) {
        self.operations.push(PendingRename { old_name, new_name });
    }

    /// Execute all renames atomically in the provided directory
    /// If any operation fails, attempt to rollback all completed operations
    ///
    /// We currently only have two entries at max, so this is quite unlikely to fail...
    #[context("Executing rename transactions")]
    fn execute_transaction(&self, target_dir: &Dir) -> Result<()> {
        let mut completed_operations = Vec::new();

        for op in &self.operations {
            match renameat_with(
                target_dir,
                &op.old_name,
                target_dir,
                &op.new_name,
                RenameFlags::empty(),
            ) {
                Ok(()) => {
                    completed_operations.push(op);
                    tracing::debug!("Renamed {} -> {}", op.old_name, op.new_name);
                }
                Err(e) => {
                    // Attempt rollback of completed operations
                    for completed_op in completed_operations.iter().rev() {
                        if let Err(rollback_err) = renameat_with(
                            target_dir,
                            &completed_op.new_name,
                            target_dir,
                            &completed_op.old_name,
                            RenameFlags::empty(),
                        ) {
                            tracing::error!(
                                "Rollback failed for {} -> {}: {}",
                                completed_op.new_name,
                                completed_op.old_name,
                                rollback_err
                            );
                        }
                    }

                    return Err(e).context(format!("Failed to rename {}", op.old_name));
                }
            }
        }

        Ok(())
    }
}

/// Plan EFI binary renames and populate the transaction
/// The actual renames are deferred to the transaction
#[context("Planning EFI renames")]
fn plan_efi_binary_renames(
    esp: &Dir,
    digest: &str,
    rename_transaction: &mut RenameTransaction,
) -> Result<()> {
    let bootc_uki_dir = esp.open_dir(BOOTC_UKI_DIR)?;

    for entry in bootc_uki_dir.entries_utf8()? {
        let entry = entry?;
        let filename = entry.file_name()?;

        if filename.starts_with(UKI_NAME_PREFIX) {
            continue;
        }

        if !filename.ends_with(EFI_EXT) && !filename.ends_with(EFI_ADDON_DIR_EXT) {
            continue;
        }

        if !filename.contains(digest) {
            continue;
        }

        let new_name = format!("{UKI_NAME_PREFIX}{filename}");
        rename_transaction.add_operation(filename.to_string(), new_name);
    }

    Ok(())
}

/// Plan BLS directory renames and populate the transaction
/// The actual renames are deferred to the transaction
#[context("Planning BLS directory renames")]
fn plan_bls_entry_rename(binaries_dir: &Dir, entry_to_fix: &str) -> Result<Option<String>> {
    for entry in binaries_dir.entries_utf8()? {
        let entry = entry?;
        let filename = entry.file_name()?;

        // We don't really put any files here, but just in case
        if !entry.file_type()?.is_dir() {
            continue;
        }

        if filename != entry_to_fix {
            continue;
        }

        let new_name = format!("{TYPE1_BOOT_DIR_PREFIX}{filename}");
        return Ok(Some(new_name));
    }

    Ok(None)
}

#[context("Staging BLS entry changes")]
fn stage_bls_entry_changes(
    storage: &Storage,
    boot_dir: &Dir,
    entries: &Vec<BLSConfig>,
    booted_cfs: &BootedComposefs,
) -> Result<(RenameTransaction, Vec<(String, BLSConfig)>)> {
    let mut rename_transaction = RenameTransaction::new();

    let root = Dir::open_ambient_dir("/", ambient_authority())?;
    let osrel = parse_os_release(&root)?;

    let os_id = osrel
        .as_ref()
        .map(|(s, _, _)| s.as_str())
        .unwrap_or("bootc");

    // to not add duplicate transactions since we share BLS entries
    // across deployements
    let mut fixed = vec![];
    let mut new_bls_entries = vec![];

    for entry in entries {
        let (digest, has_prefix) = entry.boot_artifact_info()?;
        let digest = digest.to_string();

        if has_prefix {
            continue;
        }

        let mut new_entry = entry.clone();

        let conf_filename = if *booted_cfs.cmdline.digest == digest {
            type1_entry_conf_file_name(os_id, new_entry.version(), FILENAME_PRIORITY_PRIMARY)
        } else {
            type1_entry_conf_file_name(os_id, new_entry.version(), FILENAME_PRIORITY_SECONDARY)
        };

        match &mut new_entry.cfg_type {
            BLSConfigType::NonEFI { linux, initrd, .. } => {
                let new_name =
                    plan_bls_entry_rename(&storage.bls_boot_binaries_dir()?, &digest)?
                        .ok_or_else(|| anyhow::anyhow!("Directory for entry {digest} not found"))?;

                // We don't want this multiple times in the rename_transaction if it was already
                // "fixed"
                if !fixed.contains(&digest) {
                    rename_transaction.add_operation(digest.clone(), new_name.clone());
                }

                *linux = linux.as_str().replace(&digest, &new_name).into();
                *initrd = initrd
                    .iter_mut()
                    .map(|path| path.as_str().replace(&digest, &new_name).into())
                    .collect();
            }

            BLSConfigType::EFI { efi, .. } => {
                // boot_dir in case of UKI is the ESP
                plan_efi_binary_renames(&boot_dir, &digest, &mut rename_transaction)?;
                *efi = Utf8PathBuf::from("/")
                    .join(BOOTC_UKI_DIR)
                    .join(get_uki_name(&digest));
            }

            _ => anyhow::bail!("Unknown BLS config type"),
        }

        new_bls_entries.push((conf_filename, new_entry));
        fixed.push(digest.into());
    }

    Ok((rename_transaction, new_bls_entries))
}

fn create_staged_bls_entries(boot_dir: &Dir, entries: &Vec<(String, BLSConfig)>) -> Result<()> {
    boot_dir.create_dir_all(TYPE1_ENT_PATH_STAGED)?;
    let staged_entries = boot_dir.open_dir(TYPE1_ENT_PATH_STAGED)?;

    for (filename, new_entry) in entries {
        staged_entries.atomic_write(filename, new_entry.to_string().as_bytes())?;
    }

    fsync(staged_entries.reopen_as_ownedfd()?).context("fsync")
}

fn get_boot_type(storage: &Storage, booted_cfs: &BootedComposefs) -> Result<BootType> {
    let mut config = String::new();

    let origin_path = Utf8PathBuf::from(STATE_DIR_RELATIVE)
        .join(&*booted_cfs.cmdline.digest)
        .join(format!("{}.origin", booted_cfs.cmdline.digest));

    storage
        .physical_root
        .open(origin_path)
        .context("Opening origin file")?
        .read_to_string(&mut config)
        .context("Reading origin file")?;

    let origin = tini::Ini::from_string(&config)
        .with_context(|| format!("Failed to parse origin as ini"))?;

    let boot_type = match origin.get::<String>(ORIGIN_KEY_BOOT, ORIGIN_KEY_BOOT_TYPE) {
        Some(s) => BootType::try_from(s.as_str())?,
        None => anyhow::bail!("{ORIGIN_KEY_BOOT} not found"),
    };

    Ok(boot_type)
}

fn handle_bls_conf(
    storage: &Storage,
    booted_cfs: &BootedComposefs,
    boot_dir: &Dir,
    is_uki: bool,
) -> Result<()> {
    let entries = get_sorted_type1_boot_entries(boot_dir, true)?;
    let (rename_transaction, new_bls_entries) =
        stage_bls_entry_changes(storage, boot_dir, &entries, booted_cfs)?;

    if rename_transaction.operations.is_empty() {
        tracing::debug!("Nothing to do");
        return Ok(());
    }

    create_staged_bls_entries(boot_dir, &new_bls_entries)?;

    let binaries_dir = if is_uki {
        let esp = storage.require_esp()?;
        let uki_dir = esp.fd.open_dir(BOOTC_UKI_DIR).context("Opening UKI dir")?;

        uki_dir
    } else {
        storage.bls_boot_binaries_dir()?
    };

    // execute all EFI PE renames atomically before the final exchange
    rename_transaction
        .execute_transaction(&binaries_dir)
        .context("Failed to execute EFI binary rename transaction")?;

    fsync(binaries_dir.reopen_as_ownedfd()?)?;

    let loader_dir = boot_dir.open_dir("loader").context("Opening loader dir")?;
    rename_exchange_bls_entries(&loader_dir)?;

    Ok(())
}

/// Goes through the ESP and prepends every UKI/Addon with our custom prefix
/// Goes through the BLS entries and prepends our custom prefix
#[context("Prepending custom prefix to EFI and BLS entries")]
pub(crate) async fn prepend_custom_prefix(
    storage: &Storage,
    booted_cfs: &BootedComposefs,
) -> Result<()> {
    let boot_dir = storage.require_boot_dir()?;

    let bootloader = get_bootloader()?;

    match get_boot_type(storage, booted_cfs)? {
        BootType::Bls => {
            handle_bls_conf(storage, booted_cfs, boot_dir, false)?;
        }

        BootType::Uki => match bootloader {
            Bootloader::Grub => {
                let esp = storage.require_esp()?;

                let mut buf = String::new();
                let menuentries = get_sorted_grub_uki_boot_entries(boot_dir, &mut buf)?;

                let mut new_menuentries = vec![];
                let mut rename_transaction = RenameTransaction::new();

                for entry in menuentries {
                    let (digest, has_prefix) = entry.boot_artifact_info()?;
                    let digest = digest.to_string();

                    if has_prefix {
                        continue;
                    }

                    plan_efi_binary_renames(&esp.fd, &digest, &mut rename_transaction)?;

                    let new_path = Utf8PathBuf::from("/")
                        .join(BOOTC_UKI_DIR)
                        .join(get_uki_name(&digest));

                    let mut new_entry = entry.clone();
                    new_entry.body.chainloader = new_path.into();

                    new_menuentries.push(new_entry);
                }

                if rename_transaction.operations.is_empty() {
                    tracing::debug!("Nothing to do");
                    return Ok(());
                }

                let grub_dir = boot_dir.open_dir("grub2").context("opening boot/grub2")?;

                grub_dir
                    .atomic_replace_with(USER_CFG_STAGED, |f| -> std::io::Result<_> {
                        f.write_all(get_efi_uuid_source().as_bytes())?;

                        for entry in new_menuentries {
                            f.write_all(entry.to_string().as_bytes())?;
                        }

                        Ok(())
                    })
                    .with_context(|| format!("Writing to {USER_CFG_STAGED}"))?;

                let esp = storage.require_esp()?;
                let uki_dir = esp.fd.open_dir(BOOTC_UKI_DIR).context("Opening UKI dir")?;

                // execute all EFI PE renames atomically before the final exchange
                rename_transaction
                    .execute_transaction(&uki_dir)
                    .context("Failed to execute EFI binary rename transaction")?;

                fsync(uki_dir.reopen_as_ownedfd()?)?;
                rename_exchange_user_cfg(&grub_dir)?;
            }

            Bootloader::Systemd => {
                handle_bls_conf(storage, booted_cfs, boot_dir, true)?;
            }

            Bootloader::None => unreachable!("Checked at install time"),
        },
    };

    Ok(())
}
