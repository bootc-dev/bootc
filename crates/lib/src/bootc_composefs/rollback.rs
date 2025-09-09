use std::path::PathBuf;
use std::{fmt::Write, fs::create_dir_all};

use anyhow::{anyhow, Context, Result};
use cap_std_ext::cap_std::fs::Dir;
use cap_std_ext::{cap_std, dirext::CapStdExtDirExt};
use fn_error_context::context;
use rustix::fs::{fsync, renameat_with, AtFlags, RenameFlags};

use crate::bootc_composefs::boot::BootType;
use crate::bootc_composefs::status::{composefs_deployment_status, get_sorted_bls_boot_entries};
use crate::{
    bootc_composefs::{boot::get_efi_uuid_source, status::get_sorted_uki_boot_entries},
    composefs_consts::{
        BOOT_LOADER_ENTRIES, ROLLBACK_BOOT_LOADER_ENTRIES, USER_CFG, USER_CFG_ROLLBACK,
    },
    spec::BootOrder,
};

#[context("Rolling back UKI")]
pub(crate) fn rollback_composefs_uki() -> Result<()> {
    let user_cfg_path = PathBuf::from("/sysroot/boot/grub2");

    let mut str = String::new();
    let boot_dir =
        cap_std::fs::Dir::open_ambient_dir("/sysroot/boot", cap_std::ambient_authority())
            .context("Opening boot dir")?;
    let mut menuentries =
        get_sorted_uki_boot_entries(&boot_dir, &mut str).context("Getting UKI boot entries")?;

    // TODO(Johan-Liebert): Currently assuming there are only two deployments
    assert!(menuentries.len() == 2);

    let (first, second) = menuentries.split_at_mut(1);
    std::mem::swap(&mut first[0], &mut second[0]);

    let mut buffer = get_efi_uuid_source();

    for entry in menuentries {
        write!(buffer, "{entry}")?;
    }

    let entries_dir =
        cap_std::fs::Dir::open_ambient_dir(&user_cfg_path, cap_std::ambient_authority())
            .with_context(|| format!("Opening {user_cfg_path:?}"))?;

    entries_dir
        .atomic_write(USER_CFG_ROLLBACK, buffer)
        .with_context(|| format!("Writing to {USER_CFG_ROLLBACK}"))?;

    tracing::debug!("Atomically exchanging for {USER_CFG_ROLLBACK} and {USER_CFG}");
    renameat_with(
        &entries_dir,
        USER_CFG_ROLLBACK,
        &entries_dir,
        USER_CFG,
        RenameFlags::EXCHANGE,
    )
    .context("renameat")?;

    tracing::debug!("Removing {USER_CFG_ROLLBACK}");
    rustix::fs::unlinkat(&entries_dir, USER_CFG_ROLLBACK, AtFlags::empty()).context("unlinkat")?;

    tracing::debug!("Syncing to disk");
    fsync(
        entries_dir
            .reopen_as_ownedfd()
            .with_context(|| format!("Reopening {user_cfg_path:?} as owned fd"))?,
    )
    .with_context(|| format!("fsync {user_cfg_path:?}"))?;

    Ok(())
}

#[context("Rolling back BLS")]
pub(crate) fn rollback_composefs_bls() -> Result<()> {
    let boot_dir =
        cap_std::fs::Dir::open_ambient_dir("/sysroot/boot", cap_std::ambient_authority())
            .context("Opening boot dir")?;

    // Sort in descending order as that's the order they're shown on the boot screen
    // After this:
    // all_configs[0] -> booted depl
    // all_configs[1] -> rollback depl
    let mut all_configs = get_sorted_bls_boot_entries(&boot_dir, false)?;

    // Update the indicies so that they're swapped
    for (idx, cfg) in all_configs.iter_mut().enumerate() {
        cfg.sort_key = Some(idx.to_string());
    }

    // TODO(Johan-Liebert): Currently assuming there are only two deployments
    assert!(all_configs.len() == 2);

    // Write these
    let dir_path = PathBuf::from(format!(
        "/sysroot/boot/loader/{ROLLBACK_BOOT_LOADER_ENTRIES}",
    ));
    create_dir_all(&dir_path).with_context(|| format!("Failed to create dir: {dir_path:?}"))?;

    let rollback_entries_dir =
        cap_std::fs::Dir::open_ambient_dir(&dir_path, cap_std::ambient_authority())
            .with_context(|| format!("Opening {dir_path:?}"))?;

    // Write the BLS configs in there
    for cfg in all_configs {
        // SAFETY: We set sort_key above
        let file_name = format!("bootc-composefs-{}.conf", cfg.sort_key.as_ref().unwrap());

        rollback_entries_dir
            .atomic_write(&file_name, cfg.to_string())
            .with_context(|| format!("Writing to {file_name}"))?;
    }

    // Should we sync after every write?
    fsync(
        rollback_entries_dir
            .reopen_as_ownedfd()
            .with_context(|| format!("Reopening {dir_path:?} as owned fd"))?,
    )
    .with_context(|| format!("fsync {dir_path:?}"))?;

    // Atomically exchange "entries" <-> "entries.rollback"
    let dir = Dir::open_ambient_dir("/sysroot/boot/loader", cap_std::ambient_authority())
        .context("Opening loader dir")?;

    tracing::debug!(
        "Atomically exchanging for {ROLLBACK_BOOT_LOADER_ENTRIES} and {BOOT_LOADER_ENTRIES}"
    );
    renameat_with(
        &dir,
        ROLLBACK_BOOT_LOADER_ENTRIES,
        &dir,
        BOOT_LOADER_ENTRIES,
        RenameFlags::EXCHANGE,
    )
    .context("renameat")?;

    tracing::debug!("Removing {ROLLBACK_BOOT_LOADER_ENTRIES}");
    rustix::fs::unlinkat(&dir, ROLLBACK_BOOT_LOADER_ENTRIES, AtFlags::empty())
        .context("unlinkat")?;

    tracing::debug!("Syncing to disk");
    fsync(
        dir.reopen_as_ownedfd()
            .with_context(|| format!("Reopening /sysroot/boot/loader as owned fd"))?,
    )
    .context("fsync")?;

    Ok(())
}

#[context("Rolling back composefs")]
pub(crate) async fn composefs_rollback() -> Result<()> {
    let host = composefs_deployment_status().await?;

    let new_spec = {
        let mut new_spec = host.spec.clone();
        new_spec.boot_order = new_spec.boot_order.swap();
        new_spec
    };

    // Just to be sure
    host.spec.verify_transition(&new_spec)?;

    let reverting = new_spec.boot_order == BootOrder::Default;
    if reverting {
        println!("notice: Reverting queued rollback state");
    }

    let rollback_status = host
        .status
        .rollback
        .ok_or_else(|| anyhow!("No rollback available"))?;

    // TODO: Handle staged deployment
    // Ostree will drop any staged deployment on rollback but will keep it if it is the first item
    // in the new deployment list
    let Some(rollback_composefs_entry) = &rollback_status.composefs else {
        anyhow::bail!("Rollback deployment not a composefs deployment")
    };

    match rollback_composefs_entry.boot_type {
        BootType::Bls => rollback_composefs_bls(),
        BootType::Uki => rollback_composefs_uki(),
    }?;

    if reverting {
        println!("Next boot: current deployment");
    } else {
        println!("Next boot: rollback deployment");
    }

    Ok(())
}
