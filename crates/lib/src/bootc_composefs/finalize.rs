use std::{path::Path, process::Command};

use crate::bootc_composefs::gc::{GCOpts, composefs_gc};
use crate::bootc_composefs::rollback::{rename_exchange_bls_entries, rename_exchange_user_cfg};
use crate::bootc_composefs::status::get_composefs_status;
use crate::bootc_composefs::{aboot, boot::BootType};
use crate::composefs_consts::STATE_DIR_ABS;
use crate::install::BOOT;
use crate::spec::BootloaderKind;
use crate::store::{BootedComposefs, Storage};
use anyhow::{Context, Result};
use bootc_initramfs_setup::mount_composefs_image;
use bootc_mount::tempmount::TempMount;
use cap_std_ext::cap_std::{ambient_authority, fs::Dir};
use cap_std_ext::dirext::CapStdExtDirExt;
use composefs::generic_tree::{FileSystem, Stat};
use composefs_ctl::composefs;
use etc_merge::{Diff, compute_diff, merge, traverse_etc};
use rustix::fs::{Mode, OFlags, fsync};

use fn_error_context::context;

pub(crate) async fn get_etc_diff(
    storage: &Storage,
    booted_cfs: &BootedComposefs,
    new_etc: Option<&Dir>,
) -> Result<Diff> {
    let host = get_composefs_status(storage, booted_cfs).await?;
    let booted_composefs = host.require_composefs_booted()?;

    // Mount the booted EROFS image to get pristine etc
    let sysroot_fd = storage.physical_root.reopen_as_ownedfd()?;
    let composefs_fd = mount_composefs_image(
        &sysroot_fd,
        &booted_composefs.verity,
        booted_cfs.cmdline.allow_missing_fsverity,
    )?;

    let erofs_tmp_mnt = TempMount::mount_fd(&composefs_fd)?;

    let pristine_etc =
        Dir::open_ambient_dir(erofs_tmp_mnt.dir.path().join("etc"), ambient_authority())?;
    let current_etc = Dir::open_ambient_dir("/etc", ambient_authority())?;

    let (pristine_files, current_files, new_etc_files) =
        traverse_etc(&pristine_etc, &current_etc, new_etc)?;

    let diff = compute_diff(
        &pristine_files,
        &current_files,
        &new_etc_files
            .as_ref()
            .unwrap_or(&FileSystem::new(Stat::uninitialized())),
    )?;

    Ok(diff)
}

pub(crate) async fn composefs_backend_finalize(
    storage: &Storage,
    booted_cfs: &BootedComposefs,
) -> Result<()> {
    const COMPOSEFS_FINALIZE_JOURNAL_ID: &str = "0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4";

    tracing::info!(
        message_id = COMPOSEFS_FINALIZE_JOURNAL_ID,
        bootc.operation = "finalize",
        bootc.current_deployment = booted_cfs.cmdline.digest,
        "Starting composefs staged deployment finalization"
    );

    let host = get_composefs_status(storage, booted_cfs).await?;

    let booted_composefs = host.require_composefs_booted()?;

    let Some(staged_depl) = host.status.staged.as_ref() else {
        tracing::info!(
            message_id = COMPOSEFS_FINALIZE_JOURNAL_ID,
            bootc.operation = "finalize",
            "No staged deployment found"
        );
        return Ok(());
    };

    if staged_depl.download_only {
        tracing::info!(
            message_id = COMPOSEFS_FINALIZE_JOURNAL_ID,
            bootc.operation = "finalize",
            bootc.download_only = "true",
            "Staged deployment is marked download only. Won't finalize"
        );
        return Ok(());
    }

    let staged_composefs = staged_depl.composefs.as_ref().ok_or(anyhow::anyhow!(
        "Staged deployment is not a composefs deployment"
    ))?;

    let mut aboot_state = (staged_composefs.boot_type == BootType::Aboot)
        .then(|| aboot::AbootState::open(&storage.physical_root))
        .transpose()?;
    if let Some(state) = aboot_state.as_ref()
        && state.read_attempted()?.is_some()
    {
        tracing::warn!("Aboot deployment was already attempted; not flashing it again");
        return Ok(());
    }

    // Mount the booted EROFS image to get pristine etc
    let sysroot_fd = storage.physical_root.reopen_as_ownedfd()?;
    let composefs_fd = mount_composefs_image(
        &sysroot_fd,
        &booted_composefs.verity,
        booted_cfs.cmdline.allow_missing_fsverity,
    )?;

    let erofs_tmp_mnt = TempMount::mount_fd(&composefs_fd)?;

    // Perform the /etc merge
    let pristine_etc =
        Dir::open_ambient_dir(erofs_tmp_mnt.dir.path().join("etc"), ambient_authority())?;
    let current_etc = Dir::open_ambient_dir("/etc", ambient_authority())?;

    let new_etc_path = Path::new(STATE_DIR_ABS)
        .join(&staged_composefs.verity)
        .join("etc");

    let new_etc = Dir::open_ambient_dir(new_etc_path, ambient_authority())?;

    let (pristine_files, current_files, new_files) =
        traverse_etc(&pristine_etc, &current_etc, Some(&new_etc))?;

    let new_files =
        new_files.ok_or_else(|| anyhow::anyhow!("Failed to get dirtree for new etc"))?;

    let diff = compute_diff(&pristine_files, &current_files, &new_files)?;
    merge(&current_etc, &current_files, &new_etc, &new_files, &diff)?;

    // Remove /etc/.updated from the new deployment so that ConditionNeedsUpdate=|/etc
    // services (systemd-sysusers, systemd-tmpfiles) run on the first boot, mirroring
    // what ostree does in sysroot_finalize_deployment.
    new_etc
        .remove_file_optional(".updated")
        .context("Removing /etc/.updated from staged deployment")?;

    // Unmount EROFS
    drop(erofs_tmp_mnt);

    if staged_composefs.boot_type == BootType::Aboot {
        return finalize_staged_aboot(
            storage,
            aboot_state.as_mut().unwrap(),
            &staged_composefs.verity,
        );
    }

    let boot_dir = storage.require_boot_dir()?;

    match booted_composefs.bootloader.kind()? {
        BootloaderKind::GRUBClassic => match staged_composefs.boot_type {
            BootType::Bls => {
                let entries_dir = boot_dir.open_dir("loader")?;
                rename_exchange_bls_entries(&entries_dir)?;
            }
            BootType::Uki => finalize_staged_grub_uki(boot_dir)?,
            BootType::Aboot => unreachable!(),
        },

        BootloaderKind::BLSCompatible => {
            let entries_dir = boot_dir.open_dir("loader")?;
            rename_exchange_bls_entries(&entries_dir)?;
        }
    };

    // Now that we have successfully updated bootloader entires, we can GC the unreferenced ones
    // We do not prune the composefs repository here though
    composefs_gc(
        storage,
        booted_cfs,
        GCOpts {
            dry_run: false,
            prune_repo: false,
        },
    )
    .await?;

    Ok(())
}

/// Keep /boot open until we're killed, which systemd does with SIGTERM
/// when `bootc-finalize-staged-hold.service` is stopped after
/// `bootc-finalize-staged.service`.
///
/// When /boot is an automount (e.g. the ESP set up by
/// systemd-gpt-auto-generator), an idle expire breaks finalization in two
/// ways. If it races with shutdown, it deadlocks: the finalization (which
/// looks up /boot) blocks on the expire, while the unmount is ordered after
/// the finalization. If it completes before shutdown, systemd won't remount
/// /boot once shutdown has begun, so finalization fails to open it (EHOSTDOWN)
/// and the old deployment boots. An open file descriptor makes autofs treat
/// the mount as busy, so it never expires. Note this only works from the
/// root mount namespace.
pub(crate) fn hold_boot() -> Result<()> {
    let path = format!("/{BOOT}");
    let _fd = rustix::fs::open(
        path.as_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("Opening {path}"))?;
    tracing::debug!("Holding {path} open until terminated");
    loop {
        std::thread::park();
    }
}

#[context("Finalizing staged aboot deployment {deployment}")]
fn finalize_staged_aboot(
    storage: &Storage,
    state: &mut aboot::AbootState<'_>,
    deployment: &str,
) -> Result<()> {
    let pending = state
        .read_pending()?
        .ok_or_else(|| anyhow::anyhow!("No pending aboot deployment"))?;
    anyhow::ensure!(
        pending.depl_id == deployment,
        "Pending aboot deployment changed"
    );
    anyhow::ensure!(
        !pending.finalization_locked,
        "Pending aboot deployment is download-only"
    );
    let artifacts = state.verify_artifacts(&storage.physical_root_path, &pending)?;
    let kernel_cmdline =
        std::fs::read_to_string("/proc/cmdline").context("Reading kernel command line")?;
    let booted_slot = aboot::Slot::from_cmdline(&linux_kernel_cmdline::utf8::Cmdline::from(
        kernel_cmdline.as_str(),
    ));

    state.record_attempt(deployment)?;
    if let Some(slot) = booted_slot {
        state.invalidate_other(slot)?;
    }

    let mut command = Command::new("aboot-deploy");
    command.args(["--local", "--boot-image"]);
    command.arg(artifacts.boot);
    if let Some(vbmeta) = artifacts.vbmeta {
        command.arg("--vbmeta-image").arg(vbmeta);
    }
    let status = command.status().context("Running aboot-deploy")?;
    anyhow::ensure!(status.success(), "aboot-deploy exited with status {status}");
    Ok(())
}

#[context("Grub: Finalizing staged UKI")]
fn finalize_staged_grub_uki(boot_fd: &Dir) -> Result<()> {
    let entries_dir = boot_fd.open_dir("grub2")?;
    rename_exchange_user_cfg(&entries_dir)?;

    let entries_dir = entries_dir.reopen_as_ownedfd()?;
    fsync(entries_dir).context("fsync")?;

    Ok(())
}
