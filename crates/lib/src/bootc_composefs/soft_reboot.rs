use crate::{
    bootc_composefs::{
        service::start_finalize_stated_svc, status::composefs_deployment_status_from,
    },
    composefs_consts::COMPOSEFS_CMDLINE,
    store::{BootedComposefs, Storage},
};
use anyhow::{Context, Result};
use bootc_initramfs_setup::setup_root;
use bootc_kernel_cmdline::utf8::Cmdline;
use bootc_mount::{bind_mount_from_pidns, PID1};
use camino::Utf8Path;
use std::{fs::create_dir_all, os::unix::process::CommandExt, path::PathBuf, process::Command};

const NEXTROOT: &str = "/run/nextroot";

pub(crate) async fn soft_reboot_to_deployment(
    storage: &Storage,
    booted_cfs: &BootedComposefs,
    deployment_id: &String,
    reboot: bool,
) -> Result<()> {
    if *deployment_id == *booted_cfs.cmdline.digest {
        anyhow::bail!("Cannot soft-reboot to currently booted deployment");
    }

    let host = composefs_deployment_status_from(storage, booted_cfs.cmdline).await?;

    let all_deployments = host.all_composefs_deployments()?;

    let requred_deployment = all_deployments
        .iter()
        .find(|entry| entry.deployment.verity == *deployment_id)
        .ok_or_else(|| anyhow::anyhow!("Deployment '{deployment_id}' not found"))?;

    if !requred_deployment.soft_reboot_capable {
        anyhow::bail!("Cannot soft-reboot to deployment with a different kernel state");
    }

    start_finalize_stated_svc()?;

    // escape to global mnt namespace
    let run = Utf8Path::new("/run");
    bind_mount_from_pidns(PID1, &run, &run, false).context("Bind mounting /run")?;

    create_dir_all(NEXTROOT).context("Creating nextroot")?;

    let cmdline = Cmdline::from(format!("{COMPOSEFS_CMDLINE}={deployment_id}"));

    let args = bootc_initramfs_setup::Args {
        cmd: vec![],
        sysroot: PathBuf::from("/sysroot"),
        config: Default::default(),
        root_fs: None,
        cmdline: Some(cmdline),
        target: Some(NEXTROOT.into()),
    };

    setup_root(args)?;

    if reboot {
        // Replacing the current process should be fine as we restart userspace anyway
        let err = Command::new("systemctl").arg("soft-reboot").exec();
        return Err(anyhow::Error::from(err).context("Failed to exec 'systemctl soft-reboot'"));
    }

    Ok(())
}
