use crate::{
    bootc_composefs::{
        service::start_finalize_stated_svc, status::composefs_deployment_status_from,
    },
    cli::SoftRebootMode,
    composefs_consts::COMPOSEFS_CMDLINE,
    store::{BootedComposefs, Storage},
};
use anyhow::{Context, Result};
use bootc_initramfs_setup::setup_root;
use bootc_kernel_cmdline::utf8::Cmdline;
use bootc_mount::{PID1, bind_mount_from_pidns};
use camino::Utf8Path;
use cap_std_ext::cap_std::ambient_authority;
use cap_std_ext::cap_std::fs::Dir;
use cap_std_ext::dirext::CapStdExtDirExt;
use fn_error_context::context;
use ostree_ext::systemd_has_soft_reboot;
use rustix::mount::{UnmountFlags, unmount};
use std::{fs::create_dir_all, os::unix::process::CommandExt, path::PathBuf, process::Command};

const NEXTROOT: &str = "/run/nextroot";

#[context("Resetting soft reboot state")]
pub(crate) fn reset_soft_reboot() -> Result<()> {
    // NOTE: By default bootc runs in an unshared mount namespace;
    // this sets up our /runto actually be the same as the host/run
    // so the umount (at the end of this function) actually affects the host
    //
    // Similar operation is performed in `prepare_soft_reboot_composefs`
    let run = Utf8Path::new("/run");
    bind_mount_from_pidns(PID1, &run, &run, true).context("Bind mounting /run")?;

    let run_dir = Dir::open_ambient_dir("/run", ambient_authority()).context("Opening run")?;

    let nextroot = run_dir
        .open_dir_optional("nextroot")
        .context("Opening nextroot")?;

    let Some(nextroot) = nextroot else {
        tracing::debug!("Nextroot does not exist");
        println!("No deployment staged for soft rebooting");
        return Ok(());
    };

    let nextroot_mounted = nextroot
        .is_mountpoint(".")?
        .ok_or_else(|| anyhow::anyhow!("Failed to get mount info"))?;

    if !nextroot_mounted {
        tracing::debug!("Nextroot is not a mountpoint");
        println!("No deployment staged for soft rebooting");
        return Ok(());
    }

    unmount(NEXTROOT, UnmountFlags::DETACH).context("Unmounting nextroot")?;

    println!("Cleared soft reboot queued state");

    Ok(())
}

/// Checks if the provided deployment is soft reboot capable, and soft reboots the system if
/// argument `reboot` is true
#[context("Soft rebooting")]
pub(crate) async fn prepare_soft_reboot_composefs(
    storage: &Storage,
    booted_cfs: &BootedComposefs,
    deployment_id: Option<&str>,
    soft_reboot_mode: SoftRebootMode,
    reboot: bool,
) -> Result<()> {
    if !systemd_has_soft_reboot() {
        anyhow::bail!("System does not support soft reboots")
    }

    let deployment_id = deployment_id.ok_or_else(|| anyhow::anyhow!("Expected deployment id"))?;

    if *deployment_id == *booted_cfs.cmdline.digest {
        anyhow::bail!("Cannot soft-reboot to currently booted deployment");
    }

    // We definitely need to re-query the state as some deployment might've been staged
    let host = composefs_deployment_status_from(storage, booted_cfs.cmdline).await?;

    let all_deployments = host.all_composefs_deployments()?;

    let requred_deployment = all_deployments
        .iter()
        .find(|entry| entry.deployment.verity == *deployment_id)
        .ok_or_else(|| anyhow::anyhow!("Deployment '{deployment_id}' not found"))?;

    if !requred_deployment.soft_reboot_capable {
        match soft_reboot_mode {
            SoftRebootMode::Required => {
                anyhow::bail!("Cannot soft-reboot to deployment with a different kernel state")
            }

            SoftRebootMode::Auto => return Ok(()),
        }
    }

    start_finalize_stated_svc()?;

    // escape to global mnt namespace
    let run = Utf8Path::new("/run");
    bind_mount_from_pidns(PID1, &run, &run, false).context("Bind mounting /run")?;

    create_dir_all(NEXTROOT).context("Creating nextroot")?;

    let cmdline = if booted_cfs.cmdline.insecure {
        Cmdline::from(format!("{COMPOSEFS_CMDLINE}=?{deployment_id}"))
    } else {
        Cmdline::from(format!("{COMPOSEFS_CMDLINE}={deployment_id}"))
    };

    let args = bootc_initramfs_setup::Args {
        cmd: vec![],
        sysroot: PathBuf::from("/sysroot"),
        config: Default::default(),
        root_fs: None,
        cmdline: Some(cmdline),
        target: Some(NEXTROOT.into()),
    };

    setup_root(args)?;

    println!("Soft reboot setup complete");

    if reboot {
        // Replacing the current process should be fine as we restart userspace anyway
        let err = Command::new("systemctl").arg("soft-reboot").exec();
        return Err(anyhow::Error::from(err).context("Failed to exec 'systemctl soft-reboot'"));
    }

    Ok(())
}
