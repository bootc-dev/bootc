use std::os::unix::fs::symlink;
use std::{fs::create_dir_all, process::Command};

use anyhow::{Context, Result};
use bootc_initramfs_setup::overlay_transient;
use bootc_kernel_cmdline::utf8::Cmdline;
use bootc_mount::tempmount::TempMount;
use bootc_utils::CommandRunExt;
use camino::Utf8PathBuf;
use cap_std_ext::cap_std::ambient_authority;
use cap_std_ext::cap_std::fs::Dir;
use cap_std_ext::dirext::CapStdExtDirExt;
use composefs::fsverity::{FsVerityHashValue, Sha256HashValue};
use fn_error_context::context;

use ostree_ext::container::deploy::ORIGIN_CONTAINER;
use rustix::{
    fs::{open, Mode, OFlags},
    path::Arg,
};

use crate::bootc_composefs::boot::BootType;
use crate::bootc_composefs::repo::get_imgref;
use crate::bootc_composefs::status::get_sorted_type1_boot_entries;
use crate::parsers::bls_config::BLSConfigType;
use crate::{
    composefs_consts::{
        COMPOSEFS_CMDLINE, COMPOSEFS_STAGED_DEPLOYMENT_FNAME, COMPOSEFS_TRANSIENT_STATE_DIR,
        ORIGIN_KEY_BOOT, ORIGIN_KEY_BOOT_DIGEST, ORIGIN_KEY_BOOT_TYPE, SHARED_VAR_PATH,
        STATE_DIR_RELATIVE,
    },
    parsers::bls_config::BLSConfig,
    spec::ImageReference,
    utils::path_relative_to,
};

pub(crate) fn get_booted_bls(boot_dir: &Dir) -> Result<BLSConfig> {
    let cmdline = Cmdline::from_proc()?;
    let booted = cmdline
        .find(COMPOSEFS_CMDLINE)
        .ok_or_else(|| anyhow::anyhow!("Failed to find composefs parameter in kernel cmdline"))?;

    let sorted_entries = get_sorted_type1_boot_entries(boot_dir, true)?;

    for entry in sorted_entries {
        match &entry.cfg_type {
            BLSConfigType::EFI { efi } => {
                let composfs_param_value = booted.value().ok_or(anyhow::anyhow!(
                    "Failed to get composefs kernel cmdline value"
                ))?;

                if efi.contains(composfs_param_value) {
                    return Ok(entry);
                }
            }

            BLSConfigType::NonEFI { options, .. } => {
                let Some(opts) = options else {
                    anyhow::bail!("options not found in bls config")
                };

                let opts = Cmdline::from(opts);

                if opts.iter().any(|v| v == booted) {
                    return Ok(entry);
                }
            }

            BLSConfigType::Unknown => anyhow::bail!("Unknown BLS Config type"),
        };
    }

    Err(anyhow::anyhow!("Booted BLS not found"))
}

/// Mounts an EROFS image and copies the pristine /etc to the deployment's /etc
#[context("Copying etc")]
pub(crate) fn copy_etc_to_state(
    sysroot_path: &Utf8PathBuf,
    erofs_id: &String,
    state_path: &Utf8PathBuf,
) -> Result<()> {
    let sysroot_fd = open(
        sysroot_path.as_std_path(),
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context("Opening sysroot")?;

    let composefs_fd = bootc_initramfs_setup::mount_composefs_image(&sysroot_fd, &erofs_id, false)?;

    let tempdir = TempMount::mount_fd(composefs_fd)?;

    // TODO: Replace this with a function to cap_std_ext
    let cp_ret = Command::new("cp")
        .args([
            "-a",
            &format!("{}/etc/.", tempdir.dir.path().as_str()?),
            &format!("{state_path}/etc/."),
        ])
        .run_capture_stderr();

    cp_ret
}

/// Creates and populates /sysroot/state/deploy/image_id
#[context("Writing composefs state")]
pub(crate) fn write_composefs_state(
    root_path: &Utf8PathBuf,
    deployment_id: Sha256HashValue,
    imgref: &ImageReference,
    staged: bool,
    boot_type: BootType,
    boot_digest: Option<String>,
) -> Result<()> {
    let state_path = root_path.join(format!("{STATE_DIR_RELATIVE}/{}", deployment_id.to_hex()));

    create_dir_all(state_path.join("etc"))?;

    copy_etc_to_state(&root_path, &deployment_id.to_hex(), &state_path)?;

    let actual_var_path = root_path.join(SHARED_VAR_PATH);
    create_dir_all(&actual_var_path)?;

    symlink(
        path_relative_to(state_path.as_std_path(), actual_var_path.as_std_path())
            .context("Getting var symlink path")?,
        state_path.join("var"),
    )
    .context("Failed to create symlink for /var")?;

    let ImageReference {
        image: image_name,
        transport,
        ..
    } = &imgref;

    let imgref = get_imgref(&transport, &image_name);

    let mut config = tini::Ini::new().section("origin").item(
        ORIGIN_CONTAINER,
        // TODO (Johan-Liebert1): The image won't always be unverified
        format!("ostree-unverified-image:{imgref}"),
    );

    config = config
        .section(ORIGIN_KEY_BOOT)
        .item(ORIGIN_KEY_BOOT_TYPE, boot_type);

    if let Some(boot_digest) = boot_digest {
        config = config
            .section(ORIGIN_KEY_BOOT)
            .item(ORIGIN_KEY_BOOT_DIGEST, boot_digest);
    }

    let state_dir =
        Dir::open_ambient_dir(&state_path, ambient_authority()).context("Opening state dir")?;

    state_dir
        .atomic_write(
            format!("{}.origin", deployment_id.to_hex()),
            config.to_string().as_bytes(),
        )
        .context("Failed to write to .origin file")?;

    if staged {
        std::fs::create_dir_all(COMPOSEFS_TRANSIENT_STATE_DIR)
            .with_context(|| format!("Creating {COMPOSEFS_TRANSIENT_STATE_DIR}"))?;

        let staged_depl_dir =
            Dir::open_ambient_dir(COMPOSEFS_TRANSIENT_STATE_DIR, ambient_authority())
                .with_context(|| format!("Opening {COMPOSEFS_TRANSIENT_STATE_DIR}"))?;

        staged_depl_dir
            .atomic_write(
                COMPOSEFS_STAGED_DEPLOYMENT_FNAME,
                deployment_id.to_hex().as_bytes(),
            )
            .with_context(|| format!("Writing to {COMPOSEFS_STAGED_DEPLOYMENT_FNAME}"))?;
    }

    Ok(())
}

pub(crate) fn composefs_usr_overlay() -> Result<()> {
    let usr = Dir::open_ambient_dir("/usr", ambient_authority()).context("Opening /usr")?;
    let is_usr_mounted = usr
        .is_mountpoint(".")
        .context("Failed to get mount details for /usr")?;

    let is_usr_mounted =
        is_usr_mounted.ok_or_else(|| anyhow::anyhow!("Falied to get mountinfo"))?;

    if is_usr_mounted {
        println!("A writeable overlayfs is already mounted on /usr");
        return Ok(());
    }

    overlay_transient(usr)?;

    println!("A writeable overlayfs is now mounted on /usr");
    println!("All changes there will be discarded on reboot.");

    Ok(())
}
