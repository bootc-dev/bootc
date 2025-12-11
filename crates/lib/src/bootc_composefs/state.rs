use std::io::Write;
use std::ops::Deref;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::{fs::create_dir_all, process::Command};

use anyhow::{Context, Result};
use bootc_initramfs_setup::overlay_transient;
use bootc_kernel_cmdline::utf8::Cmdline;
use bootc_mount::tempmount::TempMount;
use bootc_utils::CommandRunExt;
use camino::Utf8PathBuf;
use cap_std_ext::cap_std::ambient_authority;
use cap_std_ext::cap_std::fs::{Dir, Permissions, PermissionsExt};
use cap_std_ext::dirext::CapStdExtDirExt;
use composefs::fsverity::{FsVerityHashValue, Sha512HashValue};
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
use crate::store::{BootedComposefs, Storage};
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
                let composefs_param_value = booted.value().ok_or_else(|| {
                    anyhow::anyhow!("Failed to get composefs kernel cmdline value")
                })?;

                if efi.as_str().contains(composefs_param_value) {
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
            "--remove-destination",
            &format!("{}/etc/.", tempdir.dir.path().as_str()?),
            &format!("{state_path}/etc/."),
        ])
        .run_capture_stderr();

    cp_ret
}

/// Updates the currently booted image's target imgref
pub(crate) fn update_target_imgref_in_origin(
    storage: &Storage,
    booted_cfs: &BootedComposefs,
    imgref: &ImageReference,
) -> Result<()> {
    let path = Path::new(STATE_DIR_RELATIVE).join(booted_cfs.cmdline.digest.deref());

    let state_dir = storage
        .physical_root
        .open_dir(path)
        .context("Opening state dir")?;

    let origin_filename = format!("{}.origin", booted_cfs.cmdline.digest.deref());

    let origin_file = state_dir
        .read_to_string(&origin_filename)
        .context("Reading origin file")?;

    let mut ini =
        tini::Ini::from_string(&origin_file).context("Failed to parse file origin file as ini")?;

    // Replace the origin
    ini = ini.section("origin").item(
        ORIGIN_CONTAINER,
        format!("ostree-unverified-image:{imgref}"),
    );

    state_dir
        .atomic_replace_with(origin_filename, move |f| -> std::io::Result<_> {
            f.write_all(ini.to_string().as_bytes())?;
            f.flush()?;

            let perms = Permissions::from_mode(0o644);
            f.get_mut().as_file_mut().set_permissions(perms)?;

            Ok(())
        })
        .context("Writing to origin file")?;

    Ok(())
}

/// Creates and populates /sysroot/state/deploy/image_id
#[context("Writing composefs state")]
pub(crate) fn write_composefs_state(
    root_path: &Utf8PathBuf,
    deployment_id: Sha512HashValue,
    imgref: &ImageReference,
    staged: bool,
    boot_type: BootType,
    boot_digest: Option<String>,
) -> Result<()> {
    let state_path = root_path
        .join(STATE_DIR_RELATIVE)
        .join(deployment_id.to_hex());

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
        is_usr_mounted.ok_or_else(|| anyhow::anyhow!("Failed to get mountinfo"))?;

    if is_usr_mounted {
        println!("A writeable overlayfs is already mounted on /usr");
        return Ok(());
    }

    // Get the mode from the underlying /usr directory
    let usr_metadata = usr.metadata(".").context("Getting /usr metadata")?;
    let usr_mode = Mode::from_raw_mode(usr_metadata.permissions().mode());

    overlay_transient(usr, Some(usr_mode))?;

    println!("A writeable overlayfs is now mounted on /usr");
    println!("All changes there will be discarded on reboot.");

    Ok(())
}
