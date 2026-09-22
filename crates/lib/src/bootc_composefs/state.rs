use std::io::Write;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::{fs::create_dir_all, process::Command};

use anyhow::{Context, Result};
use bootc_initramfs_setup::{mount_at_wrapper, overlay_transient};
use bootc_mount::tempmount::TempMount;
use bootc_utils::CommandRunExt;
use camino::Utf8PathBuf;
use canon_json::CanonJsonSerialize;
use cap_std_ext::cap_std::ambient_authority;
use cap_std_ext::cap_std::fs::{Dir, Permissions, PermissionsExt};
use cap_std_ext::dirext::CapStdExtDirExt;
use composefs::fsverity::{FsVerityHashValue, Sha512HashValue};
use composefs_ctl::composefs;
use fn_error_context::context;
use linux_kernel_cmdline::utf8::Cmdline;

use ostree_ext::container::deploy::ORIGIN_CONTAINER;
use rustix::{
    fd::AsFd,
    fs::{Mode, OFlags, StatVfsMountFlags, open},
    mount::MountAttrFlags,
    path::Arg,
};

use crate::bootc_composefs::boot::BootType;
use crate::bootc_composefs::status::{
    ComposefsCmdline, StagedDeployment, get_sorted_type1_boot_entries,
};
use crate::parsers::bls_config::{BLSConfigType, EFIKey};
use crate::store::{BootedComposefs, Storage};
use crate::{
    composefs_consts::{
        COMPOSEFS_CMDLINE, COMPOSEFS_STAGED_DEPLOYMENT_FNAME, COMPOSEFS_TRANSIENT_STATE_DIR,
        ORIGIN_KEY_BOOT, ORIGIN_KEY_BOOT_DIGEST, ORIGIN_KEY_BOOT_TYPE, ORIGIN_KEY_IMAGE,
        ORIGIN_KEY_MANIFEST_DIGEST, SHARED_VAR_PATH, STATE_DIR_RELATIVE,
    },
    parsers::bls_config::BLSConfig,
    spec::ImageReference,
    spec::{FilesystemOverlay, FilesystemOverlayAccessMode, FilesystemOverlayPersistence},
    utils::path_relative_to,
};

/// Read and parse the `.origin` INI file for a deployment.
///
/// Returns `None` if the state directory or origin file doesn't exist
/// (e.g. the deployment was partially deleted).
#[context("Reading origin for deployment {deployment_id}")]
pub(crate) fn read_origin(sysroot: &Dir, deployment_id: &str) -> Result<Option<tini::Ini>> {
    let depl_state_path = std::path::PathBuf::from(STATE_DIR_RELATIVE).join(deployment_id);

    let Some(state_dir) = sysroot.open_dir_optional(&depl_state_path)? else {
        return Ok(None);
    };

    let origin_filename = format!("{deployment_id}.origin");
    let Some(origin_contents) = state_dir.read_to_string_optional(&origin_filename)? else {
        return Ok(None);
    };

    let ini = tini::Ini::from_string(&origin_contents).context("Failed to parse origin file")?;
    Ok(Some(ini))
}

/// Whether `entry` boots the deployment identified by `booted_cfs`.
fn entry_has_verity(entry: &BLSConfig, booted_cfs: &ComposefsCmdline) -> Result<bool> {
    match &entry.cfg_type {
        BLSConfigType::EFI { key } => {
            let path = match key {
                EFIKey::Efi(path) | EFIKey::Uki(path) => path,
            };
            Ok(path.as_str().contains(&*booted_cfs.digest))
        }

        BLSConfigType::NonEFI { options, .. } => {
            let Some(opts) = options else {
                anyhow::bail!("options not found in bls config")
            };

            let cfs_cmdline = ComposefsCmdline::find_in_cmdline(&Cmdline::from(opts))
                .ok_or_else(|| anyhow::anyhow!("composefs param not found in cmdline"))?;

            Ok(cfs_cmdline.digest == booted_cfs.digest)
        }

        BLSConfigType::Unknown => anyhow::bail!("Unknown BLS Config type"),
    }
}

/// The number of `options` parameters when every one of them is on
/// `kernel_cmdline`, else `None`.  `composefs=` is skipped: after a soft
/// reboot the command line still names the previous deployment.
fn options_on_cmdline(options: &Cmdline, kernel_cmdline: &Cmdline) -> Option<usize> {
    let mut n = 0;
    for param in options {
        if param.key() == COMPOSEFS_CMDLINE.into() {
            continue;
        }
        let present = kernel_cmdline
            .iter()
            .any(|k| k.key() == param.key() && k.value() == param.value());
        if !present {
            return None;
        }
        n += 1;
    }
    Some(n)
}

/// Pick the entry the running kernel was booted from.
///
/// Entries are matched by their `composefs=` digest.  A kernel-argument
/// change (`bootc loader-entries set-options-for-source`) keeps the previous
/// entry of the booted deployment as its rollback, so several entries can
/// share the digest; then the one whose `options` are all on the kernel
/// command line wins, and among those the largest set, so an entry that only
/// lacks an added argument is not mistaken for the booted one.  When none
/// matches, the first candidate in `entries` order is returned.
pub(crate) fn select_booted_bls<'a>(
    entries: impl IntoIterator<Item = &'a BLSConfig>,
    booted_cfs: &ComposefsCmdline,
    kernel_cmdline: &Cmdline,
) -> Result<Option<&'a BLSConfig>> {
    let mut best: Option<(&BLSConfig, Option<usize>)> = None;
    for entry in entries {
        if !entry_has_verity(entry, booted_cfs)? {
            continue;
        }
        let score = entry
            .get_cmdline()
            .ok()
            .and_then(|options| options_on_cmdline(options, kernel_cmdline));
        match best {
            Some((_, current)) if score <= current => {}
            _ => best = Some((entry, score)),
        }
    }
    Ok(best.map(|(entry, _)| entry))
}

pub(crate) fn get_booted_bls(boot_dir: &Dir, booted_cfs: &BootedComposefs) -> Result<BLSConfig> {
    let sorted_entries = get_sorted_type1_boot_entries(boot_dir, true)?;
    let kernel_cmdline = Cmdline::from_proc()?;

    select_booted_bls(&sorted_entries, booted_cfs.cmdline, &kernel_cmdline)?
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Booted BLS not found"))
}

/// Mounts an EROFS image and copies the pristine /etc and /var to the deployment's /etc and /var.
/// Only copies /var for initial installation of deployments (non-staged deployments)
#[context("Initializing /etc and /var for state")]
pub(crate) fn initialize_state(
    sysroot_path: &Utf8PathBuf,
    erofs_id: &String,
    state_path: &Utf8PathBuf,
    initialize_var: bool,
    allow_missing_fsverity: bool,
) -> Result<()> {
    let sysroot_fd = open(
        sysroot_path.as_std_path(),
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context("Opening sysroot")?;

    let composefs_fd = bootc_initramfs_setup::mount_composefs_image(
        &sysroot_fd,
        &erofs_id,
        allow_missing_fsverity,
    )?;

    let tempdir = TempMount::mount_fd(composefs_fd)?;

    // TODO: Replace this with a function to cap_std_ext
    if initialize_var {
        Command::new("cp")
            .args([
                "-a",
                "--remove-destination",
                &format!("{}/var/.", tempdir.dir.path().as_str()?),
                &format!("{state_path}/var/."),
            ])
            .run_capture_stderr()?;
    }

    Command::new("cp")
        .args([
            "-a",
            "--remove-destination",
            &format!("{}/etc/.", tempdir.dir.path().as_str()?),
            &format!("{state_path}/etc/."),
        ])
        .run_capture_stderr()?;

    // Remove /etc/.updated so that ConditionNeedsUpdate=|/etc services
    // (e.g. systemd-sysusers, systemd-tmpfiles) run on the first boot of
    // this deployment, mirroring what ostree does in sysroot_finalize_deployment.
    // Without this, systemd sees /etc/.updated from the container image and
    // concludes /etc is already up-to-date, causing sysusers to be skipped.
    let state_etc = Dir::open_ambient_dir(format!("{state_path}/etc"), ambient_authority())
        .context("Opening state etc dir")?;
    state_etc
        .remove_file_optional(".updated")
        .context("Removing /etc/.updated")?;

    Ok(())
}

/// Adds or updates the provided key/value pairs in the .origin file of the deployment pointed to
/// by the `deployment_id`
fn add_update_in_origin(
    storage: &Storage,
    deployment_id: &str,
    section: &str,
    kv_pairs: &[(&str, &str)],
) -> Result<()> {
    let path = Path::new(STATE_DIR_RELATIVE).join(deployment_id);

    let state_dir = storage
        .physical_root
        .open_dir(path)
        .context("Opening state dir")?;

    let origin_filename = format!("{deployment_id}.origin");

    let origin_file = state_dir
        .read_to_string(&origin_filename)
        .context("Reading origin file")?;

    let mut ini =
        tini::Ini::from_string(&origin_file).context("Failed to parse file origin file as ini")?;

    for (key, value) in kv_pairs {
        ini = ini.section(section).item(*key, *value);
    }

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

pub(crate) fn update_boot_digest_in_origin(
    storage: &Storage,
    digest: &str,
    boot_digest: &str,
) -> Result<()> {
    add_update_in_origin(
        storage,
        digest,
        ORIGIN_KEY_BOOT,
        &[(ORIGIN_KEY_BOOT_DIGEST, boot_digest)],
    )
}

/// Record `staged` as the deployment to finalize at shutdown
#[context("Recording staged deployment")]
pub(crate) fn write_staged_deployment(staged: &StagedDeployment) -> Result<()> {
    std::fs::create_dir_all(COMPOSEFS_TRANSIENT_STATE_DIR)
        .with_context(|| format!("Creating {COMPOSEFS_TRANSIENT_STATE_DIR}"))?;

    let staged_depl_dir = Dir::open_ambient_dir(COMPOSEFS_TRANSIENT_STATE_DIR, ambient_authority())
        .with_context(|| format!("Opening {COMPOSEFS_TRANSIENT_STATE_DIR}"))?;

    staged_depl_dir
        .atomic_write(
            COMPOSEFS_STAGED_DEPLOYMENT_FNAME,
            staged
                .to_canon_json_vec()
                .context("Failed to serialize staged deployment JSON")?,
        )
        .with_context(|| format!("Writing to {COMPOSEFS_STAGED_DEPLOYMENT_FNAME}"))
}

/// Creates and populates the composefs state directory for a deployment.
///
/// This function sets up the state directory structure and configuration files
/// needed for a composefs deployment. It creates the deployment state directory,
/// copies configuration, sets up the shared `/var` directory, and writes metadata
/// files including the origin configuration and image information.
///
/// # Arguments
///
/// * `root_path`         - The root filesystem path (typically `/sysroot`)
/// * `deployment_id`     - Unique SHA512 hash identifier for this deployment
/// * `imgref`            - Container image reference for the deployment
/// * `staged`            - Whether this is a staged deployment (writes to transient state dir)
/// * `boot_type`         - Boot loader type (`Bls` or `Uki`)
/// * `boot_digest`       - Optional boot digest for verification
/// * `manifest_digest`   - OCI manifest content digest, stored in the origin file so the
///                         manifest+config can be retrieved from the composefs repo later
///
/// # State Directory Structure
///
/// Creates the following structure under `/sysroot/state/deploy/{deployment_id}/`:
/// * `etc/`                    - Copy of system configuration files
/// * `var`                     - Symlink to shared `/var` directory
/// * `{deployment_id}.origin`  - Origin configuration with image ref, boot, and image metadata
///
/// For staged deployments, also writes to `/run/composefs/staged-deployment`.
#[context("Writing composefs state")]
pub(crate) async fn write_composefs_state(
    root_path: &Utf8PathBuf,
    deployment_id: &Sha512HashValue,
    target_imgref: &ImageReference,
    staged: Option<StagedDeployment>,
    boot_type: BootType,
    boot_digest: String,
    manifest_digest: &str,
    allow_missing_fsverity: bool,
) -> Result<()> {
    let state_path = root_path
        .join(STATE_DIR_RELATIVE)
        .join(deployment_id.to_hex());

    create_dir_all(state_path.join("etc"))?;

    let actual_var_path = root_path.join(SHARED_VAR_PATH);
    create_dir_all(&actual_var_path)?;

    symlink(
        path_relative_to(state_path.as_std_path(), actual_var_path.as_std_path())
            .context("Getting var symlink path")?,
        state_path.join("var"),
    )
    .context("Failed to create symlink for /var")?;

    initialize_state(
        &root_path,
        &deployment_id.to_hex(),
        &state_path,
        staged.is_none(),
        allow_missing_fsverity,
    )?;

    let imgref = target_imgref.to_image_proxy_ref()?;

    let mut config = tini::Ini::new().section("origin").item(
        ORIGIN_CONTAINER,
        // TODO (Johan-Liebert1): The image won't always be unverified
        format!("ostree-unverified-image:{imgref}"),
    );

    config = config
        .section(ORIGIN_KEY_BOOT)
        .item(ORIGIN_KEY_BOOT_TYPE, boot_type);

    config = config
        .section(ORIGIN_KEY_BOOT)
        .item(ORIGIN_KEY_BOOT_DIGEST, boot_digest);

    // Store the OCI manifest digest so we can retrieve the manifest+config
    // from the composefs repository later (composefs-rs stores them as splitstreams).
    config = config
        .section(ORIGIN_KEY_IMAGE)
        .item(ORIGIN_KEY_MANIFEST_DIGEST, manifest_digest);

    let state_dir =
        Dir::open_ambient_dir(&state_path, ambient_authority()).context("Opening state dir")?;

    state_dir
        .atomic_write(
            format!("{}.origin", deployment_id.to_hex()),
            config.to_string().as_bytes(),
        )
        .context("Failed to write to .origin file")?;

    if let Some(staged) = staged {
        write_staged_deployment(&staged)?;
    }

    Ok(())
}

pub(crate) fn composefs_usr_overlay(access_mode: FilesystemOverlayAccessMode) -> Result<()> {
    let status = get_composefs_usr_overlay_status()?;
    if status.is_some() {
        println!("An overlayfs is already mounted on /usr");
        return Ok(());
    }

    let usr = Dir::open_ambient_dir("/usr", ambient_authority()).context("Opening /usr")?;

    let mount_attr_flags = match access_mode {
        FilesystemOverlayAccessMode::ReadOnly => Some(MountAttrFlags::MOUNT_ATTR_RDONLY),
        FilesystemOverlayAccessMode::ReadWrite => None,
    };

    let overlay_fd = overlay_transient(usr.as_fd(), "transient", mount_attr_flags)?;
    mount_at_wrapper(overlay_fd, &usr, ".").context("Attaching /usr overlay")?;

    println!("A {} overlayfs is now mounted on /usr", access_mode);
    println!("All changes there will be discarded on reboot.");

    Ok(())
}

pub(crate) fn get_composefs_usr_overlay_status() -> Result<Option<FilesystemOverlay>> {
    let usr = Dir::open_ambient_dir("/usr", ambient_authority()).context("Opening /usr")?;
    let is_usr_mounted = usr
        .is_mountpoint(".")
        .context("Failed to get mount details for /usr")?
        .ok_or_else(|| anyhow::anyhow!("Failed to get mountinfo"))?;

    if is_usr_mounted {
        let st =
            rustix::fs::fstatvfs(usr.as_fd()).context("Failed to get filesystem info for /usr")?;
        let permissions = if st.f_flag.contains(StatVfsMountFlags::RDONLY) {
            FilesystemOverlayAccessMode::ReadOnly
        } else {
            FilesystemOverlayAccessMode::ReadWrite
        };
        // For the composefs backend, assume the /usr overlay is always transient.
        Ok(Some(FilesystemOverlay {
            access_mode: permissions,
            persistence: FilesystemOverlayPersistence::Transient,
        }))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::bls_config::parse_bls_config;

    const DIGEST: &str = "aaaa";
    const OTHER: &str = "bbbb";

    fn entry(options: &str) -> BLSConfig {
        parse_bls_config(&format!(
            "title t\nversion 1\nlinux /vmlinuz\ninitrd /initrd\noptions {options}\n"
        ))
        .unwrap()
    }

    #[test]
    fn select_booted_bls_prefers_the_entry_matching_the_cmdline() -> Result<()> {
        let booted = ComposefsCmdline::new(DIGEST);
        let other = entry(&format!("root=/dev/a rw composefs={OTHER} nohz=full"));
        let old = entry(&format!("root=/dev/a rw composefs={DIGEST}"));
        let new = entry(&format!("root=/dev/a rw composefs={DIGEST} nohz=full"));
        let entries = vec![other.clone(), old.clone(), new.clone()];

        let cases = [
            // The added argument is on the cmdline: the larger set wins even
            // though the smaller one is a subset too.
            (
                format!("BOOT_IMAGE=/vmlinuz root=/dev/a rw composefs={DIGEST} nohz=full"),
                &new,
            ),
            // Rolled back to the entry without it.
            (format!("root=/dev/a rw composefs={DIGEST}"), &old),
            // Soft reboot: composefs= still names the previous deployment.
            (format!("root=/dev/a rw composefs={OTHER} nohz=full"), &new),
            // Nothing matches: first candidate with the digest.
            ("root=/dev/b rw".to_string(), &old),
        ];
        for (cmdline, expected) in cases {
            let picked = select_booted_bls(&entries, &booted, &Cmdline::from(&cmdline))?
                .unwrap_or_else(|| panic!("no entry for {cmdline}"));
            assert_eq!(picked, expected, "cmdline {cmdline}");
        }

        assert!(select_booted_bls(&[other], &booted, &Cmdline::from("x"))?.is_none());
        Ok(())
    }
}
