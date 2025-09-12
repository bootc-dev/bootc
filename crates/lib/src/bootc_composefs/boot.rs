use std::fs::create_dir_all;
use std::io::Write;
use std::process::Command;
use std::{ffi::OsStr, path::PathBuf};

use anyhow::{anyhow, Context, Result};
use bootc_blockdev::find_parent_devices;
use bootc_mount::inspect_filesystem;
use bootc_utils::CommandRunExt;
use camino::{Utf8Path, Utf8PathBuf};
use cap_std_ext::{cap_std, dirext::CapStdExtDirExt};
use clap::ValueEnum;
use composefs::fs::read_file;
use composefs::tree::FileSystem;
use composefs_boot::BootOps;
use fn_error_context::context;
use ostree_ext::composefs::{
    fsverity::{FsVerityHashValue, Sha256HashValue},
    repository::Repository as ComposefsRepository,
};
use ostree_ext::composefs_boot::bootloader::UsrLibModulesVmlinuz;
use ostree_ext::composefs_boot::{
    bootloader::BootEntry as ComposefsBootEntry, cmdline::get_cmdline_composefs,
    os_release::OsReleaseInfo, uki,
};
use ostree_ext::composefs_oci::image::create_filesystem as create_composefs_filesystem;
use rustix::path::Arg;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::bootc_composefs::repo::open_composefs_repo;
use crate::bootc_composefs::state::{get_booted_bls, write_composefs_state};
use crate::bootc_composefs::status::get_sorted_uki_boot_entries;
use crate::parsers::bls_config::BLSConfig;
use crate::parsers::grub_menuconfig::MenuEntry;
use crate::spec::ImageReference;
use crate::task::Task;
use crate::{
    composefs_consts::{
        BOOT_LOADER_ENTRIES, COMPOSEFS_CMDLINE, ORIGIN_KEY_BOOT, ORIGIN_KEY_BOOT_DIGEST,
        STAGED_BOOT_LOADER_ENTRIES, STATE_DIR_ABS, USER_CFG, USER_CFG_STAGED,
    },
    install::{DPS_UUID, ESP_GUID, RW_KARG},
    spec::{Bootloader, Host},
};

use crate::install::{RootSetup, State};

/// Contains the EFP's filesystem UUID. Used by grub
pub(crate) const EFI_UUID_FILE: &str = "efiuuid.cfg";
/// The EFI Linux directory
const EFI_LINUX: &str = "EFI/Linux";

pub(crate) enum BootSetupType<'a> {
    /// For initial setup, i.e. install to-disk
    Setup((&'a RootSetup, &'a State, &'a FileSystem<Sha256HashValue>)),
    /// For `bootc upgrade`
    Upgrade((&'a FileSystem<Sha256HashValue>, &'a Host)),
}

#[derive(
    ValueEnum, Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema,
)]
pub enum BootType {
    #[default]
    Bls,
    Uki,
}

impl ::std::fmt::Display for BootType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            BootType::Bls => "bls",
            BootType::Uki => "uki",
        };

        write!(f, "{}", s)
    }
}

impl TryFrom<&str> for BootType {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        match value {
            "bls" => Ok(Self::Bls),
            "uki" => Ok(Self::Uki),
            unrecognized => Err(anyhow::anyhow!(
                "Unrecognized boot option: '{unrecognized}'"
            )),
        }
    }
}

impl From<&ComposefsBootEntry<Sha256HashValue>> for BootType {
    fn from(entry: &ComposefsBootEntry<Sha256HashValue>) -> Self {
        match entry {
            ComposefsBootEntry::Type1(..) => Self::Bls,
            ComposefsBootEntry::Type2(..) => Self::Uki,
            ComposefsBootEntry::UsrLibModulesVmLinuz(..) => Self::Bls,
        }
    }
}

/// Returns the beginning of the grub2/user.cfg file
/// where we source a file containing the ESPs filesystem UUID
pub(crate) fn get_efi_uuid_source() -> String {
    format!(
        r#"
if [ -f ${{config_directory}}/{EFI_UUID_FILE} ]; then
        source ${{config_directory}}/{EFI_UUID_FILE}
fi
"#
    )
}

pub fn get_esp_partition(device: &str) -> Result<(String, Option<String>)> {
    let device_info = bootc_blockdev::partitions_of(Utf8Path::new(device))?;
    let esp = device_info
        .partitions
        .into_iter()
        .find(|p| p.parttype.as_str() == ESP_GUID)
        .ok_or(anyhow::anyhow!("ESP not found for device: {device}"))?;

    Ok((esp.node, esp.uuid))
}

pub fn get_sysroot_parent_dev() -> Result<String> {
    let sysroot = Utf8PathBuf::from("/sysroot");

    let fsinfo = inspect_filesystem(&sysroot)?;
    let parent_devices = find_parent_devices(&fsinfo.source)?;

    let Some(parent) = parent_devices.into_iter().next() else {
        anyhow::bail!("Could not find parent device for mountpoint /sysroot");
    };

    return Ok(parent);
}

/// Compute SHA256Sum of VMlinuz + Initrd
///
/// # Arguments
/// * entry - BootEntry containing VMlinuz and Initrd
/// * repo - The composefs repository
#[context("Computing boot digest")]
fn compute_boot_digest(
    entry: &UsrLibModulesVmlinuz<Sha256HashValue>,
    repo: &ComposefsRepository<Sha256HashValue>,
) -> Result<String> {
    let vmlinuz = read_file(&entry.vmlinuz, &repo).context("Reading vmlinuz")?;

    let Some(initramfs) = &entry.initramfs else {
        anyhow::bail!("initramfs not found");
    };

    let initramfs = read_file(initramfs, &repo).context("Reading intird")?;

    let mut hasher = openssl::hash::Hasher::new(openssl::hash::MessageDigest::sha256())
        .context("Creating hasher")?;

    hasher.update(&vmlinuz).context("hashing vmlinuz")?;
    hasher.update(&initramfs).context("hashing initrd")?;

    let digest: &[u8] = &hasher.finish().context("Finishing digest")?;

    return Ok(hex::encode(digest));
}

/// Given the SHA256 sum of current VMlinuz + Initrd combo, find boot entry with the same SHA256Sum
///
/// # Returns
/// Returns the verity of the deployment that has a boot digest same as the one passed in
#[context("Checking boot entry duplicates")]
fn find_vmlinuz_initrd_duplicates(digest: &str) -> Result<Option<String>> {
    let deployments =
        cap_std::fs::Dir::open_ambient_dir(STATE_DIR_ABS, cap_std::ambient_authority());

    let deployments = match deployments {
        Ok(d) => d,
        // The first ever deployment
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => anyhow::bail!(e),
    };

    let mut symlink_to: Option<String> = None;

    for depl in deployments.entries()? {
        let depl = depl?;

        let depl_file_name = depl.file_name();
        let depl_file_name = depl_file_name.as_str()?;

        let config = depl
            .open_dir()
            .with_context(|| format!("Opening {depl_file_name}"))?
            .read_to_string(format!("{depl_file_name}.origin"))
            .context("Reading origin file")?;

        let ini = tini::Ini::from_string(&config)
            .with_context(|| format!("Failed to parse file {depl_file_name}.origin as ini"))?;

        match ini.get::<String>(ORIGIN_KEY_BOOT, ORIGIN_KEY_BOOT_DIGEST) {
            Some(hash) => {
                if hash == digest {
                    symlink_to = Some(depl_file_name.to_string());
                    break;
                }
            }

            // No SHASum recorded in origin file
            // `symlink_to` is already none, but being explicit here
            None => symlink_to = None,
        };
    }

    Ok(symlink_to)
}

#[context("Writing BLS entries to disk")]
fn write_bls_boot_entries_to_disk(
    boot_dir: &Utf8PathBuf,
    deployment_id: &Sha256HashValue,
    entry: &UsrLibModulesVmlinuz<Sha256HashValue>,
    repo: &ComposefsRepository<Sha256HashValue>,
) -> Result<()> {
    let id_hex = deployment_id.to_hex();

    // Write the initrd and vmlinuz at /boot/<id>/
    let path = boot_dir.join(&id_hex);
    create_dir_all(&path)?;

    let entries_dir = cap_std::fs::Dir::open_ambient_dir(&path, cap_std::ambient_authority())
        .with_context(|| format!("Opening {path}"))?;

    entries_dir
        .atomic_write(
            "vmlinuz",
            read_file(&entry.vmlinuz, &repo).context("Reading vmlinuz")?,
        )
        .context("Writing vmlinuz to path")?;

    let Some(initramfs) = &entry.initramfs else {
        anyhow::bail!("initramfs not found");
    };

    entries_dir
        .atomic_write(
            "initrd",
            read_file(initramfs, &repo).context("Reading initrd")?,
        )
        .context("Writing initrd to path")?;

    // Can't call fsync on O_PATH fds, so re-open it as a non O_PATH fd
    let owned_fd = entries_dir
        .reopen_as_ownedfd()
        .context("Reopen as owned fd")?;

    rustix::fs::fsync(owned_fd).context("fsync")?;

    Ok(())
}

struct BLSEntryPath<'a> {
    /// Where to write vmlinuz/initrd
    entries_path: Utf8PathBuf,
    /// The absolute path, with reference to the partition's root, where the vmlinuz/initrd are written to
    /// We need this as when installing, the mounted path will not
    abs_entries_path: &'a str,
    /// Where to write the .conf files
    config_path: Utf8PathBuf,
    /// If we mounted EFI, the target path
    mount_path: Option<Utf8PathBuf>,
}

/// Sets up and writes BLS entries and binaries (VMLinuz + Initrd) to disk
///
/// # Returns
/// Returns the SHA256Sum of VMLinuz + Initrd combo. Error if any
#[context("Setting up BLS boot")]
pub(crate) fn setup_composefs_bls_boot(
    setup_type: BootSetupType,
    // TODO: Make this generic
    repo: ComposefsRepository<Sha256HashValue>,
    id: &Sha256HashValue,
    entry: ComposefsBootEntry<Sha256HashValue>,
) -> Result<String> {
    let id_hex = id.to_hex();

    let (root_path, esp_device, cmdline_refs, fs, bootloader) = match setup_type {
        BootSetupType::Setup((root_setup, state, fs)) => {
            // root_setup.kargs has [root=UUID=<UUID>, "rw"]
            let mut cmdline_options = String::from(root_setup.kargs.join(" "));

            match &state.composefs_options {
                Some(opt) if opt.insecure => {
                    cmdline_options.push_str(&format!(" {COMPOSEFS_CMDLINE}=?{id_hex}"));
                }
                None | Some(..) => {
                    cmdline_options.push_str(&format!(" {COMPOSEFS_CMDLINE}={id_hex}"));
                }
            };

            // Locate ESP partition device
            let esp_part = root_setup
                .device_info
                .partitions
                .iter()
                .find(|p| p.parttype.as_str() == ESP_GUID)
                .ok_or_else(|| anyhow::anyhow!("ESP partition not found"))?;

            (
                root_setup.physical_root_path.clone(),
                esp_part.node.clone(),
                cmdline_options,
                fs,
                state
                    .composefs_options
                    .as_ref()
                    .map(|opts| opts.bootloader.clone())
                    .unwrap_or(Bootloader::default()),
            )
        }

        BootSetupType::Upgrade((fs, host)) => {
            let sysroot_parent = get_sysroot_parent_dev()?;
            let bootloader = host.require_composefs_booted()?.bootloader.clone();

            (
                Utf8PathBuf::from("/sysroot"),
                get_esp_partition(&sysroot_parent)?.0,
                [
                    format!("root=UUID={DPS_UUID}"),
                    RW_KARG.to_string(),
                    format!("{COMPOSEFS_CMDLINE}={id_hex}"),
                ]
                .join(" "),
                fs,
                bootloader,
            )
        }
    };

    let is_upgrade = matches!(setup_type, BootSetupType::Upgrade(..));

    let (entry_paths, _tmpdir_guard) = match bootloader {
        Bootloader::Grub => (
            BLSEntryPath {
                entries_path: root_path.join("boot"),
                config_path: root_path.join("boot"),
                abs_entries_path: "boot",
                mount_path: None,
            },
            None,
        ),

        Bootloader::Systemd => {
            let temp_efi_dir = tempfile::tempdir().map_err(|e| {
                anyhow::anyhow!("Failed to create temporary directory for EFI mount: {e}")
            })?;

            let mounted_efi = Utf8PathBuf::from_path_buf(temp_efi_dir.path().to_path_buf())
                .map_err(|_| anyhow::anyhow!("EFI dir is not valid UTF-8"))?;

            Command::new("mount")
                .args([&PathBuf::from(&esp_device), mounted_efi.as_std_path()])
                .log_debug()
                .run_inherited_with_cmd_context()
                .context("Mounting EFI")?;

            let efi_linux_dir = mounted_efi.join(EFI_LINUX);

            (
                BLSEntryPath {
                    entries_path: efi_linux_dir,
                    config_path: mounted_efi.clone(),
                    abs_entries_path: EFI_LINUX,
                    mount_path: Some(mounted_efi),
                },
                Some(temp_efi_dir),
            )
        }
    };

    let (bls_config, boot_digest) = match &entry {
        ComposefsBootEntry::Type1(..) => unimplemented!(),
        ComposefsBootEntry::Type2(..) => unimplemented!(),

        ComposefsBootEntry::UsrLibModulesVmLinuz(usr_lib_modules_vmlinuz) => {
            let boot_digest = compute_boot_digest(usr_lib_modules_vmlinuz, &repo)
                .context("Computing boot digest")?;

            // Every update should have its own /usr/lib/os-release
            let (dir, fname) = fs
                .root
                .split(OsStr::new("/usr/lib/os-release"))
                .context("Getting /usr/lib/os-release")?;

            let os_release = dir
                .get_file_opt(fname)
                .context("Getting /usr/lib/os-release")?;

            let version = os_release.and_then(|os_rel_file| {
                let file_contents = match read_file(os_rel_file, &repo) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!("Could not read /usr/lib/os-release: {e:?}");
                        return None;
                    }
                };

                let file_contents = match std::str::from_utf8(&file_contents) {
                    Ok(c) => c,
                    Err(..) => {
                        tracing::warn!("/usr/lib/os-release did not have valid UTF-8");
                        return None;
                    }
                };

                OsReleaseInfo::parse(file_contents).get_version()
            });

            let default_sort_key = "1";

            let mut bls_config = BLSConfig::default();

            bls_config
                .with_title(id_hex.clone())
                .with_sort_key(default_sort_key.into())
                .with_version(version.unwrap_or(default_sort_key.into()))
                .with_linux(format!(
                    "/{}/{id_hex}/vmlinuz",
                    entry_paths.abs_entries_path
                ))
                .with_initrd(vec![format!(
                    "/{}/{id_hex}/initrd",
                    entry_paths.abs_entries_path
                )])
                .with_options(cmdline_refs);

            if let Some(symlink_to) = find_vmlinuz_initrd_duplicates(&boot_digest)? {
                bls_config.linux =
                    format!("/{}/{symlink_to}/vmlinuz", entry_paths.abs_entries_path);

                bls_config.initrd = vec![format!(
                    "/{}/{symlink_to}/initrd",
                    entry_paths.abs_entries_path
                )];
            } else {
                write_bls_boot_entries_to_disk(
                    &entry_paths.entries_path,
                    id,
                    usr_lib_modules_vmlinuz,
                    &repo,
                )?;
            }

            (bls_config, boot_digest)
        }
    };

    let (config_path, booted_bls) = if is_upgrade {
        let mut booted_bls = get_booted_bls()?;
        booted_bls.sort_key = Some("0".into()); // entries are sorted by their filename in reverse order

        // This will be atomically renamed to 'loader/entries' on shutdown/reboot
        (
            entry_paths
                .config_path
                .join("loader")
                .join(STAGED_BOOT_LOADER_ENTRIES),
            Some(booted_bls),
        )
    } else {
        (
            entry_paths
                .config_path
                .join("loader")
                .join(BOOT_LOADER_ENTRIES),
            None,
        )
    };

    create_dir_all(&config_path).with_context(|| format!("Creating {:?}", config_path))?;

    // Scope to allow for proper unmounting
    {
        let loader_entries_dir =
            cap_std::fs::Dir::open_ambient_dir(&config_path, cap_std::ambient_authority())
                .with_context(|| format!("Opening {config_path:?}"))?;

        loader_entries_dir.atomic_write(
            // SAFETY: We set sort_key above
            format!(
                "bootc-composefs-{}.conf",
                bls_config.sort_key.as_ref().unwrap()
            ),
            bls_config.to_string().as_bytes(),
        )?;

        if let Some(booted_bls) = booted_bls {
            loader_entries_dir.atomic_write(
                // SAFETY: We set sort_key above
                format!(
                    "bootc-composefs-{}.conf",
                    booted_bls.sort_key.as_ref().unwrap()
                ),
                booted_bls.to_string().as_bytes(),
            )?;
        }

        let owned_loader_entries_fd = loader_entries_dir
            .reopen_as_ownedfd()
            .context("Reopening as owned fd")?;

        rustix::fs::fsync(owned_loader_entries_fd).context("fsync")?;
    }

    if let Some(mounted_efi) = entry_paths.mount_path {
        Command::new("umount")
            .arg(mounted_efi)
            .log_debug()
            .run_inherited_with_cmd_context()
            .context("Unmounting EFI")?;
    }

    Ok(boot_digest)
}

#[context("Setting up UKI boot")]
pub(crate) fn setup_composefs_uki_boot(
    setup_type: BootSetupType,
    // TODO: Make this generic
    repo: ComposefsRepository<Sha256HashValue>,
    id: &Sha256HashValue,
    entry: ComposefsBootEntry<Sha256HashValue>,
) -> Result<()> {
    let (root_path, esp_device, is_insecure_from_opts) = match setup_type {
        BootSetupType::Setup((root_setup, state, ..)) => {
            if let Some(v) = &state.config_opts.karg {
                if v.len() > 0 {
                    tracing::warn!("kargs passed for UKI will be ignored");
                }
            }

            let esp_part = root_setup
                .device_info
                .partitions
                .iter()
                .find(|p| p.parttype.as_str() == ESP_GUID)
                .ok_or_else(|| anyhow!("ESP partition not found"))?;

            (
                root_setup.physical_root_path.clone(),
                esp_part.node.clone(),
                state.composefs_options.as_ref().map(|x| x.insecure),
            )
        }

        BootSetupType::Upgrade(..) => {
            let sysroot = Utf8PathBuf::from("/sysroot");
            let sysroot_parent = get_sysroot_parent_dev()?;

            (sysroot, get_esp_partition(&sysroot_parent)?.0, None)
        }
    };

    let temp_efi_dir = tempfile::tempdir()
        .map_err(|e| anyhow::anyhow!("Failed to create temporary directory for EFI mount: {e}"))?;
    let mounted_efi = temp_efi_dir.path().to_path_buf();

    Task::new("Mounting ESP", "mount")
        .args([&PathBuf::from(&esp_device), &mounted_efi.clone()])
        .run()?;

    let boot_label = match entry {
        ComposefsBootEntry::Type1(..) => unimplemented!(),
        ComposefsBootEntry::UsrLibModulesVmLinuz(..) => unimplemented!(),

        ComposefsBootEntry::Type2(type2_entry) => {
            let uki = read_file(&type2_entry.file, &repo).context("Reading UKI")?;
            let cmdline = uki::get_cmdline(&uki).context("Getting UKI cmdline")?;
            let (composefs_cmdline, insecure) = get_cmdline_composefs::<Sha256HashValue>(cmdline)?;

            // If the UKI cmdline does not match what the user has passed as cmdline option
            // NOTE: This will only be checked for new installs and now upgrades/switches
            if let Some(is_insecure_from_opts) = is_insecure_from_opts {
                match is_insecure_from_opts {
                    true => {
                        if !insecure {
                            tracing::warn!(
                                "--insecure passed as option but UKI cmdline does not support it"
                            )
                        }
                    }

                    false => {
                        if insecure {
                            tracing::warn!("UKI cmdline has composefs set as insecure")
                        }
                    }
                }
            }

            let boot_label = uki::get_boot_label(&uki).context("Getting UKI boot label")?;

            if composefs_cmdline != *id {
                anyhow::bail!(
                    "The UKI has the wrong composefs= parameter (is '{composefs_cmdline:?}', should be {id:?})"
                );
            }

            // Write the UKI to ESP
            let efi_linux_path = mounted_efi.join(EFI_LINUX);
            create_dir_all(&efi_linux_path).context("Creating EFI/Linux")?;

            let efi_linux =
                cap_std::fs::Dir::open_ambient_dir(&efi_linux_path, cap_std::ambient_authority())
                    .with_context(|| format!("Opening {efi_linux_path:?}"))?;

            efi_linux
                .atomic_write(format!("{}.efi", id.to_hex()), uki)
                .context("Writing UKI")?;

            rustix::fs::fsync(
                efi_linux
                    .reopen_as_ownedfd()
                    .context("Reopening as owned fd")?,
            )
            .context("fsync")?;

            boot_label
        }
    };

    Command::new("umount")
        .arg(&mounted_efi)
        .log_debug()
        .run_inherited_with_cmd_context()
        .context("Unmounting ESP")?;

    let boot_dir = root_path.join("boot");
    create_dir_all(&boot_dir).context("Failed to create boot dir")?;

    let is_upgrade = matches!(setup_type, BootSetupType::Upgrade(..));

    let efi_uuid_source = get_efi_uuid_source();

    let user_cfg_name = if is_upgrade {
        USER_CFG_STAGED
    } else {
        USER_CFG
    };

    let grub_dir =
        cap_std::fs::Dir::open_ambient_dir(boot_dir.join("grub2"), cap_std::ambient_authority())
            .context("opening boot/grub2")?;

    // Iterate over all available deployments, and generate a menuentry for each
    //
    // TODO: We might find a staged deployment here
    if is_upgrade {
        let mut buffer = vec![];

        // Shouldn't really fail so no context here
        buffer.write_all(efi_uuid_source.as_bytes())?;
        buffer.write_all(
            MenuEntry::new(&boot_label, &id.to_hex())
                .to_string()
                .as_bytes(),
        )?;

        let mut str_buf = String::new();
        let boot_dir = cap_std::fs::Dir::open_ambient_dir(boot_dir, cap_std::ambient_authority())
            .context("Opening boot dir")?;
        let entries = get_sorted_uki_boot_entries(&boot_dir, &mut str_buf)?;

        // Write out only the currently booted entry, which should be the very first one
        // Even if we have booted into the second menuentry "boot entry", the default will be the
        // first one
        buffer.write_all(entries[0].to_string().as_bytes())?;

        grub_dir
            .atomic_write(user_cfg_name, buffer)
            .with_context(|| format!("Writing to {user_cfg_name}"))?;

        rustix::fs::fsync(grub_dir.reopen_as_ownedfd()?).context("fsync")?;

        return Ok(());
    }

    // Open grub2/efiuuid.cfg and write the EFI partition fs-UUID in there
    // This will be sourced by grub2/user.cfg to be used for `--fs-uuid`
    let esp_uuid = Task::new("blkid for ESP UUID", "blkid")
        .args(["-s", "UUID", "-o", "value", &esp_device])
        .read()?;

    grub_dir.atomic_write(
        EFI_UUID_FILE,
        format!("set EFI_PART_UUID=\"{}\"", esp_uuid.trim()).as_bytes(),
    )?;

    // Write to grub2/user.cfg
    let mut buffer = vec![];

    // Shouldn't really fail so no context here
    buffer.write_all(efi_uuid_source.as_bytes())?;
    buffer.write_all(
        MenuEntry::new(&boot_label, &id.to_hex())
            .to_string()
            .as_bytes(),
    )?;

    grub_dir
        .atomic_write(user_cfg_name, buffer)
        .with_context(|| format!("Writing to {user_cfg_name}"))?;

    rustix::fs::fsync(grub_dir.reopen_as_ownedfd()?).context("fsync")?;

    Ok(())
}

#[context("Setting up composefs boot")]
pub(crate) fn setup_composefs_boot(
    root_setup: &RootSetup,
    state: &State,
    image_id: &str,
) -> Result<()> {
    let boot_uuid = root_setup
        .get_boot_uuid()?
        .or(root_setup.rootfs_uuid.as_deref())
        .ok_or_else(|| anyhow!("No uuid for boot/root"))?;

    if cfg!(target_arch = "s390x") {
        // TODO: Integrate s390x support into install_via_bootupd
        crate::bootloader::install_via_zipl(&root_setup.device_info, boot_uuid)?;
    } else {
        crate::bootloader::install_via_bootupd(
            &root_setup.device_info,
            &root_setup.physical_root_path,
            &state.config_opts,
            None,
        )?;
    }

    let repo = open_composefs_repo(&root_setup.physical_root)?;

    let mut fs = create_composefs_filesystem(&repo, image_id, None)?;

    let entries = fs.transform_for_boot(&repo)?;
    let id = fs.commit_image(&repo, None)?;

    let Some(entry) = entries.into_iter().next() else {
        anyhow::bail!("No boot entries!");
    };

    let boot_type = BootType::from(&entry);
    let mut boot_digest: Option<String> = None;

    match boot_type {
        BootType::Bls => {
            let digest = setup_composefs_bls_boot(
                BootSetupType::Setup((&root_setup, &state, &fs)),
                repo,
                &id,
                entry,
            )?;

            boot_digest = Some(digest);
        }
        BootType::Uki => setup_composefs_uki_boot(
            BootSetupType::Setup((&root_setup, &state, &fs)),
            repo,
            &id,
            entry,
        )?,
    };

    write_composefs_state(
        &root_setup.physical_root_path,
        id,
        &ImageReference {
            image: state.source.imageref.name.clone(),
            transport: state.source.imageref.transport.to_string(),
            signature: None,
        },
        false,
        boot_type,
        boot_digest,
    )?;

    Ok(())
}
