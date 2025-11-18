use std::ffi::OsStr;
use std::fs::create_dir_all;
use std::io::Write;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use bootc_blockdev::find_parent_devices;
use bootc_kernel_cmdline::utf8::Cmdline;
use bootc_mount::inspect_filesystem_of_dir;
use bootc_mount::tempmount::TempMount;
use camino::{Utf8Path, Utf8PathBuf};
use cap_std_ext::{
    cap_std::{ambient_authority, fs::Dir},
    dirext::CapStdExtDirExt,
};
use clap::ValueEnum;
use composefs::fs::read_file;
use composefs::tree::RegularFile;
use composefs_boot::BootOps;
use composefs_boot::{
    bootloader::{PEType, EFI_ADDON_DIR_EXT, EFI_ADDON_FILE_EXT, EFI_EXT},
    uki::UkiError,
};
use fn_error_context::context;
use ostree_ext::composefs::fsverity::{FsVerityHashValue, Sha512HashValue};
use ostree_ext::composefs_boot::bootloader::UsrLibModulesVmlinuz;
use ostree_ext::composefs_boot::{
    bootloader::BootEntry as ComposefsBootEntry, cmdline::get_cmdline_composefs,
    os_release::OsReleaseInfo, uki,
};
use ostree_ext::composefs_oci::image::create_filesystem as create_composefs_filesystem;
use rustix::{mount::MountFlags, path::Arg};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::composefs_consts::{TYPE1_ENT_PATH, TYPE1_ENT_PATH_STAGED};
use crate::parsers::bls_config::{BLSConfig, BLSConfigType};
use crate::parsers::grub_menuconfig::MenuEntry;
use crate::task::Task;
use crate::{
    bootc_composefs::repo::open_composefs_repo,
    store::{ComposefsFilesystem, Storage},
};
use crate::{
    bootc_composefs::state::{get_booted_bls, write_composefs_state},
    bootloader::esp_in,
};
use crate::{bootc_composefs::status::get_sorted_grub_uki_boot_entries, install::PostFetchState};
use crate::{
    composefs_consts::{
        BOOT_LOADER_ENTRIES, COMPOSEFS_CMDLINE, ORIGIN_KEY_BOOT, ORIGIN_KEY_BOOT_DIGEST,
        STAGED_BOOT_LOADER_ENTRIES, STATE_DIR_ABS, USER_CFG, USER_CFG_STAGED,
    },
    install::RW_KARG,
    spec::{Bootloader, Host},
};

use crate::install::{RootSetup, State};

/// Contains the ESP's filesystem UUID. Used by grub
pub(crate) const EFI_UUID_FILE: &str = "efiuuid.cfg";
/// The EFI Linux directory
pub(crate) const EFI_LINUX: &str = "EFI/Linux";

/// Timeout for systemd-boot bootloader menu
const SYSTEMD_TIMEOUT: &str = "timeout 5";
const SYSTEMD_LOADER_CONF_PATH: &str = "loader/loader.conf";

const INITRD: &str = "initrd";
const VMLINUZ: &str = "vmlinuz";

/// We want to be able to control the ordering of UKIs so we put them in a directory that's not the
/// directory specified by the BLS spec. We do this because we want systemd-boot to only look at
/// our config files and not show the actual UKIs in the bootloader menu
/// This is relative to the ESP
pub(crate) const BOOTC_UKI_DIR: &str = "EFI/Linux/bootc";

pub(crate) const GLOBAL_UKI_ADDON_DIR: &str = "loader/addons";

/// Whether to install all passed in UKI Addons as global
/// For now, we don't have a reason to scope addons to a specific deployment, but we want to in the
/// future
pub const INSTALL_ADDONS_AS_GLOBAL: bool = true;

pub(crate) enum BootSetupType<'a> {
    /// For initial setup, i.e. install to-disk
    Setup(
        (
            &'a RootSetup,
            &'a State,
            &'a PostFetchState,
            &'a ComposefsFilesystem,
        ),
    ),
    /// For `bootc upgrade`
    Upgrade((&'a Storage, &'a ComposefsFilesystem, &'a Host)),
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

impl From<&ComposefsBootEntry<Sha512HashValue>> for BootType {
    fn from(entry: &ComposefsBootEntry<Sha512HashValue>) -> Self {
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

/// Returns `true` if detect the target rootfs carries a UKI.
pub(crate) fn container_root_has_uki(root: &Dir) -> Result<bool> {
    let Some(boot) = root.open_dir_optional(crate::install::BOOT)? else {
        return Ok(false);
    };
    let Some(efi_linux) = boot.open_dir_optional(EFI_LINUX)? else {
        return Ok(false);
    };
    for entry in efi_linux.entries()? {
        let entry = entry?;
        let name = entry.file_name();
        let name = Path::new(&name);
        let extension = name.extension().and_then(|v| v.to_str());
        if extension == Some("efi") {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn get_esp_partition(device: &str) -> Result<(String, Option<String>)> {
    let device_info = bootc_blockdev::partitions_of(Utf8Path::new(device))?;
    let esp = crate::bootloader::esp_in(&device_info)?;

    Ok((esp.node.clone(), esp.uuid.clone()))
}

/// Mount the ESP from the provided device
pub fn mount_esp(device: &str) -> Result<TempMount> {
    let flags = MountFlags::NOEXEC | MountFlags::NOSUID;
    TempMount::mount_dev(device, "vfat", flags, Some(c"fmask=0177,dmask=0077"))
}

pub fn get_sysroot_parent_dev(physical_root: &Dir) -> Result<String> {
    let fsinfo = inspect_filesystem_of_dir(physical_root)?;
    let parent_devices = find_parent_devices(&fsinfo.source)?;

    let Some(parent) = parent_devices.into_iter().next() else {
        anyhow::bail!("Could not find parent device of system root");
    };

    Ok(parent)
}

pub fn type1_entry_conf_file_name(sort_key: impl std::fmt::Display) -> String {
    format!("bootc-composefs-{sort_key}.conf")
}

/// Compute SHA256Sum of VMlinuz + Initrd
///
/// # Arguments
/// * entry - BootEntry containing VMlinuz and Initrd
/// * repo - The composefs repository
#[context("Computing boot digest")]
fn compute_boot_digest(
    entry: &UsrLibModulesVmlinuz<Sha512HashValue>,
    repo: &crate::store::ComposefsRepository,
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

    Ok(hex::encode(digest))
}

/// Given the SHA256 sum of current VMlinuz + Initrd combo, find boot entry with the same SHA256Sum
///
/// # Returns
/// Returns the verity of all deployments that have a boot digest same as the one passed in
#[context("Checking boot entry duplicates")]
pub(crate) fn find_vmlinuz_initrd_duplicates(digest: &str) -> Result<Option<Vec<String>>> {
    let deployments = Dir::open_ambient_dir(STATE_DIR_ABS, ambient_authority());

    let deployments = match deployments {
        Ok(d) => d,
        // The first ever deployment
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => anyhow::bail!(e),
    };

    let mut symlink_to: Option<Vec<String>> = None;

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
                    match symlink_to {
                        Some(ref mut prev) => prev.push(depl_file_name.to_string()),
                        None => symlink_to = Some(vec![depl_file_name.to_string()]),
                    }
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
    deployment_id: &Sha512HashValue,
    entry: &UsrLibModulesVmlinuz<Sha512HashValue>,
    repo: &crate::store::ComposefsRepository,
) -> Result<()> {
    let id_hex = deployment_id.to_hex();

    // Write the initrd and vmlinuz at /boot/<id>/
    let path = boot_dir.join(&id_hex);
    create_dir_all(&path)?;

    let entries_dir = Dir::open_ambient_dir(&path, ambient_authority())
        .with_context(|| format!("Opening {path}"))?;

    entries_dir
        .atomic_write(
            VMLINUZ,
            read_file(&entry.vmlinuz, &repo).context("Reading vmlinuz")?,
        )
        .context("Writing vmlinuz to path")?;

    let Some(initramfs) = &entry.initramfs else {
        anyhow::bail!("initramfs not found");
    };

    entries_dir
        .atomic_write(
            INITRD,
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

/// Parses /usr/lib/os-release and returns title and version fields
/// # Returns
/// - (title, version)
fn osrel_title_and_version(
    fs: &crate::store::ComposefsFilesystem,
    repo: &crate::store::ComposefsRepository,
) -> Result<Option<(Option<String>, Option<String>)>> {
    // Every update should have its own /usr/lib/os-release
    let (dir, fname) = fs
        .root
        .split(OsStr::new("/usr/lib/os-release"))
        .context("Getting /usr/lib/os-release")?;

    let os_release = dir
        .get_file_opt(fname)
        .context("Getting /usr/lib/os-release")?;

    let Some(os_rel_file) = os_release else {
        return Ok(None);
    };

    let file_contents = match read_file(os_rel_file, repo) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Could not read /usr/lib/os-release: {e:?}");
            return Ok(None);
        }
    };

    let file_contents = match std::str::from_utf8(&file_contents) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("/usr/lib/os-release did not have valid UTF-8: {e}");
            return Ok(None);
        }
    };

    let parsed_contents = OsReleaseInfo::parse(file_contents);

    let title = parsed_contents.get_pretty_name();
    let version = parsed_contents.get_version();

    Ok(Some((title, version)))
}

struct BLSEntryPath {
    /// Where to write vmlinuz/initrd
    entries_path: Utf8PathBuf,
    /// The absolute path, with reference to the partition's root, where the vmlinuz/initrd are written to
    abs_entries_path: Utf8PathBuf,
    /// Where to write the .conf files
    config_path: Utf8PathBuf,
}

/// Sets up and writes BLS entries and binaries (VMLinuz + Initrd) to disk
///
/// # Returns
/// Returns the SHA256Sum of VMLinuz + Initrd combo. Error if any
#[context("Setting up BLS boot")]
pub(crate) fn setup_composefs_bls_boot(
    setup_type: BootSetupType,
    repo: crate::store::ComposefsRepository,
    id: &Sha512HashValue,
    entry: &ComposefsBootEntry<Sha512HashValue>,
) -> Result<String> {
    let id_hex = id.to_hex();

    let (root_path, esp_device, cmdline_refs, fs, bootloader) = match setup_type {
        BootSetupType::Setup((root_setup, state, postfetch, fs)) => {
            // root_setup.kargs has [root=UUID=<UUID>, "rw"]
            let mut cmdline_options = Cmdline::new();

            cmdline_options.extend(&root_setup.kargs);

            let composefs_cmdline = if state.composefs_options.insecure {
                format!("{COMPOSEFS_CMDLINE}=?{id_hex}")
            } else {
                format!("{COMPOSEFS_CMDLINE}={id_hex}")
            };

            cmdline_options.extend(&Cmdline::from(&composefs_cmdline));

            // Locate ESP partition device
            let esp_part = esp_in(&root_setup.device_info)?;

            (
                root_setup.physical_root_path.clone(),
                esp_part.node.clone(),
                cmdline_options,
                fs,
                postfetch.detected_bootloader.clone(),
            )
        }

        BootSetupType::Upgrade((storage, fs, host)) => {
            let sysroot_parent = get_sysroot_parent_dev(&storage.physical_root)?;
            let bootloader = host.require_composefs_booted()?.bootloader.clone();

            (
                Utf8PathBuf::from("/sysroot"),
                get_esp_partition(&sysroot_parent)?.0,
                Cmdline::from(format!("{RW_KARG} {COMPOSEFS_CMDLINE}={id_hex}")),
                fs,
                bootloader,
            )
        }
    };

    let is_upgrade = matches!(setup_type, BootSetupType::Upgrade(..));

    let (entry_paths, _tmpdir_guard) = match bootloader {
        Bootloader::Grub => {
            let root = Dir::open_ambient_dir(&root_path, ambient_authority())
                .context("Opening root path")?;

            // Grub wants the paths to be absolute against the mounted drive that the kernel +
            // initrd live in
            //
            // If "boot" is a partition, we want the paths to be absolute to "/"
            let entries_path = match root.is_mountpoint("boot")? {
                Some(true) => "/",
                // We can be fairly sure that the kernels we target support `statx`
                Some(false) | None => "/boot",
            };

            (
                BLSEntryPath {
                    entries_path: root_path.join("boot"),
                    config_path: root_path.join("boot"),
                    abs_entries_path: entries_path.into(),
                },
                None,
            )
        }

        Bootloader::Systemd => {
            let efi_mount = mount_esp(&esp_device).context("Mounting ESP")?;

            let mounted_efi = Utf8PathBuf::from(efi_mount.dir.path().as_str()?);
            let efi_linux_dir = mounted_efi.join(EFI_LINUX);

            (
                BLSEntryPath {
                    entries_path: efi_linux_dir,
                    config_path: mounted_efi.clone(),
                    abs_entries_path: Utf8PathBuf::from("/").join(EFI_LINUX),
                },
                Some(efi_mount),
            )
        }
    };

    let (bls_config, boot_digest) = match &entry {
        ComposefsBootEntry::Type1(..) => anyhow::bail!("Found Type1 entries in /boot"),
        ComposefsBootEntry::Type2(..) => anyhow::bail!("Found UKI"),

        ComposefsBootEntry::UsrLibModulesVmLinuz(usr_lib_modules_vmlinuz) => {
            let boot_digest = compute_boot_digest(usr_lib_modules_vmlinuz, &repo)
                .context("Computing boot digest")?;

            let default_sort_key = "1";
            let default_title_version = (id.to_hex(), default_sort_key.to_string());

            let osrel_res = osrel_title_and_version(fs, &repo)?;

            let (title, version) = match osrel_res {
                Some((t, v)) => (
                    t.unwrap_or(default_title_version.0),
                    v.unwrap_or(default_title_version.1),
                ),

                None => default_title_version,
            };

            let mut bls_config = BLSConfig::default();

            bls_config
                .with_title(title)
                .with_sort_key(default_sort_key.into())
                .with_version(version)
                .with_cfg(BLSConfigType::NonUKI {
                    linux: entry_paths.abs_entries_path.join(&id_hex).join(VMLINUZ),
                    initrd: vec![entry_paths.abs_entries_path.join(&id_hex).join(INITRD)],
                    options: Some(cmdline_refs),
                });

            match find_vmlinuz_initrd_duplicates(&boot_digest)? {
                Some(symlink_to) => {
                    let symlink_to = &symlink_to[0];

                    match bls_config.cfg_type {
                        BLSConfigType::NonUKI {
                            ref mut linux,
                            ref mut initrd,
                            ..
                        } => {
                            *linux = entry_paths.abs_entries_path.join(&symlink_to).join(VMLINUZ);

                            *initrd =
                                vec![entry_paths.abs_entries_path.join(&symlink_to).join(INITRD)];
                        }

                        _ => unreachable!(),
                    };
                }

                None => {
                    write_bls_boot_entries_to_disk(
                        &entry_paths.entries_path,
                        id,
                        usr_lib_modules_vmlinuz,
                        &repo,
                    )?;
                }
            };

            (bls_config, boot_digest)
        }
    };

    let loader_path = entry_paths.config_path.join("loader");

    let (config_path, booted_bls) = if is_upgrade {
        let boot_dir = Dir::open_ambient_dir(&entry_paths.config_path, ambient_authority())?;

        let mut booted_bls = get_booted_bls(&boot_dir)?;
        booted_bls.sort_key = Some("0".into()); // entries are sorted by their filename in reverse order

        // This will be atomically renamed to 'loader/entries' on shutdown/reboot
        (
            loader_path.join(STAGED_BOOT_LOADER_ENTRIES),
            Some(booted_bls),
        )
    } else {
        (loader_path.join(BOOT_LOADER_ENTRIES), None)
    };

    create_dir_all(&config_path).with_context(|| format!("Creating {:?}", config_path))?;

    let loader_entries_dir = Dir::open_ambient_dir(&config_path, ambient_authority())
        .with_context(|| format!("Opening {config_path:?}"))?;

    loader_entries_dir.atomic_write(
        // SAFETY: We set sort_key above
        type1_entry_conf_file_name(bls_config.sort_key.as_ref().unwrap()),
        bls_config.to_string().as_bytes(),
    )?;

    if let Some(booted_bls) = booted_bls {
        loader_entries_dir.atomic_write(
            // SAFETY: We set sort_key above
            type1_entry_conf_file_name(booted_bls.sort_key.as_ref().unwrap()),
            booted_bls.to_string().as_bytes(),
        )?;
    }

    let owned_loader_entries_fd = loader_entries_dir
        .reopen_as_ownedfd()
        .context("Reopening as owned fd")?;

    rustix::fs::fsync(owned_loader_entries_fd).context("fsync")?;

    Ok(boot_digest)
}

struct UKILabels {
    boot_label: String,
    version: Option<String>,
}

/// Writes a PortableExecutable to ESP along with any PE specific or Global addons
#[context("Writing {file_path} to ESP")]
fn write_pe_to_esp(
    repo: &crate::store::ComposefsRepository,
    file: &RegularFile<Sha512HashValue>,
    file_path: &Utf8Path,
    pe_type: PEType,
    uki_id: &Sha512HashValue,
    is_insecure_from_opts: bool,
    mounted_efi: impl AsRef<Path>,
) -> Result<Option<UKILabels>> {
    let efi_bin = read_file(file, &repo).context("Reading .efi binary")?;

    let mut boot_label: Option<UKILabels> = None;

    // UKI Extension might not even have a cmdline
    // TODO: UKI Addon might also have a composefs= cmdline?
    if matches!(pe_type, PEType::Uki) {
        let cmdline = uki::get_cmdline(&efi_bin).context("Getting UKI cmdline")?;

        let (composefs_cmdline, insecure) =
            get_cmdline_composefs::<Sha512HashValue>(cmdline).context("Parsing composefs=")?;

        // If the UKI cmdline does not match what the user has passed as cmdline option
        // NOTE: This will only be checked for new installs and now upgrades/switches
        match is_insecure_from_opts {
            true if !insecure => {
                tracing::warn!("--insecure passed as option but UKI cmdline does not support it");
            }

            false if insecure => {
                tracing::warn!("UKI cmdline has composefs set as insecure");
            }

            _ => { /* no-op */ }
        }

        if composefs_cmdline != *uki_id {
            anyhow::bail!(
                "The UKI has the wrong composefs= parameter (is '{composefs_cmdline:?}', should be {uki_id:?})"
            );
        }

        let osrel = uki::get_text_section(&efi_bin, ".osrel")
            .ok_or(UkiError::PortableExecutableError)??;

        let parsed_osrel = OsReleaseInfo::parse(osrel);

        boot_label = Some(UKILabels {
            boot_label: uki::get_boot_label(&efi_bin).context("Getting UKI boot label")?,
            version: parsed_osrel.get_version(),
        });
    }

    // Directory to write the PortableExecutable to
    let pe_install_dir = mounted_efi.as_ref().join(match pe_type {
        PEType::UkiAddon if INSTALL_ADDONS_AS_GLOBAL => GLOBAL_UKI_ADDON_DIR,
        PEType::Uki | PEType::UkiAddon => BOOTC_UKI_DIR,
    });

    create_dir_all(&pe_install_dir)
        .with_context(|| format!("Creating {}", pe_install_dir.display()))?;

    let final_pe_path = match (INSTALL_ADDONS_AS_GLOBAL, file_path.parent()) {
        (true, ..) => pe_install_dir,

        (false, Some(parent)) => {
            let renamed_path = match parent.as_str().ends_with(EFI_ADDON_DIR_EXT) {
                true => {
                    let dir_name = format!("{}{}", uki_id.to_hex(), EFI_ADDON_DIR_EXT);

                    parent
                        .parent()
                        .map(|p| p.join(&dir_name))
                        .unwrap_or(dir_name.into())
                }

                false => parent.to_path_buf(),
            };

            let full_path = pe_install_dir.join(renamed_path);
            create_dir_all(&full_path)?;

            full_path
        }

        (false, None) => pe_install_dir,
    };

    let pe_dir = Dir::open_ambient_dir(&final_pe_path, ambient_authority())
        .with_context(|| format!("Opening {final_pe_path:?}"))?;

    let pe_name = match pe_type {
        PEType::Uki => &format!("{}{}", uki_id.to_hex(), EFI_EXT),
        PEType::UkiAddon => file_path
            .components()
            .last()
            .ok_or_else(|| anyhow::anyhow!("Failed to get UKI Addon file name"))?
            .as_str(),
    };

    pe_dir
        .atomic_write(pe_name, efi_bin)
        .context("Writing UKI")?;

    rustix::fs::fsync(
        pe_dir
            .reopen_as_ownedfd()
            .context("Reopening as owned fd")?,
    )
    .context("fsync")?;

    Ok(boot_label)
}

#[context("Writing Grub menuentry")]
fn write_grub_uki_menuentry(
    root_path: Utf8PathBuf,
    setup_type: &BootSetupType,
    boot_label: String,
    id: &Sha512HashValue,
    esp_device: &String,
) -> Result<()> {
    let boot_dir = root_path.join("boot");
    create_dir_all(&boot_dir).context("Failed to create boot dir")?;

    let is_upgrade = matches!(setup_type, BootSetupType::Upgrade(..));

    let efi_uuid_source = get_efi_uuid_source();

    let user_cfg_name = if is_upgrade {
        USER_CFG_STAGED
    } else {
        USER_CFG
    };

    let grub_dir = Dir::open_ambient_dir(boot_dir.join("grub2"), ambient_authority())
        .context("opening boot/grub2")?;

    // Iterate over all available deployments, and generate a menuentry for each
    if is_upgrade {
        let mut str_buf = String::new();
        let boot_dir =
            Dir::open_ambient_dir(boot_dir, ambient_authority()).context("Opening boot dir")?;
        let entries = get_sorted_grub_uki_boot_entries(&boot_dir, &mut str_buf)?;

        grub_dir
            .atomic_replace_with(user_cfg_name, |f| -> std::io::Result<_> {
                f.write_all(efi_uuid_source.as_bytes())?;
                f.write_all(
                    MenuEntry::new(&boot_label, &id.to_hex())
                        .to_string()
                        .as_bytes(),
                )?;

                // Write out only the currently booted entry, which should be the very first one
                // Even if we have booted into the second menuentry "boot entry", the default will be the
                // first one
                f.write_all(entries[0].to_string().as_bytes())?;

                Ok(())
            })
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
    grub_dir
        .atomic_replace_with(user_cfg_name, |f| -> std::io::Result<_> {
            f.write_all(efi_uuid_source.as_bytes())?;
            f.write_all(
                MenuEntry::new(&boot_label, &id.to_hex())
                    .to_string()
                    .as_bytes(),
            )?;

            Ok(())
        })
        .with_context(|| format!("Writing to {user_cfg_name}"))?;

    rustix::fs::fsync(grub_dir.reopen_as_ownedfd()?).context("fsync")?;

    Ok(())
}

#[context("Writing systemd UKI config")]
fn write_systemd_uki_config(
    esp_dir: &Dir,
    setup_type: &BootSetupType,
    boot_label: UKILabels,
    id: &Sha512HashValue,
) -> Result<()> {
    let default_sort_key = "0";

    let mut bls_conf = BLSConfig::default();
    bls_conf
        .with_title(boot_label.boot_label)
        .with_cfg(BLSConfigType::UKI {
            uki: format!("/{BOOTC_UKI_DIR}/{}{}", id.to_hex(), EFI_EXT).into(),
        })
        .with_sort_key(default_sort_key.into())
        .with_version(boot_label.version.unwrap_or(default_sort_key.into()));

    let (entries_dir, booted_bls) = match setup_type {
        BootSetupType::Setup(..) => {
            esp_dir
                .create_dir_all(TYPE1_ENT_PATH)
                .with_context(|| format!("Creating {TYPE1_ENT_PATH}"))?;

            (esp_dir.open_dir(TYPE1_ENT_PATH)?, None)
        }

        BootSetupType::Upgrade(_) => {
            esp_dir
                .create_dir_all(TYPE1_ENT_PATH_STAGED)
                .with_context(|| format!("Creating {TYPE1_ENT_PATH_STAGED}"))?;

            let mut booted_bls = get_booted_bls(&esp_dir)?;
            booted_bls.sort_key = Some("1".into());

            (esp_dir.open_dir(TYPE1_ENT_PATH_STAGED)?, Some(booted_bls))
        }
    };

    entries_dir
        .atomic_write(
            type1_entry_conf_file_name(default_sort_key),
            bls_conf.to_string().as_bytes(),
        )
        .context("Writing conf file")?;

    if let Some(booted_bls) = booted_bls {
        entries_dir.atomic_write(
            // SAFETY: We set sort_key above
            type1_entry_conf_file_name(booted_bls.sort_key.as_ref().unwrap()),
            booted_bls.to_string().as_bytes(),
        )?;
    }

    // Write the timeout for bootloader menu if not exists
    if !esp_dir.exists(SYSTEMD_LOADER_CONF_PATH) {
        esp_dir
            .atomic_write(SYSTEMD_LOADER_CONF_PATH, SYSTEMD_TIMEOUT)
            .with_context(|| format!("Writing to {SYSTEMD_LOADER_CONF_PATH}"))?;
    }

    let esp_dir = esp_dir
        .reopen_as_ownedfd()
        .context("Reopening as owned fd")?;
    rustix::fs::fsync(esp_dir).context("fsync")?;

    Ok(())
}

#[context("Setting up UKI boot")]
pub(crate) fn setup_composefs_uki_boot(
    setup_type: BootSetupType,
    repo: crate::store::ComposefsRepository,
    id: &Sha512HashValue,
    entries: Vec<ComposefsBootEntry<Sha512HashValue>>,
) -> Result<()> {
    let (root_path, esp_device, bootloader, is_insecure_from_opts, uki_addons) = match setup_type {
        BootSetupType::Setup((root_setup, state, postfetch, ..)) => {
            state.require_no_kargs_for_uki()?;

            let esp_part = esp_in(&root_setup.device_info)?;

            (
                root_setup.physical_root_path.clone(),
                esp_part.node.clone(),
                postfetch.detected_bootloader.clone(),
                state.composefs_options.insecure,
                state.composefs_options.uki_addon.as_ref(),
            )
        }

        BootSetupType::Upgrade((storage, _, host)) => {
            let sysroot = Utf8PathBuf::from("/sysroot"); // Still needed for root_path
            let sysroot_parent = get_sysroot_parent_dev(&storage.physical_root)?;
            let bootloader = host.require_composefs_booted()?.bootloader.clone();

            (
                sysroot,
                get_esp_partition(&sysroot_parent)?.0,
                bootloader,
                false,
                None,
            )
        }
    };

    let esp_mount = mount_esp(&esp_device).context("Mounting ESP")?;

    let mut uki_label: Option<UKILabels> = None;

    for entry in entries {
        match entry {
            ComposefsBootEntry::Type1(..) => tracing::debug!("Skipping Type1 Entry"),
            ComposefsBootEntry::UsrLibModulesVmLinuz(..) => {
                tracing::debug!("Skipping vmlinuz in /usr/lib/modules")
            }

            ComposefsBootEntry::Type2(entry) => {
                // If --uki-addon is not passed, we don't install any addon
                if matches!(entry.pe_type, PEType::UkiAddon) {
                    let Some(addons) = uki_addons else {
                        continue;
                    };

                    let addon_name = entry
                        .file_path
                        .components()
                        .last()
                        .ok_or_else(|| anyhow::anyhow!("Could not get UKI addon name"))?;

                    let addon_name = addon_name.as_str()?;

                    let addon_name =
                        addon_name.strip_suffix(EFI_ADDON_FILE_EXT).ok_or_else(|| {
                            anyhow::anyhow!("UKI addon doesn't end with {EFI_ADDON_DIR_EXT}")
                        })?;

                    if !addons.iter().any(|passed_addon| passed_addon == addon_name) {
                        tracing::debug!("Skipping addon '{addon_name}'");
                        continue;
                    }
                }

                let utf8_file_path = Utf8Path::from_path(&entry.file_path)
                    .ok_or_else(|| anyhow::anyhow!("Path is not valid UTf8"))?;

                let ret = write_pe_to_esp(
                    &repo,
                    &entry.file,
                    utf8_file_path,
                    entry.pe_type,
                    &id,
                    is_insecure_from_opts,
                    esp_mount.dir.path(),
                )?;

                if let Some(label) = ret {
                    uki_label = Some(label);
                }
            }
        };
    }

    let uki_label = uki_label
        .ok_or_else(|| anyhow::anyhow!("Failed to get version and boot label from UKI"))?;

    match bootloader {
        Bootloader::Grub => write_grub_uki_menuentry(
            root_path,
            &setup_type,
            uki_label.boot_label,
            id,
            &esp_device,
        )?,

        Bootloader::Systemd => write_systemd_uki_config(&esp_mount.fd, &setup_type, uki_label, id)?,
    };

    Ok(())
}

#[context("Setting up composefs boot")]
pub(crate) fn setup_composefs_boot(
    root_setup: &RootSetup,
    state: &State,
    image_id: &str,
) -> Result<()> {
    let repo = open_composefs_repo(&root_setup.physical_root)?;
    let mut fs = create_composefs_filesystem(&repo, image_id, None)?;
    let entries = fs.transform_for_boot(&repo)?;
    let id = fs.commit_image(&repo, None)?;
    let mounted_fs = Dir::reopen_dir(
        &repo
            .mount(&id.to_hex())
            .context("Failed to mount composefs image")?,
    )?;

    let postfetch = PostFetchState::new(state, &mounted_fs)?;

    let boot_uuid = root_setup
        .get_boot_uuid()?
        .or(root_setup.rootfs_uuid.as_deref())
        .ok_or_else(|| anyhow!("No uuid for boot/root"))?;

    if cfg!(target_arch = "s390x") {
        // TODO: Integrate s390x support into install_via_bootupd
        crate::bootloader::install_via_zipl(&root_setup.device_info, boot_uuid)?;
    } else if postfetch.detected_bootloader == Bootloader::Grub {
        crate::bootloader::install_via_bootupd(
            &root_setup.device_info,
            &root_setup.physical_root_path,
            &state.config_opts,
            None,
        )?;
    } else {
        crate::bootloader::install_systemd_boot(
            &root_setup.device_info,
            &root_setup.physical_root_path,
            &state.config_opts,
            None,
        )?;
    }

    let Some(entry) = entries.iter().next() else {
        anyhow::bail!("No boot entries!");
    };

    let boot_type = BootType::from(entry);
    let mut boot_digest: Option<String> = None;

    match boot_type {
        BootType::Bls => {
            let digest = setup_composefs_bls_boot(
                BootSetupType::Setup((&root_setup, &state, &postfetch, &fs)),
                repo,
                &id,
                entry,
            )?;

            boot_digest = Some(digest);
        }
        BootType::Uki => setup_composefs_uki_boot(
            BootSetupType::Setup((&root_setup, &state, &postfetch, &fs)),
            repo,
            &id,
            entries,
        )?,
    };

    write_composefs_state(
        &root_setup.physical_root_path,
        id,
        &crate::spec::ImageReference::from(state.target_imgref.clone()),
        false,
        boot_type,
        boot_digest,
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std_ext::cap_std;

    #[test]
    fn test_root_has_uki() -> Result<()> {
        // Test case 1: No boot directory
        let tempdir = cap_std_ext::cap_tempfile::tempdir(cap_std::ambient_authority())?;
        assert_eq!(container_root_has_uki(&tempdir)?, false);

        // Test case 2: boot directory exists but no EFI/Linux
        tempdir.create_dir(crate::install::BOOT)?;
        assert_eq!(container_root_has_uki(&tempdir)?, false);

        // Test case 3: boot/EFI/Linux exists but no .efi files
        tempdir.create_dir_all("boot/EFI/Linux")?;
        assert_eq!(container_root_has_uki(&tempdir)?, false);

        // Test case 4: boot/EFI/Linux exists with non-.efi file
        tempdir.atomic_write("boot/EFI/Linux/readme.txt", b"some file")?;
        assert_eq!(container_root_has_uki(&tempdir)?, false);

        // Test case 5: boot/EFI/Linux exists with .efi file
        tempdir.atomic_write("boot/EFI/Linux/bootx64.efi", b"fake efi binary")?;
        assert_eq!(container_root_has_uki(&tempdir)?, true);

        Ok(())
    }
}
