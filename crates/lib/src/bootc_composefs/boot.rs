//! Composefs boot setup and configuration.
//!
//! This module handles setting up boot entries for composefs-based deployments,
//! including generating BLS (Boot Loader Specification) entries, copying kernel/initrd
//! files, managing UKI (Unified Kernel Images), and configuring the ESP (EFI System
//! Partition).
//!
//! ## Boot Ordering
//!
//! A critical aspect of this module is boot entry ordering, which must work correctly
//! across both Grub and systemd-boot bootloaders despite their fundamentally different
//! sorting behaviors.
//!
//! ## Critical Context: Grub's Filename Parsing
//!
//! **Grub does NOT read BLS fields** - it parses the filename as an RPM package name!
//! See: <https://github.com/ostreedev/ostree/issues/2961>
//!
//! Grub's `split_package_string()` parsing algorithm:
//! 1. Strip `.conf` suffix
//! 2. Find LAST `-` → extract **release** field
//! 3. Find SECOND-TO-LAST `-` → extract **version** field
//! 4. Remainder → **name** field
//!
//! Example: `kernel-5.14.0-362.fc38.conf`
//! - name: `kernel`
//! - version: `5.14.0`
//! - release: `362.fc38`
//!
//! **Critical:** Grub sorts by (name, version, release) in DESCENDING order.
//!
//! ## Bootloader Differences
//!
//! ### Grub
//! - Ignores BLS sort-key field completely
//! - Parses filename to extract name-version-release
//! - Sorts by (name, version, release) DESCENDING
//! - Any `-` in name/version gets incorrectly split
//!
//! ### Systemd-boot
//! - Reads BLS sort-key field
//! - Sorts by sort-key ASCENDING (A→Z, 0→9)
//! - Filename is mostly irrelevant
//!
//! ## Implementation Strategy
//!
//! **Filenames** (for Grub's RPM-style parsing and descending sort):
//! - Format: `bootc_{os_id}-{version}-{priority}.conf`
//! - Replace `-` with `_` in os_id to prevent mis-parsing
//! - Primary: `bootc_fedora-41.20251125.0-1.conf` → (name=bootc_fedora, version=41.20251125.0, release=1)
//! - Secondary: `bootc_fedora-41.20251124.0-0.conf` → (name=bootc_fedora, version=41.20251124.0, release=0)
//! - Grub sorts: Primary (release=1) > Secondary (release=0) when versions equal
//!
//! **Sort-keys** (for systemd-boot's ascending sort):
//! - Primary: `bootc-{os_id}-0` (lower value, sorts first)
//! - Secondary: `bootc-{os_id}-1` (higher value, sorts second)
//!
//! ## Boot Entry Ordering
//!
//! After an upgrade, both bootloaders show:
//! 1. **Primary**: New/upgraded deployment (default boot target)
//! 2. **Secondary**: Currently booted deployment (rollback option)

use std::ffi::OsStr;
use std::fs::create_dir_all;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use bootc_blockdev::find_parent_devices;
use bootc_kernel_cmdline::utf8::{Cmdline, Parameter};
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
use composefs_boot::bootloader::{EFI_ADDON_DIR_EXT, EFI_ADDON_FILE_EXT, EFI_EXT, PEType};
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

use crate::parsers::bls_config::{BLSConfig, BLSConfigType};
use crate::parsers::grub_menuconfig::MenuEntry;
use crate::task::Task;
use crate::{
    bootc_composefs::repo::get_imgref,
    composefs_consts::{TYPE1_ENT_PATH, TYPE1_ENT_PATH_STAGED},
};
use crate::{
    bootc_composefs::repo::open_composefs_repo,
    store::{ComposefsFilesystem, Storage},
};
use crate::{
    bootc_composefs::state::{get_booted_bls, write_composefs_state},
    bootloader::esp_in,
};
use crate::{
    bootc_composefs::status::get_container_manifest_and_config, bootc_kargs::compute_new_kargs,
};
use crate::{bootc_composefs::status::get_sorted_grub_uki_boot_entries, install::PostFetchState};
use crate::{
    composefs_consts::{
        BOOT_LOADER_ENTRIES, COMPOSEFS_CMDLINE, ORIGIN_KEY_BOOT, ORIGIN_KEY_BOOT_DIGEST,
        STAGED_BOOT_LOADER_ENTRIES, STATE_DIR_ABS, USER_CFG, USER_CFG_STAGED,
    },
    spec::{Bootloader, Host},
};

use crate::install::{RootSetup, State};

/// Contains the EFP's filesystem UUID. Used by grub
pub(crate) const EFI_UUID_FILE: &str = "efiuuid.cfg";
/// The EFI Linux directory
pub(crate) const EFI_LINUX: &str = "EFI/Linux";

/// Timeout for systemd-boot bootloader menu
const SYSTEMD_TIMEOUT: &str = "timeout 5";
const SYSTEMD_LOADER_CONF_PATH: &str = "loader/loader.conf";

const INITRD: &str = "initrd";
const VMLINUZ: &str = "vmlinuz";

const BOOTC_AUTOENROLL_PATH: &str = "usr/lib/bootc/install/secureboot-keys";

const AUTH_EXT: &str = "auth";

/// We want to be able to control the ordering of UKIs so we put them in a directory that's not the
/// directory specified by the BLS spec. We do this because we want systemd-boot to only look at
/// our config files and not show the actual UKIs in the bootloader menu
/// This is relative to the ESP
pub(crate) const SYSTEMD_UKI_DIR: &str = "EFI/Linux/bootc";

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

/// Filename release field for primary (new/upgraded) entry.
/// Grub parses this as the "release" field and sorts descending, so "1" > "0".
pub(crate) const FILENAME_PRIORITY_PRIMARY: &str = "1";

/// Filename release field for secondary (currently booted) entry.
pub(crate) const FILENAME_PRIORITY_SECONDARY: &str = "0";

/// Sort-key priority for primary (new/upgraded) entry.
/// Systemd-boot sorts by sort-key in ascending order, so "0" appears before "1".
pub(crate) const SORTKEY_PRIORITY_PRIMARY: &str = "0";

/// Sort-key priority for secondary (currently booted) entry.
pub(crate) const SORTKEY_PRIORITY_SECONDARY: &str = "1";

/// Generate BLS Type 1 entry filename compatible with Grub's RPM-style parsing.
///
/// Format: `bootc_{os_id}-{version}-{priority}.conf`
///
/// Grub parses this as:
/// - name: `bootc_{os_id}` (hyphens in os_id replaced with underscores)
/// - version: `{version}`
/// - release: `{priority}`
///
/// The underscore replacement prevents Grub from mis-parsing os_id values
/// containing hyphens (e.g., "fedora-coreos" → "fedora_coreos").
pub fn type1_entry_conf_file_name(
    os_id: &str,
    version: impl std::fmt::Display,
    priority: &str,
) -> String {
    let os_id_safe = os_id.replace('-', "_");
    format!("bootc_{os_id_safe}-{version}-{priority}.conf")
}

/// Generate sort key for the primary (new/upgraded) boot entry.
/// Format: bootc-{id}-0
/// Systemd-boot sorts ascending by sort-key, so "0" comes first.
/// Grub ignores sort-key and uses filename/version ordering.
pub(crate) fn primary_sort_key(os_id: &str) -> String {
    format!("bootc-{os_id}-{SORTKEY_PRIORITY_PRIMARY}")
}

/// Generate sort key for the secondary (currently booted) boot entry.
/// Format: bootc-{id}-1
pub(crate) fn secondary_sort_key(os_id: &str) -> String {
    format!("bootc-{os_id}-{SORTKEY_PRIORITY_SECONDARY}")
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

/// Compute SHA256Sum of .linux + .initrd section of the UKI
///
/// # Arguments
/// * entry - BootEntry containing VMlinuz and Initrd
/// * repo - The composefs repository
#[context("Computing boot digest")]
pub(crate) fn compute_boot_digest_uki(uki: &[u8]) -> Result<String> {
    let vmlinuz = composefs_boot::uki::get_section(uki, ".linux")
        .ok_or_else(|| anyhow::anyhow!(".linux not present"))??;

    let initramfs = composefs_boot::uki::get_section(uki, ".initrd")
        .ok_or_else(|| anyhow::anyhow!(".initrd not present"))??;

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

/// Parses /usr/lib/os-release and returns (id, title, version)
fn parse_os_release(
    fs: &crate::store::ComposefsFilesystem,
    repo: &crate::store::ComposefsRepository,
) -> Result<Option<(String, Option<String>, Option<String>)>> {
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

    let parsed = OsReleaseInfo::parse(file_contents);

    let os_id = parsed
        .get_value(&["ID"])
        .unwrap_or_else(|| "bootc".to_string());

    Ok(Some((
        os_id,
        parsed.get_pretty_name(),
        parsed.get_version(),
    )))
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
    mounted_erofs: &Dir,
) -> Result<String> {
    let id_hex = id.to_hex();

    let (root_path, esp_device, mut cmdline_refs, fs, bootloader) = match setup_type {
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

            // Find all ESP partitions across all backing devices.
            // For composefs with systemd-boot, we only support a single ESP.
            let mut esp_parts: Vec<&bootc_blockdev::Partition> = Vec::new();
            for device in &root_setup.device_info {
                if let Some(esp) = device.find_partition_of_esp()? {
                    esp_parts.push(esp);
                }
            }
            let esp_part = match esp_parts.len() {
                0 => {
                    anyhow::bail!("Cannot locate ESP: no ESP partition found on any backing device")
                }
                1 => esp_parts.into_iter().next().unwrap(),
                n => anyhow::bail!(
                    "Found {n} ESP partitions across backing devices; only a single ESP is supported for composefs boot"
                ),
            };

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

            let boot_dir = storage.require_boot_dir()?;
            let current_cfg = get_booted_bls(&boot_dir)?;

            let mut cmdline = match current_cfg.cfg_type {
                BLSConfigType::NonEFI { options, .. } => {
                    let options = options
                        .ok_or_else(|| anyhow::anyhow!("No 'options' found in BLS Config"))?;

                    Cmdline::from(options)
                }

                _ => anyhow::bail!("Found NonEFI config"),
            };

            // Copy all cmdline args, replacing only `composefs=`
            let param = format!("{COMPOSEFS_CMDLINE}={id_hex}");
            let param =
                Parameter::parse(&param).context("Failed to create 'composefs=' parameter")?;
            cmdline.add_or_modify(&param);

            (
                Utf8PathBuf::from("/sysroot"),
                get_esp_partition(&sysroot_parent)?.0,
                cmdline,
                fs,
                bootloader,
            )
        }
    };

    let is_upgrade = matches!(setup_type, BootSetupType::Upgrade(..));

    let current_root = if is_upgrade {
        Some(&Dir::open_ambient_dir("/", ambient_authority()).context("Opening root")?)
    } else {
        None
    };

    compute_new_kargs(mounted_erofs, current_root, &mut cmdline_refs)?;

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

    let (bls_config, boot_digest, os_id) = match &entry {
        ComposefsBootEntry::Type1(..) => anyhow::bail!("Found Type1 entries in /boot"),
        ComposefsBootEntry::Type2(..) => anyhow::bail!("Found UKI"),

        ComposefsBootEntry::UsrLibModulesVmLinuz(usr_lib_modules_vmlinuz) => {
            let boot_digest = compute_boot_digest(usr_lib_modules_vmlinuz, &repo)
                .context("Computing boot digest")?;

            let osrel = parse_os_release(fs, &repo)?;

            let (os_id, title, version, sort_key) = match osrel {
                Some((id_str, title_opt, version_opt)) => (
                    id_str.clone(),
                    title_opt.unwrap_or_else(|| id.to_hex()),
                    version_opt.unwrap_or_else(|| id.to_hex()),
                    primary_sort_key(&id_str),
                ),
                None => {
                    let default_id = "bootc".to_string();
                    (
                        default_id.clone(),
                        id.to_hex(),
                        id.to_hex(),
                        primary_sort_key(&default_id),
                    )
                }
            };

            let mut bls_config = BLSConfig::default();

            bls_config
                .with_title(title)
                .with_version(version)
                .with_sort_key(sort_key)
                .with_cfg(BLSConfigType::NonEFI {
                    linux: entry_paths.abs_entries_path.join(&id_hex).join(VMLINUZ),
                    initrd: vec![entry_paths.abs_entries_path.join(&id_hex).join(INITRD)],
                    options: Some(cmdline_refs),
                });

            match find_vmlinuz_initrd_duplicates(&boot_digest)? {
                Some(shared_entries) => {
                    // Multiple deployments could be using the same kernel + initrd, but there
                    // would be only one available
                    //
                    // Symlinking directories themselves would be better, but vfat does not support
                    // symlinks

                    let mut shared_entry: Option<String> = None;

                    let entries =
                        Dir::open_ambient_dir(entry_paths.entries_path, ambient_authority())
                            .context("Opening entries path")?
                            .entries_utf8()
                            .context("Getting dir entries")?;

                    for ent in entries {
                        let ent = ent?;
                        // We shouldn't error here as all our file names are UTF-8 compatible
                        let ent_name = ent.file_name()?;

                        if shared_entries.contains(&ent_name) {
                            shared_entry = Some(ent_name);
                            break;
                        }
                    }

                    let shared_entry = shared_entry
                        .ok_or_else(|| anyhow::anyhow!("Shared boot binaries not found"))?;

                    match bls_config.cfg_type {
                        BLSConfigType::NonEFI {
                            ref mut linux,
                            ref mut initrd,
                            ..
                        } => {
                            *linux = entry_paths
                                .abs_entries_path
                                .join(&shared_entry)
                                .join(VMLINUZ);

                            *initrd = vec![
                                entry_paths
                                    .abs_entries_path
                                    .join(&shared_entry)
                                    .join(INITRD),
                            ];
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

            (bls_config, boot_digest, os_id)
        }
    };

    let loader_path = entry_paths.config_path.join("loader");

    let (config_path, booted_bls) = if is_upgrade {
        let boot_dir = Dir::open_ambient_dir(&entry_paths.config_path, ambient_authority())?;

        let mut booted_bls = get_booted_bls(&boot_dir)?;
        booted_bls.sort_key = Some(secondary_sort_key(&os_id));

        let staged_path = loader_path.join(STAGED_BOOT_LOADER_ENTRIES);

        // Delete the staged entries directory if it exists as we want to overwrite the entries
        // anyway
        if boot_dir
            .remove_all_optional(TYPE1_ENT_PATH_STAGED)
            .context("Failed to remove staged directory")?
        {
            tracing::debug!("Removed existing staged entries directory");
        }

        // This will be atomically renamed to 'loader/entries' on shutdown/reboot
        (staged_path, Some(booted_bls))
    } else {
        (loader_path.join(BOOT_LOADER_ENTRIES), None)
    };

    create_dir_all(&config_path).with_context(|| format!("Creating {:?}", config_path))?;

    let loader_entries_dir = Dir::open_ambient_dir(&config_path, ambient_authority())
        .with_context(|| format!("Opening {config_path:?}"))?;

    loader_entries_dir.atomic_write(
        type1_entry_conf_file_name(&os_id, &bls_config.version(), FILENAME_PRIORITY_PRIMARY),
        bls_config.to_string().as_bytes(),
    )?;

    if let Some(booted_bls) = booted_bls {
        loader_entries_dir.atomic_write(
            type1_entry_conf_file_name(&os_id, &booted_bls.version(), FILENAME_PRIORITY_SECONDARY),
            booted_bls.to_string().as_bytes(),
        )?;
    }

    let owned_loader_entries_fd = loader_entries_dir
        .reopen_as_ownedfd()
        .context("Reopening as owned fd")?;

    rustix::fs::fsync(owned_loader_entries_fd).context("fsync")?;

    Ok(boot_digest)
}

struct UKIInfo {
    boot_label: String,
    version: Option<String>,
    os_id: Option<String>,
    boot_digest: String,
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
    bootloader: &Bootloader,
) -> Result<Option<UKIInfo>> {
    let efi_bin = read_file(file, &repo).context("Reading .efi binary")?;

    let mut boot_label: Option<UKIInfo> = None;

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

        let osrel = uki::get_text_section(&efi_bin, ".osrel")?;

        let parsed_osrel = OsReleaseInfo::parse(osrel);

        let boot_digest = compute_boot_digest_uki(&efi_bin)?;

        boot_label = Some(UKIInfo {
            boot_label: uki::get_boot_label(&efi_bin).context("Getting UKI boot label")?,
            version: parsed_osrel.get_version(),
            os_id: parsed_osrel.get_value(&["ID"]),
            boot_digest,
        });
    }

    // Write the UKI to ESP
    let efi_linux_path = mounted_efi.as_ref().join(match bootloader {
        Bootloader::Grub => EFI_LINUX,
        Bootloader::Systemd => SYSTEMD_UKI_DIR,
    });

    create_dir_all(&efi_linux_path).context("Creating EFI/Linux")?;

    let final_pe_path = match file_path.parent() {
        Some(parent) => {
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

            let full_path = efi_linux_path.join(renamed_path);
            create_dir_all(&full_path)?;

            full_path
        }

        None => efi_linux_path,
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
    boot_label: UKIInfo,
    id: &Sha512HashValue,
) -> Result<()> {
    let os_id = boot_label.os_id.as_deref().unwrap_or("bootc");
    let primary_sort_key = primary_sort_key(os_id);

    let mut bls_conf = BLSConfig::default();
    bls_conf
        .with_title(boot_label.boot_label)
        .with_cfg(BLSConfigType::EFI {
            efi: format!("/{SYSTEMD_UKI_DIR}/{}{}", id.to_hex(), EFI_EXT).into(),
        })
        .with_sort_key(primary_sort_key.clone())
        .with_version(boot_label.version.unwrap_or_else(|| id.to_hex()));

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
            booted_bls.sort_key = Some(secondary_sort_key(os_id));

            (esp_dir.open_dir(TYPE1_ENT_PATH_STAGED)?, Some(booted_bls))
        }
    };

    entries_dir
        .atomic_write(
            type1_entry_conf_file_name(os_id, &bls_conf.version(), FILENAME_PRIORITY_PRIMARY),
            bls_conf.to_string().as_bytes(),
        )
        .context("Writing conf file")?;

    if let Some(booted_bls) = booted_bls {
        entries_dir.atomic_write(
            type1_entry_conf_file_name(os_id, &booted_bls.version(), FILENAME_PRIORITY_SECONDARY),
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
) -> Result<String> {
    let (root_path, esp_device, bootloader, is_insecure_from_opts, uki_addons) = match setup_type {
        BootSetupType::Setup((root_setup, state, postfetch, ..)) => {
            state.require_no_kargs_for_uki()?;

            //TODO: Handle multiple devices (RAID, LVM, etc)
            let device_info = root_setup
                .device_info
                .first()
                .ok_or_else(|| anyhow!("Cannot locate ESP: no backing device found"))?;
            let esp_part = esp_in(device_info)?;

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

    let mut uki_info: Option<UKIInfo> = None;

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
                    &bootloader,
                )?;

                if let Some(label) = ret {
                    uki_info = Some(label);
                }
            }
        };
    }

    let uki_info =
        uki_info.ok_or_else(|| anyhow::anyhow!("Failed to get version and boot label from UKI"))?;

    let boot_digest = uki_info.boot_digest.clone();

    match bootloader {
        Bootloader::Grub => {
            write_grub_uki_menuentry(root_path, &setup_type, uki_info.boot_label, id, &esp_device)?
        }

        Bootloader::Systemd => write_systemd_uki_config(&esp_mount.fd, &setup_type, uki_info, id)?,
    };

    Ok(boot_digest)
}

pub struct SecurebootKeys {
    pub dir: Dir,
    pub keys: Vec<Utf8PathBuf>,
}

fn get_secureboot_keys(fs: &Dir, p: &str) -> Result<Option<SecurebootKeys>> {
    let mut entries = vec![];

    // if the dir doesn't exist, return None
    let keys_dir = match fs.open_dir_optional(p)? {
        Some(d) => d,
        _ => return Ok(None),
    };

    // https://github.com/systemd/systemd/blob/26b2085d54ebbfca8637362eafcb4a8e3faf832f/man/systemd-boot.xml#L392

    for entry in keys_dir.entries()? {
        let dir_e = entry?;
        let dirname = dir_e.file_name();
        if !dir_e.file_type()?.is_dir() {
            bail!("/{p}/{dirname:?} is not a directory");
        }

        let dir_path: Utf8PathBuf = dirname.try_into()?;
        let dir = dir_e.open_dir()?;
        for entry in dir.entries()? {
            let e = entry?;
            let local: Utf8PathBuf = e.file_name().try_into()?;
            let path = dir_path.join(local);

            if path.extension() != Some(AUTH_EXT) {
                continue;
            }

            if !e.file_type()?.is_file() {
                bail!("/{p}/{path:?} is not a file");
            }
            entries.push(path);
        }
    }
    return Ok(Some(SecurebootKeys {
        dir: keys_dir,
        keys: entries,
    }));
}

#[context("Setting up composefs boot")]
pub(crate) async fn setup_composefs_boot(
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
        // zipl only supports single device
        crate::bootloader::install_via_zipl(root_setup.device_info.first(), boot_uuid)?;
    } else if postfetch.detected_bootloader == Bootloader::Grub {
        crate::bootloader::install_via_bootupd(
            &root_setup.device_info,
            &root_setup.physical_root_path,
            &state.config_opts,
            None,
        )?;
    } else {
        // systemd-boot only supports a single ESP
        crate::bootloader::install_systemd_boot(
            root_setup.device_info.first(),
            &root_setup.physical_root_path,
            &state.config_opts,
            None,
            get_secureboot_keys(&mounted_fs, BOOTC_AUTOENROLL_PATH)?,
        )?;
    }

    let Some(entry) = entries.iter().next() else {
        anyhow::bail!("No boot entries!");
    };

    let boot_type = BootType::from(entry);

    let boot_digest = match boot_type {
        BootType::Bls => setup_composefs_bls_boot(
            BootSetupType::Setup((&root_setup, &state, &postfetch, &fs)),
            repo,
            &id,
            entry,
            &mounted_fs,
        )?,
        BootType::Uki => setup_composefs_uki_boot(
            BootSetupType::Setup((&root_setup, &state, &postfetch, &fs)),
            repo,
            &id,
            entries,
        )?,
    };

    write_composefs_state(
        &root_setup.physical_root_path,
        &id,
        &crate::spec::ImageReference::from(state.target_imgref.clone()),
        None,
        boot_type,
        boot_digest,
        &get_container_manifest_and_config(&get_imgref(
            &state.source.imageref.transport.to_string(),
            &state.source.imageref.name,
        ))
        .await?,
    )
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type1_filename_generation() {
        // Test basic os_id without hyphens
        let filename =
            type1_entry_conf_file_name("fedora", "41.20251125.0", FILENAME_PRIORITY_PRIMARY);
        assert_eq!(filename, "bootc_fedora-41.20251125.0-1.conf");

        // Test primary vs secondary priority
        let primary =
            type1_entry_conf_file_name("fedora", "41.20251125.0", FILENAME_PRIORITY_PRIMARY);
        let secondary =
            type1_entry_conf_file_name("fedora", "41.20251125.0", FILENAME_PRIORITY_SECONDARY);
        assert_eq!(primary, "bootc_fedora-41.20251125.0-1.conf");
        assert_eq!(secondary, "bootc_fedora-41.20251125.0-0.conf");

        // Test os_id with hyphens (should be replaced with underscores)
        let filename =
            type1_entry_conf_file_name("fedora-coreos", "41.20251125.0", FILENAME_PRIORITY_PRIMARY);
        assert_eq!(filename, "bootc_fedora_coreos-41.20251125.0-1.conf");

        // Test multiple hyphens in os_id
        let filename =
            type1_entry_conf_file_name("my-custom-os", "1.0.0", FILENAME_PRIORITY_PRIMARY);
        assert_eq!(filename, "bootc_my_custom_os-1.0.0-1.conf");

        // Test rhel example
        let filename = type1_entry_conf_file_name("rhel", "9.3.0", FILENAME_PRIORITY_SECONDARY);
        assert_eq!(filename, "bootc_rhel-9.3.0-0.conf");
    }

    #[test]
    fn test_grub_filename_parsing() {
        // Verify our filename format works correctly with Grub's parsing logic
        // Grub parses: bootc_fedora-41.20251125.0-1.conf
        // Expected:
        //   - name: bootc_fedora
        //   - version: 41.20251125.0
        //   - release: 1

        // For fedora-coreos (with hyphens), we convert to underscores
        let filename = type1_entry_conf_file_name("fedora-coreos", "41.20251125.0", "1");
        assert_eq!(filename, "bootc_fedora_coreos-41.20251125.0-1.conf");

        // Grub parsing simulation (from right):
        // 1. Strip .conf -> bootc_fedora_coreos-41.20251125.0-1
        // 2. Last '-' splits: release="1", remainder="bootc_fedora_coreos-41.20251125.0"
        // 3. Second-to-last '-' splits: version="41.20251125.0", name="bootc_fedora_coreos"

        let without_ext = filename.strip_suffix(".conf").unwrap();
        let parts: Vec<&str> = without_ext.rsplitn(3, '-').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "1"); // release
        assert_eq!(parts[1], "41.20251125.0"); // version
        assert_eq!(parts[2], "bootc_fedora_coreos"); // name
    }

    #[test]
    fn test_sort_keys() {
        // Test sort-key generation for systemd-boot
        let primary = primary_sort_key("fedora");
        let secondary = secondary_sort_key("fedora");

        assert_eq!(primary, "bootc-fedora-0");
        assert_eq!(secondary, "bootc-fedora-1");

        // Systemd-boot sorts ascending, so "bootc-fedora-0" < "bootc-fedora-1"
        assert!(primary < secondary);

        // Test with hyphenated os_id (sort-key keeps hyphens)
        let primary_coreos = primary_sort_key("fedora-coreos");
        assert_eq!(primary_coreos, "bootc-fedora-coreos-0");
    }

    #[test]
    fn test_filename_sorting_grub_style() {
        // Simulate Grub's descending sort by (name, version, release)

        // Test 1: Same version, different release (priority)
        let primary =
            type1_entry_conf_file_name("fedora", "41.20251125.0", FILENAME_PRIORITY_PRIMARY);
        let secondary =
            type1_entry_conf_file_name("fedora", "41.20251125.0", FILENAME_PRIORITY_SECONDARY);

        // Descending sort: "bootc_fedora-41.20251125.0-1" > "bootc_fedora-41.20251125.0-0"
        assert!(
            primary > secondary,
            "Primary should sort before secondary in descending order"
        );

        // Test 2: Different versions
        let newer =
            type1_entry_conf_file_name("fedora", "42.20251125.0", FILENAME_PRIORITY_PRIMARY);
        let older =
            type1_entry_conf_file_name("fedora", "41.20251125.0", FILENAME_PRIORITY_PRIMARY);

        // Descending sort: version "42" > "41"
        assert!(
            newer > older,
            "Newer version should sort before older in descending order"
        );

        // Test 3: Different os_id (different name)
        let fedora = type1_entry_conf_file_name("fedora", "41.0", FILENAME_PRIORITY_PRIMARY);
        let rhel = type1_entry_conf_file_name("rhel", "9.0", FILENAME_PRIORITY_PRIMARY);

        // Names differ: bootc_rhel > bootc_fedora (descending alphabetical)
        assert!(
            rhel > fedora,
            "RHEL should sort before Fedora in descending order"
        );
    }
}
