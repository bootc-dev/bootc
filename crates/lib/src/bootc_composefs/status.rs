use std::{collections::HashSet, io::Read, sync::OnceLock};

use anyhow::{Context, Result};
use bootc_kernel_cmdline::utf8::Cmdline;
use bootc_mount::inspect_filesystem;
use cfsctl::composefs::fsverity::Sha512HashValue;
use cfsctl::composefs_oci;
use composefs_oci::OciImage;
use fn_error_context::context;
use serde::{Deserialize, Serialize};

use crate::{
    bootc_composefs::{
        boot::BootType,
        selinux::are_selinux_policies_compatible,
        state::{get_composefs_usr_overlay_status, read_origin},
        utils::{compute_store_boot_digest_for_uki, get_uki_cmdline},
    },
    composefs_consts::{
        COMPOSEFS_CMDLINE, ORIGIN_KEY_BOOT_DIGEST, ORIGIN_KEY_IMAGE, ORIGIN_KEY_MANIFEST_DIGEST,
        TYPE1_ENT_PATH, TYPE1_ENT_PATH_STAGED, USER_CFG, USER_CFG_STAGED,
    },
    install::EFI_LOADER_INFO,
    parsers::{
        bls_config::{BLSConfig, BLSConfigType, parse_bls_config},
        grub_menuconfig::{MenuEntry, parse_grub_menuentry_file},
    },
    spec::{BootEntry, BootOrder, Host, HostSpec, ImageReference, ImageStatus},
    store::Storage,
    utils::{EfiError, read_uefi_var},
};

use std::str::FromStr;

use bootc_utils::try_deserialize_timestamp;
use cap_std_ext::{cap_std::fs::Dir, dirext::CapStdExtDirExt};
use ostree_container::OstreeImageReference;
use ostree_ext::container::{self as ostree_container};
use ostree_ext::containers_image_proxy;
use ostree_ext::oci_spec;
use ostree_ext::{container::deploy::ORIGIN_CONTAINER, oci_spec::image::ImageConfiguration};

use ostree_ext::oci_spec::image::ImageManifest;
use tokio::io::AsyncReadExt;

use crate::composefs_consts::{
    COMPOSEFS_STAGED_DEPLOYMENT_FNAME, COMPOSEFS_TRANSIENT_STATE_DIR, ORIGIN_KEY_BOOT,
    ORIGIN_KEY_BOOT_TYPE, STATE_DIR_RELATIVE,
};
use crate::spec::Bootloader;

/// Used for storing the container image info alongside of .origin file
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ImgConfigManifest {
    pub(crate) config: ImageConfiguration,
    pub(crate) manifest: ImageManifest,
}

/// A parsed composefs command line
#[derive(Clone)]
pub(crate) struct ComposefsCmdline {
    pub allow_missing_fsverity: bool,
    pub digest: Box<str>,
}

/// Information about a deployment for soft reboot comparison
struct DeploymentBootInfo<'a> {
    boot_digest: &'a str,
    full_cmdline: &'a Cmdline<'a>,
    verity: &'a str,
}

impl ComposefsCmdline {
    pub(crate) fn new(s: &str) -> Self {
        let (allow_missing_fsverity, digest_str) = s
            .strip_prefix('?')
            .map(|v| (true, v))
            .unwrap_or_else(|| (false, s));
        ComposefsCmdline {
            allow_missing_fsverity,
            digest: digest_str.into(),
        }
    }

    pub(crate) fn build(digest: &str, allow_missing_fsverity: bool) -> Self {
        ComposefsCmdline {
            allow_missing_fsverity,
            digest: digest.into(),
        }
    }

    /// Search for the `composefs=` parameter in the passed in kernel command line
    pub(crate) fn find_in_cmdline(cmdline: &Cmdline) -> Option<Self> {
        match cmdline.find(COMPOSEFS_CMDLINE) {
            Some(param) => {
                let value = param.value()?;
                Some(Self::new(value))
            }
            None => None,
        }
    }
}

impl std::fmt::Display for ComposefsCmdline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let allow_missing_fsverity = if self.allow_missing_fsverity { "?" } else { "" };
        write!(
            f,
            "{}={}{}",
            COMPOSEFS_CMDLINE, allow_missing_fsverity, self.digest
        )
    }
}

/// The JSON schema for staged deployment information
/// stored in `/run/composefs/staged-deployment`
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct StagedDeployment {
    /// The id (verity hash of the EROFS image) of the staged deployment
    pub(crate) depl_id: String,
    /// Whether to finalize this staged deployment on reboot or not
    /// This also maps to `download_only` field in `BootEntry`
    pub(crate) finalization_locked: bool,
}

#[derive(Debug, PartialEq)]
pub(crate) struct BootloaderEntry {
    /// The fsverity digest associated with the bootloader entry
    /// This is the value of composefs= param
    pub(crate) fsverity: String,
    /// The name of the (UKI/Kernel+Initrd directory) related to the entry
    ///
    /// For UKI, this is the name of the UKI stripped of our custom
    /// prefix and .efi suffix
    ///
    /// For Type1 entries, this is the name to the directory containing
    /// Kernel+Initrd, stripped of our custom prefix
    ///
    /// Since this is stripped of all our custom prefixes + file extensions
    /// this is basically the verity digest part of the name
    ///
    /// We mainly need this in order to GC shared Type1 entries
    pub(crate) boot_artifact_name: String,
}

/// Detect if we have `composefs=<digest>` in `/proc/cmdline`
pub(crate) fn composefs_booted() -> Result<Option<&'static ComposefsCmdline>> {
    static CACHED_DIGEST_VALUE: OnceLock<Option<ComposefsCmdline>> = OnceLock::new();
    if let Some(v) = CACHED_DIGEST_VALUE.get() {
        return Ok(v.as_ref());
    }
    let cmdline = Cmdline::from_proc()?;
    let Some(kv) = cmdline.find(COMPOSEFS_CMDLINE) else {
        return Ok(None);
    };
    let Some(v) = kv.value() else { return Ok(None) };
    let v = ComposefsCmdline::new(v);

    // Find the source of / mountpoint as the cmdline doesn't change on soft-reboot
    let root_mnt = inspect_filesystem("/".into())?;

    // This is of the format composefs:<composefs_hash>
    let verity_from_mount_src = root_mnt
        .source
        .strip_prefix("composefs:")
        .ok_or_else(|| anyhow::anyhow!("Root not mounted using composefs"))?;

    let r = if *verity_from_mount_src != *v.digest {
        // soft rebooted into another deployment
        CACHED_DIGEST_VALUE.get_or_init(|| Some(ComposefsCmdline::new(verity_from_mount_src)))
    } else {
        CACHED_DIGEST_VALUE.get_or_init(|| Some(v))
    };

    Ok(r.as_ref())
}

/// Get the staged grub UKI menuentries
pub(crate) fn get_sorted_grub_uki_boot_entries_staged<'a>(
    boot_dir: &Dir,
    str: &'a mut String,
) -> Result<Vec<MenuEntry<'a>>> {
    get_sorted_grub_uki_boot_entries_helper(boot_dir, str, true)
}

/// Get the grub UKI menuentries
pub(crate) fn get_sorted_grub_uki_boot_entries<'a>(
    boot_dir: &Dir,
    str: &'a mut String,
) -> Result<Vec<MenuEntry<'a>>> {
    get_sorted_grub_uki_boot_entries_helper(boot_dir, str, false)
}

// Need str to store lifetime
fn get_sorted_grub_uki_boot_entries_helper<'a>(
    boot_dir: &Dir,
    str: &'a mut String,
    staged: bool,
) -> Result<Vec<MenuEntry<'a>>> {
    let file = if staged {
        boot_dir
            // As the staged entry might not exist
            .open_optional(format!("grub2/{USER_CFG_STAGED}"))
            .with_context(|| format!("Opening {USER_CFG_STAGED}"))?
    } else {
        let f = boot_dir
            .open(format!("grub2/{USER_CFG}"))
            .with_context(|| format!("Opening {USER_CFG}"))?;

        Some(f)
    };

    let Some(mut file) = file else {
        return Ok(Vec::new());
    };

    file.read_to_string(str)?;
    parse_grub_menuentry_file(str)
}

pub(crate) fn get_sorted_type1_boot_entries(
    boot_dir: &Dir,
    ascending: bool,
) -> Result<Vec<BLSConfig>> {
    get_sorted_type1_boot_entries_helper(boot_dir, ascending, false)
}

pub(crate) fn get_sorted_staged_type1_boot_entries(
    boot_dir: &Dir,
    ascending: bool,
) -> Result<Vec<BLSConfig>> {
    get_sorted_type1_boot_entries_helper(boot_dir, ascending, true)
}

#[context("Getting sorted Type1 boot entries")]
fn get_sorted_type1_boot_entries_helper(
    boot_dir: &Dir,
    ascending: bool,
    get_staged_entries: bool,
) -> Result<Vec<BLSConfig>> {
    let mut all_configs = vec![];

    let dir = match get_staged_entries {
        true => {
            let dir = boot_dir.open_dir_optional(TYPE1_ENT_PATH_STAGED)?;

            let Some(dir) = dir else {
                return Ok(all_configs);
            };

            dir.read_dir(".")?
        }

        false => boot_dir.read_dir(TYPE1_ENT_PATH)?,
    };

    for entry in dir {
        let entry = entry?;

        let file_name = entry.file_name();

        let file_name = file_name
            .to_str()
            .ok_or(anyhow::anyhow!("Found non UTF-8 characters in filename"))?;

        if !file_name.ends_with(".conf") {
            continue;
        }

        let mut file = entry
            .open()
            .with_context(|| format!("Failed to open {:?}", file_name))?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .with_context(|| format!("Failed to read {:?}", file_name))?;

        let config = parse_bls_config(&contents).context("Parsing bls config")?;

        all_configs.push(config);
    }

    all_configs.sort_by(|a, b| if ascending { a.cmp(b) } else { b.cmp(a) });

    Ok(all_configs)
}

pub(crate) fn list_type1_entries(boot_dir: &Dir) -> Result<Vec<BootloaderEntry>> {
    // Type1 Entry
    let boot_entries = get_sorted_type1_boot_entries(boot_dir, true)?;

    // We wouldn't want to delete the staged deployment if the GC runs when a
    // deployment is staged
    let staged_boot_entries = get_sorted_staged_type1_boot_entries(boot_dir, true)?;

    boot_entries
        .into_iter()
        .chain(staged_boot_entries)
        .map(|entry| {
            Ok(BootloaderEntry {
                fsverity: entry.get_verity()?,
                boot_artifact_name: entry.boot_artifact_name()?.to_string(),
            })
        })
        .collect::<Result<Vec<_>, _>>()
}

/// Get all Type1/Type2 bootloader entries
///
/// # Returns
/// The fsverity of EROFS images corresponding to boot entries
#[fn_error_context::context("Listing bootloader entries")]
pub(crate) fn list_bootloader_entries(storage: &Storage) -> Result<Vec<BootloaderEntry>> {
    let bootloader = get_bootloader()?;
    let boot_dir = storage.require_boot_dir()?;

    let entries = match bootloader {
        Bootloader::Grub => {
            // Grub entries are always in boot
            let grub_dir = boot_dir.open_dir("grub2").context("Opening grub dir")?;

            // Grub UKI
            if grub_dir.exists(USER_CFG) {
                let mut s = String::new();
                let boot_entries = get_sorted_grub_uki_boot_entries(boot_dir, &mut s)?;

                let mut staged = String::new();
                let boot_entries_staged =
                    get_sorted_grub_uki_boot_entries_staged(boot_dir, &mut staged)?;

                boot_entries
                    .into_iter()
                    .chain(boot_entries_staged)
                    .map(|entry| {
                        Ok(BootloaderEntry {
                            fsverity: entry.get_verity()?,
                            boot_artifact_name: entry.boot_artifact_name()?,
                        })
                    })
                    .collect::<Result<Vec<_>, anyhow::Error>>()?
            } else {
                list_type1_entries(boot_dir)?
            }
        }

        Bootloader::Systemd => list_type1_entries(boot_dir)?,

        Bootloader::None => unreachable!("Checked at install time"),
    };

    Ok(entries)
}

/// imgref = transport:image_name
#[context("Getting container info")]
pub(crate) async fn get_container_manifest_and_config(
    imgref: &String,
) -> Result<ImgConfigManifest> {
    let mut config = crate::deploy::new_proxy_config();
    ostree_ext::container::merge_default_container_proxy_opts(&mut config)?;
    let proxy = containers_image_proxy::ImageProxy::new_with_config(config).await?;

    let img = proxy
        .open_image(&imgref)
        .await
        .with_context(|| format!("Opening image {imgref}"))?;

    let (_, manifest) = proxy.fetch_manifest(&img).await?;
    let (mut reader, driver) = proxy.get_descriptor(&img, manifest.config()).await?;

    let mut buf = Vec::with_capacity(manifest.config().size() as usize);
    buf.resize(manifest.config().size() as usize, 0);
    reader.read_exact(&mut buf).await?;
    driver.await?;

    let config: oci_spec::image::ImageConfiguration = serde_json::from_slice(&buf)?;

    Ok(ImgConfigManifest { manifest, config })
}

#[context("Getting bootloader")]
pub(crate) fn get_bootloader() -> Result<Bootloader> {
    match read_uefi_var(EFI_LOADER_INFO) {
        Ok(loader) => {
            if loader.to_lowercase().contains("systemd-boot") {
                return Ok(Bootloader::Systemd);
            }

            return Ok(Bootloader::Grub);
        }

        Err(efi_error) => match efi_error {
            EfiError::SystemNotUEFI => return Ok(Bootloader::Grub),
            EfiError::MissingVar => return Ok(Bootloader::Grub),

            e => return Err(anyhow::anyhow!("Failed to read EfiLoaderInfo: {e:?}")),
        },
    }
}

/// Retrieves the OCI manifest and config for a deployment from the composefs repository.
///
/// The manifest digest is read from the deployment's `.origin` file,
/// then `OciImage::open()` retrieves manifest+config from the composefs repo
/// where composefs-rs stores them as splitstreams during pull.
///
/// Falls back to reading legacy `.imginfo` files for backwards compatibility
/// with deployments created before the manifest digest was stored in `.origin`.
#[context("Reading image info for deployment {deployment_id}")]
pub(crate) fn get_imginfo(storage: &Storage, deployment_id: &str) -> Result<ImgConfigManifest> {
    let ini = read_origin(&storage.physical_root, deployment_id)?
        .ok_or_else(|| anyhow::anyhow!("No origin file for deployment {deployment_id}"))?;

    // Try to read the manifest digest from the origin file (new path)
    if let Some(manifest_digest_str) =
        ini.get::<String>(ORIGIN_KEY_IMAGE, ORIGIN_KEY_MANIFEST_DIGEST)
    {
        let repo = storage.get_ensure_composefs()?;
        let manifest_digest: composefs_oci::OciDigest = manifest_digest_str
            .parse()
            .with_context(|| format!("Parsing manifest digest {manifest_digest_str}"))?;
        let oci_image = OciImage::<Sha512HashValue>::open(&repo, &manifest_digest, None)
            .with_context(|| format!("Opening OCI image for manifest {manifest_digest}"))?;

        let manifest = oci_image.manifest().clone();
        let config = oci_image
            .config()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("OCI image has no config (artifact?)"))?;

        return Ok(ImgConfigManifest { config, manifest });
    }

    // Fallback: read legacy .imginfo file for deployments created before
    // the manifest digest was stored in .origin
    let depl_state_path = std::path::PathBuf::from(STATE_DIR_RELATIVE).join(deployment_id);
    let imginfo_fname = format!("{deployment_id}.imginfo");
    let path = depl_state_path.join(&imginfo_fname);

    let mut img_conf = storage
        .physical_root
        .open_optional(&path)
        .with_context(|| format!("Opening legacy {imginfo_fname}"))?;

    let Some(img_conf) = &mut img_conf else {
        anyhow::bail!(
            "No manifest_digest in origin and no legacy .imginfo file \
             for deployment {deployment_id}"
        );
    };

    let mut buffer = String::new();
    img_conf.read_to_string(&mut buffer)?;

    let img_conf = serde_json::from_str::<ImgConfigManifest>(&buffer)
        .context("Failed to parse .imginfo file as JSON")?;

    Ok(img_conf)
}

#[context("Getting composefs deployment metadata")]
fn boot_entry_from_composefs_deployment(
    storage: &Storage,
    origin: tini::Ini,
    verity: &str,
) -> Result<BootEntry> {
    let image = match origin.get::<String>("origin", ORIGIN_CONTAINER) {
        Some(img_name_from_config) => {
            let ostree_img_ref = OstreeImageReference::from_str(&img_name_from_config)?;
            let img_ref = ImageReference::from(ostree_img_ref);

            let img_conf = get_imginfo(storage, &verity)?;

            let image_digest = img_conf.manifest.config().digest().to_string();
            let architecture = img_conf.config.architecture().to_string();
            let version = img_conf
                .manifest
                .annotations()
                .as_ref()
                .and_then(|a| a.get(oci_spec::image::ANNOTATION_VERSION).cloned());

            let created_at = img_conf.config.created().clone();
            let timestamp = created_at.and_then(|x| try_deserialize_timestamp(&x));

            Some(ImageStatus {
                image: img_ref,
                version,
                timestamp,
                image_digest,
                architecture,
            })
        }

        // Wasn't booted using a container image. Do nothing
        None => None,
    };

    let boot_type = match origin.get::<String>(ORIGIN_KEY_BOOT, ORIGIN_KEY_BOOT_TYPE) {
        Some(s) => BootType::try_from(s.as_str())?,
        None => anyhow::bail!("{ORIGIN_KEY_BOOT} not found"),
    };

    let boot_digest = origin.get::<String>(ORIGIN_KEY_BOOT, ORIGIN_KEY_BOOT_DIGEST);

    let e = BootEntry {
        image,
        cached_update: None,
        incompatible: false,
        pinned: false,
        download_only: false, // Set later on
        store: None,
        ostree: None,
        composefs: Some(crate::spec::BootEntryComposefs {
            verity: verity.into(),
            boot_type,
            bootloader: get_bootloader()?,
            boot_digest,
        }),
        soft_reboot_capable: false,
    };

    Ok(e)
}

/// Get composefs status using provided storage and booted composefs data
/// instead of scraping global state.
#[context("Getting composefs deployment status")]
pub(crate) async fn get_composefs_status(
    storage: &crate::store::Storage,
    booted_cfs: &crate::store::BootedComposefs,
) -> Result<Host> {
    composefs_deployment_status_from(&storage, booted_cfs.cmdline).await
}

/// Check whether any deployment is capable of being soft rebooted or not
#[context("Checking soft reboot capability")]
fn set_soft_reboot_capability(
    storage: &Storage,
    host: &mut Host,
    bls_entries: Option<Vec<BLSConfig>>,
    booted_cmdline: &ComposefsCmdline,
) -> Result<()> {
    let booted = host.require_composefs_booted()?;

    match booted.boot_type {
        BootType::Bls => {
            let mut bls_entries =
                bls_entries.ok_or_else(|| anyhow::anyhow!("BLS entries not provided"))?;

            let staged_entries =
                get_sorted_staged_type1_boot_entries(storage.require_boot_dir()?, false)?;

            // We will have a duplicate booted entry here, but that's fine as we only use this
            // vector to check for existence of an entry
            bls_entries.extend(staged_entries);

            set_reboot_capable_type1_deployments(storage, booted_cmdline, host, bls_entries)
        }

        BootType::Uki => set_reboot_capable_uki_deployments(storage, booted_cmdline, host),
    }
}

fn find_bls_entry<'a>(
    verity: &str,
    bls_entries: &'a Vec<BLSConfig>,
) -> Result<Option<&'a BLSConfig>> {
    for ent in bls_entries {
        if ent.get_verity()? == *verity {
            return Ok(Some(ent));
        }
    }

    Ok(None)
}

/// Compares cmdline `first` and `second` skipping `composefs=`
fn compare_cmdline_skip_cfs(first: &Cmdline<'_>, second: &Cmdline<'_>) -> bool {
    for param in first {
        if param.key() == COMPOSEFS_CMDLINE.into() {
            continue;
        }

        let second_param = second.iter().find(|b| *b == param);

        let Some(found_param) = second_param else {
            return false;
        };

        if found_param.value() != param.value() {
            return false;
        }
    }

    return true;
}

#[context("Setting soft reboot capability for Type1 entries")]
fn set_reboot_capable_type1_deployments(
    storage: &Storage,
    booted_cmdline: &ComposefsCmdline,
    host: &mut Host,
    bls_entries: Vec<BLSConfig>,
) -> Result<()> {
    let booted = host
        .status
        .booted
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Failed to find booted entry"))?;

    let booted_boot_digest = booted.composefs_boot_digest()?;

    let booted_bls_entry = find_bls_entry(&*booted_cmdline.digest, &bls_entries)?
        .ok_or_else(|| anyhow::anyhow!("Booted BLS entry not found"))?;

    let booted_full_cmdline = booted_bls_entry.get_cmdline()?;

    let booted_info = DeploymentBootInfo {
        boot_digest: booted_boot_digest,
        full_cmdline: booted_full_cmdline,
        verity: &booted_cmdline.digest,
    };

    for depl in host
        .status
        .staged
        .iter_mut()
        .chain(host.status.rollback.iter_mut())
        .chain(host.status.other_deployments.iter_mut())
    {
        let depl_verity = &depl.require_composefs()?.verity;

        let entry = find_bls_entry(&depl_verity, &bls_entries)?
            .ok_or_else(|| anyhow::anyhow!("Entry not found"))?;

        let depl_cmdline = entry.get_cmdline()?;

        let target_info = DeploymentBootInfo {
            boot_digest: depl.composefs_boot_digest()?,
            full_cmdline: depl_cmdline,
            verity: &depl_verity,
        };

        depl.soft_reboot_capable =
            is_soft_rebootable(storage, booted_cmdline, &booted_info, &target_info)?;
    }

    Ok(())
}

/// Determines whether a soft reboot can be performed between the currently booted
/// deployment and a target deployment.
///
/// # Arguments
///
/// * `storage`      - The bootc storage backend
/// * `booted_cmdline` - The composefs command line parameters of the currently booted deployment
/// * `booted`       - Boot information for the currently booted deployment
/// * `target`       - Boot information for the target deployment
fn is_soft_rebootable(
    storage: &Storage,
    booted_cmdline: &ComposefsCmdline,
    booted: &DeploymentBootInfo,
    target: &DeploymentBootInfo,
) -> Result<bool> {
    if target.boot_digest != booted.boot_digest {
        tracing::debug!("Soft reboot not allowed due to kernel skew");
        return Ok(false);
    }

    if target.full_cmdline.as_bytes().len() != booted.full_cmdline.as_bytes().len() {
        tracing::debug!("Soft reboot not allowed due to differing cmdline");
        return Ok(false);
    }

    let cmdline_eq = compare_cmdline_skip_cfs(target.full_cmdline, booted.full_cmdline)
        && compare_cmdline_skip_cfs(booted.full_cmdline, target.full_cmdline);

    let selinux_compatible =
        are_selinux_policies_compatible(storage, booted_cmdline, target.verity)?;

    return Ok(cmdline_eq && selinux_compatible);
}

#[context("Setting soft reboot capability for UKI deployments")]
fn set_reboot_capable_uki_deployments(
    storage: &Storage,
    booted_cmdline: &ComposefsCmdline,
    host: &mut Host,
) -> Result<()> {
    let booted = host
        .status
        .booted
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Failed to find booted entry"))?;

    // Since older booted systems won't have the boot digest for UKIs
    let booted_boot_digest = match booted.composefs_boot_digest() {
        Ok(d) => d,
        Err(_) => &compute_store_boot_digest_for_uki(storage, &booted_cmdline.digest)?,
    };

    let booted_full_cmdline = get_uki_cmdline(storage, &booted_cmdline.digest)?;

    let booted_info = DeploymentBootInfo {
        boot_digest: booted_boot_digest,
        full_cmdline: &booted_full_cmdline,
        verity: &booted_cmdline.digest,
    };

    for deployment in host
        .status
        .staged
        .iter_mut()
        .chain(host.status.rollback.iter_mut())
        .chain(host.status.other_deployments.iter_mut())
    {
        let depl_verity = &deployment.require_composefs()?.verity;

        // Since older booted systems won't have the boot digest for UKIs
        let depl_boot_digest = match deployment.composefs_boot_digest() {
            Ok(d) => d,
            Err(_) => &compute_store_boot_digest_for_uki(storage, depl_verity)?,
        };

        let depl_cmdline = get_uki_cmdline(storage, &deployment.require_composefs()?.verity)?;

        let target_info = DeploymentBootInfo {
            boot_digest: depl_boot_digest,
            full_cmdline: &depl_cmdline,
            verity: depl_verity,
        };

        deployment.soft_reboot_capable =
            is_soft_rebootable(storage, booted_cmdline, &booted_info, &target_info)?;
    }

    Ok(())
}

#[context("Getting composefs deployment status")]
async fn composefs_deployment_status_from(
    storage: &Storage,
    cmdline: &ComposefsCmdline,
) -> Result<Host> {
    let booted_composefs_digest = &cmdline.digest;

    let boot_dir = storage.require_boot_dir()?;

    // This is our source of truth
    let bootloader_entry_verity = list_bootloader_entries(storage)?;

    let host_spec = HostSpec {
        image: None,
        boot_order: BootOrder::Default,
    };

    let mut host = Host::new(host_spec);

    let staged_deployment = match std::fs::File::open(format!(
        "{COMPOSEFS_TRANSIENT_STATE_DIR}/{COMPOSEFS_STAGED_DEPLOYMENT_FNAME}"
    )) {
        Ok(mut f) => {
            let mut s = String::new();
            f.read_to_string(&mut s)?;

            Ok(Some(s))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }?;

    // NOTE: This cannot work if we support both BLS and UKI at the same time
    let mut boot_type: Option<BootType> = None;

    // Boot entries from deployments that are neither booted nor staged deployments
    // Rollback deployment is in here, but may also contain stale deployment entries
    let mut extra_deployment_boot_entries: Vec<BootEntry> = Vec::new();

    for BootloaderEntry {
        fsverity: verity_digest,
        ..
    } in bootloader_entry_verity
    {
        let ini = read_origin(&storage.physical_root, &verity_digest)?
            .ok_or_else(|| anyhow::anyhow!("No origin file for deployment {verity_digest}"))?;

        let mut boot_entry = boot_entry_from_composefs_deployment(storage, ini, &verity_digest)?;

        // SAFETY: boot_entry.composefs will always be present
        let boot_type_from_origin = boot_entry.composefs.as_ref().unwrap().boot_type;

        match boot_type {
            Some(current_type) => {
                if current_type != boot_type_from_origin {
                    anyhow::bail!("Conflicting boot types")
                }
            }

            None => {
                boot_type = Some(boot_type_from_origin);
            }
        };

        if verity_digest == booted_composefs_digest.as_ref() {
            host.spec.image = boot_entry.image.as_ref().map(|x| x.image.clone());
            host.status.booted = Some(boot_entry);
            continue;
        }

        if let Some(staged_deployment) = &staged_deployment {
            let staged_depl = serde_json::from_str::<StagedDeployment>(&staged_deployment)?;

            if verity_digest == staged_depl.depl_id {
                boot_entry.download_only = staged_depl.finalization_locked;
                host.status.staged = Some(boot_entry);
                continue;
            }
        }

        extra_deployment_boot_entries.push(boot_entry);
    }

    // Shouldn't really happen, but for sanity nonetheless
    let Some(boot_type) = boot_type else {
        anyhow::bail!("Could not determine boot type");
    };

    let booted_cfs = host.require_composefs_booted()?;

    let mut grub_menu_string = String::new();
    let (is_rollback_queued, sorted_bls_config, grub_menu_entries) = match booted_cfs.bootloader {
        Bootloader::Grub => match boot_type {
            BootType::Bls => {
                let bls_configs = get_sorted_type1_boot_entries(boot_dir, false)?;
                let bls_config = bls_configs
                    .first()
                    .ok_or_else(|| anyhow::anyhow!("First boot entry not found"))?;

                match &bls_config.cfg_type {
                    BLSConfigType::NonEFI { options, .. } => {
                        let is_rollback_queued = !options
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("options key not found in bls config"))?
                            .contains(booted_composefs_digest.as_ref());

                        (is_rollback_queued, Some(bls_configs), None)
                    }

                    BLSConfigType::EFI { .. } => {
                        anyhow::bail!("Found 'efi' field in Type1 boot entry")
                    }

                    BLSConfigType::Unknown => anyhow::bail!("Unknown BLS Config Type"),
                }
            }

            BootType::Uki => {
                let menuentries =
                    get_sorted_grub_uki_boot_entries(boot_dir, &mut grub_menu_string)?;

                let is_rollback_queued = !menuentries
                    .first()
                    .ok_or(anyhow::anyhow!("First boot entry not found"))?
                    .body
                    .chainloader
                    .contains(booted_composefs_digest.as_ref());

                (is_rollback_queued, None, Some(menuentries))
            }
        },

        // We will have BLS stuff and the UKI stuff in the same DIR
        Bootloader::Systemd => {
            let bls_configs = get_sorted_type1_boot_entries(boot_dir, true)?;
            let bls_config = bls_configs
                .first()
                .ok_or(anyhow::anyhow!("First boot entry not found"))?;

            let is_rollback_queued = match &bls_config.cfg_type {
                // For UKI boot
                BLSConfigType::EFI { efi } => {
                    efi.as_str().contains(booted_composefs_digest.as_ref())
                }

                // For boot entry Type1
                BLSConfigType::NonEFI { options, .. } => !options
                    .as_ref()
                    .ok_or(anyhow::anyhow!("options key not found in bls config"))?
                    .contains(booted_composefs_digest.as_ref()),

                BLSConfigType::Unknown => anyhow::bail!("Unknown BLS Config Type"),
            };

            (is_rollback_queued, Some(bls_configs), None)
        }

        Bootloader::None => unreachable!("Checked at install time"),
    };

    // Determine rollback deployment by matching extra deployment boot entries against entires read from /boot
    // This collects verity digest across bls and grub enties, we should just have one of them, but still works
    let bootloader_configured_verity = sorted_bls_config
        .iter()
        .flatten()
        .map(|cfg| cfg.get_verity())
        .chain(
            grub_menu_entries
                .iter()
                .flatten()
                .map(|menu| menu.get_verity()),
        )
        .collect::<Result<HashSet<_>>>()?;

    let rollback_candidates: Vec<_> = extra_deployment_boot_entries
        .into_iter()
        .filter(|entry| {
            let verity = &entry
                .composefs
                .as_ref()
                .expect("composefs is always Some for composefs deployments")
                .verity;
            bootloader_configured_verity.contains(verity)
        })
        .collect();

    if rollback_candidates.len() > 1 {
        anyhow::bail!("Multiple extra entries in /boot, could not determine rollback entry");
    } else if let Some(rollback_entry) = rollback_candidates.into_iter().next() {
        host.status.rollback = Some(rollback_entry);
    }

    host.status.rollback_queued = is_rollback_queued;

    if host.status.rollback_queued {
        host.spec.boot_order = BootOrder::Rollback
    };

    host.status.usr_overlay = get_composefs_usr_overlay_status().ok().flatten();

    set_soft_reboot_capability(storage, &mut host, sorted_bls_config, cmdline)?;

    Ok(host)
}

#[cfg(test)]
mod tests {
    use cap_std_ext::{cap_std, dirext::CapStdExtDirExt};

    use crate::parsers::{bls_config::BLSConfigType, grub_menuconfig::MenuentryBody};

    use super::*;

    #[test]
    fn test_composefs_parsing() {
        const DIGEST: &str = "8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52";
        let v = ComposefsCmdline::new(DIGEST);
        assert!(!v.allow_missing_fsverity);
        assert_eq!(v.digest.as_ref(), DIGEST);
        let v = ComposefsCmdline::new(&format!("?{}", DIGEST));
        assert!(v.allow_missing_fsverity);
        assert_eq!(v.digest.as_ref(), DIGEST);
    }

    #[test]
    fn test_sorted_bls_boot_entries() -> Result<()> {
        let tempdir = cap_std_ext::cap_tempfile::tempdir(cap_std::ambient_authority())?;

        let entry1 = r#"
            title Fedora 42.20250623.3.1 (CoreOS)
            version fedora-42.0
            sort-key 1
            linux /boot/7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6/vmlinuz-5.14.10
            initrd /boot/7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6/initramfs-5.14.10.img
            options root=UUID=abc123 rw composefs=7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6
        "#;

        let entry2 = r#"
            title Fedora 41.20250214.2.0 (CoreOS)
            version fedora-42.0
            sort-key 2
            linux /boot/febdf62805de2ae7b6b597f2a9775d9c8a753ba1e5f09298fc8fbe0b0d13bf01/vmlinuz-5.14.10
            initrd /boot/febdf62805de2ae7b6b597f2a9775d9c8a753ba1e5f09298fc8fbe0b0d13bf01/initramfs-5.14.10.img
            options root=UUID=abc123 rw composefs=febdf62805de2ae7b6b597f2a9775d9c8a753ba1e5f09298fc8fbe0b0d13bf01
        "#;

        tempdir.create_dir_all("loader/entries")?;
        tempdir.atomic_write(
            "loader/entries/random_file.txt",
            "Random file that we won't parse",
        )?;
        tempdir.atomic_write("loader/entries/entry1.conf", entry1)?;
        tempdir.atomic_write("loader/entries/entry2.conf", entry2)?;

        let result = get_sorted_type1_boot_entries(&tempdir, true).unwrap();

        let mut config1 = BLSConfig::default();
        config1.title = Some("Fedora 42.20250623.3.1 (CoreOS)".into());
        config1.sort_key = Some("1".into());
        config1.cfg_type = BLSConfigType::NonEFI {
            linux: "/boot/7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6/vmlinuz-5.14.10".into(),
            initrd: vec!["/boot/7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6/initramfs-5.14.10.img".into()],
            options: Some("root=UUID=abc123 rw composefs=7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6".into()),
        };

        let mut config2 = BLSConfig::default();
        config2.title = Some("Fedora 41.20250214.2.0 (CoreOS)".into());
        config2.sort_key = Some("2".into());
        config2.cfg_type = BLSConfigType::NonEFI {
            linux: "/boot/febdf62805de2ae7b6b597f2a9775d9c8a753ba1e5f09298fc8fbe0b0d13bf01/vmlinuz-5.14.10".into(),
            initrd: vec!["/boot/febdf62805de2ae7b6b597f2a9775d9c8a753ba1e5f09298fc8fbe0b0d13bf01/initramfs-5.14.10.img".into()],
            options: Some("root=UUID=abc123 rw composefs=febdf62805de2ae7b6b597f2a9775d9c8a753ba1e5f09298fc8fbe0b0d13bf01".into())
        };

        assert_eq!(result[0].sort_key.as_ref().unwrap(), "1");
        assert_eq!(result[1].sort_key.as_ref().unwrap(), "2");

        let result = get_sorted_type1_boot_entries(&tempdir, false).unwrap();
        assert_eq!(result[0].sort_key.as_ref().unwrap(), "2");
        assert_eq!(result[1].sort_key.as_ref().unwrap(), "1");

        Ok(())
    }

    #[test]
    fn test_sorted_uki_boot_entries() -> Result<()> {
        let user_cfg = r#"
            if [ -f ${config_directory}/efiuuid.cfg ]; then
                    source ${config_directory}/efiuuid.cfg
            fi

            menuentry "Fedora Bootc UKI: (f7415d75017a12a387a39d2281e033a288fc15775108250ef70a01dcadb93346)" {
                insmod fat
                insmod chain
                search --no-floppy --set=root --fs-uuid "${EFI_PART_UUID}"
                chainloader /EFI/Linux/f7415d75017a12a387a39d2281e033a288fc15775108250ef70a01dcadb93346.efi
            }

            menuentry "Fedora Bootc UKI: (7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6)" {
                insmod fat
                insmod chain
                search --no-floppy --set=root --fs-uuid "${EFI_PART_UUID}"
                chainloader /EFI/Linux/7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6.efi
            }
        "#;

        let bootdir = cap_std_ext::cap_tempfile::tempdir(cap_std::ambient_authority())?;
        bootdir.create_dir_all(format!("grub2"))?;
        bootdir.atomic_write(format!("grub2/{USER_CFG}"), user_cfg)?;

        let mut s = String::new();
        let result = get_sorted_grub_uki_boot_entries(&bootdir, &mut s)?;

        let expected = vec![
            MenuEntry {
                title: "Fedora Bootc UKI: (f7415d75017a12a387a39d2281e033a288fc15775108250ef70a01dcadb93346)".into(),
                body: MenuentryBody {
                    insmod: vec!["fat", "chain"],
                    chainloader: "/EFI/Linux/f7415d75017a12a387a39d2281e033a288fc15775108250ef70a01dcadb93346.efi".into(),
                    search: "--no-floppy --set=root --fs-uuid \"${EFI_PART_UUID}\"",
                    version: 0,
                    extra: vec![],
                },
            },
            MenuEntry {
                title: "Fedora Bootc UKI: (7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6)".into(),
                body: MenuentryBody {
                    insmod: vec!["fat", "chain"],
                    chainloader: "/EFI/Linux/7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6.efi".into(),
                    search: "--no-floppy --set=root --fs-uuid \"${EFI_PART_UUID}\"",
                    version: 0,
                    extra: vec![],
                },
            },
        ];

        assert_eq!(result, expected);

        Ok(())
    }

    #[test]
    fn test_find_in_cmdline() {
        const DIGEST: &str = "8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52";

        // Test case: cmdline contains composefs parameter
        let cmdline = Cmdline::from(format!("root=UUID=abc123 rw composefs={}", DIGEST));
        let result = ComposefsCmdline::find_in_cmdline(&cmdline);
        assert!(result.is_some());
        let cfs = result.unwrap();
        assert_eq!(cfs.digest.as_ref(), DIGEST);
        assert!(!cfs.allow_missing_fsverity);

        // Test case: cmdline contains composefs parameter with allow_missing_fsverity
        let cmdline = Cmdline::from(format!("root=UUID=abc123 rw composefs=?{}", DIGEST));
        let result = ComposefsCmdline::find_in_cmdline(&cmdline);
        assert!(result.is_some());
        let cfs = result.unwrap();
        assert_eq!(cfs.digest.as_ref(), DIGEST);
        assert!(cfs.allow_missing_fsverity);

        // Test case: cmdline does not contain composefs parameter
        let cmdline = Cmdline::from("root=UUID=abc123 rw quiet");
        let result = ComposefsCmdline::find_in_cmdline(&cmdline);
        assert!(result.is_none());

        // Test case: empty cmdline
        let cmdline = Cmdline::from("");
        let result = ComposefsCmdline::find_in_cmdline(&cmdline);
        assert!(result.is_none());

        // Test case: cmdline with other parameters and composefs at different positions
        let cmdline = Cmdline::from(format!("quiet composefs={} loglevel=3", DIGEST));
        let result = ComposefsCmdline::find_in_cmdline(&cmdline);
        assert!(result.is_some());
        let cfs = result.unwrap();
        assert_eq!(cfs.digest.as_ref(), DIGEST);
        assert!(!cfs.allow_missing_fsverity);

        // Test case: cmdline with composefs at the beginning
        let cmdline = Cmdline::from(format!("composefs=?{} root=UUID=abc123 quiet", DIGEST));
        let result = ComposefsCmdline::find_in_cmdline(&cmdline);
        assert!(result.is_some());
        let cfs = result.unwrap();
        assert_eq!(cfs.digest.as_ref(), DIGEST);
        assert!(cfs.allow_missing_fsverity);

        // Test case: cmdline with similar parameter names (should not match)
        let cmdline = Cmdline::from(format!("composefs_backup={} root=UUID=abc123", DIGEST));
        let result = ComposefsCmdline::find_in_cmdline(&cmdline);
        assert!(result.is_none());
    }

    use crate::testutils::fake_digest_version;

    /// Test that staged entries are also collected by list_type1_entries.
    /// This is important for GC to not delete staged deployments' boot binaries.
    #[test]
    fn test_list_type1_entries_includes_staged() -> Result<()> {
        let tempdir = cap_std_ext::cap_tempfile::tempdir(cap_std::ambient_authority())?;

        let digest_active = fake_digest_version(0);
        let digest_staged = fake_digest_version(1);

        let active_entry = format!(
            r#"
            title Active Deployment
            version 2
            sort-key 1
            linux /boot/bootc_composefs-{digest_active}/vmlinuz
            initrd /boot/bootc_composefs-{digest_active}/initramfs.img
            options root=UUID=abc123 rw composefs={digest_active}
        "#
        );

        let staged_entry = format!(
            r#"
            title Staged Deployment
            version 3
            sort-key 0
            linux /boot/bootc_composefs-{digest_staged}/vmlinuz
            initrd /boot/bootc_composefs-{digest_staged}/initramfs.img
            options root=UUID=abc123 rw composefs={digest_staged}
        "#
        );

        tempdir.create_dir_all("loader/entries")?;
        tempdir.create_dir_all("loader/entries.staged")?;
        tempdir.atomic_write("loader/entries/active.conf", active_entry)?;
        tempdir.atomic_write("loader/entries.staged/staged.conf", staged_entry)?;

        let result = list_type1_entries(&tempdir)?;
        assert_eq!(result.len(), 2);

        let verity_set: std::collections::HashSet<&str> =
            result.iter().map(|e| e.fsverity.as_str()).collect();
        assert!(
            verity_set.contains(digest_active.as_str()),
            "Should contain active entry"
        );
        assert!(
            verity_set.contains(digest_staged.as_str()),
            "Should contain staged entry"
        );

        Ok(())
    }
}
