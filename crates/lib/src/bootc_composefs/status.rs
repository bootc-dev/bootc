use std::{collections::HashSet, io::Read, sync::OnceLock};

use anyhow::{Context, Result};
use bootc_kernel_cmdline::utf8::Cmdline;
use bootc_mount::inspect_filesystem;
use fn_error_context::context;
use serde::{Deserialize, Serialize};

use crate::{
    bootc_composefs::{
        boot::BootType,
        repo::get_imgref,
        utils::{compute_store_boot_digest_for_uki, get_uki_cmdline},
    },
    composefs_consts::{
        COMPOSEFS_CMDLINE, ORIGIN_KEY_BOOT_DIGEST, TYPE1_ENT_PATH, TYPE1_ENT_PATH_STAGED, USER_CFG,
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
    #[allow(dead_code)]
    pub insecure: bool,
    pub digest: Box<str>,
}

impl ComposefsCmdline {
    pub(crate) fn new(s: &str) -> Self {
        let (insecure, digest_str) = s
            .strip_prefix('?')
            .map(|v| (true, v))
            .unwrap_or_else(|| (false, s));
        ComposefsCmdline {
            insecure,
            digest: digest_str.into(),
        }
    }
}

impl std::fmt::Display for ComposefsCmdline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let insecure = if self.insecure { "?" } else { "" };
        write!(f, "{}={}{}", COMPOSEFS_CMDLINE, insecure, self.digest)
    }
}

/// Detect if we have composefs=<digest> in /proc/cmdline
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

// Need str to store lifetime
pub(crate) fn get_sorted_grub_uki_boot_entries<'a>(
    boot_dir: &Dir,
    str: &'a mut String,
) -> Result<Vec<MenuEntry<'a>>> {
    let mut file = boot_dir
        .open(format!("grub2/{USER_CFG}"))
        .with_context(|| format!("Opening {USER_CFG}"))?;
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

/// imgref = transport:image_name
#[context("Getting container info")]
pub(crate) async fn get_container_manifest_and_config(
    imgref: &String,
) -> Result<ImgConfigManifest> {
    let config = containers_image_proxy::ImageProxyConfig::default();
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

/// Reads the .imginfo file for the provided deployment
#[context("Reading imginfo")]
pub(crate) async fn get_imginfo(
    storage: &Storage,
    deployment_id: &str,
    imgref: Option<&ImageReference>,
) -> Result<ImgConfigManifest> {
    let imginfo_fname = format!("{deployment_id}.imginfo");

    let depl_state_path = std::path::PathBuf::from(STATE_DIR_RELATIVE).join(deployment_id);
    let path = depl_state_path.join(imginfo_fname);

    let mut img_conf = storage
        .physical_root
        .open_optional(&path)
        .context("Failed to open file")?;

    let Some(img_conf) = &mut img_conf else {
        let imgref = imgref.ok_or_else(|| anyhow::anyhow!("No imgref or imginfo file found"))?;

        let container_details =
            get_container_manifest_and_config(&get_imgref(&imgref.transport, &imgref.image))
                .await?;

        let state_dir = storage.physical_root.open_dir(depl_state_path)?;

        state_dir
            .atomic_write(
                format!("{}.imginfo", deployment_id),
                serde_json::to_vec(&container_details)?,
            )
            .context("Failed to write to .imginfo file")?;

        let state_dir = state_dir.reopen_as_ownedfd()?;

        rustix::fs::fsync(state_dir).context("fsync")?;

        return Ok(container_details);
    };

    let mut buffer = String::new();
    img_conf.read_to_string(&mut buffer)?;

    let img_conf = serde_json::from_str::<ImgConfigManifest>(&buffer)
        .context("Failed to parse file as JSON")?;

    Ok(img_conf)
}

#[context("Getting composefs deployment metadata")]
async fn boot_entry_from_composefs_deployment(
    storage: &Storage,
    origin: tini::Ini,
    verity: String,
) -> Result<BootEntry> {
    let image = match origin.get::<String>("origin", ORIGIN_CONTAINER) {
        Some(img_name_from_config) => {
            let ostree_img_ref = OstreeImageReference::from_str(&img_name_from_config)?;
            let img_ref = ImageReference::from(ostree_img_ref);

            let img_conf = get_imginfo(storage, &verity, Some(&img_ref)).await?;

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
        download_only: false, // Not yet supported for composefs backend
        store: None,
        ostree: None,
        composefs: Some(crate::spec::BootEntryComposefs {
            verity,
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
    cmdline: &ComposefsCmdline,
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

            set_reboot_capable_type1_deployments(cmdline, host, bls_entries)
        }

        BootType::Uki => set_reboot_capable_uki_deployments(storage, cmdline, host),
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

    let booted_cmdline = booted_bls_entry.get_cmdline()?;

    for depl in host
        .status
        .staged
        .iter_mut()
        .chain(host.status.rollback.iter_mut())
        .chain(host.status.other_deployments.iter_mut())
    {
        let entry = find_bls_entry(&depl.require_composefs()?.verity, &bls_entries)?
            .ok_or_else(|| anyhow::anyhow!("Entry not found"))?;

        let depl_cmdline = entry.get_cmdline()?;

        depl.soft_reboot_capable = is_soft_rebootable(
            depl.composefs_boot_digest()?,
            booted_boot_digest,
            depl_cmdline,
            booted_cmdline,
        );
    }

    Ok(())
}

fn is_soft_rebootable(
    depl_boot_digest: &str,
    booted_boot_digest: &str,
    depl_cmdline: &Cmdline,
    booted_cmdline: &Cmdline,
) -> bool {
    if depl_boot_digest != booted_boot_digest {
        tracing::debug!("Soft reboot not allowed due to kernel skew");
        return false;
    }

    if depl_cmdline.as_bytes().len() != booted_cmdline.as_bytes().len() {
        tracing::debug!("Soft reboot not allowed due to differing cmdline");
        return false;
    }

    return compare_cmdline_skip_cfs(depl_cmdline, booted_cmdline)
        && compare_cmdline_skip_cfs(booted_cmdline, depl_cmdline);
}

#[context("Setting soft reboot capability for UKI deployments")]
fn set_reboot_capable_uki_deployments(
    storage: &Storage,
    cmdline: &ComposefsCmdline,
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
        Err(_) => &compute_store_boot_digest_for_uki(storage, &cmdline.digest)?,
    };

    let booted_cmdline = get_uki_cmdline(storage, &booted.require_composefs()?.verity)?;

    for deployment in host
        .status
        .staged
        .iter_mut()
        .chain(host.status.rollback.iter_mut())
        .chain(host.status.other_deployments.iter_mut())
    {
        // Since older booted systems won't have the boot digest for UKIs
        let depl_boot_digest = match deployment.composefs_boot_digest() {
            Ok(d) => d,
            Err(_) => &compute_store_boot_digest_for_uki(
                storage,
                &deployment.require_composefs()?.verity,
            )?,
        };

        let depl_cmdline = get_uki_cmdline(storage, &deployment.require_composefs()?.verity)?;

        deployment.soft_reboot_capable = is_soft_rebootable(
            depl_boot_digest,
            booted_boot_digest,
            &depl_cmdline,
            &booted_cmdline,
        );
    }

    Ok(())
}

#[context("Getting composefs deployment status")]
pub(crate) async fn composefs_deployment_status_from(
    storage: &Storage,
    cmdline: &ComposefsCmdline,
) -> Result<Host> {
    let booted_composefs_digest = &cmdline.digest;

    let boot_dir = storage.require_boot_dir()?;

    let deployments = storage
        .physical_root
        .read_dir(STATE_DIR_RELATIVE)
        .with_context(|| format!("Reading sysroot {STATE_DIR_RELATIVE}"))?;

    let host_spec = HostSpec {
        image: None,
        boot_order: BootOrder::Default,
    };

    let mut host = Host::new(host_spec);

    let staged_deployment_id = match std::fs::File::open(format!(
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

    for depl in deployments {
        let depl = depl?;

        let depl_file_name = depl.file_name();
        let depl_file_name = depl_file_name.to_string_lossy();

        // read the origin file
        let config = depl
            .open_dir()
            .with_context(|| format!("Failed to open {depl_file_name}"))?
            .read_to_string(format!("{depl_file_name}.origin"))
            .with_context(|| format!("Reading file {depl_file_name}.origin"))?;

        let ini = tini::Ini::from_string(&config)
            .with_context(|| format!("Failed to parse file {depl_file_name}.origin as ini"))?;

        let boot_entry =
            boot_entry_from_composefs_deployment(storage, ini, depl_file_name.to_string()).await?;

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

        if depl.file_name() == booted_composefs_digest.as_ref() {
            host.spec.image = boot_entry.image.as_ref().map(|x| x.image.clone());
            host.status.booted = Some(boot_entry);
            continue;
        }

        if let Some(staged_deployment_id) = &staged_deployment_id {
            if depl_file_name == staged_deployment_id.trim() {
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
        assert!(!v.insecure);
        assert_eq!(v.digest.as_ref(), DIGEST);
        let v = ComposefsCmdline::new(&format!("?{}", DIGEST));
        assert!(v.insecure);
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
}
