use std::{io::Read, sync::OnceLock};

use anyhow::{Context, Result};
use bootc_kernel_cmdline::utf8::Cmdline;
use fn_error_context::context;
use serde::{Deserialize, Serialize};

use crate::{
    bootc_composefs::boot::BootType,
    composefs_consts::{COMPOSEFS_CMDLINE, ORIGIN_KEY_BOOT_DIGEST, TYPE1_ENT_PATH, USER_CFG},
    install::EFI_LOADER_INFO,
    parsers::{
        bls_config::{parse_bls_config, BLSConfig, BLSConfigType},
        grub_menuconfig::{parse_grub_menuentry_file, MenuEntry},
    },
    spec::{BootEntry, BootOrder, Host, HostSpec, ImageReference, ImageStatus},
    store::Storage,
    utils::{read_uefi_var, EfiError},
};

use std::str::FromStr;

use bootc_utils::try_deserialize_timestamp;
use cap_std_ext::cap_std::fs::Dir;
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
    let r = CACHED_DIGEST_VALUE.get_or_init(|| Some(v));
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

#[context("Getting sorted Type1 boot entries")]
pub(crate) fn get_sorted_type1_boot_entries(
    boot_dir: &Dir,
    ascending: bool,
) -> Result<Vec<BLSConfig>> {
    let mut all_configs = vec![];

    for entry in boot_dir.read_dir(TYPE1_ENT_PATH)? {
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

    let img = proxy.open_image(&imgref).await.context("Opening image")?;

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

            let path = std::path::PathBuf::from(STATE_DIR_RELATIVE)
                .join(&verity)
                .join(format!("{verity}.imginfo"));

            let img_conf = storage
                .physical_root
                .read_to_string(&path)
                .context("Failed to open imginfo file")?;

            let img_conf: ImgConfigManifest =
                serde_json::from_str(&img_conf).context("Failed to parse imginfo file as JSON")?;

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

#[context("Getting composefs deployment status")]
pub(crate) async fn composefs_deployment_status_from(
    storage: &Storage,
    cmdline: &ComposefsCmdline,
) -> Result<Host> {
    let composefs_digest = &cmdline.digest;

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

        if depl.file_name() == composefs_digest.as_ref() {
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

        host.status.rollback = Some(boot_entry);
    }

    // Shouldn't really happen, but for sanity nonetheless
    let Some(boot_type) = boot_type else {
        anyhow::bail!("Could not determine boot type");
    };

    let booted = host.require_composefs_booted()?;

    let is_rollback_queued = match booted.bootloader {
        Bootloader::Grub => match boot_type {
            BootType::Bls => {
                let bls_config = get_sorted_type1_boot_entries(boot_dir, false)?;
                let bls_config = bls_config
                    .first()
                    .ok_or(anyhow::anyhow!("First boot entry not found"))?;

                match &bls_config.cfg_type {
                    BLSConfigType::NonEFI { options, .. } => !options
                        .as_ref()
                        .ok_or(anyhow::anyhow!("options key not found in bls config"))?
                        .contains(composefs_digest.as_ref()),

                    BLSConfigType::EFI { .. } => {
                        anyhow::bail!("Found 'efi' field in Type1 boot entry")
                    }
                    BLSConfigType::Unknown => anyhow::bail!("Unknown BLS Config Type"),
                }
            }

            BootType::Uki => {
                let mut s = String::new();

                !get_sorted_grub_uki_boot_entries(boot_dir, &mut s)?
                    .first()
                    .ok_or(anyhow::anyhow!("First boot entry not found"))?
                    .body
                    .chainloader
                    .contains(composefs_digest.as_ref())
            }
        },

        // We will have BLS stuff and the UKI stuff in the same DIR
        Bootloader::Systemd => {
            let bls_config = get_sorted_type1_boot_entries(boot_dir, false)?;
            let bls_config = bls_config
                .first()
                .ok_or(anyhow::anyhow!("First boot entry not found"))?;

            match &bls_config.cfg_type {
                // For UKI boot
                BLSConfigType::EFI { efi } => efi.as_str().contains(composefs_digest.as_ref()),

                // For boot entry Type1
                BLSConfigType::NonEFI { options, .. } => !options
                    .as_ref()
                    .ok_or(anyhow::anyhow!("options key not found in bls config"))?
                    .contains(composefs_digest.as_ref()),

                BLSConfigType::Unknown => anyhow::bail!("Unknown BLS Config Type"),
            }
        }
    };

    host.status.rollback_queued = is_rollback_queued;

    if host.status.rollback_queued {
        host.spec.boot_order = BootOrder::Rollback
    };

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
