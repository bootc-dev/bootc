//! Shared helpers for building `bcvk` CLI arguments.
//!
//! Both the sysext dev-VM flow and the tmt test runner need to translate
//! `BOOTC_*` environment variables into `bcvk libvirt run` flags.  This
//! module centralises that logic so the two code paths stay in sync.

use anyhow::Result;
use camino::Utf8Path;
use fn_error_context::context;

use crate::{Bootloader, SealState};

/// Default directory for secure boot test keys.
const DEFAULT_SB_KEYS_DIR: &str = "target/test-secureboot";

/// Resolved bcvk install options, ready to be turned into CLI args.
///
/// Construct via [`BcvkInstallOpts::from_env`] (reads `BOOTC_*` env vars)
/// or populate fields directly.
#[derive(Debug, Default)]
pub(crate) struct BcvkInstallOpts {
    pub(crate) composefs_backend: bool,
    pub(crate) bootloader: Option<Bootloader>,
    pub(crate) filesystem: Option<String>,
    pub(crate) seal_state: Option<SealState>,
    pub(crate) kargs: Vec<String>,
}

impl BcvkInstallOpts {
    /// Build from `BOOTC_*` environment variables.
    ///
    /// `BOOTC_variant=composefs` implies `composefs_backend = true`.
    pub(crate) fn from_env() -> Self {
        let composefs_backend = std::env::var("BOOTC_variant")
            .map(|v| v == "composefs")
            .unwrap_or(false);

        let bootloader = std::env::var("BOOTC_bootloader")
            .ok()
            .and_then(|v| match v.as_str() {
                "grub" => Some(Bootloader::Grub),
                "systemd" => Some(Bootloader::Systemd),
                _ => None,
            });

        let filesystem = std::env::var("BOOTC_filesystem").ok();

        let seal_state = std::env::var("BOOTC_seal_state")
            .ok()
            .and_then(|v| match v.as_str() {
                "sealed" => Some(SealState::Sealed),
                "unsealed" => Some(SealState::Unsealed),
                _ => None,
            });

        Self {
            composefs_backend,
            bootloader,
            filesystem,
            seal_state,
            kargs: Vec::new(),
        }
    }

    /// Return the install-related args for `bcvk libvirt run`.
    ///
    /// This covers `--composefs-backend`, `--filesystem`, `--bootloader`,
    /// and `--karg` flags.
    pub(crate) fn install_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if self.composefs_backend {
            args.push("--composefs-backend".into());
            let fs = self.filesystem.as_deref().unwrap_or("ext4");
            args.push(format!("--filesystem={fs}"));
        }
        if let Some(b) = &self.bootloader {
            args.push(format!("--bootloader={b}"));
        }
        for k in &self.kargs {
            args.push(format!("--karg={k}"));
        }
        args
    }

    fn is_sealed(&self) -> bool {
        self.seal_state
            .as_ref()
            .is_some_and(|s| *s == SealState::Sealed)
    }

    /// Return firmware / secure-boot args for `bcvk libvirt run`.
    ///
    /// For sealed images the secure boot keys directory must already
    /// exist; the caller can use [`ensure_secureboot_keys`] first.
    #[context("Building firmware arguments")]
    pub(crate) fn firmware_args(&self) -> Result<Vec<String>> {
        let sb_keys_dir = Utf8Path::new(DEFAULT_SB_KEYS_DIR);
        if self.is_sealed() {
            if sb_keys_dir.try_exists()? {
                let sb_keys_dir = sb_keys_dir.canonicalize_utf8()?;
                Ok(vec![
                    "--firmware=uefi-secure".into(),
                    format!("--secure-boot-keys={sb_keys_dir}"),
                ])
            } else {
                anyhow::bail!(
                    "Sealed image but no secure boot keys at {sb_keys_dir}. \
                     Run 'just generate-secureboot-keys' to generate them."
                );
            }
        } else if matches!(self.bootloader, Some(Bootloader::Systemd)) {
            Ok(vec!["--firmware=uefi-insecure".into()])
        } else {
            Ok(Vec::new())
        }
    }
}
