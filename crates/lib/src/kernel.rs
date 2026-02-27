//! Kernel detection for container images.
//!
//! This module provides functionality to detect kernel information in container
//! images, supporting both traditional kernels (with separate vmlinuz/initrd) and
//! Unified Kernel Images (UKI).

use std::path::Path;

use anyhow::{Context, Result};
use bootc_kernel_cmdline::utf8::Cmdline;
use camino::Utf8PathBuf;
use cap_std_ext::cap_std::fs::Dir;
use cap_std_ext::dirext::CapStdExtDirExt;
use fn_error_context::context;
use serde::Serialize;

use crate::bootc_composefs::boot::EFI_LINUX;
use crate::bootc_composefs::status::ComposefsCmdline;
use crate::composefs_consts::COMPOSEFS_CMDLINE;

/// Information about the kernel in a container image.
#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct Kernel {
    /// The kernel version identifier. For traditional kernels, this is derived from the
    /// `/usr/lib/modules/<version>` directory name. For UKI images, this is the UKI filename
    /// (without the .efi extension).
    pub(crate) version: String,
    /// Whether the kernel is packaged as a UKI (Unified Kernel Image).
    pub(crate) unified: bool,
}

/// Path to kernel component(s)
///
/// UKI kernels only have the single PE binary, whereas
/// traditional "vmlinuz" kernels have distinct kernel and
/// initramfs.
pub(crate) enum KernelType {
    Uki {
        path: Utf8PathBuf,
        allow_missing_fsverity: bool,
    },
    Vmlinuz {
        path: Utf8PathBuf,
        initramfs: Utf8PathBuf,
    },
}

/// Internal-only kernel wrapper with extra path information that are
/// useful but we don't want to leak out via serialization to
/// inspection.
///
/// `Kernel` implements `From<KernelInternal>` so we can just `.into()`
/// to get the "public" form where needed.
pub(crate) struct KernelInternal {
    pub(crate) kernel: Kernel,
    pub(crate) k_type: KernelType,
}

impl From<KernelInternal> for Kernel {
    fn from(kernel_internal: KernelInternal) -> Self {
        kernel_internal.kernel
    }
}

/// Find the kernel in a container image root directory.
///
/// This function first attempts to find a UKI in `/boot/EFI/Linux/*.efi`.
/// If that doesn't exist, it falls back to looking for a traditional kernel
/// layout with `/usr/lib/modules/<version>/vmlinuz`.
///
/// Returns `None` if no kernel is found.
#[context("Finding kernel")]
pub(crate) fn find_kernel(root: &Dir) -> Result<Option<KernelInternal>> {
    // First, try to find a UKI
    if let Some(uki_path) = find_uki_path(root)? {
        let version = uki_path.file_stem().unwrap_or(uki_path.as_str()).to_owned();

        let uki = root.read(&uki_path).context("Reading UKI")?;

        // Best effort to check for composefs=?verity in the UKI cmdline
        let cmdline = composefs_boot::uki::get_section(&uki, ".cmdline");

        let allow_missing_fsverity = match cmdline {
            Some(Ok(cmdline)) => {
                let cmdline_str = std::str::from_utf8(cmdline)?;

                let cmdline = Cmdline::from(cmdline_str);

                match cmdline.find(COMPOSEFS_CMDLINE) {
                    Some(param) => ComposefsCmdline::new(&param).allow_missing_fsverity,

                    // The cmdline might be in an addon, so don't allow missing verity
                    None => false,
                }
            }

            Some(Err(uki_error)) => match uki_error {
                composefs_boot::uki::UkiError::MissingSection(_) => {
                    // TODO(Johan-Liebert1): Check this when we have full UKI Addons support
                    // The cmdline might be in an addon, so don't allow missing verity
                    false
                }

                e => anyhow::bail!("Failed to read UKI cmdline: {e:?}"),
            },

            None => false,
        };

        return Ok(Some(KernelInternal {
            kernel: Kernel {
                version,
                unified: true,
            },
            k_type: KernelType::Uki {
                path: uki_path,
                allow_missing_fsverity,
            },
        }));
    }

    // Fall back to checking for a traditional kernel via ostree_ext
    if let Some(modules_dir) = ostree_ext::bootabletree::find_kernel_dir_fs(root)? {
        let version = modules_dir
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("kernel dir should have a file name: {modules_dir}"))?
            .to_owned();
        let vmlinuz = modules_dir.join("vmlinuz");
        let initramfs = modules_dir.join("initramfs.img");
        return Ok(Some(KernelInternal {
            kernel: Kernel {
                version,
                unified: false,
            },
            k_type: KernelType::Vmlinuz {
                path: vmlinuz,
                initramfs,
            },
        }));
    }

    Ok(None)
}

/// Returns the path to the first UKI found in the container root, if any.
///
/// Looks in `/boot/EFI/Linux/*.efi`. If multiple UKIs are present, returns
/// the first one in sorted order for determinism.
fn find_uki_path(root: &Dir) -> Result<Option<Utf8PathBuf>> {
    let Some(boot) = root.open_dir_optional(crate::install::BOOT)? else {
        return Ok(None);
    };
    let Some(efi_linux) = boot.open_dir_optional(EFI_LINUX)? else {
        return Ok(None);
    };

    let mut uki_files = Vec::new();
    for entry in efi_linux.entries()? {
        let entry = entry?;
        let name = entry.file_name();
        let name_path = Path::new(&name);
        let extension = name_path.extension().and_then(|v| v.to_str());
        if extension == Some("efi") {
            if let Some(name_str) = name.to_str() {
                uki_files.push(name_str.to_owned());
            }
        }
    }

    // Sort for deterministic behavior when multiple UKIs are present
    uki_files.sort();
    Ok(uki_files
        .into_iter()
        .next()
        .map(|filename| Utf8PathBuf::from(format!("boot/{EFI_LINUX}/{filename}"))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std_ext::{cap_std, cap_tempfile, dirext::CapStdExtDirExt};

    #[test]
    fn test_find_kernel_none() -> Result<()> {
        let tempdir = cap_tempfile::tempdir(cap_std::ambient_authority())?;
        assert!(find_kernel(&tempdir)?.is_none());
        Ok(())
    }

    #[test]
    fn test_find_kernel_traditional() -> Result<()> {
        let tempdir = cap_tempfile::tempdir(cap_std::ambient_authority())?;
        tempdir.create_dir_all("usr/lib/modules/6.12.0-100.fc41.x86_64")?;
        tempdir.atomic_write(
            "usr/lib/modules/6.12.0-100.fc41.x86_64/vmlinuz",
            b"fake kernel",
        )?;

        let kernel_internal = find_kernel(&tempdir)?.expect("should find kernel");
        assert_eq!(kernel_internal.kernel.version, "6.12.0-100.fc41.x86_64");
        assert!(!kernel_internal.kernel.unified);
        match &kernel_internal.k_type {
            KernelType::Vmlinuz { path, initramfs } => {
                assert_eq!(
                    path.as_str(),
                    "usr/lib/modules/6.12.0-100.fc41.x86_64/vmlinuz"
                );
                assert_eq!(
                    initramfs.as_str(),
                    "usr/lib/modules/6.12.0-100.fc41.x86_64/initramfs.img"
                );
            }
            KernelType::Uki { .. } => panic!("Expected Vmlinuz, got Uki"),
        }
        Ok(())
    }

    #[test]
    fn test_find_kernel_uki() -> Result<()> {
        let tempdir = cap_tempfile::tempdir(cap_std::ambient_authority())?;
        tempdir.create_dir_all("boot/EFI/Linux")?;
        tempdir.atomic_write("boot/EFI/Linux/fedora-6.12.0.efi", b"fake uki")?;

        let kernel_internal = find_kernel(&tempdir)?.expect("should find kernel");
        assert_eq!(kernel_internal.kernel.version, "fedora-6.12.0");
        assert!(kernel_internal.kernel.unified);
        match &kernel_internal.k_type {
            KernelType::Uki { path, .. } => {
                assert_eq!(path.as_str(), "boot/EFI/Linux/fedora-6.12.0.efi");
            }
            KernelType::Vmlinuz { .. } => panic!("Expected Uki, got Vmlinuz"),
        }
        Ok(())
    }

    #[test]
    fn test_find_kernel_uki_takes_precedence() -> Result<()> {
        let tempdir = cap_tempfile::tempdir(cap_std::ambient_authority())?;
        // Both traditional and UKI exist
        tempdir.create_dir_all("usr/lib/modules/6.12.0-100.fc41.x86_64")?;
        tempdir.atomic_write(
            "usr/lib/modules/6.12.0-100.fc41.x86_64/vmlinuz",
            b"fake kernel",
        )?;
        tempdir.create_dir_all("boot/EFI/Linux")?;
        tempdir.atomic_write("boot/EFI/Linux/fedora-6.12.0.efi", b"fake uki")?;

        let kernel_internal = find_kernel(&tempdir)?.expect("should find kernel");
        // UKI should take precedence
        assert_eq!(kernel_internal.kernel.version, "fedora-6.12.0");
        assert!(kernel_internal.kernel.unified);
        Ok(())
    }

    #[test]
    fn test_find_uki_path_sorted() -> Result<()> {
        let tempdir = cap_tempfile::tempdir(cap_std::ambient_authority())?;
        tempdir.create_dir_all("boot/EFI/Linux")?;
        tempdir.atomic_write("boot/EFI/Linux/zzz.efi", b"fake uki")?;
        tempdir.atomic_write("boot/EFI/Linux/aaa.efi", b"fake uki")?;
        tempdir.atomic_write("boot/EFI/Linux/mmm.efi", b"fake uki")?;

        // Should return first in sorted order
        let path = find_uki_path(&tempdir)?.expect("should find uki");
        assert_eq!(path.as_str(), "boot/EFI/Linux/aaa.efi");
        Ok(())
    }
}
