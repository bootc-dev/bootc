//! Kernel detection for container images.
//!
//! This module provides functionality to detect kernel information in container
//! images, supporting both traditional kernels (with separate vmlinuz/initrd) and
//! Unified Kernel Images (UKI).

use std::path::Path;

use anyhow::Result;
use camino::Utf8PathBuf;
use cap_std_ext::cap_std::fs::Dir;
use cap_std_ext::dirext::CapStdExtDirExt;
use serde::Serialize;

use crate::bootc_composefs::boot::EFI_LINUX;

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

/// Internal-only kernel wrapper with extra information (paths to
/// vmlinuz, initramfs) that are useful but we don't want to leak out
/// via serialization to inspection.
///
/// `Kernel` implements `From<KernelInternal>` so we can just `.into()`
/// to get the "public" form where needed.
pub(crate) struct KernelInternal {
    pub(crate) kernel: Kernel,
    /// Path to vmlinuz for traditional kernels.
    /// This is `None` for UKI images.
    pub(crate) vmlinuz: Option<Utf8PathBuf>,
    /// Path to initramfs.img for traditional kernels.
    /// This is `None` for UKI images.
    pub(crate) initramfs: Option<Utf8PathBuf>,
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
pub(crate) fn find_kernel(root: &Dir) -> Result<Option<KernelInternal>> {
    // First, try to find a UKI
    if let Some(uki_filename) = find_uki_filename(root)? {
        let version = uki_filename
            .strip_suffix(".efi")
            .unwrap_or(&uki_filename)
            .to_owned();
        return Ok(Some(KernelInternal {
            kernel: Kernel {
                version,
                unified: true,
            },
            vmlinuz: None,
            initramfs: None,
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
            vmlinuz: Some(vmlinuz),
            initramfs: Some(initramfs),
        }));
    }

    Ok(None)
}

/// Returns the filename of the first UKI found in the container root, if any.
///
/// Looks in `/boot/EFI/Linux/*.efi`. If multiple UKIs are present, returns
/// the first one in sorted order for determinism.
fn find_uki_filename(root: &Dir) -> Result<Option<String>> {
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
    Ok(uki_files.into_iter().next())
}

#[cfg(test)]
mod tests {
    use super::*;
    use camino::Utf8Path;
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
        assert_eq!(
            kernel_internal.vmlinuz.as_deref(),
            Some(Utf8Path::new(
                "usr/lib/modules/6.12.0-100.fc41.x86_64/vmlinuz"
            ))
        );
        assert_eq!(
            kernel_internal.initramfs.as_deref(),
            Some(Utf8Path::new(
                "usr/lib/modules/6.12.0-100.fc41.x86_64/initramfs.img"
            ))
        );
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
        assert!(kernel_internal.vmlinuz.is_none());
        assert!(kernel_internal.initramfs.is_none());
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
    fn test_find_uki_filename_sorted() -> Result<()> {
        let tempdir = cap_tempfile::tempdir(cap_std::ambient_authority())?;
        tempdir.create_dir_all("boot/EFI/Linux")?;
        tempdir.atomic_write("boot/EFI/Linux/zzz.efi", b"fake uki")?;
        tempdir.atomic_write("boot/EFI/Linux/aaa.efi", b"fake uki")?;
        tempdir.atomic_write("boot/EFI/Linux/mmm.efi", b"fake uki")?;

        // Should return first in sorted order
        let filename = find_uki_filename(&tempdir)?.expect("should find uki");
        assert_eq!(filename, "aaa.efi");
        Ok(())
    }
}
