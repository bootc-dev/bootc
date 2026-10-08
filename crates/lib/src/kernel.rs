//! Kernel detection for container images.
//!
//! This module provides functionality to detect kernel information in container
//! images, supporting both traditional kernels (with separate vmlinuz/initrd) and
//! Unified Kernel Images (UKI), and aboot payloads.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use anyhow::{Context, Result};
use camino::Utf8PathBuf;
use cap_std_ext::cap_std::fs::Dir;
use cap_std_ext::dirext::CapStdExtDirExt;
use composefs_boot::{
    android_boot::{AndroidBootImage, Component},
    bootloader::AbootEncoding,
};
use composefs_ctl::composefs_boot;
use linux_kernel_cmdline::utf8::Cmdline;
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

/// Path to kernel component(s)
///
/// UKI kernels only have the single PE binary, whereas
/// traditional "vmlinuz" kernels have distinct kernel and
/// initramfs.
pub(crate) enum KernelType {
    Aboot {
        path: Utf8PathBuf,
        encoding: AbootEncoding,
        cmdline: Cmdline<'static>,
    },
    Uki {
        path: Utf8PathBuf,
        /// The commandline we found in the UKI
        /// Again due to UKI Addons, we may or may not have it in the UKI itself
        cmdline: Option<Cmdline<'static>>,
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
/// layout with `/usr/lib/modules/<version>/vmlinuz`. Modern aboot payloads
/// are detected in `/boot/aboot-<version>.img` and cannot coexist with either.
///
/// Returns `None` if no kernel is found.
pub(crate) fn find_kernel(root: &Dir) -> Result<Option<KernelInternal>> {
    if let Some(aboot) = find_aboot_kernel(root)? {
        anyhow::ensure!(
            find_uki_path(root)?.is_none()
                && ostree_ext::bootabletree::find_kernel_dir_fs(root)?.is_none()
                && !has_type1_entries(root)?,
            "aboot payload cannot be combined with other boot artifacts"
        );
        return Ok(Some(aboot));
    }

    // First, try to find a UKI
    if let Some(uki_path) = find_uki_path(root)? {
        let version = uki_path.file_stem().unwrap_or(uki_path.as_str()).to_owned();

        let mut uki = root.open(&uki_path).context("Opening UKI")?;

        // Best effort to check for composefs=?verity in the UKI cmdline
        let cmdline = composefs_boot::uki::get_section_buffered(&mut uki, ".cmdline");

        let cmdline = match cmdline {
            Ok(cmdline) => {
                let cmdline_str = std::str::from_utf8(&cmdline)?;
                Some(Cmdline::from(cmdline_str.to_owned()))
            }

            Err(uki_error) => match uki_error {
                composefs_boot::uki::UkiError::MissingSection(_) => {
                    // TODO(Johan-Liebert1): Check this when we have full UKI Addons support
                    // The cmdline might be in an addon, so don't allow missing verity
                    None
                }

                e => anyhow::bail!("Failed to read UKI cmdline: {e:?}"),
            },
        };

        return Ok(Some(KernelInternal {
            kernel: Kernel {
                version,
                unified: true,
            },
            k_type: KernelType::Uki {
                path: uki_path,
                cmdline,
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

pub(crate) fn read_aboot_metadata<R: Read + Seek>(
    image: &mut R,
) -> Result<(AbootEncoding, Cmdline<'static>)> {
    let mut magic = [0; 8];
    image
        .read_exact(&mut magic)
        .context("Reading aboot payload magic")?;
    image.seek(SeekFrom::Start(0))?;
    let (encoding, cmdline) = if magic == *b"ANDROID!" {
        let header = AndroidBootImage::parse(image).context("Parsing Android boot image")?;
        header.component(image, Component::Kernel)?;
        header.component(image, Component::Ramdisk)?;
        (AbootEncoding::AndroidV2, header.cmdline()?.to_owned())
    } else {
        composefs_boot::uki::get_section_buffered(image, ".linux")?;
        image.seek(SeekFrom::Start(0))?;
        composefs_boot::uki::get_section_buffered(image, ".initrd")?;
        image.seek(SeekFrom::Start(0))?;
        (
            AbootEncoding::Uki,
            composefs_boot::uki::get_cmdline_buffered(image)?,
        )
    };
    Ok((encoding, Cmdline::from(cmdline)))
}

fn find_aboot_kernel(root: &Dir) -> Result<Option<KernelInternal>> {
    let Some(boot) = root.open_dir_optional("boot")? else {
        return Ok(None);
    };
    let mut payload = None;
    let mut vbmeta_versions = Vec::new();
    for entry in boot.entries()? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if let Some(version) = name
            .strip_prefix("vbmeta-")
            .and_then(|s| s.strip_suffix(".img"))
        {
            anyhow::ensure!(entry.file_type()?.is_file(), "{name} is not a regular file");
            vbmeta_versions.push(version.to_owned());
        }
        let Some(version) = name
            .strip_prefix("aboot-")
            .and_then(|s| s.strip_suffix(".img"))
        else {
            continue;
        };
        anyhow::ensure!(!version.is_empty(), "aboot payload has no kernel version");
        anyhow::ensure!(entry.file_type()?.is_file(), "{name} is not a regular file");
        anyhow::ensure!(payload.is_none(), "multiple aboot payloads found");
        payload = Some((version.to_owned(), name.to_owned()));
    }
    for version in &vbmeta_versions {
        anyhow::ensure!(
            payload.as_ref().is_some_and(|(v, _)| v == version),
            "vbmeta image has no matching aboot payload"
        );
    }
    let Some((version, name)) = payload else {
        return Ok(None);
    };
    let path = Utf8PathBuf::from("boot").join(name);
    let mut file = root
        .open(&path)
        .with_context(|| format!("Opening {path}"))?;
    let (encoding, cmdline) =
        read_aboot_metadata(&mut file).with_context(|| format!("Parsing {path}"))?;
    anyhow::ensure!(
        encoding != AbootEncoding::Uki || vbmeta_versions.is_empty(),
        "ukiboot payload must not have a vbmeta image"
    );
    Ok(Some(KernelInternal {
        kernel: Kernel {
            version,
            unified: encoding == AbootEncoding::Uki,
        },
        k_type: KernelType::Aboot {
            path,
            encoding,
            cmdline,
        },
    }))
}

/// The boot artifact type reported by `bootc container inspect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ContainerImageType {
    Aboot,
    AbootEfi,
    Uki,
    Vmlinuz,
}

impl ContainerImageType {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Aboot => "aboot",
            Self::AbootEfi => "aboot-efi",
            Self::Uki => "UKI",
            Self::Vmlinuz => "vmlinuz",
        }
    }
}

impl KernelType {
    pub(crate) fn cmdline(&self) -> Option<&Cmdline<'static>> {
        match self {
            Self::Aboot { cmdline, .. } => Some(cmdline),
            Self::Uki { cmdline, .. } => cmdline.as_ref(),
            Self::Vmlinuz { .. } => None,
        }
    }

    pub(crate) fn is_unified(&self) -> bool {
        matches!(self, Self::Uki { .. } | Self::Aboot { .. })
    }

    pub(crate) fn image_type(&self) -> ContainerImageType {
        match self {
            Self::Aboot {
                encoding: AbootEncoding::AndroidV2,
                ..
            } => ContainerImageType::Aboot,
            Self::Aboot {
                encoding: AbootEncoding::Uki,
                ..
            } => ContainerImageType::AbootEfi,
            Self::Uki { .. } => ContainerImageType::Uki,
            Self::Vmlinuz { .. } => ContainerImageType::Vmlinuz,
        }
    }
}

/// Files that distributions ship next to `vmlinuz` in `/usr/lib/modules/<kver>/`
/// which belong to that kernel binary, and so must travel with it.
///
/// - `.vmlinuz.hmac`: the kernel's HMAC, which dracut's `fips` module checks
///   at boot in FIPS mode. Shipped by Fedora and RHEL derivatives' kernel
///   packages; ostree and Fedora's grub2 kernel-install plugin install it next
///   to the kernel as `.vmlinuz-<kver>.hmac`.
///
/// This is deliberately limited to companions of the kernel binary. Userspace
/// metadata such as `config`, `System.map` or `symvers.xz` stays in the rootfs,
/// where tools look for it. ostree also installs a `devicetree` file or `dtb/`
/// directory and an `aboot.img` from this directory, but those are separate
/// boot inputs rather than companions of `vmlinuz`, so they are left alone.
pub(crate) const KERNEL_COMPANION_FILES: &[&str] = &[".vmlinuz.hmac"];

/// Move the kernel out of `root` into `output/<kver>/`.
///
/// The kernel is written as `vmlinuz` and the initramfs as `initramfs.img`,
/// along with any [`KERNEL_COMPANION_FILES`] present, under the same names.
/// UKIs are not supported. Returns the kernel version.
pub(crate) fn split_kernel(root: &Dir, output: &Dir) -> Result<String> {
    let kernel = find_kernel(root)?.ok_or_else(|| anyhow::anyhow!("No kernel found in rootfs"))?;
    let KernelType::Vmlinuz { path, initramfs } = &kernel.k_type else {
        anyhow::bail!("Only traditional kernels can be split");
    };
    let kver = kernel.kernel.version;

    output
        .create_dir_all(&kver)
        .with_context(|| format!("Creating {kver} in output directory"))?;
    let dest = output.open_dir(&kver)?;

    root.rename(path, &dest, "vmlinuz")
        .with_context(|| format!("Moving {path}"))?;
    root.rename(initramfs, &dest, "initramfs.img")
        .with_context(|| format!("Moving {initramfs}"))?;

    for &name in KERNEL_COMPANION_FILES {
        let src = path.with_file_name(name);
        match root.rename(&src, &dest, name) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            r => r.with_context(|| format!("Moving {src}"))?,
        }
    }

    Ok(kver)
}

fn has_type1_entries(root: &Dir) -> Result<bool> {
    let Some(entries) = root.open_dir_optional("boot/loader/entries")? else {
        return Ok(false);
    };
    for entry in entries.entries()? {
        if Path::new(&entry?.file_name())
            .extension()
            .is_some_and(|s| s == "conf")
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Returns the path to the first UKI found in the container root, if any.
///
/// Looks in `/boot/EFI/Linux/*.efi`, excluding addons. If multiple UKIs are present, returns
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
        if extension == Some("efi") && !name.to_string_lossy().ends_with(".addon.efi") {
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
    use bootc_utils::create_minimal_pe;
    use cap_std_ext::{cap_std, cap_tempfile, dirext::CapStdExtDirExt};

    fn android_image() -> Vec<u8> {
        let mut image = vec![0; 4097];
        image[..8].copy_from_slice(b"ANDROID!");
        for (offset, value) in [(8, 1u32), (16, 1), (36, 2048), (40, 2), (1644, 1660)] {
            image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        image[64..69].copy_from_slice(b"quiet");
        image[2048] = 1;
        image[4096] = 2;
        image
    }

    fn aboot_uki() -> Vec<u8> {
        let mut image = create_minimal_pe();
        image[0x86..0x88].copy_from_slice(&3u16.to_le_bytes());
        let headers = 0x188;
        for (i, name) in [b".linux\0\0", b".initrd\0"].iter().enumerate() {
            let offset = headers + 40 * (i + 1);
            image[offset..offset + 8].copy_from_slice(*name);
            image[offset + 8..offset + 12].copy_from_slice(&1u32.to_le_bytes());
            image[offset + 16..offset + 20].copy_from_slice(&1u32.to_le_bytes());
            image[offset + 20..offset + 24].copy_from_slice(&0x200u32.to_le_bytes());
        }
        image
    }

    #[test]
    fn test_aboot_kernel_detection() -> Result<()> {
        for (payload, encoding, image_type) in [
            (
                android_image(),
                AbootEncoding::AndroidV2,
                ContainerImageType::Aboot,
            ),
            (
                aboot_uki(),
                AbootEncoding::Uki,
                ContainerImageType::AbootEfi,
            ),
        ] {
            let root = cap_tempfile::tempdir(cap_std::ambient_authority())?;
            root.create_dir("boot")?;
            root.write("boot/aboot-6.12.img", payload)?;
            let kernel = find_kernel(&root)?.unwrap();
            assert_eq!(kernel.kernel.version, "6.12");
            assert_eq!(kernel.k_type.image_type(), image_type);
            assert!(kernel.k_type.is_unified());
            assert!(
                kernel
                    .k_type
                    .cmdline()
                    .unwrap()
                    .to_string()
                    .contains("quiet")
            );
            let KernelType::Aboot {
                path,
                encoding: actual,
                ..
            } = kernel.k_type
            else {
                panic!()
            };
            assert_eq!(path, "boot/aboot-6.12.img");
            assert_eq!(actual, encoding);
            root.write("boot/aboot-6.13.img", android_image())?;
            assert!(find_kernel(&root).is_err());
        }
        Ok(())
    }

    #[test]
    fn test_aboot_detection_validation() -> Result<()> {
        for (files, valid) in [
            (vec![("boot/aboot-6.12.img", android_image())], true),
            (
                vec![
                    ("boot/aboot-6.12.img", android_image()),
                    ("boot/EFI/Linux/slot.addon.efi", create_minimal_pe()),
                ],
                true,
            ),
            (
                vec![
                    ("boot/aboot-6.12.img", android_image()),
                    ("boot/loader/entries/example.conf", vec![0]),
                ],
                false,
            ),
            (vec![("boot/aboot-6.12.img", b"ANDROID!".to_vec())], false),
            (vec![("boot/aboot-.img", android_image())], false),
            (vec![("boot/vbmeta-6.12.img", vec![0])], false),
            (
                vec![
                    ("boot/aboot-6.12.img", aboot_uki()),
                    ("boot/vbmeta-6.12.img", vec![0]),
                ],
                false,
            ),
            (
                vec![
                    ("boot/aboot-6.12.img", android_image()),
                    ("usr/lib/modules/6.12/vmlinuz", vec![0]),
                ],
                false,
            ),
        ] {
            let root = cap_tempfile::tempdir(cap_std::ambient_authority())?;
            for (path, contents) in files {
                let path = std::path::Path::new(path);
                root.create_dir_all(path.parent().unwrap())?;
                root.write(path, contents)?;
            }
            assert_eq!(find_kernel(&root).is_ok(), valid);
        }
        let root = cap_tempfile::tempdir(cap_std::ambient_authority())?;
        root.create_dir_all("usr/lib/modules/6.12")?;
        root.write("usr/lib/modules/6.12/vmlinuz", b"kernel")?;
        root.write("usr/lib/modules/6.12/aboot.img", b"legacy")?;
        assert!(matches!(
            find_kernel(&root)?.unwrap().k_type,
            KernelType::Vmlinuz { .. }
        ));
        Ok(())
    }

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
        assert!(!kernel_internal.k_type.is_unified());
        assert!(kernel_internal.k_type.cmdline().is_none());
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
            _ => panic!("Expected Vmlinuz"),
        }
        Ok(())
    }

    #[test]
    fn test_find_kernel_uki() -> Result<()> {
        let tempdir = cap_tempfile::tempdir(cap_std::ambient_authority())?;
        tempdir.create_dir_all("boot/EFI/Linux")?;
        tempdir.atomic_write("boot/EFI/Linux/fedora-6.12.0.efi", &create_minimal_pe())?;

        let kernel_internal = find_kernel(&tempdir)?.expect("should find kernel");
        assert_eq!(kernel_internal.kernel.version, "fedora-6.12.0");
        assert!(kernel_internal.kernel.unified);
        assert!(kernel_internal.k_type.is_unified());
        match &kernel_internal.k_type {
            KernelType::Uki { path, .. } => {
                assert_eq!(path.as_str(), "boot/EFI/Linux/fedora-6.12.0.efi");
            }
            _ => panic!("Expected Uki"),
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
        tempdir.atomic_write("boot/EFI/Linux/fedora-6.12.0.efi", &create_minimal_pe())?;

        let kernel_internal = find_kernel(&tempdir)?.expect("should find kernel");
        // UKI should take precedence
        assert_eq!(kernel_internal.kernel.version, "fedora-6.12.0");
        assert!(kernel_internal.kernel.unified);
        Ok(())
    }

    #[test]
    fn test_split_kernel() -> Result<()> {
        const KVER: &str = "6.12.0-100.fc41.x86_64";
        let moddir = format!("usr/lib/modules/{KVER}");
        // Userspace metadata that distributions also put here; it must stay.
        const STAYS: &[&str] = &["modules.dep", "config", "System.map"];
        // Companion files are optional: try none, each one alone, and all of them.
        let cases = std::iter::once(&[][..])
            .chain(KERNEL_COMPANION_FILES.chunks(1))
            .chain(std::iter::once(KERNEL_COMPANION_FILES));
        for present in cases {
            let root = cap_tempfile::tempdir(cap_std::ambient_authority())?;
            let output = cap_tempfile::tempdir(cap_std::ambient_authority())?;
            root.create_dir_all(&moddir)?;
            root.atomic_write(format!("{moddir}/vmlinuz"), b"kernel")?;
            root.atomic_write(format!("{moddir}/initramfs.img"), b"initramfs")?;
            for name in STAYS.iter().chain(present) {
                root.atomic_write(format!("{moddir}/{name}"), name)?;
            }

            assert_eq!(split_kernel(&root, &output)?, KVER);

            let mut remaining: Vec<_> = root
                .read_dir(&moddir)?
                .map(|e| e.map(|e| e.file_name()))
                .collect::<std::io::Result<_>>()?;
            remaining.sort();
            let mut expected = STAYS.to_vec();
            expected.sort();
            assert_eq!(remaining, expected, "{present:?}");

            let dest = output.open_dir(KVER)?;
            assert_eq!(dest.read("vmlinuz")?, b"kernel");
            assert_eq!(dest.read("initramfs.img")?, b"initramfs");
            for &name in KERNEL_COMPANION_FILES {
                if present.contains(&name) {
                    assert_eq!(dest.read(name)?, name.as_bytes(), "{name}");
                } else {
                    assert!(!dest.try_exists(name)?, "{name}");
                }
            }
        }
        Ok(())
    }

    #[test]
    fn test_split_kernel_uki() -> Result<()> {
        let root = cap_tempfile::tempdir(cap_std::ambient_authority())?;
        let output = cap_tempfile::tempdir(cap_std::ambient_authority())?;
        root.create_dir_all("boot/EFI/Linux")?;
        root.atomic_write("boot/EFI/Linux/fedora-6.12.0.efi", &create_minimal_pe())?;
        assert!(split_kernel(&root, &output).is_err());
        // An empty rootfs has no kernel at all
        assert!(split_kernel(&output, &root).is_err());
        Ok(())
    }

    #[test]
    fn test_find_uki_path_sorted() -> Result<()> {
        let tempdir = cap_tempfile::tempdir(cap_std::ambient_authority())?;
        tempdir.create_dir_all("boot/EFI/Linux")?;
        tempdir.atomic_write("boot/EFI/Linux/zzz.efi", &create_minimal_pe())?;
        tempdir.atomic_write("boot/EFI/Linux/aaa.efi", &create_minimal_pe())?;
        tempdir.atomic_write("boot/EFI/Linux/mmm.efi", &create_minimal_pe())?;

        // Should return first in sorted order
        let path = find_uki_path(&tempdir)?.expect("should find uki");
        assert_eq!(path.as_str(), "boot/EFI/Linux/aaa.efi");
        Ok(())
    }

    #[test]
    fn test_find_kernel_with_addons() -> Result<()> {
        for (has_uki, has_vmlinuz, has_cmdline, expected_unified) in [
            (true, false, true, Some(true)),
            (false, false, false, None),
            (false, true, false, Some(false)),
            (true, false, false, Some(true)),
        ] {
            let root = cap_tempfile::tempdir(cap_std::ambient_authority())?;
            root.create_dir_all("boot/EFI/Linux")?;
            root.write("boot/EFI/Linux/000.addon.efi", create_minimal_pe())?;
            if has_uki {
                let mut uki = create_minimal_pe();
                if !has_cmdline {
                    const SECTION_HEADER_OFFSET: usize = 0x188;
                    uki[SECTION_HEADER_OFFSET..SECTION_HEADER_OFFSET + 8]
                        .copy_from_slice(b".linux\0\0");
                }
                root.write("boot/EFI/Linux/kernel.efi", uki)?;
            }
            if has_vmlinuz {
                root.create_dir_all("usr/lib/modules/6.12")?;
                root.write("usr/lib/modules/6.12/vmlinuz", b"kernel")?;
            }

            let kernel = find_kernel(&root)?;
            assert_eq!(kernel.as_ref().map(|k| k.kernel.unified), expected_unified);
            if let Some(kernel) = kernel {
                assert_eq!(
                    kernel.kernel.version,
                    if has_uki { "kernel" } else { "6.12" }
                );
                if let KernelType::Uki { path, cmdline } = kernel.k_type {
                    assert_eq!(path, "boot/EFI/Linux/kernel.efi");
                    assert_eq!(
                        cmdline.as_ref().map(ToString::to_string).as_deref(),
                        has_cmdline.then_some("quiet splash")
                    );
                } else {
                    let KernelType::Vmlinuz { path, .. } = kernel.k_type else {
                        panic!("Expected vmlinuz");
                    };
                    assert_eq!(path, "usr/lib/modules/6.12/vmlinuz");
                }
            }
        }
        Ok(())
    }
}
