use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use cap_std_ext::cap_std::fs::Dir;
use composefs::erofs::format::FormatVersion;
use composefs::fsverity::{FsVerityHashValue, Sha512HashValue};
use composefs_ctl::composefs;
use linux_kernel_cmdline::utf8::Cmdline;

use crate::bootc_composefs::digest::compute_composefs_digest;
use crate::bootc_composefs::status::build_composefs_karg;
use crate::cli::ErofsVersionArg;
use crate::kernel::KernelType;

fn resolve_erofs_version(requested: Option<ErofsVersionArg>) -> FormatVersion {
    requested.map(Into::into).unwrap_or(FormatVersion::V1)
}

fn composefs_kargs_for_boot_artifact(
    preferred_digest: Sha512HashValue,
    preferred_version: FormatVersion,
    compatibility_v2_digest: Option<Sha512HashValue>,
    allow_missing_fsverity: bool,
) -> Vec<String> {
    let mut kargs = vec![build_composefs_karg(
        preferred_digest,
        preferred_version,
        allow_missing_fsverity,
    )];
    if let Some(v2_digest) = compatibility_v2_digest {
        kargs.push(build_composefs_karg(
            v2_digest,
            FormatVersion::V2,
            allow_missing_fsverity,
        ));
    }
    kargs
}

#[derive(Debug)]
pub(crate) struct BootArtifactInputs {
    pub(crate) kernel_version: String,
    pub(crate) vmlinuz: Utf8PathBuf,
    pub(crate) initramfs: Utf8PathBuf,
    pub(crate) cmdline: String,
}

pub(crate) async fn prepare_boot_artifact(
    rootfs: &Utf8Path,
    kernel_dir: Option<&Utf8Path>,
    extra_kargs: &[String],
    allow_missing_fsverity: bool,
    erofs_version: Option<ErofsVersionArg>,
    write_dumpfile_to: Option<&Utf8Path>,
) -> Result<BootArtifactInputs> {
    let root = Dir::open_ambient_dir(rootfs, cap_std_ext::cap_std::ambient_authority())
        .with_context(|| format!("Opening rootfs {rootfs}"))?;

    let (kernel_version, vmlinuz, initramfs, external_paths) = match kernel_dir {
        Some(kernel_dir) => {
            let kver = kernel_dir
                .components()
                .next_back()
                .ok_or_else(|| anyhow::anyhow!("Could not determine kernel version"))?;
            (
                kver.to_string(),
                kernel_dir.join("vmlinuz"),
                kernel_dir.join("initramfs.img"),
                true,
            )
        }
        None => {
            let kernel = crate::kernel::find_kernel(&root)?
                .ok_or_else(|| anyhow::anyhow!("No kernel found in {rootfs}"))?;
            match kernel.k_type {
                KernelType::Vmlinuz { path, initramfs } => {
                    (kernel.kernel.version, path, initramfs, false)
                }
                KernelType::Uki { path, .. } => anyhow::bail!(
                    "Cannot build boot artifact: rootfs already contains a UKI at {path}"
                ),
            }
        }
    };

    if external_paths {
        if !vmlinuz.exists() {
            anyhow::bail!("Kernel not found at {vmlinuz}");
        }
        if !initramfs.exists() {
            anyhow::bail!("Initramfs not found at {initramfs}");
        }
    } else {
        if !root.try_exists(&vmlinuz).context("Checking for vmlinuz")? {
            anyhow::bail!("Kernel not found at {vmlinuz}");
        }
        if !root
            .try_exists(&initramfs)
            .context("Checking for initramfs")?
        {
            anyhow::bail!("Initramfs not found at {initramfs}");
        }
    }

    let erofs_version = resolve_erofs_version(erofs_version);
    let composefs_digest =
        compute_composefs_digest(rootfs, erofs_version, write_dumpfile_to).await?;
    let composefs_digest = Sha512HashValue::from_hex(&composefs_digest)
        .context("Parsing computed composefs digest")?;
    let compatibility_v2_digest = if erofs_version == FormatVersion::V1 {
        let digest = compute_composefs_digest(rootfs, FormatVersion::V2, None).await?;
        Some(Sha512HashValue::from_hex(&digest).context("Parsing computed V2 digest")?)
    } else {
        None
    };

    let mut cmdline = crate::bootc_kargs::get_kargs_in_root(&root, std::env::consts::ARCH)?;
    for karg in composefs_kargs_for_boot_artifact(
        composefs_digest,
        erofs_version,
        compatibility_v2_digest,
        allow_missing_fsverity,
    ) {
        cmdline.extend(&Cmdline::from(karg));
    }
    for karg in extra_kargs {
        cmdline.extend(&Cmdline::from(karg));
    }

    Ok(BootArtifactInputs {
        kernel_version,
        vmlinuz,
        initramfs,
        cmdline: cmdline.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use bootc_utils::create_minimal_pe;

    use super::*;

    #[tokio::test]
    async fn no_kernel() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = Utf8Path::from_path(tempdir.path()).unwrap();

        let err = prepare_boot_artifact(path, None, &[], false, None, None)
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("No kernel found"));
    }

    #[tokio::test]
    async fn rejects_uki() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = Utf8Path::from_path(tempdir.path()).unwrap();
        fs::create_dir_all(tempdir.path().join("boot/EFI/Linux")).unwrap();
        fs::write(
            tempdir.path().join("boot/EFI/Linux/test.efi"),
            &create_minimal_pe(),
        )
        .unwrap();

        let err = prepare_boot_artifact(path, None, &[], false, None, None)
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("already contains a UKI"));
    }

    #[test]
    fn test_composefs_kargs_for_boot_artifact() {
        let v1 = Sha512HashValue::EMPTY;
        let v2 = Sha512HashValue::from_hex("aa".repeat(64)).unwrap();
        for (requested, expected_version, fallback, expected_len, expected_prefixes) in [
            (
                None,
                FormatVersion::V1,
                Some(v2.clone()),
                2,
                ["composefs.digest=v1-sha512-12:", "composefs="],
            ),
            (
                Some(ErofsVersionArg::V1),
                FormatVersion::V1,
                Some(v2.clone()),
                2,
                ["composefs.digest=v1-sha512-12:", "composefs="],
            ),
            (
                Some(ErofsVersionArg::V2),
                FormatVersion::V2,
                None,
                1,
                ["composefs=", ""],
            ),
        ] {
            let version = resolve_erofs_version(requested);
            let kargs = composefs_kargs_for_boot_artifact(v1.clone(), version, fallback, false);
            assert_eq!(kargs.len(), expected_len);
            for (karg, prefix) in kargs.iter().zip(expected_prefixes) {
                assert!(karg.starts_with(prefix), "unexpected karg: {karg}");
            }
            assert_eq!(version, expected_version);
        }
    }
}
