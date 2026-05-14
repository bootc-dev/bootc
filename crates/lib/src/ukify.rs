//! Build Unified Kernel Images (UKI) using ukify.
//!
//! This module provides functionality to build UKIs by computing the necessary
//! arguments from a container image and invoking the ukify tool.

use std::ffi::OsString;
use std::process::Command;

use anyhow::{Context, Result};
use bootc_kernel_cmdline::utf8::Cmdline;
use bootc_utils::CommandRunExt;
use camino::Utf8Path;
use cap_std_ext::cap_std::fs::Dir;
use fn_error_context::context;

use crate::bootc_composefs::digest::compute_composefs_digest;
use crate::bootc_composefs::status::ComposefsCmdline;
use crate::kernel::KernelInternal;

/// Build a UKI from the given rootfs.
///
/// This function:
/// 1. Verifies that ukify is available
/// 2. Finds the kernel in the rootfs
/// 3. Computes the composefs digest
/// 4. Reads kernel arguments from kargs.d
/// 5. Appends any additional kargs provided via --karg
/// 6. Invokes ukify with computed arguments plus any pass-through args
#[context("Building UKI")]
pub(crate) async fn build_ukify(
    rootfs: &Utf8Path,
    extra_kargs: &[String],
    args: &[OsString],
    kernel: Option<KernelInternal>,
    allow_missing_fsverity: bool,
    write_dumpfile_to: Option<&Utf8Path>,
) -> Result<()> {
    // Warn if --karg is used (temporary workaround)
    if !extra_kargs.is_empty() {
        tracing::warn!(
            "The --karg flag is temporary and will be removed as soon as possible \
            (https://github.com/bootc-dev/bootc/issues/1826)"
        );
    }

    // Verify ukify is available
    if !crate::utils::have_executable("ukify")? {
        anyhow::bail!(
            "ukify executable not found in PATH. Please install systemd-ukify or equivalent."
        );
    }

    // Open the rootfs directory
    let root = Dir::open_ambient_dir(rootfs, cap_std_ext::cap_std::ambient_authority())
        .with_context(|| format!("Opening rootfs {rootfs}"))?;

    let kernel_final = match kernel {
        Some(ref kernel) => kernel,
        None => &crate::kernel::find_kernel(&root)?
            .ok_or_else(|| anyhow::anyhow!("No kernel found in {rootfs}"))?,
    };

    // Extract vmlinuz and initramfs paths, or bail if this is already a UKI
    let (vmlinuz_path, initramfs_path) = match &kernel_final.k_type {
        crate::kernel::KernelType::Vmlinuz { path, initramfs } => (path, initramfs),
        crate::kernel::KernelType::Uki { path, .. } => {
            anyhow::bail!("Cannot build UKI: rootfs already contains a UKI at {path}");
        }
    };

    // Verify kernel and initramfs exist
    //
    // NOTE: Not using cap_std here as the vmlinuz/initramfs path from
    // args can be outside of "rootfs"
    if kernel.is_some() {
        if !vmlinuz_path.exists() {
            anyhow::bail!("Kernel not found at {vmlinuz_path}");
        }

        if !initramfs_path.exists() {
            anyhow::bail!("Initramfs not found at {initramfs_path}");
        }
    } else {
        if !root
            .try_exists(&vmlinuz_path)
            .context("Checking for vmlinuz")?
        {
            anyhow::bail!("Kernel not found at {vmlinuz_path}");
        }

        if !root
            .try_exists(&initramfs_path)
            .context("Checking for initramfs")?
        {
            anyhow::bail!("Initramfs not found at {initramfs_path}");
        }
    }

    // Compute the composefs digest
    let composefs_digest = compute_composefs_digest(rootfs, write_dumpfile_to).await?;

    // Get kernel arguments from kargs.d
    let mut cmdline = crate::bootc_kargs::get_kargs_in_root(&root, std::env::consts::ARCH)?;

    // Add the composefs digest
    cmdline.extend(&Cmdline::from(
        ComposefsCmdline::build(&composefs_digest, allow_missing_fsverity).to_string(),
    ));

    // Add any extra kargs provided via --karg
    for karg in extra_kargs {
        cmdline.extend(&Cmdline::from(karg));
    }

    let cmdline_str = cmdline.to_string();

    // Build the ukify command with cwd set to rootfs so paths can be relative
    let mut cmd = Command::new("ukify");
    cmd.current_dir(rootfs);
    cmd.arg("build")
        .arg("--linux")
        .arg(&vmlinuz_path)
        .arg("--initrd")
        .arg(&initramfs_path)
        .arg("--uname")
        .arg(&kernel_final.kernel.version)
        .arg("--cmdline")
        .arg(&cmdline_str)
        .arg("--os-release")
        .arg("@usr/lib/os-release");

    // Add pass-through arguments
    cmd.args(args);

    tracing::debug!("Executing ukify: {:?}", cmd);

    // Run ukify
    cmd.run_inherited().context("Running ukify")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use bootc_utils::create_minimal_pe;

    use super::*;
    use std::fs;

    #[tokio::test]
    async fn test_build_ukify_no_kernel() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = Utf8Path::from_path(tempdir.path()).unwrap();

        let result = build_ukify(path, &[], &[], None, false, None).await;
        assert!(result.is_err());
        let err = format!("{:#}", result.unwrap_err());
        assert!(
            err.contains("No kernel found") || err.contains("ukify executable not found"),
            "Unexpected error message: {err}"
        );
    }

    #[tokio::test]
    async fn test_build_ukify_already_uki() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = Utf8Path::from_path(tempdir.path()).unwrap();

        // Create a UKI structure
        fs::create_dir_all(tempdir.path().join("boot/EFI/Linux")).unwrap();
        fs::write(
            tempdir.path().join("boot/EFI/Linux/test.efi"),
            &create_minimal_pe(),
        )
        .unwrap();

        let result = build_ukify(path, &[], &[], None, false, None).await;
        assert!(result.is_err());
        let err = format!("{:#}", result.unwrap_err());
        assert!(
            err.contains("already contains a UKI") || err.contains("ukify executable not found"),
            "Unexpected error message: {err}"
        );
    }
}
