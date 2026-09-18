//! Build Android boot or ukiboot images using aboot-update.

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::process::Command;

use anyhow::{Context, Result, ensure};
use bootc_utils::CommandRunExt;
use camino::Utf8Path;
use composefs_ctl::composefs_boot::{android_boot::AndroidBootImage, uki};
use fn_error_context::context;
use linux_kernel_cmdline::utf8::Cmdline;

use crate::boot_artifact::prepare_boot_artifact;

#[context("Building aboot image")]
pub(crate) async fn build_aboot(
    rootfs: &Utf8Path,
    extra_kargs: &[String],
    kernel_dir: Option<&Utf8Path>,
    out: Option<&Utf8Path>,
    allow_missing_fsverity: bool,
    write_dumpfile_to: Option<&Utf8Path>,
) -> Result<()> {
    if !extra_kargs.is_empty() {
        tracing::warn!(
            "The --karg flag is temporary and will be removed as soon as possible \
            (https://github.com/bootc-dev/bootc/issues/1826)"
        );
    }

    if !crate::utils::have_executable("aboot-update")? {
        anyhow::bail!("aboot-update executable not found in PATH");
    }

    let inputs = prepare_boot_artifact(
        rootfs,
        kernel_dir,
        extra_kargs,
        allow_missing_fsverity,
        None,
        write_dumpfile_to,
    )
    .await?;

    let mut cmd = Command::new("aboot-update");
    cmd.arg("--root")
        .arg(rootfs)
        .arg("--cmdline")
        .arg(&inputs.cmdline);
    if let Some(kernel_dir) = kernel_dir {
        cmd.arg("--kernel-dir").arg(kernel_dir);
    }
    if let Some(out) = out {
        cmd.arg("--out").arg(out);
    }
    cmd.arg(&inputs.kernel_version);

    tracing::debug!("Executing aboot-update: {:?}", cmd);
    cmd.run_inherited().context("Running aboot-update")?;

    let output_dir = out
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| rootfs.join("boot"));
    let image_path = output_dir.join(format!("aboot-{}.img", inputs.kernel_version));
    let actual_cmdline = read_cmdline(&image_path)?;
    validate_composefs_cmdline(&inputs.cmdline, &actual_cmdline)
}

fn read_cmdline(path: &Utf8Path) -> Result<String> {
    let image = File::open(path).with_context(|| format!("Opening generated image {path}"))?;
    let mut image = BufReader::new(image);
    let mut magic = [0; 8];
    image
        .read_exact(&mut magic)
        .with_context(|| format!("Reading generated image {path}"))?;
    image.seek(SeekFrom::Start(0))?;

    if magic == *b"ANDROID!" {
        let header = AndroidBootImage::parse(&mut image)
            .with_context(|| format!("Parsing generated Android boot image {path}"))?;
        Ok(header.cmdline()?.to_owned())
    } else {
        uki::get_cmdline_buffered(&mut image)
            .with_context(|| format!("Parsing generated ukiboot image {path}"))
    }
}

fn validate_composefs_cmdline(expected: &str, actual: &str) -> Result<()> {
    let composefs_args = |cmdline: &str| -> Vec<String> {
        Cmdline::from(cmdline)
            .iter_str()
            .filter(|arg| arg.starts_with("composefs=") || arg.starts_with("composefs.digest="))
            .map(str::to_owned)
            .collect()
    };
    let mut expected = composefs_args(expected);
    ensure!(
        !expected.is_empty(),
        "Generated command line has no composefs parameter"
    );
    let mut actual = composefs_args(actual);
    expected.sort_unstable();
    actual.sort_unstable();
    ensure!(
        actual == expected,
        "Generated image has the wrong composefs parameters"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_composefs_cmdline() {
        validate_composefs_cmdline("quiet composefs=?abcd", "bootconfig composefs=?abcd").unwrap();
        validate_composefs_cmdline(
            "composefs.digest=v1-sha512-12:abcd composefs=efgh",
            "composefs=efgh composefs.digest=v1-sha512-12:abcd",
        )
        .unwrap();

        for actual in [
            "quiet",
            "composefs=efgh",
            "composefs=abcd composefs=abcd",
            "composefs=?abcd composefs=?abcd",
            "composefs.digest=v1-sha512-12:abcd composefs=efgh composefs=efgh",
        ] {
            assert!(validate_composefs_cmdline("composefs=?abcd", actual).is_err());
        }
    }
}
