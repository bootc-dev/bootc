use std::fs::create_dir_all;
use std::process::Command;
use std::sync::OnceLock;

use anyhow::{Context, Result, anyhow, bail};
use bootc_utils::{ChrootCmd, CommandRunExt};
use camino::Utf8Path;
use cap_std_ext::cap_std::fs::Dir;
use cap_std_ext::dirext::CapStdExtDirExt;
use fn_error_context::context;

use bootc_mount as mount;
use rustix::fs::statfs;

use crate::bootc_composefs::boot::{MountedImageRoot, SecurebootKeys};
use crate::utils;

/// The name of the mountpoint for efi (as a subdirectory of /boot, or at the toplevel)
pub(crate) const EFI_DIR: &str = "efi";
/// The EFI system partition GUID
/// Path to the bootupd update payload
#[allow(dead_code)]
const BOOTUPD_UPDATES: &str = "usr/lib/bootupd/updates";

// from: https://github.com/systemd/systemd/blob/26b2085d54ebbfca8637362eafcb4a8e3faf832f/man/systemd-boot.xml#L392
const SYSTEMD_KEY_DIR: &str = "loader/keys";

/// Redirect bootctl's entry-token write into a tmpfs scratch area.
///
/// bootctl unconditionally writes `<KERNEL_INSTALL_CONF_ROOT>/entry-token`
/// during installation.  Because systemd's `path_join()` is naive string
/// concatenation (see `src/bootctl/bootctl-install.c`), setting this to
/// `/tmp` causes the write to land at `<composefs_root>/tmp/entry-token`
/// on the MountedImageRoot tmpfs, where it is automatically discarded.
/// bootc does not use the entry-token at all.
const KERNEL_INSTALL_CONF_ROOT: &str = "/tmp";

/// First systemd release whose `bootctl install` accepts `--random-seed`.
/// See: <https://www.freedesktop.org/software/systemd/man/latest/bootctl.html>
const BOOTCTL_RANDOM_SEED_MIN_VERSION: u32 = 257;

/// Mount the first ESP found among backing devices at /boot/efi.
///
/// This is used by the install-alongside path to clean stale bootloader
/// files before reinstallation.  On multi-device setups only the first
/// ESP is mounted and cleaned; stale files on additional ESPs are left
/// in place (bootupd will overwrite them during installation).
// TODO: clean all ESPs on multi-device setups
pub(crate) fn mount_esp_part(root: &Dir, root_path: &Utf8Path, is_ostree: bool) -> Result<()> {
    // systemd-gpt-auto-generator automounts ESP at /boot
    let is_boot_mountpoint = root.is_mountpoint("boot")?;

    if matches!(is_boot_mountpoint, Some(true)) {
        let statfs = statfs(root_path.join("boot").as_std_path())?;

        // We probably don't need to be this thorough, but no harm done
        if statfs.f_type == libc::MSDOS_SUPER_MAGIC {
            return Ok(());
        }
    }

    let efi_path = Utf8Path::new("boot").join(crate::bootloader::EFI_DIR);
    let Some(esp_fd) = root
        .open_dir_optional(&efi_path)
        .context("Opening /boot/efi")?
    else {
        return Ok(());
    };

    let Some(false) = esp_fd.is_mountpoint(".")? else {
        return Ok(());
    };

    tracing::debug!("Not a mountpoint: /boot/efi");
    // On ostree env with enabled composefs, should be /target/sysroot
    let physical_root = if is_ostree {
        &root.open_dir("sysroot").context("Opening /sysroot")?
    } else {
        root
    };

    let roots = bootc_blockdev::list_dev_by_dir(physical_root)?.find_all_roots()?;
    for dev in &roots {
        if let Some(esp_dev) = dev.find_partition_of_esp_optional()? {
            let esp_path = esp_dev.path();
            bootc_mount::mount(&esp_path, &root_path.join(&efi_path))?;
            tracing::debug!("Mounted {esp_path} at /boot/efi");
            return Ok(());
        }
    }
    tracing::debug!(
        "No ESP partition found among {} root device(s)",
        roots.len()
    );
    Ok(())
}

/// Determine if the invoking environment contains bootupd, and if there are bootupd-based
/// updates in the target root.
#[context("Querying for bootupd")]
pub(crate) fn supports_bootupd(root: &Dir) -> Result<bool> {
    if !utils::have_executable("bootupctl")? {
        tracing::trace!("No bootupctl binary found");
        return Ok(false);
    };
    let r = root.try_exists(BOOTUPD_UPDATES)?;
    tracing::trace!("bootupd updates: {r}");
    Ok(r)
}

/// Check whether the target bootupd supports `--filesystem`.
///
/// Runs `bootupctl backend install --help` and looks for `--filesystem` in the
/// output. When `deployment_path` is set the command runs inside a chroot
/// (via [`ChrootCmd`]) so we probe the binary from the target image.
fn bootupd_supports_filesystem(rootfs: &Utf8Path, deployment_path: Option<&str>) -> Result<bool> {
    let help_args = ["bootupctl", "backend", "install", "--help"];
    let output = if let Some(deploy) = deployment_path {
        let target_root = rootfs.join(deploy);
        ChrootCmd::new(&target_root)
            .set_default_path()
            .run_get_string(help_args)?
    } else {
        Command::new("bootupctl")
            .args(&help_args[1..])
            .log_debug()
            .run_get_string()?
    };

    let use_filesystem = output.contains("--filesystem");

    if use_filesystem {
        tracing::debug!("bootupd supports --filesystem");
    } else {
        tracing::debug!("bootupd does not support --filesystem, falling back to --device");
    }

    Ok(use_filesystem)
}

/// Install the bootloader via bootupd.
///
/// When the target bootupd supports `--filesystem` we pass it pointing at a
/// block-backed mount so that bootupd can resolve the backing device(s) itself
/// via `lsblk`.  In the chroot path we bind-mount the physical root at
/// `/sysroot` to give `lsblk` a real block-backed path.
///
/// For older bootupd versions that lack `--filesystem` we fall back to the
/// legacy `--device <device_path> <rootfs>` invocation.
#[context("Installing bootloader")]
pub(crate) fn install_via_bootupd(
    device: &bootc_blockdev::Device,
    rootfs: &Utf8Path,
    configopts: &crate::install::InstallConfigOpts,
    deployment_path: Option<&str>,
) -> Result<()> {
    let verbose = std::env::var_os("BOOTC_BOOTLOADER_DEBUG").map(|_| "-vvvv");
    // bootc defaults to only targeting the platform boot method.
    let bootupd_opts = (!configopts.generic_image).then_some(["--update-firmware", "--auto"]);

    // When not running inside the target container (through `--src-imgref`) we
    // run bootupctl from the deployment via a chroot ([`ChrootCmd`]).
    // This makes sure we use binaries from the target image rather than the buildroot.
    // In that case, the target rootfs is replaced with `/` because this is just used by
    // bootupd to find the backing device.
    let rootfs_mount = if deployment_path.is_none() {
        rootfs.as_str()
    } else {
        "/"
    };

    println!("Installing bootloader via bootupd");

    // Build the bootupctl arguments
    let mut bootupd_args: Vec<&str> = vec!["backend", "install"];
    if configopts.bootupd_skip_boot_uuid {
        bootupd_args.push("--with-static-configs")
    } else {
        bootupd_args.push("--write-uuid");
    }
    if let Some(v) = verbose {
        bootupd_args.push(v);
    }

    if let Some(ref opts) = bootupd_opts {
        bootupd_args.extend(opts.iter().copied());
    }

    // When the target bootupd lacks --filesystem support, fall back to the
    // legacy --device flag.  For --device we need the whole-disk device path
    // (e.g. /dev/vda), not a partition (e.g. /dev/vda3), so resolve the
    // parent via require_single_root().  (Older bootupd doesn't support
    // multiple backing devices anyway.)
    // Computed before building bootupd_args so the String lives long enough.
    let root_device_path = if bootupd_supports_filesystem(rootfs, deployment_path)
        .context("Probing bootupd --filesystem support")?
    {
        None
    } else {
        Some(device.require_single_root()?.path())
    };
    if let Some(ref dev) = root_device_path {
        tracing::debug!("bootupd does not support --filesystem, falling back to --device {dev}");
        bootupd_args.extend(["--device", dev]);
        bootupd_args.push(rootfs_mount);
    } else {
        tracing::debug!("bootupd supports --filesystem");
        bootupd_args.extend(["--filesystem", rootfs_mount]);
        bootupd_args.push(rootfs_mount);
    }

    // Run inside a chroot ([`ChrootCmd`]). It sets up a fresh mount
    // namespace and the necessary API filesystems in the target
    // deployment, without requiring a user namespace (which fails under
    // qemu-user — see <https://github.com/bootc-dev/bootc/issues/2111>).
    if let Some(deploy) = deployment_path {
        let target_root = rootfs.join(deploy);
        let boot_path = rootfs.join("boot");
        let rootfs_path = rootfs.to_path_buf();

        tracing::debug!("Running bootupctl via chroot in {}", target_root);

        // Prepend "bootupctl" to the args (ChrootCmd's calling
        // convention puts the program in args[0]).
        let mut chroot_args = vec!["bootupctl"];
        chroot_args.extend(bootupd_args);

        let mut cmd = ChrootCmd::new(&target_root)
            // Bind mount /boot from the physical target root so bootupctl can find
            // the boot partition and install the bootloader there
            .bind(&boot_path, &"/boot");

        // Only bind mount the physical root at /sysroot when using --filesystem;
        // bootupd needs it to resolve backing block devices via lsblk.
        if root_device_path.is_none() {
            cmd = cmd.bind(&rootfs_path, &"/sysroot");
        }

        // ChrootCmd starts the child with a cleared environment, so we
        // inject a default $PATH for it to find sub-tools.
        cmd.set_default_path().run(chroot_args)
    } else {
        // Running directly without chroot
        Command::new("bootupctl")
            .args(&bootupd_args)
            .log_debug()
            .run_inherited_with_cmd_context()
    }
}

/// Install systemd-boot using a pre-prepared boot root.
#[context("Installing bootloader")]
pub(crate) fn install_systemd_boot(
    prepared_root: &MountedImageRoot,
    configopts: &crate::install::InstallConfigOpts,
    autoenroll: Option<SecurebootKeys>,
) -> Result<()> {
    println!("Installing bootloader via systemd-boot");

    // We use the --root of the mounted target root, so we have the right /etc/os-release.
    let root_path = prepared_root
        .root_path()
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("composefs tmpdir path is not UTF-8"))?;
    let esp_path_in_root = format!("/{}", prepared_root.esp_subdir);

    let mut bootctl_args = vec![
        "install",
        "--root",
        root_path,
        "--esp-path",
        esp_path_in_root.as_str(),
        // If we supported XBOOTLDR in the future, that'd go here with --boot-path.
    ];

    if configopts.generic_image {
        bootctl_args.push("--no-variables");
        // `--random-seed` was only added to `bootctl install` in systemd 257.
        let systemd_version = bootctl_systemd_version()?;
        if systemd_version >= BOOTCTL_RANDOM_SEED_MIN_VERSION {
            bootctl_args.extend(["--random-seed", "no"]);
        } else {
            tracing::debug!(
                "Skipping --random-seed: requires systemd >= {BOOTCTL_RANDOM_SEED_MIN_VERSION}, found {systemd_version}"
            );
        }
    }

    Command::new("bootctl")
        .args(bootctl_args)
        // Skip partition-type GUID validation because e.g. osbuild
        // may not provide the udev database.
        .env("SYSTEMD_RELAX_ESP_CHECKS", "1")
        // bootc doesn't use the entry-token file, but bootctl still tries to
        // write it.  Redirect into /tmp (a tmpfs mounted by MountedImageRoot)
        // so the write succeeds and is automatically discarded.
        .env("KERNEL_INSTALL_CONF_ROOT", KERNEL_INSTALL_CONF_ROOT)
        .log_debug()
        // Capture stderr so bootctl error messages appear in our error chain.
        .run_capture_stderr()?;

    if let Some(SecurebootKeys { dir, keys }) = autoenroll {
        let esp_dir = prepared_root.open_esp_dir()?;
        let keys_path = prepared_root
            .root_path()
            .join(prepared_root.esp_subdir)
            .join(SYSTEMD_KEY_DIR);
        create_dir_all(&keys_path).with_context(|| {
            format!("Creating secureboot key directory {}", keys_path.display())
        })?;

        let keys_dir = esp_dir
            .open_dir(SYSTEMD_KEY_DIR)
            .with_context(|| format!("Opening {SYSTEMD_KEY_DIR}"))?;

        for filename in keys.iter() {
            // Each key lives in a subdirectory, e.g. "PK/PK.auth".
            // Create the per-key subdirectory before copying the file into it.
            if let Some(parent) = filename.parent() {
                if !parent.as_str().is_empty() {
                    keys_dir
                        .create_dir_all(parent)
                        .with_context(|| format!("Creating key subdirectory {parent}"))?;
                }
            }
            dir.copy(filename, &keys_dir, filename)
                .with_context(|| format!("Copying secure boot key {filename:?}"))?;
            println!(
                "Wrote Secure Boot key: {}/{}",
                keys_path.display(),
                filename.as_str()
            );
        }
        if keys.is_empty() {
            tracing::debug!("No Secure Boot keys provided for systemd-boot enrollment");
        }
    }

    Ok(())
}

#[context("Querying bootctl version")]
pub(crate) fn bootctl_systemd_version() -> Result<u32> {
    static VERSION: OnceLock<u32> = OnceLock::new();

    if let Some(v) = VERSION.get() {
        return Ok(*v);
    };

    let out = Command::new("bootctl").arg("--version").run_get_string()?;
    let v = parse_systemd_version(&out).context("Failed to parse version to integer")?;

    let version = VERSION.get_or_init(|| v);

    Ok(*version)
}

/// Parse the systemd major version from `bootctl --version` output, whose first
/// line looks like `systemd 259 (259.5-0ubuntu3)`.
fn parse_systemd_version(output: &str) -> Result<u32> {
    output
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(|| {
            anyhow!("Could not parse systemd version from bootctl --version: {output:?}")
        })
}

#[context("Installing bootloader using zipl")]
pub(crate) fn install_via_zipl(device: &bootc_blockdev::Device, boot_uuid: &str) -> Result<()> {
    // Identify the target boot partition from UUID
    let fs = mount::inspect_filesystem_by_uuid(boot_uuid)?;
    let boot_dir = Utf8Path::new(&fs.target);
    let maj_min = fs.maj_min;

    // Ensure that the found partition is a part of the target device
    let device_path = device.path();

    let partitions = bootc_blockdev::list_dev(Utf8Path::new(&device_path))?
        .children
        .with_context(|| format!("no partition found on {device_path}"))?;
    let boot_part = partitions
        .iter()
        .find(|part| part.maj_min.as_deref() == Some(maj_min.as_str()))
        .with_context(|| format!("partition device {maj_min} is not on {device_path}"))?;
    let boot_part_offset = boot_part.start.unwrap_or(0);

    // Find exactly one BLS configuration under /boot/loader/entries
    // TODO: utilize the BLS parser in ostree
    let bls_dir = boot_dir.join("boot/loader/entries");
    let bls_entry = bls_dir
        .read_dir_utf8()?
        .try_fold(None, |acc, e| -> Result<_> {
            let e = e?;
            let name = Utf8Path::new(e.file_name());
            if let Some("conf") = name.extension() {
                if acc.is_some() {
                    bail!("more than one BLS configurations under {bls_dir}");
                }
                Ok(Some(e.path().to_owned()))
            } else {
                Ok(None)
            }
        })?
        .with_context(|| format!("no BLS configuration under {bls_dir}"))?;

    let bls_path = bls_dir.join(bls_entry);
    let bls_conf =
        std::fs::read_to_string(&bls_path).with_context(|| format!("reading {bls_path}"))?;

    let mut kernel = None;
    let mut initrd = None;
    let mut options = None;

    for line in bls_conf.lines() {
        match line.split_once(char::is_whitespace) {
            Some(("linux", val)) => kernel = Some(val.trim().trim_start_matches('/')),
            Some(("initrd", val)) => initrd = Some(val.trim().trim_start_matches('/')),
            Some(("options", val)) => options = Some(val.trim()),
            _ => (),
        }
    }

    let kernel = kernel.ok_or_else(|| anyhow!("missing 'linux' key in default BLS config"))?;
    let initrd = initrd.ok_or_else(|| anyhow!("missing 'initrd' key in default BLS config"))?;
    let options = options.ok_or_else(|| anyhow!("missing 'options' key in default BLS config"))?;

    let image = boot_dir.join(kernel).canonicalize_utf8()?;
    let ramdisk = boot_dir.join(initrd).canonicalize_utf8()?;

    // Execute the zipl command to install bootloader
    println!("Running zipl on {device_path}");
    Command::new("zipl")
        .args(["--target", boot_dir.as_str()])
        .args(["--image", image.as_str()])
        .args(["--ramdisk", ramdisk.as_str()])
        .args(["--parameters", options])
        .args(["--targetbase", &device_path])
        .args(["--targettype", "SCSI"])
        .args(["--targetblocksize", "512"])
        .args(["--targetoffset", &boot_part_offset.to_string()])
        .args(["--add-files", "--verbose"])
        .log_debug()
        .run_inherited_with_cmd_context()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_systemd_version() {
        // The first line of `bootctl --version`. the trailing feature line is ignored.
        let cases = [
            ("systemd 259 (259.5-0ubuntu3)", 259),
            ("systemd 257 (257-26.el10-g1d19ad5)", 257),
            ("systemd 255 (255.4-1ubuntu8.16)", 255),
        ];
        for (input, expected) in cases {
            assert_eq!(
                parse_systemd_version(input).unwrap(),
                expected,
                "input: {input:?}"
            );
        }
        for bad in ["", "systemd", "not a version string"] {
            assert!(
                parse_systemd_version(bad).is_err(),
                "should reject: {bad:?}"
            );
        }
    }
}
