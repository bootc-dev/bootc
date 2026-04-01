use std::fs::create_dir_all;
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use bootc_utils::{BwrapCmd, CommandRunExt};
use camino::Utf8Path;
use cap_std_ext::cap_std::fs::Dir;
use cap_std_ext::dirext::CapStdExtDirExt;
use fn_error_context::context;

use bootc_mount as mount;

use crate::bootc_composefs::boot::{mount_esp, SecurebootKeys};
use crate::{discoverable_partition_specification, utils};

/// The name of the mountpoint for efi (as a subdirectory of /boot, or at the toplevel)
pub(crate) const EFI_DIR: &str = "efi";
/// The EFI system partition GUID
/// Path to the bootupd update payload
#[allow(dead_code)]
const BOOTUPD_UPDATES: &str = "usr/lib/bootupd/updates";

// from: https://github.com/systemd/systemd/blob/26b2085d54ebbfca8637362eafcb4a8e3faf832f/man/systemd-boot.xml#L392
const SYSTEMD_KEY_DIR: &str = "loader/keys";

/// Mount the first ESP found among backing devices at /boot/efi.
///
/// This is used by the install-alongside path to clean stale bootloader
/// files before reinstallation.  On multi-device setups only the first
/// ESP is mounted and cleaned; stale files on additional ESPs are left
/// in place (bootupd will overwrite them during installation).
// TODO: clean all ESPs on multi-device setups
pub(crate) fn mount_esp_part(root: &Dir, root_path: &Utf8Path, is_ostree: bool) -> Result<()> {
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
        if let Some(esp_dev) = dev.find_partition_of_type(bootc_blockdev::ESP) {
            let esp_path = esp_dev.path();
            bootc_mount::mount(&esp_path, &root_path.join(&efi_path))?;
            tracing::debug!("Mounted {esp_path} at /boot/efi");
            return Ok(());
        }
    }
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
/// output. When `deployment_path` is set the command runs inside a bwrap
/// container so we probe the binary from the target image.
fn bootupd_supports_filesystem(rootfs: &Utf8Path, deployment_path: Option<&str>) -> Result<bool> {
    let help_args = ["bootupctl", "backend", "install", "--help"];
    let output = if let Some(deploy) = deployment_path {
        let target_root = rootfs.join(deploy);
        BwrapCmd::new(&target_root)
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
/// via `lsblk`.  In the bwrap path we bind-mount the physical root at
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

    // When not running inside the target container (through `--src-imgref`) we use
    // will bwrap as a chroot to run bootupctl from the deployment.
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

    // Run inside a bwrap container. It takes care of mounting and creating
    // the necessary API filesystems in the target deployment and acts as
    // a nicer `chroot`.
    if let Some(deploy) = deployment_path {
        let target_root = rootfs.join(deploy);
        let boot_path = rootfs.join("boot");
        let rootfs_path = rootfs.to_path_buf();

        tracing::debug!("Running bootupctl via bwrap in {}", target_root);

        // Prepend "bootupctl" to the args for bwrap
        let mut bwrap_args = vec!["bootupctl"];
        bwrap_args.extend(bootupd_args);

        let mut cmd = BwrapCmd::new(&target_root)
            // Bind mount /boot from the physical target root so bootupctl can find
            // the boot partition and install the bootloader there
            .bind(&boot_path, &"/boot");

        // Only bind mount the physical root at /sysroot when using --filesystem;
        // bootupd needs it to resolve backing block devices via lsblk.
        if root_device_path.is_none() {
            cmd = cmd.bind(&rootfs_path, &"/sysroot");
        }

        // The $PATH in the bwrap env is not complete enough for some images
        // so we inject a reasonable default.
        cmd.set_default_path().run(bwrap_args)
    } else {
        // Running directly without chroot
        Command::new("bootupctl")
            .args(&bootupd_args)
            .log_debug()
            .run_inherited_with_cmd_context()
    }
}

/// Install systemd-boot to the first ESP found among backing devices.
///
/// On multi-device setups only the first ESP is installed to; additional
/// ESPs on other backing devices are left untouched.
// TODO: install to all ESPs on multi-device setups
#[context("Installing bootloader")]
pub(crate) fn install_systemd_boot(
    device: &bootc_blockdev::Device,
    _rootfs: &Utf8Path,
    _configopts: &crate::install::InstallConfigOpts,
    _deployment_path: Option<&str>,
    autoenroll: Option<SecurebootKeys>,
) -> Result<()> {
    let roots = device.find_all_roots()?;
    let esp_part = roots
        .iter()
        .find_map(|root| root.find_partition_of_type(discoverable_partition_specification::ESP))
        .ok_or_else(|| anyhow::anyhow!("ESP partition not found"))?;

    let esp_mount = mount_esp(&esp_part.path()).context("Mounting ESP")?;
    let esp_path = Utf8Path::from_path(esp_mount.dir.path())
        .ok_or_else(|| anyhow::anyhow!("Failed to convert ESP mount path to UTF-8"))?;

    println!("Installing bootloader via systemd-boot");
    Command::new("bootctl")
        .args(["install", "--esp-path", esp_path.as_str()])
        .log_debug()
        .run_inherited_with_cmd_context()?;

    if let Some(SecurebootKeys { dir, keys }) = autoenroll {
        let path = esp_path.join(SYSTEMD_KEY_DIR);
        create_dir_all(&path)?;

        let keys_dir = esp_mount
            .fd
            .open_dir(SYSTEMD_KEY_DIR)
            .with_context(|| format!("Opening {path}"))?;

        for filename in keys.iter() {
            let p = path.join(&filename);

            // create directory if it doesn't already exist
            if let Some(parent) = p.parent() {
                create_dir_all(parent)?;
            }

            dir.copy(&filename, &keys_dir, &filename)
                .with_context(|| format!("Copying secure boot key: {p}"))?;
            println!("Wrote Secure Boot key: {p}");
        }
        if keys.is_empty() {
            tracing::debug!("No Secure Boot keys provided for systemd-boot enrollment");
        }
    }

    Ok(())
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
