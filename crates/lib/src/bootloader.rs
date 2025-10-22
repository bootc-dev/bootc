use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use bootc_utils::CommandRunExt;
use camino::Utf8Path;
use fn_error_context::context;

use bootc_blockdev::{Partition, PartitionTable};
use bootc_mount as mount;

#[cfg(any(feature = "composefs-backend", feature = "install-to-disk"))]
use crate::bootc_composefs::boot::mount_esp;
use crate::{discoverable_partition_specification, utils};

/// The name of the mountpoint for efi (as a subdirectory of /boot, or at the toplevel)
pub(crate) const EFI_DIR: &str = "efi";
/// The EFI system partition GUID
/// Path to the bootupd update payload
#[allow(dead_code)]
const BOOTUPD_UPDATES: &str = "usr/lib/bootupd/updates";

#[allow(dead_code)]
pub(crate) fn esp_in(device: &PartitionTable) -> Result<&Partition> {
    device
        .find_partition_of_type(discoverable_partition_specification::ESP)
        .ok_or(anyhow::anyhow!("ESP not found in partition table"))
}

/// Determine if the invoking environment contains bootupd, and if there are bootupd-based
/// updates in the target root.
#[context("Querying for bootupd")]
#[allow(dead_code)]
pub(crate) fn supports_bootupd(deployment_path: Option<&str>) -> Result<bool> {
    if !utils::have_executable("bootupctl")? {
        tracing::trace!("No bootupctl binary found");
        return Ok(false);
    };
    let deployment_path = Utf8Path::new(deployment_path.unwrap_or("/"));
    let updates = deployment_path.join(BOOTUPD_UPDATES);
    let r = updates.try_exists()?;
    tracing::trace!("bootupd updates: {r}");
    Ok(r)
}

#[context("Installing bootloader")]
pub(crate) fn install_via_bootupd(
    device: &PartitionTable,
    rootfs: &Utf8Path,
    configopts: &crate::install::InstallConfigOpts,
    deployment_path: Option<&str>,
) -> Result<()> {
    let verbose = std::env::var_os("BOOTC_BOOTLOADER_DEBUG").map(|_| "-vvvv");
    // bootc defaults to only targeting the platform boot method.
    let bootupd_opts = (!configopts.generic_image).then_some(["--update-firmware", "--auto"]);

    let abs_deployment_path = deployment_path.map(|v| rootfs.join(v));
    let src_root_arg = if let Some(p) = abs_deployment_path.as_deref() {
        vec!["--src-root", p.as_str()]
    } else {
        vec![]
    };
    let devpath = device.path();
    println!("Installing bootloader via bootupd");
    Command::new("bootupctl")
        .args(["backend", "install", "--write-uuid"])
        .args(verbose)
        .args(bootupd_opts.iter().copied().flatten())
        .args(src_root_arg)
        .args(["--device", devpath.as_str(), rootfs.as_str()])
        .log_debug()
        .run_inherited_with_cmd_context()
}

#[context("Installing bootloader")]
#[cfg(any(feature = "composefs-backend", feature = "install-to-disk"))]
pub(crate) fn install_systemd_boot(
    device: &PartitionTable,
    _rootfs: &Utf8Path,
    _configopts: &crate::install::InstallConfigOpts,
    _deployment_path: Option<&str>,
) -> Result<()> {
    let esp_part = device
        .find_partition_of_type(discoverable_partition_specification::ESP)
        .ok_or_else(|| anyhow::anyhow!("ESP partition not found"))?;

    let esp_mount = mount_esp(&esp_part.node).context("Mounting ESP")?;
    let esp_path = Utf8Path::from_path(esp_mount.dir.path())
        .ok_or_else(|| anyhow::anyhow!("Failed to convert ESP mount path to UTF-8"))?;

    println!("Installing bootloader via systemd-boot");
    Command::new("bootctl")
        .args(["install", "--esp-path", esp_path.as_str()])
        .log_debug()
        .run_inherited_with_cmd_context()
}

#[context("Installing bootloader using zipl")]
pub(crate) fn install_via_zipl(device: &PartitionTable, boot_uuid: &str) -> Result<()> {
    // Identify the target boot partition from UUID
    let fs = mount::inspect_filesystem_by_uuid(boot_uuid)?;
    let boot_dir = Utf8Path::new(&fs.target);
    let maj_min = fs.maj_min;

    // Ensure that the found partition is a part of the target device
    let device_path = device.path();

    let partitions = bootc_blockdev::list_dev(device_path)?
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
        .args(["--targetbase", device_path.as_str()])
        .args(["--targettype", "SCSI"])
        .args(["--targetblocksize", "512"])
        .args(["--targetoffset", &boot_part_offset.to_string()])
        .args(["--add-files", "--verbose"])
        .log_debug()
        .run_inherited_with_cmd_context()
}
