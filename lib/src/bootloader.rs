use anyhow::{anyhow, bail, Context, Result};
use camino::Utf8Path;
use fn_error_context::context;

use crate::task::Task;
use bootc_blockdev::PartitionTable;

/// The name of the mountpoint for efi (as a subdirectory of /boot, or at the toplevel)
pub(crate) const EFI_DIR: &str = "efi";

#[context("Installing bootloader")]
pub(crate) fn install_via_bootupd(
    device: &PartitionTable,
    rootfs: &Utf8Path,
    configopts: &crate::install::InstallConfigOpts,
) -> Result<()> {
    let verbose = std::env::var_os("BOOTC_BOOTLOADER_DEBUG").map(|_| "-vvvv");
    // bootc defaults to only targeting the platform boot method.
    let bootupd_opts = (!configopts.generic_image).then_some(["--update-firmware", "--auto"]);

    let devpath = device.path();
    let args = ["backend", "install", "--write-uuid"]
        .into_iter()
        .chain(verbose)
        .chain(bootupd_opts.iter().copied().flatten())
        .chain(["--device", devpath.as_str(), rootfs.as_str()]);
    Task::new("Running bootupctl to install bootloader", "bootupctl")
        .args(args)
        .verbose()
        .run()
}

#[context("Installing bootloader using zipl")]
pub(crate) fn install_via_zipl(device: &PartitionTable, boot_uuid: &str) -> Result<()> {
    // Identify the target boot partition from UUID
    let fs = crate::mount::inspect_filesystem_by_uuid(boot_uuid)?;
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
    let zipl_desc = format!("running zipl to install bootloader on {device_path}");
    let zipl_task = Task::new(&zipl_desc, "zipl")
        .args(["--target", boot_dir.as_str()])
        .args(["--image", image.as_str()])
        .args(["--ramdisk", ramdisk.as_str()])
        .args(["--parameters", options])
        .args(["--targetbase", device_path.as_str()])
        .args(["--targettype", "SCSI"])
        .args(["--targetblocksize", "512"])
        .args(["--targetoffset", &boot_part_offset.to_string()])
        .args(["--add-files", "--verbose"]);
    zipl_task.verbose().run().context(zipl_desc)
}
