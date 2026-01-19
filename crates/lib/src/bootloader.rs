use std::fs::create_dir_all;
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use bootc_utils::CommandRunExt;
use camino::Utf8Path;
use cap_std_ext::cap_std::fs::Dir;
use cap_std_ext::dirext::CapStdExtDirExt;
use fn_error_context::context;

use bootc_blockdev::{Partition, PartitionTable};
use bootc_mount as mount;
use rustix::mount::UnmountFlags;

use crate::bootc_composefs::boot::{SecurebootKeys, get_sysroot_parent_dev, mount_esp};
use crate::{discoverable_partition_specification, utils};

/// The name of the mountpoint for efi (as a subdirectory of /boot, or at the toplevel)
pub(crate) const EFI_DIR: &str = "efi";
/// The EFI system partition GUID
/// Path to the bootupd update payload
#[allow(dead_code)]
const BOOTUPD_UPDATES: &str = "usr/lib/bootupd/updates";

// from: https://github.com/systemd/systemd/blob/26b2085d54ebbfca8637362eafcb4a8e3faf832f/man/systemd-boot.xml#L392
const SYSTEMD_KEY_DIR: &str = "loader/keys";

#[allow(dead_code)]
pub(crate) fn esp_in(device: &PartitionTable) -> Result<&Partition> {
    device
        .find_partition_of_type(discoverable_partition_specification::ESP)
        .ok_or(anyhow::anyhow!("ESP not found in partition table"))
}

/// Get esp partition node based on the root dir
pub(crate) fn get_esp_partition_node(root: &Dir) -> Result<Option<String>> {
    let device = get_sysroot_parent_dev(&root)?;
    let base_partitions = bootc_blockdev::partitions_of(Utf8Path::new(&device))?;
    let esp = base_partitions.find_partition_of_esp()?;
    Ok(esp.map(|v| v.node.clone()))
}

/// Mount ESP part at /boot/efi
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
    if let Some(esp_part) = get_esp_partition_node(physical_root)? {
        bootc_mount::mount(&esp_part, &root_path.join(&efi_path))?;
        tracing::debug!("Mounted {esp_part} at /boot/efi");
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

    let abs_deployment_path = deployment_path.map(|deploy| rootfs.join(deploy));
    // When not running inside the target container (through `--src-imgref`) we chroot
    // into the deployment before running bootupd. This makes sure we use binaries
    // from the target image rather than the buildroot
    // In some cases (e.g. --write-uuid), bootupd needs to find the underlying device
    // for /boot. But since we don't control where the destination rootfs is mounted
    // let's bind mount it to a temp mountpoint under /run
    // so it gets carried over in the chroot.

    // let rootfs_mountpoint: TempDir;
    let rootfs_mount = if rootfs.starts_with("/run") {
        rootfs.as_str()
    } else {
        "/"
    };

    // We mount the linux API file systems into the target deployment before chrooting
    // so bootupd can find the proper backing device.
    // xref https://systemd.io/API_FILE_SYSTEMS/
    let bind_mount_dirs = ["/dev", "/run", "/proc", "/sys"];
    let chroot_args = if let Some(target_root) = abs_deployment_path.as_deref() {
        tracing::debug!("Setting up bind-mounts before chrooting to the target deployment");
        // First off, we bind-mount target on itself, so it becomes a mount point and the chrooted
        // `findmnt` calls are able to resolve the mount in the chroot
        // See https://github.com/coreos/bootupd/issues/1051#issuecomment-3768271509 and following comments
        tracing::debug!("bind mounting the target deployement on itslelf");
        rustix::mount::mount_bind(target_root.as_std_path(), target_root.as_std_path())?;

        for src in bind_mount_dirs {
            let dest = target_root
                // joining an absolute path
                // makes it replace self, so we strip the prefix
                .join_os(src.strip_prefix("/").unwrap());
            tracing::debug!("bind mounting {}", dest.display());
            rustix::mount::mount_bind_recursive(src, dest)?;
        }
        // WIP : let's try to bind-mount /target/boot into the deployment as well rather than bind-mounting the whole thing??
        if !rootfs.starts_with("/run") {
            tracing::debug!(
                "We need to access the target /boot filesystem so let's also bind-mount it"
            );
            let trgt_boot = rootfs.as_std_path().join("boot");
            let chrooted_boot = target_root.join_os("boot");
            tracing::debug!(
                "bind-mounting {} in {}",
                &trgt_boot.display(),
                &chrooted_boot.display()
            );
            rustix::mount::mount_bind_recursive(trgt_boot, chrooted_boot)?;
        }

        // Append the `bootupctl` command, it will be passed as
        // an argument to chroot
        vec![target_root.as_str(), "bootupctl"]
    } else {
        vec![]
    };

    let devpath = device.path();
    println!("Installing bootloader via bootupd");
    let mut bootupctl = if abs_deployment_path.is_some() {
        Command::new("chroot")
    } else {
        Command::new("bootupctl")
    };
    let install_result = bootupctl
        .args(chroot_args)
        // Inject a reasonnable PATH here so we find the required tools
        // when running chrooted in the deployment. Testing show that
        // the default $PATH value in the chroot is insufficient.
        .env(
            "PATH",
            "/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin",
        )
        .args(["backend", "install", "--write-uuid"])
        .args(verbose)
        .args(bootupd_opts.iter().copied().flatten())
        .args(["--device", devpath.as_str(), rootfs_mount])
        .log_debug()
        .run_inherited_with_cmd_context();

    // Clean up the mounts after ourselves
    if let Some(target_root) = abs_deployment_path {
        if let Err(e) = rustix::mount::unmount(
            target_root.join("boot").into_std_path_buf(),
            UnmountFlags::DETACH,
        ) {
            tracing::warn!("Error unmounting target/boot: {e}");
        }
        for dir in bind_mount_dirs {
            let mount = target_root
                .join(dir.strip_prefix("/").unwrap())
                .into_std_path_buf();
            if let Err(e) = rustix::mount::unmount(&mount, UnmountFlags::DETACH) {
                // let's not propagate the error up because in some cases we can't unmount
                // e.g. when running `to-existing-root`
                tracing::warn!("Error unmounting {}: {e}", mount.display());
            }
        }
        if let Err(e) =
            rustix::mount::unmount(&target_root.into_std_path_buf(), UnmountFlags::DETACH)
        {
            tracing::warn!("Error unmounting target root bind mount: {e}");
        }
    }
    install_result
}

#[context("Installing bootloader")]
pub(crate) fn install_systemd_boot(
    device: &PartitionTable,
    _rootfs: &Utf8Path,
    _configopts: &crate::install::InstallConfigOpts,
    _deployment_path: Option<&str>,
    autoenroll: Option<SecurebootKeys>,
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
