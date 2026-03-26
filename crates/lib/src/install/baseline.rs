//! # The baseline installer
//!
//! This module handles creation of simple root filesystem setups.  At the current time
//! it's very simple - just a direct filesystem (e.g. xfs, ext4, btrfs etc.).  It is
//! intended to add opinionated handling of TPM2-bound LUKS too.  But that's about it;
//! other more complex flows should set things up externally and use `bootc install to-filesystem`.

use std::borrow::Cow;
use std::fmt::Display;
use std::fmt::Write as _;
use std::process::Command;
use std::process::Stdio;

use anyhow::Ok;
use anyhow::{Context, Result};
use bootc_utils::CommandRunExt;
use camino::Utf8Path;
use camino::Utf8PathBuf;
use cap_std::fs::Dir;
use cap_std_ext::cap_std;
use clap::ValueEnum;
use fn_error_context::context;
use serde::{Deserialize, Serialize};

use super::MountSpec;
use super::RUN_BOOTC;
use super::RW_KARG;
use super::RootSetup;
use super::State;
use super::config::Filesystem;
use crate::task::Task;
use bootc_kernel_cmdline::utf8::Cmdline;
#[cfg(feature = "install-to-disk")]
use bootc_mount::is_mounted_in_pid1_mountns;

// This ensures we end up under 512 to be small-sized.
pub(crate) const BOOTPN_SIZE_MB: u32 = 510;
pub(crate) const EFIPN_SIZE_MB: u32 = 512;
/// EFI Partition size for composefs installations
/// We need more space than ostree as we have UKIs and UKI addons
/// We might also need to store UKIs for pinned deployments
pub(crate) const CFS_EFIPN_SIZE_MB: u32 = 1024;
#[cfg(feature = "install-to-disk")]
pub(crate) const PREPBOOT_GUID: &str = "9E1A2D38-C612-4316-AA26-8B49521E5A8B";
#[cfg(feature = "install-to-disk")]
pub(crate) const PREPBOOT_LABEL: &str = "PowerPC-PReP-boot";

#[derive(clap::ValueEnum, Default, Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum BlockSetup {
    #[default]
    Direct,
    Tpm2Luks,
}

impl Display for BlockSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_possible_value().unwrap().get_name().fmt(f)
    }
}

/// Options for installing to a block device
#[derive(Debug, Clone, clap::Args, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct InstallBlockDeviceOpts {
    /// Target block device for installation.  The entire device will be wiped.
    pub(crate) device: Utf8PathBuf,

    /// Automatically wipe all existing data on device
    #[clap(long)]
    #[serde(default)]
    pub(crate) wipe: bool,

    /// Target root block device setup.
    ///
    /// direct: Filesystem written directly to block device
    /// tpm2-luks: Bind unlock of filesystem to presence of the default tpm2 device.
    #[clap(long, value_enum)]
    pub(crate) block_setup: Option<BlockSetup>,

    /// Target root filesystem type.
    #[clap(long, value_enum)]
    pub(crate) filesystem: Option<Filesystem>,

    /// Size of the root partition (default specifier: M).  Allowed specifiers: M (mebibytes), G (gibibytes), T (tebibytes).
    ///
    /// By default, all remaining space on the disk will be used.
    #[clap(long)]
    pub(crate) root_size: Option<String>,
}

impl BlockSetup {
    /// Returns true if the block setup requires a separate /boot aka XBOOTLDR partition.
    pub(crate) fn requires_bootpart(&self) -> bool {
        match self {
            BlockSetup::Direct => false,
            BlockSetup::Tpm2Luks => true,
        }
    }
}

#[cfg(feature = "install-to-disk")]
fn mkfs<'a>(
    dev: &str,
    fs: Filesystem,
    label: &str,
    wipe: bool,
    opts: impl IntoIterator<Item = &'a str>,
) -> Result<uuid::Uuid> {
    mkfs_with_reserve(dev, fs, label, wipe, opts, 0)
}

/// Create a filesystem, optionally reserving trailing space on the device.
///
/// When `reserve_mib` is non-zero, the filesystem is created smaller than the
/// partition by that amount. This is used to reserve space for a LUKS header
/// that will be inserted on first boot via `cryptsetup reencrypt --encrypt`.
#[cfg(feature = "install-to-disk")]
fn mkfs_with_reserve<'a>(
    dev: &str,
    fs: Filesystem,
    label: &str,
    wipe: bool,
    opts: impl IntoIterator<Item = &'a str>,
    reserve_mib: u32,
) -> Result<uuid::Uuid> {
    let devinfo = bootc_blockdev::list_dev(dev.into())?;
    let size = ostree_ext::glib::format_size(devinfo.size);

    // Generate a random UUID for the filesystem
    let u = uuid::Uuid::new_v4();

    let mut t = Task::new(
        &format!("Creating {label} filesystem ({fs}) on device {dev} (size={size})"),
        format!("mkfs.{fs}"),
    );
    match fs {
        Filesystem::Xfs => {
            if wipe {
                t.cmd.arg("-f");
            }
            t.cmd.arg("-m");
            t.cmd.arg(format!("uuid={u}"));
            if reserve_mib > 0 {
                let fs_bytes = devinfo.size - u64::from(reserve_mib) * 1024 * 1024;
                t.cmd.args(["-d", &format!("size={fs_bytes}")]);
            }
        }
        Filesystem::Btrfs => {
            t.cmd.arg("-U");
            t.cmd.arg(u.to_string());
            if reserve_mib > 0 {
                let fs_bytes = devinfo.size - u64::from(reserve_mib) * 1024 * 1024;
                t.cmd.args(["-b", &fs_bytes.to_string()]);
            }
        }
        Filesystem::Ext4 => {
            t.cmd.arg("-U");
            t.cmd.arg(u.to_string());
        }
    };
    // Today all the above mkfs commands take -L
    t.cmd.args(["-L", label]);
    t.cmd.args(opts);
    t.cmd.arg(dev);
    // For ext4 with reserved space, append the filesystem size in 1K blocks
    // as a positional argument after the device path.
    if reserve_mib > 0 && fs == Filesystem::Ext4 {
        let fs_blocks_1k = (devinfo.size - u64::from(reserve_mib) * 1024 * 1024) / 1024;
        t.cmd.arg(fs_blocks_1k.to_string());
    }
    // All the mkfs commands are unnecessarily noisy by default
    t.cmd.stdout(Stdio::null());
    // But this one is notable so let's print the whole thing with verbose()
    t.verbose().run()?;
    Ok(u)
}

pub(crate) fn wipefs(dev: &Utf8Path) -> Result<()> {
    println!("Wiping device {dev}");
    Command::new("wipefs")
        .args(["-a", dev.as_str()])
        .run_inherited_with_cmd_context()
}

pub(crate) fn udev_settle() -> Result<()> {
    // There's a potential window after rereading the partition table where
    // udevd hasn't yet received updates from the kernel, settle will return
    // immediately, and lsblk won't pick up partition labels.  Try to sleep
    // our way out of this.
    std::thread::sleep(std::time::Duration::from_millis(200));

    let st = super::run_in_host_mountns("udevadm")?
        .arg("settle")
        .status()?;
    if !st.success() {
        anyhow::bail!("Failed to run udevadm settle: {st:?}");
    }
    Ok(())
}

#[context("Creating rootfs")]
#[cfg(feature = "install-to-disk")]
pub(crate) fn install_create_rootfs(
    state: &State,
    opts: InstallBlockDeviceOpts,
) -> Result<RootSetup> {
    let install_config = state.install_config.as_ref();
    // Ensure we have a root filesystem upfront
    let root_filesystem = opts
        .filesystem
        .or(install_config
            .and_then(|c| c.filesystem_root())
            .and_then(|r| r.fstype))
        .ok_or_else(|| anyhow::anyhow!("No root filesystem specified"))?;
    // Verify that the target is empty (if not already wiped in particular, but it's
    // also good to verify that the wipe worked)
    let mut device = bootc_blockdev::list_dev(&opts.device)?;

    // Always disallow writing to mounted device
    if is_mounted_in_pid1_mountns(&device.path())? {
        anyhow::bail!("Device {} is mounted", device.path())
    }

    // Handle wiping any existing data
    if opts.wipe {
        let dev = &opts.device;
        for child in device.children.iter().flatten() {
            let child = child.path();
            println!("Wiping {child}");
            wipefs(Utf8Path::new(&child))?;
        }
        println!("Wiping {dev}");
        wipefs(dev)?;
    } else if device.has_children() {
        anyhow::bail!(
            "Detected existing partitions on {}; use e.g. `wipefs` or --wipe if you intend to overwrite",
            opts.device
        );
    }

    let run_bootc = Utf8Path::new(RUN_BOOTC);
    let mntdir = run_bootc.join("mounts");
    if mntdir.exists() {
        std::fs::remove_dir_all(&mntdir)?;
    }

    // Use the install configuration to find the block setup, if we have one
    let block_setup = if let Some(config) = install_config {
        config.get_block_setup(opts.block_setup.as_ref().copied())?
    } else if opts.filesystem.is_some() {
        // Otherwise, if a filesystem is specified then we default to whatever was
        // specified via --block-setup, or the default
        opts.block_setup.unwrap_or_default()
    } else {
        // If there was no default filesystem, then there's no default block setup,
        // and we need to error out.
        anyhow::bail!("No install configuration found, and no filesystem specified")
    };
    let serial = device.serial.as_deref().unwrap_or("<unknown>");
    let model = device.model.as_deref().unwrap_or("<unknown>");
    println!("Block setup: {block_setup}");
    println!("       Size: {}", device.size);
    println!("     Serial: {serial}");
    println!("      Model: {model}");

    let root_size = opts
        .root_size
        .as_deref()
        .map(bootc_blockdev::parse_size_mib)
        .transpose()
        .context("Parsing root size")?;

    // Load the policy from the container root, which also must be our install root
    let sepolicy = state.load_policy()?;
    let sepolicy = sepolicy.as_ref();

    // Create a temporary directory to use for mount points.  Note that we're
    // in a mount namespace, so these should not be visible on the host.
    let physical_root_path = mntdir.join("rootfs");
    std::fs::create_dir_all(&physical_root_path)?;
    let bootfs = mntdir.join("boot");
    std::fs::create_dir_all(bootfs)?;

    // Generate partitioning spec as input to sfdisk
    let mut partno = 0;
    let mut partitioning_buf = String::new();
    writeln!(partitioning_buf, "label: gpt")?;
    let random_label = uuid::Uuid::new_v4();
    writeln!(&mut partitioning_buf, "label-id: {random_label}")?;
    if cfg!(target_arch = "x86_64") {
        partno += 1;
        writeln!(
            &mut partitioning_buf,
            r#"size=1MiB, bootable, type=21686148-6449-6E6F-744E-656564454649, name="BIOS-BOOT""#
        )?;
    } else if cfg!(target_arch = "powerpc64") {
        // PowerPC-PReP-boot
        partno += 1;
        let label = PREPBOOT_LABEL;
        let uuid = PREPBOOT_GUID;
        writeln!(
            &mut partitioning_buf,
            r#"size=4MiB, bootable, type={uuid}, name="{label}""#
        )?;
    } else if cfg!(any(target_arch = "aarch64", target_arch = "s390x")) {
        // No bootloader partition is necessary
    } else {
        anyhow::bail!("Unsupported architecture: {}", std::env::consts::ARCH);
    }

    let esp_partno = if super::ARCH_USES_EFI {
        let esp_guid = crate::discoverable_partition_specification::ESP;
        partno += 1;

        let esp_size = if state.composefs_options.composefs_backend {
            CFS_EFIPN_SIZE_MB
        } else {
            EFIPN_SIZE_MB
        };

        writeln!(
            &mut partitioning_buf,
            r#"size={esp_size}MiB, type={esp_guid}, name="EFI-SYSTEM""#
        )?;
        Some(partno)
    } else {
        None
    };

    // Initialize the /boot filesystem.  Note that in the future, we may match
    // what systemd/uapi-group encourages and make /boot be FAT32 as well, as
    // it would aid systemd-boot.
    let boot_partno = if block_setup.requires_bootpart() {
        partno += 1;
        writeln!(
            &mut partitioning_buf,
            r#"size={BOOTPN_SIZE_MB}MiB, name="boot""#
        )?;
        Some(partno)
    } else {
        None
    };
    let rootpn = partno + 1;
    let root_size = root_size
        .map(|v| Cow::Owned(format!("size={v}MiB, ")))
        .unwrap_or_else(|| Cow::Borrowed(""));
    let rootpart_uuid =
        uuid::Uuid::parse_str(crate::discoverable_partition_specification::this_arch_root())?;
    writeln!(
        &mut partitioning_buf,
        r#"{root_size}type={rootpart_uuid}, name="root""#
    )?;
    tracing::debug!("Partitioning: {partitioning_buf}");
    Task::new("Initializing partitions", "sfdisk")
        .arg("--wipe=always")
        .arg(device.path())
        .quiet()
        .run_with_stdin_buf(Some(partitioning_buf.as_bytes()))
        .context("Failed to run sfdisk")?;
    tracing::debug!("Created partition table");

    // Full udev sync; it'd obviously be better to await just the devices
    // we're targeting, but this is a simple coarse hammer.
    udev_settle()?;

    // Re-read partition table to get updated children
    device.refresh()?;

    let root_device = device.find_device_by_partno(rootpn)?;
    // Verify the partition type matches the DPS root partition type for this architecture
    let expected_parttype = crate::discoverable_partition_specification::this_arch_root();
    if !root_device
        .parttype
        .as_ref()
        .is_some_and(|pt| pt.eq_ignore_ascii_case(expected_parttype))
    {
        anyhow::bail!(
            "root partition {rootpn} has type {}; expected {expected_parttype}",
            root_device.parttype.as_deref().unwrap_or("<none>")
        );
    }
    // For tpm2-luks, we reserve space for a LUKS header but do not perform
    // any encryption during install. Encryption is deferred to first boot,
    // where it runs on real hardware with access to the actual TPM device
    // and correct firmware state (PCRs, shim version). This avoids both the
    // IPC namespace deadlock (#2089) and the shim/PCR mismatch (#421).
    let luks_reserve_mib: u32 = match block_setup {
        BlockSetup::Direct => 0,
        BlockSetup::Tpm2Luks => 32,
    };
    let root_blockdev_kargs = match block_setup {
        BlockSetup::Direct => None,
        BlockSetup::Tpm2Luks => Some(vec!["rd.bootc.luks.encrypt=tpm2".to_string()]),
    };
    let rootdev_path = root_device.path();

    // Initialize the /boot filesystem
    let bootdev = if let Some(bootpn) = boot_partno {
        Some(device.find_device_by_partno(bootpn)?)
    } else {
        None
    };
    let boot_uuid = if let Some(bootdev) = bootdev {
        Some(
            mkfs(&bootdev.path(), root_filesystem, "boot", opts.wipe, [])
                .context("Initializing /boot")?,
        )
    } else {
        None
    };

    // Unconditionally enable fsverity for ext4
    let mkfs_options = match root_filesystem {
        Filesystem::Ext4 => ["-O", "verity"].as_slice(),
        _ => [].as_slice(),
    };

    // Initialize rootfs. When encrypting on first boot, reserve trailing space
    // for the LUKS header that cryptsetup reencrypt --encrypt will insert.
    let root_uuid = mkfs_with_reserve(
        &rootdev_path,
        root_filesystem,
        "root",
        opts.wipe,
        mkfs_options.iter().copied(),
        luks_reserve_mib,
    )?;
    let rootarg = format!("root=UUID={root_uuid}");
    let bootsrc = boot_uuid.as_ref().map(|uuid| format!("UUID={uuid}"));
    let bootarg = bootsrc.as_deref().map(|bootsrc| format!("boot={bootsrc}"));
    let boot = bootsrc.map(|bootsrc| MountSpec {
        source: bootsrc,
        target: "/boot".into(),
        fstype: MountSpec::AUTO.into(),
        options: Some("ro".into()),
    });

    let mut kargs = Cmdline::new();

    // Add root blockdev kargs (e.g., LUKS parameters)
    if let Some(root_blockdev_kargs) = root_blockdev_kargs {
        for karg in root_blockdev_kargs {
            kargs.extend(&Cmdline::from(karg.as_str()));
        }
    }

    // Add root= and rw argument
    kargs.extend(&Cmdline::from(format!("{rootarg} {RW_KARG}")));

    // Add boot= argument if present
    if let Some(bootarg) = bootarg {
        kargs.extend(&Cmdline::from(bootarg.as_str()));
    }

    // Add CLI kargs
    if let Some(cli_kargs) = state.config_opts.karg.as_ref() {
        for karg in cli_kargs {
            kargs.extend(karg);
        }
    }

    bootc_mount::mount(&rootdev_path, &physical_root_path)?;
    let target_rootfs = Dir::open_ambient_dir(&physical_root_path, cap_std::ambient_authority())?;
    crate::lsm::ensure_dir_labeled(&target_rootfs, "", Some("/".into()), 0o755.into(), sepolicy)?;
    let physical_root = Dir::open_ambient_dir(&physical_root_path, cap_std::ambient_authority())?;
    let bootfs = physical_root_path.join("boot");
    // Create the underlying mount point directory, which should be labeled
    crate::lsm::ensure_dir_labeled(&target_rootfs, "boot", None, 0o755.into(), sepolicy)?;
    if let Some(bootdev) = bootdev {
        bootc_mount::mount(&bootdev.path(), &bootfs)?;
    }
    // And we want to label the root mount of /boot
    crate::lsm::ensure_dir_labeled(&target_rootfs, "boot", None, 0o755.into(), sepolicy)?;

    // Create the EFI system partition, if applicable
    if let Some(esp_partno) = esp_partno {
        let espdev = device.find_device_by_partno(esp_partno)?;
        Task::new("Creating ESP filesystem", "mkfs.fat")
            .args([&espdev.path(), "-n", "EFI-SYSTEM"])
            .verbose()
            .quiet_output()
            .run()?;
        let efifs_path = bootfs.join(crate::bootloader::EFI_DIR);
        std::fs::create_dir(&efifs_path).context("Creating efi dir")?;
    }

    // With first-boot LUKS, no dm-crypt device is opened during install,
    // so there is nothing to close. The root partition is written unencrypted.
    let luks_device = None;
    Ok(RootSetup {
        luks_device,
        device_info: device,
        physical_root_path,
        physical_root,
        target_root_path: None,
        rootfs_uuid: Some(root_uuid.to_string()),
        boot,
        kargs,
        skip_finalize: false,
    })
}
