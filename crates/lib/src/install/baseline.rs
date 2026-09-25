//! # The baseline installer
//!
//! This module handles creation of simple root filesystem setups.  At the current time
//! it's very simple - just a direct filesystem (e.g. xfs, ext4, btrfs etc.).  It is
//! intended to add opinionated handling of TPM2-bound LUKS too.  But that's about it;
//! other more complex flows should set things up externally and use `bootc install to-filesystem`.

use std::borrow::Cow;
use std::fmt::Display;
use std::fmt::Write as _;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::process::Stdio;

use anyhow::Ok;
use anyhow::{Context, Result};
use bootc_blockdev::Device;
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
use crate::bootloader::systemd_version;
use crate::discoverable_partition_specification::BIOS_BOOT;
use crate::task::Task;
#[cfg(feature = "install-to-disk")]
use bootc_mount::is_mounted_in_pid1_mountns;
use linux_kernel_cmdline::utf8::Cmdline;

/// Check whether DPS auto-discovery is enabled.  When `true`,
/// `root=UUID=` is omitted and `systemd-gpt-auto-generator` discovers
/// the root partition via its DPS type GUID instead.
///
/// Defaults to `true` for systemd-boot (which always implements BLI).
/// For GRUB the default is `false` because we cannot know at install
/// time whether the GRUB build includes the `bli` module — the module
/// is baked into the signed EFI binary with no external manifest.
/// Distros shipping a BLI-capable GRUB should set
/// `discoverable-partitions = true` in their install config.
#[cfg(feature = "install-to-disk")]
fn use_discoverable_partitions(state: &State) -> bool {
    // Explicit config takes priority
    if let Some(ref config) = state.install_config {
        if let Some(v) = config.discoverable_partitions {
            return v;
        }
    }
    // systemd-boot always supports BLI
    matches!(
        state.config_opts.bootloader,
        Some(crate::spec::Bootloader::Systemd) | Some(crate::spec::Bootloader::GrubCC)
    )
}

// This ensures we end up under 512 to be small-sized.
pub(crate) const BOOTPN_SIZE_MB: u32 = 510;
pub(crate) const EFIPN_SIZE_MB: u32 = 512;
/// EFI Partition size for composefs installations
/// We need more space than ostree as we have UKIs and UKI addons
/// We might also need to store UKIs for pinned deployments
pub(crate) const CFS_EFIPN_SIZE_MB: u32 = 2048;
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
        }
        Filesystem::Btrfs | Filesystem::Ext4 => {
            t.cmd.arg("-U");
            t.cmd.arg(u.to_string());
        }
    };
    // Today all the above mkfs commands take -L
    t.cmd.args(["-L", label]);
    t.cmd.args(opts);
    t.cmd.arg(dev);
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

/// Partition numbers resulting from partitioning, used to look up devices after.
#[derive(Debug)]
struct PartitionLayout {
    esp_partno: Option<u32>,
    boot_partno: Option<u32>,
    rootpn: u32,
    /// Whether systemd-repart created the ESP/boot partitions (skip mkfs for those)
    used_repart: bool,
}

/// The json output for systemd-repart
#[derive(Debug, Deserialize)]
struct RepartPartition {
    /// Human readable partition name
    /// Ex. "esp", "root-x86_64"
    #[serde(rename = "type")]
    partition_type: String,
    /// 0-indexed partition number
    /// absent in older systemd-repart
    /// versions, in c9s
    #[serde(default)]
    partno: Option<u32>,
    #[serde(default)]
    raw_size: u64,
    #[serde(default)]
    raw_padding: u64,
    #[allow(dead_code)]
    fs: Option<String>,
    /// The file used to generate this partition
    file: String,
}

fn can_use_systemd_repart() -> bool {
    if Command::new("systemd-repart")
        .arg("--help")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        return false;
    }

    let repart_config_dirs = [
        Path::new("/etc/repart.d"),
        Path::new("/run/repart.d"),
        Path::new("/usr/local/lib/repart.d"),
        Path::new("/usr/lib/repart.d"),
    ];

    let has_config = repart_config_dirs.iter().any(|d| {
        d.is_dir()
            && d.read_dir()
                .ok()
                .is_some_and(|mut entries| entries.next().is_some())
    });

    return has_config;
}

/// The first systemd version that supports `systemd-repart --include-partitions=`.
const REPART_INCLUDE_PARTITIONS_MIN_VERSION: u32 = 253;

/// The first systemd version whose systemd-repart honors the
/// `SYSTEMD_REPART_MKFS_OPTIONS_<FSTYPE>` environment variable (used to enable
/// ext4 fs-verity). Older versions silently ignore it.
const REPART_MKFS_OPTIONS_MIN_VERSION: u32 = 254;

/// Directory we assemble the filtered set of repart.d definitions into when
/// emulating `--include-partitions=` on systemd older than
/// [`REPART_INCLUDE_PARTITIONS_MIN_VERSION`].
const REPART_FILTERED_DEFINITIONS_DIR: &str = "/tmp/repart.d";

/// The repart.d configuration search directories, in descending priority. A
/// definition present in a higher-priority directory masks a same-named one
/// below it (matching systemd's own semantics).
const REPART_CONFIG_DIRS: &[&str] = &[
    "/etc/repart.d",
    "/run/repart.d",
    "/usr/local/lib/repart.d",
    "/usr/lib/repart.d",
];

/// Whether we must emulate `--include-partitions=` by pre-filtering the
/// definitions ourselves
fn need_filtered_definitions(generic_image: bool) -> Result<bool> {
    Ok(generic_image && systemd_version()? < REPART_INCLUDE_PARTITIONS_MIN_VERSION)
}

/// Whether a partition (as reported by systemd-repart) is one we must create
/// even for a generic image: root, ESP or BIOS boot.
fn repart_partition_is_required(part: &RepartPartition) -> bool {
    let ptype = part.partition_type.as_str();
    ptype.starts_with("root")
        || ptype.starts_with("esp")
        || ptype == "bios"
        || ptype.eq_ignore_ascii_case(BIOS_BOOT)
}

/// Collect the repart.d definitions for the partitions we require (root, ESP
/// and BIOS boot) into [`REPART_FILTERED_DEFINITIONS_DIR`].
///
/// systemd < 253 does not support the `--include-partitions=` option, so instead
/// we point systemd-repart at a directory containing only the definitions we want
/// it to act on
fn collect_repart_definitions(dry_partitions: &[RepartPartition]) -> Result<()> {
    let dest_dir = Path::new(REPART_FILTERED_DEFINITIONS_DIR);
    // Start from a clean directory so stale definitions from a previous run
    // don't leak in.
    if dest_dir.exists() {
        std::fs::remove_dir_all(dest_dir)
            .with_context(|| format!("Removing {REPART_FILTERED_DEFINITIONS_DIR}"))?;
    }

    std::fs::create_dir_all(dest_dir)
        .with_context(|| format!("Creating {REPART_FILTERED_DEFINITIONS_DIR}"))?;

    for part in dry_partitions {
        if !repart_partition_is_required(part) {
            continue;
        }

        // Older version of systemd-repart does not provide the full path to the file
        // so we need to search one by one
        let src = REPART_CONFIG_DIRS
            .iter()
            .map(|d| Path::new(d).join(&part.file))
            .find(|p| p.exists())
            .ok_or_else(|| anyhow::anyhow!("Could not find repart.d definition {}", part.file))?;

        std::fs::copy(&src, dest_dir.join(&part.file))
            .with_context(|| format!("Copying repart.d definition {}", src.display()))?;
    }

    Ok(())
}

/// Create partitions using systemd-repart
/// Assumes we have systemd-repart definitions
#[context("Running systemd-repart")]
fn systemd_repart(
    device: &Device,
    root_size: Option<u64>,
    rootfs: Option<Filesystem>,
    generic_image: bool,
) -> Result<PartitionLayout> {
    // Dry-run to check what partitions would be created
    // Send `generic_image` as false so that we can see ALL defined
    // partitions
    let dry_partitions = systemd_repart_run(device, false, true)?;

    if dry_partitions.is_empty() {
        anyhow::bail!("systemd-repart returned empty partitions");
    }

    let has_root = dry_partitions
        .iter()
        .any(|p| p.partition_type.starts_with("root-"));

    if has_root {
        // Root partition is defined in repart.d config, run for real
        if need_filtered_definitions(generic_image)? {
            collect_repart_definitions(&dry_partitions)?;
        }

        let partitions = systemd_repart_run(device, generic_image, false)?;
        let layout = parse_repart_layout(&partitions)?;
        return Ok(layout);
    }

    // Root partition is not defined, create defintion for the root part
    let mut root_conf = String::from("[Partition]\nType=root\n");

    match root_size {
        Some(size_mib) => {
            writeln!(root_conf, "SizeMinBytes={size_mib}M")?;
            writeln!(root_conf, "SizeMaxBytes={size_mib}M")?;
        }
        None => {
            let mb = 1024 * 1024;
            // Save 64 MB as partition headroom for GPT headers
            let partition_headroom = 64 * mb;

            // Installing to a disk, compute the root ptn size
            // by taking all other partitions into account
            //
            // We're doing this to accomodate for partitions that are
            // supposed to be crated on first boot, like home,var,swap etc
            let space_taken = dry_partitions
                .iter()
                .fold(0u64, |acc, x| acc + x.raw_size + x.raw_padding);
            let root_size_mib = (device.size - space_taken - partition_headroom) / mb;

            tracing::debug!(
                "space_taken: {} M, device.size: {} M, Root Size: {root_size_mib} M",
                space_taken / mb,
                device.size / mb
            );

            writeln!(root_conf, "SizeMinBytes={root_size_mib}M")?;
            writeln!(root_conf, "SizeMaxBytes={root_size_mib}M")?;
        }
    };

    match rootfs {
        Some(fs) => writeln!(root_conf, "Format={fs}")?,
        None => {
            anyhow::bail!("Rootfs not specified")
        }
    }

    if need_filtered_definitions(generic_image)? {
        collect_repart_definitions(&dry_partitions)?;

        std::fs::write(
            Path::new(REPART_FILTERED_DEFINITIONS_DIR).join("50-root.conf"),
            &root_conf,
        )
        .context("Writing root repart config to filtered definitions")?;
    } else {
        std::fs::create_dir_all("/run/repart.d").context("Creating /run/repart.d")?;
        std::fs::write("/run/repart.d/50-root.conf", &root_conf)
            .context("Writing root repart config")?;
    }

    let partitions = systemd_repart_run(device, generic_image, false)?;
    let layout = parse_repart_layout(&partitions)?;

    Ok(layout)
}

/// Run systemd-repart on the device and return the parsed JSON output.
/// `dry_run`: if true, no changes are written to disk.
/// `definitions`: if set, uses `--definitions=` and `--empty=allow`;
/// otherwise uses the default config search paths with `--empty=force`.
fn systemd_repart_run(
    device: &Device,
    generic_image: bool,
    dry_run: bool,
) -> Result<Vec<RepartPartition>> {
    let mut cmd = Command::new("systemd-repart");

    // Enable fsverity for ext4
    // btrfs has fsverity enabled out of the box
    //
    // NOTE: systemd < v254 doesn't support this
    cmd.env("SYSTEMD_REPART_MKFS_OPTIONS_EXT4", "-O verity");

    let dry_run_arg = if dry_run {
        "--dry-run=yes"
    } else {
        "--dry-run=no"
    };
    cmd.args([
        dry_run_arg,
        "--no-pager",
        "--json=pretty",
        "--empty=force",
        "--root=/",
    ]);

    // If generic image, only run repart definitions that we absolutely
    // require, (BIOS/ESP and root). Others can run at first boot since we
    // don't know if the user would want to run those on this disk itself
    // or if this disk would be used to create an AMI/VHD and a separate disk
    // would be used for the other partitions
    if generic_image {
        if need_filtered_definitions(generic_image)? {
            // Older systemd lacks --include-partitions; act only on the
            // pre-filtered definitions collected by collect_repart_definitions.
            cmd.arg(format!("--definitions={REPART_FILTERED_DEFINITIONS_DIR}"));
        } else {
            cmd.arg(format!("--include-partitions=root,esp,{BIOS_BOOT}"));
        }
    }

    cmd.arg(device.path());

    let output = cmd.output().context("Failed to run systemd-repart")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("systemd-repart failed: {stderr}");
    }

    if !dry_run {
        tracing::debug!(
            "Partitions ({}): {}",
            if dry_run { "Dry Run" } else { "Actual" },
            std::str::from_utf8(&output.stdout).unwrap_or("Failed to serialize output as UTF-8")
        );
    }

    serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "Failed to deserialize systemd-repart output: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

/// Parse partition layout from systemd-repart JSON output.
fn parse_repart_layout(partitions: &[RepartPartition]) -> Result<PartitionLayout> {
    let mut esp_partno = None;
    let mut boot_partno = None;
    let mut rootpn = None;

    for (idx, part) in partitions.iter().enumerate() {
        // repart partno is 0-indexed, lsblk/sfdisk use 1-indexed
        // Fall back to array indexing for older systemd-repart without partno
        // like the version in c9s
        let partno = part.partno.unwrap_or(idx as u32) + 1;

        match part.partition_type.as_str() {
            "esp" => esp_partno = Some(partno),
            "xbootldr" => boot_partno = Some(partno),
            t if t.starts_with("root-") => rootpn = Some(partno),
            _ => {}
        }
    }

    let rootpn =
        rootpn.ok_or_else(|| anyhow::anyhow!("systemd-repart output missing root partition"))?;

    Ok(PartitionLayout {
        esp_partno,
        boot_partno,
        rootpn,
        used_repart: true,
    })
}

/// Use sfdisk to create partitions
#[context("Running sfdisk")]
fn sfdisk(
    device: &Device,
    root_size: Option<u64>,
    composefs_backend: bool,
    requires_bootpart: bool,
) -> Result<PartitionLayout> {
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

        let esp_size = if composefs_backend {
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
    let boot_partno = if requires_bootpart {
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

    Ok(PartitionLayout {
        esp_partno,
        boot_partno,
        rootpn,
        used_repart: false,
    })
}

#[context("Creating rootfs")]
#[cfg(feature = "install-to-disk")]
pub(crate) fn install_create_rootfs(
    state: &State,
    opts: InstallBlockDeviceOpts,
) -> Result<RootSetup> {
    let install_config = state.install_config.as_ref();
    let luks_name = "root";
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

    let use_systemd_repart = can_use_systemd_repart();

    // Use the install configuration to find the block setup, if we have one
    let block_setup = if let Some(config) = install_config {
        config.get_block_setup(opts.block_setup.as_ref().copied())?
    } else if opts.filesystem.is_some() || use_systemd_repart {
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
    let discoverable = use_discoverable_partitions(state);
    println!("Block setup: {block_setup}");
    println!("       Size: {}", device.size);
    println!("     Serial: {serial}");
    println!("      Model: {model}");
    println!(
        " Partitions: {}",
        if discoverable { "Discoverable" } else { "UUID" }
    );

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

    let layout = if use_systemd_repart {
        systemd_repart(
            &device,
            root_size,
            opts.filesystem,
            state.config_opts.generic_image,
        )?
    } else {
        sfdisk(
            &device,
            root_size,
            state.composefs_options.composefs_backend,
            block_setup.requires_bootpart(),
        )?
    };

    tracing::debug!(
        "Created partition table using {}",
        if layout.used_repart {
            "systemd-repart"
        } else {
            "sfdisk"
        }
    );

    // Full udev sync; it'd obviously be better to await just the devices
    // we're targeting, but this is a simple coarse hammer.
    udev_settle()?;

    // Re-read partition table to get updated children
    device.refresh()?;

    // Ensure we have a root filesystem
    let root_filesystem = if layout.used_repart {
        let root = device.find_device_by_partno(layout.rootpn)?;
        root.fstype
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("repart: Root filesystem type not defined"))?
    } else {
        let root_filesystem = opts
            .filesystem
            .or(install_config
                .and_then(|c| c.filesystem_root())
                .and_then(|r| r.fstype))
            .ok_or_else(|| anyhow::anyhow!("No root filesystem specified"))?;

        &root_filesystem.to_string()
    };

    let root_device = device.find_device_by_partno(layout.rootpn)?;

    // Verify the partition type matches the DPS root partition type for this architecture
    let expected_parttype = crate::discoverable_partition_specification::this_arch_root();
    if !root_device
        .parttype
        .as_ref()
        .is_some_and(|pt| pt.eq_ignore_ascii_case(expected_parttype))
    {
        anyhow::bail!(
            "root partition {} has type {}; expected {expected_parttype}",
            layout.rootpn,
            root_device.parttype.as_deref().unwrap_or("<none>")
        );
    }
    let (rootdev_path, root_blockdev_kargs) = match block_setup {
        BlockSetup::Direct => (root_device.path(), None),
        BlockSetup::Tpm2Luks => {
            let uuid = uuid::Uuid::new_v4().to_string();
            // This will be replaced via --wipe-slot=all when binding to tpm below
            let dummy_passphrase = uuid::Uuid::new_v4().to_string();
            let mut tmp_keyfile = tempfile::NamedTempFile::new()?;
            tmp_keyfile.write_all(dummy_passphrase.as_bytes())?;
            tmp_keyfile.flush()?;
            let tmp_keyfile = tmp_keyfile.path();
            let dummy_passphrase_input = Some(dummy_passphrase.as_bytes());

            let root_devpath = root_device.path();

            Task::new("Initializing LUKS for root", "cryptsetup")
                .args(["luksFormat", "--uuid", uuid.as_str(), "--key-file"])
                .args([tmp_keyfile])
                .arg(&root_devpath)
                .run()?;
            // The --wipe-slot=all removes our temporary passphrase, and binds to the local TPM device.
            // We also use .verbose() here as the details are important/notable.
            Task::new("Enrolling root device with TPM", "systemd-cryptenroll")
                .args(["--wipe-slot=all", "--tpm2-device=auto", "--unlock-key-file"])
                .args([tmp_keyfile])
                .arg(&root_devpath)
                .verbose()
                .run_with_stdin_buf(dummy_passphrase_input)?;
            Task::new("Opening root LUKS device", "cryptsetup")
                .args(["luksOpen", &root_devpath, luks_name])
                .run()?;
            let rootdev = format!("/dev/mapper/{luks_name}");
            let kargs = vec![
                format!("luks.uuid={uuid}"),
                format!("luks.options=tpm2-device=auto,headless=true"),
            ];
            (rootdev, Some(kargs))
        }
    };

    // Initialize the /boot filesystem
    let bootdev = if let Some(bootpn) = layout.boot_partno {
        Some(device.find_device_by_partno(bootpn)?)
    } else {
        None
    };

    let boot_uuid = match bootdev {
        Some(bootdev) => {
            let u = if layout.used_repart {
                let u = bootdev
                    .uuid
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("bootdev UUID not found"))?;

                u.parse::<uuid::Uuid>()
                    .with_context(|| format!("Parsing bootdev UUID {u}"))?
            } else {
                mkfs(
                    &bootdev.path(),
                    root_filesystem.as_str().try_into()?,
                    "boot",
                    opts.wipe,
                    [],
                )
                .context("Initializing /boot")?
            };

            Some(u)
        }
        None => None,
    };

    let root_uuid = if layout.used_repart {
        // systemd-repart creates filesystem, just read the UUID it assigned
        let u = root_device.uuid.as_ref().ok_or_else(|| {
            anyhow::anyhow!("Root device created by repart has no filesystem UUID")
        })?;

        // systemd < v254 (e.g. c9s) doesn't honor SYSTEMD_REPART_MKFS_OPTIONS_EXT4
        // so enable verity ourselves
        if systemd_version()? < REPART_MKFS_OPTIONS_MIN_VERSION && root_filesystem == "ext4" {
            tracing::debug!("Manually enabling fs-verity on root partition");

            Command::new("tune2fs")
                .args(["-O", "verity", root_device.path().as_str()])
                .run_inherited()
                .context("Running tune2fs enabling fs-verity")?;
        }

        u.parse::<uuid::Uuid>()
            .with_context(|| format!("Parsing root fs UUID {u}"))?
    } else {
        let rootfs: Filesystem = root_filesystem.as_str().try_into()?;

        // Unconditionally enable fsverity for ext4
        let mkfs_options = match rootfs {
            Filesystem::Ext4 => ["-O", "verity"].as_slice(),
            _ => [].as_slice(),
        };

        mkfs(
            &rootdev_path,
            rootfs,
            "root",
            opts.wipe,
            mkfs_options.iter().copied(),
        )?
    };
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

    // When discoverable-partitions is enabled, omit root= so that
    // systemd-gpt-auto-generator discovers root by its DPS type GUID.
    if discoverable {
        kargs.extend(&Cmdline::from(RW_KARG));
    } else {
        let rootarg = format!("root=UUID={root_uuid}");
        kargs.extend(&Cmdline::from(format!("{rootarg} {RW_KARG}")));
    }

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

    let fstype = &root_filesystem.to_string();
    bootc_mount::mount_typed(&rootdev_path, fstype, &physical_root_path)?;
    let target_rootfs = Dir::open_ambient_dir(&physical_root_path, cap_std::ambient_authority())?;
    crate::lsm::ensure_dir_labeled(&target_rootfs, "", Some("/".into()), 0o755.into(), sepolicy)?;
    let physical_root = Dir::open_ambient_dir(&physical_root_path, cap_std::ambient_authority())?;
    let bootfs = physical_root_path.join("boot");
    // Create the underlying mount point directory, which should be labeled
    crate::lsm::ensure_dir_labeled(&target_rootfs, "boot", None, 0o755.into(), sepolicy)?;
    if let Some(bootdev) = bootdev {
        bootc_mount::mount_typed(&bootdev.path(), fstype, &bootfs)?;
    }
    // And we want to label the root mount of /boot
    crate::lsm::ensure_dir_labeled(&target_rootfs, "boot", None, 0o755.into(), sepolicy)?;

    // Create the EFI system partition, if applicable
    if let Some(esp_partno) = layout.esp_partno {
        let espdev = device.find_device_by_partno(esp_partno)?;
        if !layout.used_repart {
            Task::new("Creating ESP filesystem", "mkfs.fat")
                .args([&espdev.path(), "-n", "EFI-SYSTEM"])
                .verbose()
                .quiet_output()
                .run()?;
        }
        let efifs_path = bootfs.join(crate::bootloader::EFI_DIR);
        std::fs::create_dir(&efifs_path).context("Creating efi dir")?;
    }

    let luks_device = match block_setup {
        BlockSetup::Direct => None,
        BlockSetup::Tpm2Luks => Some(luks_name.to_string()),
    };
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
