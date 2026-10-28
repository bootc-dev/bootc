//! # The baseline installer
//!
//! This module handles creation of simple root filesystem setups.  At the current time
//! it's very simple - just a direct filesystem (e.g. xfs, ext4, btrfs etc.).  It is
//! intended to add opinionated handling of TPM2-bound LUKS too.  But that's about it;
//! other more complex flows should set things up externally and use `bootc install to-filesystem`.

use std::borrow::Cow;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fmt::Display;
use std::fmt::Write as _;
use std::io::Write;
use std::num::NonZeroU64;
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

use super::AbootDiskLayout;
use super::BOOT;
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
// NOTE: If you change this or [`CFS_EFIPN_SIZE_MB`] below,
// make sure to update the test test-install-reaprt.nu
pub(crate) const EFIPN_SIZE_MB: u32 = 512;
/// EFI Partition size for composefs installations
/// We need more space than ostree as we have UKIs and UKI addons
/// We might also need to store UKIs for pinned deployments
pub(crate) const CFS_EFIPN_SIZE_MB: u32 = 2048;
const ABOOT_BOOT_SIZE_MB: u32 = 192;
const ABOOT_VBMETA_SIZE_MB: u32 = 64;
const UKIBOOT_ESP_SIZE_MB: u32 = 100;
const UKIBOOT_CTL_SIZE_MB: u32 = 1;
pub(crate) const ABOOT_BOOT_GUID: &str = "20117f86-e985-4357-b9ee-374bc1d8487d";
pub(crate) const ABOOT_VBMETA_GUID: &str = "4b7a15d6-322c-42ac-8110-88b7da0c5d77";
pub(crate) const UKIBOOT_BOOT_GUID: &str = "df331e4d-be00-463f-b4a7-8b43e18fb53a";
const UKIBOOT_CTL_GUID: &str = "fefd9070-346f-4c9a-85e6-17f07f922773";
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
    /// By default, the root partition takes the remaining space, leaving room
    /// for any other partitions the image's repart.d definitions describe.
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
    #[serde(default)]
    label: Option<String>,
    /// 0-indexed partition number
    /// absent in older systemd-repart
    /// versions, in c9s
    #[serde(default)]
    partno: Option<u32>,
    #[serde(default)]
    raw_size: u64,
    #[allow(dead_code)]
    fs: Option<String>,
    /// The file used to generate this partition
    file: String,
}

fn has_systemd_repart() -> bool {
    if Command::new("systemd-repart")
        .arg("--help")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        return false;
    }

    true
}

fn can_use_systemd_repart() -> bool {
    if !has_systemd_repart() {
        return false;
    }

    let has_config = REPART_CONFIG_DIRS.iter().map(Path::new).any(|d| {
        d.is_dir()
            && d.read_dir()
                .ok()
                .is_some_and(|mut entries| entries.next().is_some())
    });

    has_config
}

/// The first systemd version that supports `systemd-repart --include-partitions=`.
const REPART_INCLUDE_PARTITIONS_MIN_VERSION: u32 = 253;

/// The first systemd version whose systemd-repart honors the
/// `SYSTEMD_REPART_MKFS_OPTIONS_<FSTYPE>` environment variable (used to enable
/// ext4 fs-verity). Older versions silently ignore it.
const REPART_MKFS_OPTIONS_MIN_VERSION: u32 = 254;

/// The repart.d directory for definitions generated at runtime. bootc does
/// not write there: in `to-disk` it may be the host's.
const REPART_RUNTIME_DIR: &str = "/run/repart.d";

/// The repart.d configuration search directories, in descending priority. A
/// definition present in a higher-priority directory masks a same-named one
/// below it (matching systemd's own semantics).
const REPART_CONFIG_DIRS: &[&str] = &[
    "/etc/repart.d",
    REPART_RUNTIME_DIR,
    "/usr/local/lib/repart.d",
    "/usr/lib/repart.d",
];

/// The name of the root partition definition we generate when the image's
/// repart.d definitions have none.
const REPART_GENERATED_ROOT_NAME: &str = "50-root.conf";

/// The name of the drop-in that pins a definition's partition to its planned
/// size. Drop-ins apply in name order, so the name sorts after those images
/// usually ship, such as `override.conf` or `10-size.conf`.
const REPART_PLANNED_SIZE_DROPIN: &str = "zz-bootc-planned-size.conf";

/// Bytes per MiB, the unit we pin the generated root partition's size in.
const MIB: u64 = 1024 * 1024;

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

/// Collect the selected repart.d definitions into dest_dir, a fresh directory.
///
/// systemd < 253 does not support the `--include-partitions=` option, so instead
/// we point systemd-repart at a directory containing only the definitions we want
/// it to act on
fn collect_repart_definitions(
    dry_partitions: &[RepartPartition],
    dest_dir: &Path,
    filter: impl Fn(&RepartPartition) -> bool,
) -> Result<()> {
    std::fs::create_dir_all(dest_dir)
        .with_context(|| format!("Creating {}", dest_dir.display()))?;

    for part in dry_partitions {
        if !filter(part) {
            continue;
        }

        // Older version of systemd-repart does not provide the full path to the file
        // so we need to search one by one
        let src = REPART_CONFIG_DIRS
            .iter()
            .map(|d| Path::new(d).join(&part.file))
            .find(|p| p.exists())
            .ok_or_else(|| anyhow::anyhow!("Could not find repart.d definition {}", part.file))?;
        let name = src
            .file_name()
            .context("Missing repart.d definition filename")?;

        std::fs::copy(&src, dest_dir.join(name))
            .with_context(|| format!("Copying repart.d definition {}", src.display()))?;
    }

    Ok(())
}

/// The size in MiB to pin the root partition we generate to, given a dry run of
/// all definitions in which it has no size limits. systemd-repart gives it the
/// space the other definitions leave, padding included, and shares that by
/// Weight= with any of them that can grow, so the partitions created only on
/// first boot still fit after it. Rounded down to whole MiB.
fn planned_root_size_mib(planned: &[RepartPartition]) -> Result<NonZeroU64> {
    let root = planned
        .iter()
        .find(|p| p.partition_type.starts_with("root-"))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "systemd-repart planned no root partition for {REPART_GENERATED_ROOT_NAME}"
            )
        })?;
    NonZeroU64::new(root.raw_size / MIB).ok_or_else(|| {
        anyhow::anyhow!("systemd-repart planned less than 1 MiB for the root partition")
    })
}

/// The partitions other than root that a generic image's install creates (the
/// ESP and BIOS boot), as the file name of their definition and the size in
/// bytes systemd-repart planned for them with all definitions.
///
/// That install leaves the other partitions to first boot, so a definition
/// among these that can grow would take the space planned for them, unless it
/// is pinned to its planned size.
fn planned_boot_partition_sizes(planned: &[RepartPartition]) -> Result<Vec<(String, u64)>> {
    planned
        .iter()
        .filter(|p| repart_partition_is_required(p) && !p.partition_type.starts_with("root"))
        .map(|p| {
            let name = Utf8Path::new(&p.file)
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("Invalid repart.d definition path {}", p.file))?;
            Ok((name.to_owned(), p.raw_size))
        })
        .collect()
}

/// The repart.d drop-in that pins a partition to `size` bytes.
fn planned_size_pin(size: u64) -> String {
    format!("[Partition]\nSizeMinBytes={size}\nSizeMaxBytes={size}\n")
}

/// Fail when one of `config_dirs` has a file with the name of the root
/// definition we generate: a definition of the image, which one of the two
/// would mask, or a mask, which hides the generated one too. Masks never show
/// up in a dry run, so look at the directories themselves.
fn ensure_generated_root_name_unused(config_dirs: &[impl AsRef<Path>]) -> Result<()> {
    for dir in config_dirs {
        let path = dir.as_ref().join(REPART_GENERATED_ROOT_NAME);
        if let Err(e) = path.symlink_metadata() {
            if e.kind() == std::io::ErrorKind::NotFound {
                continue;
            }
            return Err(e).with_context(|| format!("Checking {}", path.display()));
        }
        anyhow::bail!(
            "{} has the name of the root partition definition bootc generates, rename or remove it",
            path.display()
        );
    }
    Ok(())
}

/// Write the repart.d definition or drop-in `name` into `dir`, creating parent
/// directories as needed.
fn write_repart_file(dir: &Path, name: &str, conf: &str) -> Result<()> {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Creating {}", parent.display()))?;
    }
    std::fs::write(&path, conf).with_context(|| format!("Writing {}", path.display()))
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
    let dry_partitions = systemd_repart_run(device, false, true, RepartDefinitions::Image)?;

    if dry_partitions.is_empty() {
        anyhow::bail!("systemd-repart returned empty partitions");
    }

    let has_root = dry_partitions
        .iter()
        .any(|p| p.partition_type.starts_with("root-"));

    if has_root {
        // Root partition is defined in repart.d config, run for real
        let filtered;
        let definitions = if need_filtered_definitions(generic_image)? {
            filtered =
                tempfile::tempdir().context("Creating a directory for repart.d definitions")?;
            collect_repart_definitions(
                &dry_partitions,
                filtered.path(),
                repart_partition_is_required,
            )?;
            RepartDefinitions::Only(filtered.path())
        } else {
            RepartDefinitions::Image
        };
        let partitions = systemd_repart_run(device, generic_image, false, definitions)?;
        let layout = parse_repart_layout(&partitions)?;
        return Ok(layout);
    }

    // Root partition is not defined, create definition for the root part
    ensure_generated_root_name_unused(REPART_CONFIG_DIRS)?;
    let Some(fs) = rootfs else {
        anyhow::bail!("Rootfs not specified");
    };
    let mut root_conf = format!("[Partition]\nType=root\nFormat={fs}\n");
    if let Some(size_mib) = root_size {
        writeln!(root_conf, "SizeMinBytes={size_mib}M")?;
        writeln!(root_conf, "SizeMaxBytes={size_mib}M")?;
    }
    // Not in /run/repart.d, which may be the host's
    let generated = tempfile::tempdir().context("Creating a directory for repart.d definitions")?;

    // A generic image's install creates only root, the ESP and BIOS boot, and
    // leaves the other partitions to first boot. Plan the layout with all
    // definitions and pin those three to it, so that none of them takes the
    // space planned for the others. With --root-size there is no such plan:
    // the other partitions may only fit once the disk has been grown. Without
    // a generic image, the real run creates all the partitions, and sizes an
    // unsized root by itself.
    let boot_partition_sizes = if generic_image && root_size.is_none() {
        write_repart_file(generated.path(), REPART_GENERATED_ROOT_NAME, &root_conf)?;
        let planned = systemd_repart_run(
            device,
            false,
            true,
            RepartDefinitions::WithGenerated(generated.path()),
        )
        .context("Planning the root partition size")?;
        let size_mib = planned_root_size_mib(&planned)?.get();
        tracing::debug!(
            "Root partition size: {size_mib} MiB of {} MiB",
            device.size / MIB
        );
        writeln!(root_conf, "SizeMinBytes={size_mib}M")?;
        writeln!(root_conf, "SizeMaxBytes={size_mib}M")?;
        planned_boot_partition_sizes(&planned)?
    } else {
        Vec::new()
    };

    let definitions = if need_filtered_definitions(generic_image)? {
        // The run then reads only this directory, so it needs the copies too
        collect_repart_definitions(
            &dry_partitions,
            generated.path(),
            repart_partition_is_required,
        )?;
        RepartDefinitions::Only(generated.path())
    } else {
        RepartDefinitions::WithGenerated(generated.path())
    };
    write_repart_file(generated.path(), REPART_GENERATED_ROOT_NAME, &root_conf)?;
    for (name, size) in &boot_partition_sizes {
        let dropin = format!("{name}.d/{REPART_PLANNED_SIZE_DROPIN}");
        write_repart_file(generated.path(), &dropin, &planned_size_pin(*size))?;
    }

    let partitions = systemd_repart_run(device, generic_image, false, definitions)?;
    let layout = parse_repart_layout(&partitions)?;

    Ok(layout)
}

/// Which repart.d definitions a systemd-repart run reads.
#[derive(Debug, Clone, Copy)]
enum RepartDefinitions<'a> {
    /// The image's, from the standard search paths.
    Image,
    /// The image's plus those generated in this directory, which take the
    /// priority of [`REPART_RUNTIME_DIR`].
    WithGenerated(&'a Path),
    /// Only those in this directory, such as the copies a generic image needs
    /// on systemd < 253 (see [`need_filtered_definitions`]).
    Only(&'a Path),
}

impl RepartDefinitions<'_> {
    /// The systemd-repart arguments that select these definitions, and for a
    /// generic image the partitions to create.
    fn args(self, generic_image: bool) -> Vec<OsString> {
        let definitions = |dir: &OsStr| {
            let mut arg = OsString::from("--definitions=");
            arg.push(dir);
            arg
        };
        let mut args = Vec::new();
        match self {
            // With a generic image, callers pass copies of just the definitions
            // to act on this way where systemd lacks --include-partitions=.
            Self::Only(dir) => args.push(definitions(dir.as_os_str())),
            Self::Image | Self::WithGenerated(_) => {
                if let Self::WithGenerated(generated) = self {
                    for dir in REPART_CONFIG_DIRS {
                        if *dir == REPART_RUNTIME_DIR {
                            args.push(definitions(generated.as_os_str()));
                        }
                        args.push(definitions(OsStr::new(dir)));
                    }
                }
                // If generic image, only run repart definitions that we absolutely
                // require, (BIOS/ESP and root). Others can run at first boot since we
                // don't know if the user would want to run those on this disk itself
                // or if this disk would be used to create an AMI/VHD and a separate disk
                // would be used for the other partitions
                if generic_image {
                    args.push(format!("--include-partitions=root,esp,{BIOS_BOOT}").into());
                }
            }
        }
        args
    }
}

/// Run systemd-repart on the device and return the parsed JSON output.
/// `dry_run`: if true, no changes are written to disk.
/// `definitions`: which repart.d definitions to read.
fn systemd_repart_run(
    device: &Device,
    generic_image: bool,
    dry_run: bool,
    definitions: RepartDefinitions,
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

    cmd.args(definitions.args(generic_image));
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

fn aboot_partition_labels(layout: AbootDiskLayout) -> &'static [&'static str] {
    match layout {
        AbootDiskLayout::Android => &["boot_a", "boot_b", "vbmeta_a", "vbmeta_b"],
        AbootDiskLayout::Ukiboot => &["ukiboot_a", "ukiboot_b", "ukibootctl"],
    }
}

fn aboot_partition_type(label: &str) -> &'static str {
    match label {
        "boot_a" | "boot_b" => ABOOT_BOOT_GUID,
        "vbmeta_a" | "vbmeta_b" => ABOOT_VBMETA_GUID,
        "ukiboot_a" | "ukiboot_b" => UKIBOOT_BOOT_GUID,
        "ukibootctl" => UKIBOOT_CTL_GUID,
        _ => unreachable!("unknown aboot partition label"),
    }
}

fn validate_aboot_repart_partitions(
    partitions: &[RepartPartition],
    layout: AbootDiskLayout,
) -> Result<()> {
    let other_layout = match layout {
        AbootDiskLayout::Android => AbootDiskLayout::Ukiboot,
        AbootDiskLayout::Ukiboot => AbootDiskLayout::Android,
    };
    let labels = aboot_partition_labels(layout);
    let other_labels = aboot_partition_labels(other_layout);
    anyhow::ensure!(
        !partitions
            .iter()
            .any(|p| other_labels.contains(&p.label.as_deref().unwrap_or(""))),
        "repart.d contains partitions for a different aboot layout"
    );
    for label in labels {
        let count = partitions
            .iter()
            .filter(|p| p.label.as_deref() == Some(*label))
            .count();
        anyhow::ensure!(
            count <= 1,
            "Duplicate {label} partition in aboot repart.d layout"
        );
        if let Some(partition) = partitions
            .iter()
            .find(|p| p.label.as_deref() == Some(*label))
        {
            anyhow::ensure!(
                partition
                    .partition_type
                    .eq_ignore_ascii_case(aboot_partition_type(label)),
                "aboot partition {label} has the wrong type GUID"
            );
        }
    }
    Ok(())
}

fn validate_repart_boot_layout(
    partitions: &[RepartPartition],
    layout: Option<AbootDiskLayout>,
) -> Result<()> {
    if let Some(layout) = layout {
        return validate_aboot_repart_partitions(partitions, layout);
    }
    anyhow::ensure!(
        !partitions
            .iter()
            .any(|p| [AbootDiskLayout::Android, AbootDiskLayout::Ukiboot]
                .iter()
                .any(|layout| aboot_partition_labels(*layout)
                    .contains(&p.label.as_deref().unwrap_or("")))),
        "aboot repart.d layout requires a matching aboot boot artifact"
    );
    Ok(())
}

fn image_repart_partitions(
    device: &Device,
    layout: Option<AbootDiskLayout>,
) -> Result<Vec<RepartPartition>> {
    if !can_use_systemd_repart() {
        return Ok(Vec::new());
    }
    let partitions = systemd_repart_run(device, false, true, RepartDefinitions::Image)?;
    validate_repart_boot_layout(&partitions, layout)?;
    Ok(partitions)
}

fn verify_image_aboot_filesystems(
    device: &Device,
    aboot_layout: AbootDiskLayout,
    partition_layout: &PartitionLayout,
) -> Result<()> {
    let labels = aboot_partition_labels(aboot_layout);
    for label in labels {
        let partition = device
            .children
            .iter()
            .flatten()
            .find(|part| part.partlabel.as_deref() == Some(label))
            .ok_or_else(|| anyhow::anyhow!("Missing {label} partition"))?;
        anyhow::ensure!(
            partition
                .parttype
                .as_deref()
                .is_some_and(|guid| guid.eq_ignore_ascii_case(aboot_partition_type(label))),
            "aboot partition {label} has the wrong type GUID"
        );
        anyhow::ensure!(
            partition.fstype.is_none(),
            "aboot partition {label} must not contain a filesystem"
        );
    }
    if aboot_layout == AbootDiskLayout::Ukiboot {
        let esp = device
            .find_device_by_partno(partition_layout.esp_partno.context("Missing ukiboot ESP")?)?;
        anyhow::ensure!(
            esp.fstype.as_deref() == Some("vfat"),
            "ukiboot ESP must be formatted as vfat"
        );
    }
    Ok(())
}

fn aboot_repart_definitions(
    layout: AbootDiskLayout,
    root_size: Option<u64>,
    rootfs: Option<Filesystem>,
    partitions: &[RepartPartition],
) -> Result<Vec<(String, String)>> {
    let mut definitions = Vec::new();
    if layout == AbootDiskLayout::Ukiboot && !partitions.iter().any(|p| p.partition_type == "esp") {
        let esp = format!(
            "[Partition]\nType=esp\nFormat=vfat\nSizeMinBytes={UKIBOOT_ESP_SIZE_MB}M\nSizeMaxBytes={UKIBOOT_ESP_SIZE_MB}M\n"
        );
        definitions.push(("05-efi.conf".into(), esp));
    }
    let mut add = |order: u32, name: &str, part_type: &str, size: u32, flags: Option<&str>| {
        if partitions.iter().any(|p| p.label.as_deref() == Some(name)) {
            return;
        }
        let mut config = format!(
            "[Partition]\nType={part_type}\nLabel={name}\nSizeMinBytes={size}M\nSizeMaxBytes={size}M\n"
        );
        if let Some(flags) = flags {
            config.push_str(&format!("Flags={flags}\n"));
        }
        definitions.push((format!("{order:02}-{name}.conf"), config));
    };

    match layout {
        AbootDiskLayout::Android => {
            add(
                10,
                "boot_a",
                ABOOT_BOOT_GUID,
                ABOOT_BOOT_SIZE_MB,
                Some("0x3f000000000000"),
            );
            add(
                11,
                "boot_b",
                ABOOT_BOOT_GUID,
                ABOOT_BOOT_SIZE_MB,
                Some("0x3d000000000000"),
            );
            for (order, name) in [(12, "vbmeta_a"), (13, "vbmeta_b")] {
                add(order, name, ABOOT_VBMETA_GUID, ABOOT_VBMETA_SIZE_MB, None);
            }
        }
        AbootDiskLayout::Ukiboot => {
            for (order, name) in [(10, "ukiboot_a"), (11, "ukiboot_b")] {
                add(order, name, UKIBOOT_BOOT_GUID, ABOOT_BOOT_SIZE_MB, None);
            }
            add(
                12,
                "ukibootctl",
                UKIBOOT_CTL_GUID,
                UKIBOOT_CTL_SIZE_MB,
                None,
            );
        }
    }

    if partitions
        .iter()
        .any(|p| p.partition_type.starts_with("root-"))
    {
        return Ok(definitions);
    }
    let rootfs = rootfs.context(
        "No root repart.d definition found; specify --filesystem or a root filesystem in the install config",
    )?;
    let mut root = format!("[Partition]\nType=root\nFormat={rootfs}\n");
    if let Some(size) = root_size {
        root.push_str(&format!("SizeMinBytes={size}M\nSizeMaxBytes={size}M\n"));
    }
    definitions.push((REPART_GENERATED_ROOT_NAME.into(), root));
    Ok(definitions)
}

#[context("Running systemd-repart for aboot")]
fn systemd_repart_aboot(
    device: &Device,
    layout: AbootDiskLayout,
    image_partitions: &[RepartPartition],
    generated_definitions: &[(String, String)],
    generic_image: bool,
) -> Result<PartitionLayout> {
    let definitions = tempfile::tempdir().context("Creating aboot repart definitions directory")?;
    collect_repart_definitions(image_partitions, definitions.path(), |part| {
        !generic_image
            || repart_partition_is_required(part)
            || aboot_partition_labels(layout).contains(&part.label.as_deref().unwrap_or(""))
    })?;
    for (name, config) in generated_definitions {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(definitions.path().join(name))
            .with_context(|| format!("Creating generated repart definition {name}"))?
            .write_all(config.as_bytes())?;
    }
    let partitions = systemd_repart_run(
        device,
        false,
        false,
        RepartDefinitions::Only(definitions.path()),
    )?;
    parse_repart_layout(&partitions)
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
    run_repart: bool,
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

    if state.aboot_disk_layout.is_some() {
        anyhow::ensure!(
            has_systemd_repart(),
            "aboot to-disk install requires systemd-repart"
        );
    }
    let image_partitions = if state.aboot_disk_layout.is_some() || run_repart {
        image_repart_partitions(&device, state.aboot_disk_layout)?
    } else {
        Vec::new()
    };
    let use_systemd_repart =
        state.aboot_disk_layout.is_some() || (run_repart && can_use_systemd_repart());

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
    let discoverable = state.aboot_disk_layout.is_none() && use_discoverable_partitions(state);
    if let Some(layout) = state.aboot_disk_layout {
        anyhow::ensure!(
            block_setup == BlockSetup::Direct,
            "{layout:?} aboot layout requires --block-setup direct"
        );
        anyhow::ensure!(
            layout != AbootDiskLayout::Ukiboot || super::ARCH_USES_EFI,
            "ukiboot disk layout requires x86_64 or aarch64"
        );
        anyhow::ensure!(
            state.composefs_options.composefs_backend,
            "aboot disk layouts require the composefs backend"
        );
    }
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
    let aboot_definitions = state
        .aboot_disk_layout
        .map(|layout| {
            aboot_repart_definitions(
                layout,
                root_size,
                opts.filesystem.or(install_config
                    .and_then(|c| c.filesystem_root())
                    .and_then(|r| r.fstype)),
                &image_partitions,
            )
        })
        .transpose()?;

    // Load the policy from the container root, which also must be our install root
    let sepolicy = state.load_policy()?;
    let sepolicy = sepolicy.as_ref();

    // Create a temporary directory to use for mount points.  Note that we're
    // in a mount namespace, so these should not be visible on the host.
    let physical_root_path = mntdir.join("rootfs");
    std::fs::create_dir_all(&physical_root_path)?;
    let bootfs = mntdir.join("boot");
    std::fs::create_dir_all(bootfs)?;

    let layout = if let Some(aboot_disk_layout) = state.aboot_disk_layout {
        systemd_repart_aboot(
            &device,
            aboot_disk_layout,
            &image_partitions,
            aboot_definitions.as_deref().unwrap(),
            state.config_opts.generic_image,
        )?
    } else if use_systemd_repart {
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

    if let Some(aboot_layout) = state.aboot_disk_layout {
        verify_image_aboot_filesystems(&device, aboot_layout, &layout)?;
    }

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
        target: format!("/{BOOT}"),
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
    let bootfs = physical_root_path.join(BOOT);
    // Create the underlying mount point directory, which should be labeled
    crate::lsm::ensure_dir_labeled(&target_rootfs, BOOT, None, 0o755.into(), sepolicy)?;
    if let Some(bootdev) = bootdev {
        bootc_mount::mount_typed(&bootdev.path(), fstype, &bootfs)?;
    }
    // And we want to label the root mount of /boot
    crate::lsm::ensure_dir_labeled(&target_rootfs, BOOT, None, 0o755.into(), sepolicy)?;

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
        aboot_disk_layout: state.aboot_disk_layout,
        disk_install: true,
        boot,
        kargs,
        skip_finalize: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aboot_repart_specs() {
        let android =
            aboot_repart_definitions(AbootDiskLayout::Android, None, Some(Filesystem::Ext4), &[])
                .unwrap();
        assert_eq!(android.len(), 5);
        assert_eq!(android[0].0, "10-boot_a.conf");
        assert!(android[0].1.contains("Flags=0x3f000000000000\n"));
        assert!(android[1].1.contains("Flags=0x3d000000000000\n"));
        assert!(android[4].1.contains("Type=root\nFormat=ext4\n"));

        let ukiboot = aboot_repart_definitions(
            AbootDiskLayout::Ukiboot,
            Some(4096),
            Some(Filesystem::Ext4),
            &[],
        )
        .unwrap();
        assert_eq!(ukiboot.len(), 5);
        assert_eq!(ukiboot[0].0, "05-efi.conf");
        assert!(ukiboot[0].1.contains("Type=esp\nFormat=vfat\n"));
        assert!(
            ukiboot[4]
                .1
                .contains("SizeMinBytes=4096M\nSizeMaxBytes=4096M\n")
        );
    }

    #[test]
    fn image_aboot_repart_layout() -> Result<()> {
        let mut partitions: Vec<RepartPartition> = serde_json::from_value(serde_json::json!([
            { "type": "20117f86-e985-4357-b9ee-374bc1d8487d", "label": "boot_a", "file": "10-boot-a.conf" },
            { "type": "20117f86-e985-4357-b9ee-374bc1d8487d", "label": "boot_b", "file": "11-boot-b.conf" },
            { "type": "4b7a15d6-322c-42ac-8110-88b7da0c5d77", "label": "vbmeta_a", "file": "12-vbmeta-a.conf" },
            { "type": "4b7a15d6-322c-42ac-8110-88b7da0c5d77", "label": "vbmeta_b", "file": "13-vbmeta-b.conf" },
            { "type": "root-arm64", "label": "root", "file": "50-root.conf" }
        ]))?;
        validate_aboot_repart_partitions(&partitions, AbootDiskLayout::Android)?;
        assert!(validate_repart_boot_layout(&partitions, None).is_err());
        assert!(validate_repart_boot_layout(&partitions, Some(AbootDiskLayout::Ukiboot)).is_err());
        validate_repart_boot_layout(&[], None)?;
        let correct_type =
            std::mem::replace(&mut partitions[0].partition_type, "linux-generic".into());
        assert!(validate_aboot_repart_partitions(&partitions, AbootDiskLayout::Android).is_err());
        partitions[0].partition_type = correct_type;

        let unrelated: RepartPartition = serde_json::from_value(serde_json::json!({
            "type": ABOOT_BOOT_GUID,
            "label": "cache",
            "file": "20-cache.conf"
        }))?;
        assert!(!repart_partition_is_required(&partitions[0]));
        assert!(!repart_partition_is_required(&unrelated));
        validate_aboot_repart_partitions(&[], AbootDiskLayout::Android)?;
        validate_aboot_repart_partitions(&partitions[..3], AbootDiskLayout::Android)?;
        let missing =
            aboot_repart_definitions(AbootDiskLayout::Android, None, None, &partitions[1..])?;
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].0, "10-boot_a.conf");
        Ok(())
    }

    #[test]
    fn aboot_preserves_image_repart_definitions() -> Result<()> {
        for (layout, generic_image) in [
            (AbootDiskLayout::Android, false),
            (AbootDiskLayout::Android, true),
            (AbootDiskLayout::Ukiboot, false),
            (AbootDiskLayout::Ukiboot, true),
        ] {
            let source = tempfile::tempdir()?;
            let destination = tempfile::tempdir()?;
            let root_config = "[Partition]\nType=root\nFormat=ext4\nLabel=custom-root\nSizeMinBytes=2G\nSizeMaxBytes=4G\n";
            let root_file = source.path().join("20-root.conf");
            std::fs::write(&root_file, root_config)?;
            let var_file = source.path().join("30-var.conf");
            std::fs::write(&var_file, "[Partition]\nType=var\nFormat=ext4\n")?;
            let mut partitions: Vec<RepartPartition> = serde_json::from_value(serde_json::json!([
                { "type": "root-x86-64", "label": "custom-root", "file": root_file },
                { "type": "var", "file": var_file }
            ]))?;
            let esp_config =
                "[Partition]\nType=esp\nFormat=vfat\nLabel=custom-esp\nSizeMinBytes=512M\n";
            if layout == AbootDiskLayout::Ukiboot {
                let esp_file = source.path().join("05-esp.conf");
                std::fs::write(&esp_file, esp_config)?;
                partitions.push(serde_json::from_value(serde_json::json!({
                    "type": "esp", "file": esp_file
                }))?);
            }

            validate_aboot_repart_partitions(&partitions, layout)?;
            let generated = aboot_repart_definitions(layout, Some(8192), None, &partitions)?;
            assert_eq!(generated.len(), aboot_partition_labels(layout).len());
            assert!(
                generated
                    .iter()
                    .all(|(_, config)| !config.contains("Format="))
            );
            collect_repart_definitions(&partitions, destination.path(), |part| {
                !generic_image
                    || repart_partition_is_required(part)
                    || aboot_partition_labels(layout).contains(&part.label.as_deref().unwrap_or(""))
            })?;
            assert_eq!(
                std::fs::read_to_string(destination.path().join("20-root.conf"))?,
                root_config
            );
            assert_eq!(
                destination.path().join("30-var.conf").exists(),
                !generic_image
            );
            if layout == AbootDiskLayout::Ukiboot {
                assert_eq!(
                    std::fs::read_to_string(destination.path().join("05-esp.conf"))?,
                    esp_config
                );
            }
            assert!(aboot_repart_definitions(layout, None, None, &[]).is_err());
        }
        Ok(())
    }

    #[test]
    fn test_planned_root_size_mib() {
        // This module imports anyhow::Ok
        use std::result::Result::Ok;
        let cases = [
            // A dry run on a 10 GiB disk of the definitions of
            // tmt/tests/booted/test-install-repart.nu (ESP, home and swap,
            // 1 GiB each) plus the generated root without size limits, which
            // gets the rest minus the GPT and alignment overhead.
            (
                include_str!("../fixtures/repart-dry-run-v262.json"),
                Ok(7166),
            ),
            // A dry run without root, where systemd 262 reports the unused
            // space as padding of the last partition.
            (
                r#"[{"type": "swap", "file": "30-swap.conf", "raw_size": 1073741824, "raw_padding": 7515123712}]"#,
                Err("planned no root partition"),
            ),
            (
                r#"[{"type": "root-x86-64", "file": "50-root.conf", "raw_size": 1044480}]"#,
                Err("less than 1 MiB"),
            ),
            (
                r#"[{"type": "root-x86-64", "file": "50-root.conf"}]"#,
                Err("less than 1 MiB"),
            ),
        ];
        for (json, expected) in cases {
            let planned: Vec<RepartPartition> = serde_json::from_str(json).unwrap();
            match (planned_root_size_mib(&planned), expected) {
                (Ok(size_mib), Ok(expected)) => assert_eq!(size_mib.get(), expected),
                (Err(e), Err(expected)) => {
                    assert!(format!("{e:#}").contains(expected), "{e:#}")
                }
                (result, expected) => panic!("{json}: got {result:?}, expected {expected:?}"),
            }
        }
    }

    #[test]
    fn test_planned_boot_partition_sizes() {
        let cases = [
            // systemd 262 names the definitions with their full path; only the
            // ESP is created by a generic install.
            (
                include_str!("../fixtures/repart-dry-run-v262.json"),
                vec![("00-esp.conf", 1073741824)],
            ),
            // systemd 252 names them without a path, and BIOS boot by its GUID.
            (
                r#"[
                    {"type": "21686148-6449-6e6f-744e-656564454649", "file": "00-bios.conf", "raw_size": 1048576},
                    {"type": "esp", "file": "00-esp.conf", "raw_size": 536870912},
                    {"type": "xbootldr", "file": "10-xbootldr.conf", "raw_size": 1073741824},
                    {"type": "root-x86-64", "file": "50-root.conf", "raw_size": 7516192768}
                ]"#,
                vec![("00-bios.conf", 1048576), ("00-esp.conf", 536870912)],
            ),
            (r#"[]"#, vec![]),
        ];
        for (json, expected) in cases {
            let planned: Vec<RepartPartition> = serde_json::from_str(json).unwrap();
            let sizes = planned_boot_partition_sizes(&planned).unwrap();
            let sizes = sizes
                .iter()
                .map(|(name, size)| (name.as_str(), *size))
                .collect::<Vec<_>>();
            assert_eq!(sizes, expected, "{json}");
        }
    }

    #[test]
    fn test_ensure_generated_root_name_unused() -> Result<()> {
        let td = tempfile::tempdir()?;
        let etc = td.path().join("etc");
        let usr = td.path().join("usr");
        std::fs::create_dir(&etc)?;
        std::fs::create_dir(&usr)?;
        let dirs = [&etc, &usr, &td.path().join("missing")];
        std::fs::write(usr.join("00-esp.conf"), "[Partition]\nType=esp\n")?;
        ensure_generated_root_name_unused(&dirs)?;

        // An image definition for another partition with that name
        let clash = usr.join(REPART_GENERATED_ROOT_NAME);
        std::fs::write(&clash, "[Partition]\nType=var\n")?;
        assert!(ensure_generated_root_name_unused(&dirs).is_err());
        std::fs::remove_file(&clash)?;

        // A mask, as of a root definition of a base image, which would hide
        // the generated one as well
        let mask = etc.join(REPART_GENERATED_ROOT_NAME);
        std::os::unix::fs::symlink("/dev/null", &mask)?;
        let e = ensure_generated_root_name_unused(&dirs).unwrap_err();
        assert!(
            format!("{e:#}").contains(&mask.display().to_string()),
            "{e:#}"
        );
        Ok(())
    }

    #[test]
    fn test_repart_definitions_args() {
        use RepartDefinitions::{Image, Only, WithGenerated};
        let include = format!("--include-partitions=root,esp,{BIOS_BOOT}");
        let with_generated = [
            "--definitions=/etc/repart.d",
            "--definitions=/tmp/generated",
            "--definitions=/run/repart.d",
            "--definitions=/usr/local/lib/repart.d",
            "--definitions=/usr/lib/repart.d",
        ];
        let generated = WithGenerated(Path::new("/tmp/generated"));
        let copies = Only(Path::new("/tmp/copies"));
        let cases = [
            (Image, false, vec![]),
            (Image, true, vec![include.as_str()]),
            (generated, false, with_generated.to_vec()),
            (
                generated,
                true,
                [&with_generated[..], &[include.as_str()]].concat(),
            ),
            // Already just the definitions to act on
            (copies, false, vec!["--definitions=/tmp/copies"]),
            (copies, true, vec!["--definitions=/tmp/copies"]),
        ];
        for (definitions, generic_image, expected) in cases {
            let expected = expected.into_iter().map(OsString::from).collect::<Vec<_>>();
            assert_eq!(
                definitions.args(generic_image),
                expected,
                "{definitions:?}, generic image: {generic_image}"
            );
        }
    }
}
