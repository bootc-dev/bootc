use std::fs::create_dir_all;
use std::process::Command;
use std::sync::OnceLock;

use anyhow::{Context, Result, anyhow, bail};
use bootc_utils::{BindMode, ChrootCmd, CommandRunExt};
use camino::Utf8Path;
use cap_std_ext::cap_std::fs::Dir;
use cap_std_ext::dirext::CapStdExtDirExt;
use fn_error_context::context;

use bootc_mount as mount;

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
    let efi_path = Utf8Path::new(crate::install::BOOT).join(crate::bootloader::EFI_DIR);
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

/// The flags in a clap help line's leading option column: `--flag` for
/// `--flag <VAL>`, or `-f` and `--flag` for `-f, --flag <VAL>`. Description
/// lines have none.
fn help_line_flags(line: &str) -> impl Iterator<Item = &str> {
    line.split_whitespace()
        .take_while(|token| token.starts_with('-'))
        .map(|token| token.trim_end_matches(','))
}

/// Whether the help of `bootupctl backend install` advertises `flag`.
///
/// clap renders an option as `--flag <VAL>`, or `-f, --flag <VAL>` when it has a
/// short form, always ahead of the description. Match only in that leading
/// option column, and on a whole token: a flag named inside another option's
/// prose is not support for it, and `--boot` is not `--bootloader`.
fn help_advertises_flag(help: &str, flag: &str) -> bool {
    help.lines()
        .any(|line| help_line_flags(line).any(|f| f == flag))
}

/// The values clap lists for `flag` as `[possible values: a, b]`, anywhere in
/// that option's entry: on the option line itself in short help, or on a
/// description line below it in long help. clap wraps long lines, so the
/// entry is matched with its whitespace collapsed. `None` when `flag` is not
/// advertised or lists no values.
fn help_flag_values(help: &str, flag: &str) -> Option<Vec<String>> {
    let mut lines = help
        .lines()
        .skip_while(|line| !help_line_flags(line).any(|f| f == flag));
    let first = lines.next()?;
    let entry = std::iter::once(first)
        .chain(lines.take_while(|line| help_line_flags(line).next().is_none()))
        .flat_map(str::split_whitespace)
        .collect::<Vec<_>>()
        .join(" ");
    let (_, rest) = entry.split_once("[possible values: ")?;
    let (values, _) = rest.split_once(']')?;
    Some(values.split(',').map(|v| v.trim().to_owned()).collect())
}

/// The short help (`-h`) of `bootupctl backend install` from the target
/// bootupd. Unlike `--help`, which switches to a list once the values have
/// help text of their own, short help always lists an option's values inline
/// as `[possible values: ...]`.
///
/// When `chroot_target` is set the command runs inside a chroot (via
/// [`ChrootCmd`]) so we probe the binary from the target image rather than the
/// buildroot.
#[context("Querying bootupd install options")]
fn bootupd_install_help(chroot_target: Option<&Utf8Path>) -> Result<String> {
    let help_args = ["bootupctl", "backend", "install", "-h"];
    let output = if let Some(target_root) = chroot_target {
        ChrootCmd::new(target_root)
            .set_default_path()
            .run_get_string(help_args)?
    } else {
        Command::new("bootupctl")
            .args(&help_args[1..])
            .log_debug()
            .run_get_string()?
    };
    Ok(output)
}

/// What the target bootupd's `backend install` accepts, from its help.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BootupdInstallSupport {
    /// `--filesystem`, which lets bootupd find the backing devices itself.
    filesystem: bool,
    /// The bootloaders `--bootloader` accepts. Empty when bootupd has no such
    /// option (before 0.2.36) or lists no values for it. Packaged 0.2.36
    /// builds accept only GRUB, although they advertise the option.
    bootloaders: Vec<crate::spec::Bootloader>,
}

impl BootupdInstallSupport {
    /// Parse the help of `bootupctl backend install`. bootupd's `--bootloader`
    /// values are the names [`crate::spec::Bootloader`]'s `Display` produces.
    fn parse(help: &str) -> Self {
        use crate::spec::Bootloader;
        let values = help_flag_values(help, "--bootloader").unwrap_or_default();
        let bootloaders = [Bootloader::Grub, Bootloader::GrubCC, Bootloader::Systemd]
            .into_iter()
            .filter(|bootloader| values.contains(&bootloader.to_string()))
            .collect();
        Self {
            filesystem: help_advertises_flag(help, "--filesystem"),
            bootloaders,
        }
    }

    /// Probe the target bootupd, see [`bootupd_install_help`].
    fn probe(chroot_target: Option<&Utf8Path>) -> Result<Self> {
        Ok(Self::parse(&bootupd_install_help(chroot_target)?))
    }
}

/// The `--bootloader` value to pass to bootupd for `bootloader`, if any.
///
/// A bootupd that cannot be asked for GRUB, such as one from before 0.2.36,
/// which has no `--bootloader`, is left to install what it finds, as before.
/// Asking such a bootupd for anything else is an error rather than a silent
/// GRUB install.
///
/// Only a bootupd that also accepts grub-cc or systemd limits the install to
/// the bootloader it is asked for. Versions 0.2.30 to 0.2.35, which have no
/// `--bootloader`, and a packaged 0.2.36 build that accepts only grub copy
/// every component under usr/lib/efi, so another bootloader's component can
/// overwrite GRUB's second stage.
fn bootupd_bootloader_arg(
    support: &BootupdInstallSupport,
    bootloader: crate::spec::Bootloader,
) -> Result<Option<String>> {
    use crate::spec::Bootloader;
    if support.bootloaders.contains(&bootloader) {
        return Ok(Some(bootloader.to_string()));
    }
    match bootloader {
        Bootloader::Grub => Ok(None),
        Bootloader::None => bail!("BUG: bootupd invoked to install no bootloader"),
        _ if support.bootloaders.is_empty() => {
            bail!("bootupd in the image cannot be asked to install {bootloader}")
        }
        _ => {
            let accepted = support
                .bootloaders
                .iter()
                .map(|b| b.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            bail!("bootupd in the image cannot install {bootloader}, only {accepted}")
        }
    }
}

/// Which of bootupd's components to install, unless the image is generic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BootupdComponents {
    /// The ones for how the installing host booted, as bootupd's `--auto`
    /// picks them: EFI or BIOS.
    Auto,
    /// Only EFI, for a bootloader that only boots from there.
    Efi,
}

/// The bootupd arguments that select the components to install.
///
/// Generic images get every component, and bootupd skips those that cannot
/// install the bootloader. Otherwise bootc targets only what this machine
/// boots. A bootloader that only boots from EFI needs
/// [`BootupdComponents::Efi`]: on an x86_64 host booted in BIOS/CSM mode,
/// `--auto` picks BIOS, and bootupd then installs nothing on the ESP and still
/// succeeds.
fn bootupd_target_args(
    generic_image: bool,
    components: BootupdComponents,
) -> &'static [&'static str] {
    match components {
        _ if generic_image => &[],
        BootupdComponents::Auto => &["--update-firmware", "--auto"],
        BootupdComponents::Efi => &["--update-firmware", "--component", "EFI"],
    }
}

/// Install the bootloader via bootupd.
///
/// When the target bootupd supports `--filesystem` we pass it pointing at a
/// block-backed mount so that bootupd can resolve the backing device(s) itself
/// via `lsblk`.  When `chroot_target` is set, bootupctl is executed inside the
/// given chroot root via [`ChrootCmd`], with the physical root bind-mounted at
/// `/sysroot` so `lsblk` can resolve a real block-backed path.
///
/// For older bootupd versions that lack `--filesystem` we fall back to the
/// legacy `--device <device_path> <rootfs>` invocation.
///
/// If `bind_boot_path` is set, the given host path is bind-mounted onto
/// `/boot` inside the chroot.  Both the ostree and composefs backends use
/// this to expose the physical root's real `/boot` inside their respective
/// chroots, since neither chroot target (an ostree deployment, or a mounted
/// composefs image) has a `/boot` backed by the real root filesystem on its
/// own.  This matters because bootupd derives the UUID it writes for
/// `--write-uuid` from whatever filesystem is mounted at `<chroot>/boot`,
/// and looks for an empty `boot/efi` directory there to discover and mount
/// the real ESP into.
///
/// `bootloader` is passed on as `--bootloader` when the target bootupd accepts
/// it, see [`bootupd_bootloader_arg`] for what that guarantees. It takes
/// precedence over any `default_bootloader` recorded in the image's bootupd
/// metadata, deliberately: bootc's own choice already governs the boot layout
/// it writes (see [`crate::spec::BootloaderKind`]), so letting bootupd pick a
/// different one would leave the two disagreeing.
///
/// `components` selects what to install, see [`bootupd_target_args`].
#[context("Installing bootloader")]
pub(crate) fn install_via_bootupd(
    device: &bootc_blockdev::Device,
    rootfs: &Utf8Path,
    configopts: &crate::install::InstallConfigOpts,
    chroot_target: Option<&Utf8Path>,
    bind_boot_path: Option<&Utf8Path>,
    bootloader: crate::spec::Bootloader,
    components: BootupdComponents,
) -> Result<()> {
    let verbose = std::env::var_os("BOOTC_BOOTLOADER_DEBUG").map(|_| "-vvvv");

    // Probe the target bootupd's install options once, up front.
    let support = BootupdInstallSupport::probe(chroot_target)?;
    let bootloader_arg = bootupd_bootloader_arg(&support, bootloader)?;

    // When not running inside the target container (through `--src-imgref`) we
    // run bootupctl from the deployment via a chroot ([`ChrootCmd`]).
    // This makes sure we use binaries from the target image rather than the buildroot.
    // In that case, the target rootfs is replaced with `/` because this is just used by
    // bootupd to find the backing device.
    let rootfs_mount = if chroot_target.is_none() {
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

    bootupd_args.extend(bootupd_target_args(configopts.generic_image, components));
    if let Some(name) = &bootloader_arg {
        bootupd_args.extend(["--bootloader", name.as_str()]);
    } else {
        tracing::debug!("bootupd cannot be asked for {bootloader}, relying on its own choice");
    }

    // When the target bootupd lacks --filesystem support, fall back to the
    // legacy --device flag.  For --device we need the whole-disk device path
    // (e.g. /dev/vda), not a partition (e.g. /dev/vda3), so resolve the
    // parent via require_single_root().  (Older bootupd doesn't support
    // multiple backing devices anyway.)
    // Computed before building bootupd_args so the String lives long enough.
    let root_device_path = if support.filesystem {
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
        // Inside a chroot the physical root is bind-mounted at /sysroot (see
        // below) so bootupd's own device resolution (via lsblk) sees a real
        // block-backed path. This matters for composefs, where the chroot's
        // own "/" is a virtual composefs mount with no backing block device.
        let filesystem_path = if chroot_target.is_some() {
            "/sysroot"
        } else {
            rootfs_mount
        };
        bootupd_args.extend(["--filesystem", filesystem_path]);
        bootupd_args.push(rootfs_mount);
    }

    // Run inside a chroot ([`ChrootCmd`]). It sets up a fresh mount
    // namespace and the necessary API filesystems in the target
    // deployment, without requiring a user namespace (which fails under
    // qemu-user — see <https://github.com/bootc-dev/bootc/issues/2111>).
    if let Some(target_root) = chroot_target {
        let rootfs_path = rootfs.to_path_buf();

        tracing::debug!("Running bootupctl via chroot in {}", target_root);

        // Prepend "bootupctl" to the args (ChrootCmd's calling
        // convention puts the program in args[0]).
        let mut chroot_args = vec!["bootupctl"];
        chroot_args.extend(bootupd_args);

        let mut cmd = ChrootCmd::new(target_root);
        // Bind mount /boot from the physical target root so bootupctl can find
        // the boot partition and install the bootloader there. This is a
        // non-recursive bind: the physical root's /boot may itself have the
        // ESP mounted at boot/efi (see clean_boot_directories()), and we
        // don't want that mount to be dragged along, since bootupd's own EFI
        // component expects to find an empty boot/efi directory to mount the
        // real ESP onto itself (see MountedImageRoot::with_esp()). A stray
        // nested ESP mount there has also been observed to confuse grub-probe
        // into embedding the wrong root device in the BIOS boot prefix.
        if let Some(boot_path) = &bind_boot_path {
            cmd = cmd.bind(boot_path, &"/boot", BindMode::Default);
        }

        // Only bind mount the physical root at /sysroot when using --filesystem;
        // bootupd needs it to resolve backing block devices via lsblk.
        if root_device_path.is_none() {
            cmd = cmd.bind(&rootfs_path, &"/sysroot", BindMode::Recursive);
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
        let systemd_version = systemd_version()?;
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
        // If systemd thinks it's inside of a chroot, it will fall
        // back to "graceful" mode.  This means that bootctl will exit
        // 0 even if bootloader installation doesn't go as expected,
        // and we don't want that.  Explicitly disable chroot
        // detection.
        //
        // See: https://github.com/bootc-dev/bootc/issues/2486
        .env("SYSTEMD_IN_CHROOT", "0")
        .log_debug()
        // Capture stderr so bootctl error messages appear in our error chain.
        .run_capture_stderr()?;

    write_autoenroll_keys(prepared_root, autoenroll)
}

/// Stage Secure Boot keys on the ESP for systemd-boot's setup-mode enrollment.
///
/// This is systemd-boot specific: the keys go in `loader/keys`, which only
/// systemd-boot reads.
#[context("Writing Secure Boot enrollment keys")]
fn write_autoenroll_keys(
    prepared_root: &MountedImageRoot,
    autoenroll: Option<SecurebootKeys>,
) -> Result<()> {
    let Some(SecurebootKeys { dir, keys }) = autoenroll else {
        return Ok(());
    };

    let esp_dir = prepared_root.open_esp_dir()?;
    let keys_path = prepared_root
        .root_path()
        .join(prepared_root.esp_subdir)
        .join(SYSTEMD_KEY_DIR);
    create_dir_all(&keys_path)
        .with_context(|| format!("Creating secureboot key directory {}", keys_path.display()))?;

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

    Ok(())
}

/// Query the major version of systemd via `systemctl --version`, caching the
/// result so it can be shared across callers (bootctl, systemd-repart, etc.).
#[context("Querying systemd version")]
pub(crate) fn systemd_version() -> Result<u32> {
    static VERSION: OnceLock<u32> = OnceLock::new();

    if let Some(v) = VERSION.get() {
        return Ok(*v);
    };

    let out = Command::new("systemctl")
        .arg("--version")
        .run_get_string()?;
    let v = parse_systemd_version(&out).context("Failed to parse version to integer")?;

    let version = VERSION.get_or_init(|| v);

    Ok(*version)
}

/// Parse the systemd major version from `bootctl --version` output, whose first
/// line looks like `systemd 259 (259.5-0ubuntu3)`.
pub(crate) fn parse_systemd_version(output: &str) -> Result<u32> {
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
    fn test_help_advertises_flag() {
        // Excerpted from the help of `bootupctl backend install` of a recent
        // and an old release.
        const NEW: &str = "      --filesystem <FILESYSTEM>\n      --bootloader <BOOTLOADER>\n";
        const OLD: &str = "      --device <DEVICE>\n";
        let cases = [
            (NEW, "--filesystem", true),
            (NEW, "--bootloader", true),
            (OLD, "--filesystem", false),
            (OLD, "--bootloader", false),
            // An option rendered with a short form still counts.
            ("  -f, --filesystem <FS>\n", "--filesystem", true),
            // A flag must not match a longer one that starts with it.
            ("      --bootloader <B>\n", "--boot", false),
            // Nor a mention inside another option's description.
            (
                "      --device <D>  ignored when --filesystem is given\n",
                "--filesystem",
                false,
            ),
        ];
        for (help, flag, expected) in cases {
            assert_eq!(
                help_advertises_flag(help, flag),
                expected,
                "{flag} in {help:?}"
            );
        }
    }

    #[test]
    fn test_parse_install_help() {
        use crate::spec::Bootloader::{Grub, GrubCC, Systemd};
        // The help of real builds: `bootupctl backend install -h` of CentOS
        // Stream 10's 0.2.35 and of Fedora's 0.3.2, which wraps at 100
        // columns, and the long `--help` of Fedora's 0.2.36-3.fc46, with
        // trailing whitespace trimmed. That 0.2.36 build was made from a crate
        // without build.rs, so only GRUB is compiled in.
        let cases = [
            (
                include_str!("fixtures/bootupctl-install-help-0.2.35.txt"),
                true,
                vec![],
            ),
            (
                include_str!("fixtures/bootupctl-install-help-0.2.36.txt"),
                true,
                vec![Grub],
            ),
            (
                include_str!("fixtures/bootupctl-install-help-0.3.2.txt"),
                true,
                vec![Grub, GrubCC, Systemd],
            ),
            // Short help renders the values on the option line.
            (
                "      --bootloader <BOOTLOADER>  The bootloader to use [possible values: grub, systemd]\n",
                false,
                vec![Grub, Systemd],
            ),
            // Values that clap wrapped onto the following lines.
            (
                "      --bootloader <BOOTLOADER>  The bootloader to use [possible\n                                 values: grub, grub-cc,\n                                 systemd]\n",
                false,
                vec![Grub, GrubCC, Systemd],
            ),
            // An option without listed values, and values that belong to the
            // next option, accept nothing.
            (
                "      --bootloader <BOOTLOADER>\n          The bootloader to use\n      --component <C>\n          [possible values: grub]\n",
                false,
                vec![],
            ),
            ("      --device <DEVICE>\n", false, vec![]),
        ];
        for (help, filesystem, bootloaders) in cases {
            assert_eq!(
                BootupdInstallSupport::parse(help),
                BootupdInstallSupport {
                    filesystem,
                    bootloaders,
                },
                "{help:?}"
            );
        }
    }

    #[test]
    fn test_bootupd_bootloader_arg() {
        use crate::spec::Bootloader::{self, Grub, GrubCC, None as NoBootloader, Systemd};
        let support = |bootloaders: &[Bootloader]| BootupdInstallSupport {
            filesystem: true,
            bootloaders: bootloaders.to_vec(),
        };
        let current = support(&[Grub, GrubCC, Systemd]);
        let grub_only = support(&[Grub]);
        let too_old = support(&[]);
        // Ok(Some(value)), Ok(None) for bootupd's own choice, or Err(()).
        let cases: [(&BootupdInstallSupport, Bootloader, Result<Option<&str>, ()>); 10] = [
            (&current, Grub, Ok(Some("grub"))),
            (&current, GrubCC, Ok(Some("grub-cc"))),
            (&current, Systemd, Ok(Some("systemd"))),
            (&current, NoBootloader, Err(())),
            (&grub_only, Grub, Ok(Some("grub"))),
            (&grub_only, Systemd, Err(())),
            (&grub_only, GrubCC, Err(())),
            (&too_old, Grub, Ok(None)),
            (&too_old, Systemd, Err(())),
            (&too_old, GrubCC, Err(())),
        ];
        for (support, bootloader, expected) in cases {
            let arg = bootupd_bootloader_arg(support, bootloader);
            assert_eq!(
                arg.as_ref().map(|v| v.as_deref()).map_err(|_| ()),
                expected,
                "{bootloader} with {support:?}"
            );
        }
    }

    #[test]
    fn test_bootupd_target_args() {
        use BootupdComponents::{Auto, Efi};
        let auto: &[&str] = &["--update-firmware", "--auto"];
        let efi: &[&str] = &["--update-firmware", "--component", "EFI"];
        let cases = [
            (false, Auto, auto),
            (false, Efi, efi),
            (true, Auto, &[][..]),
            (true, Efi, &[][..]),
        ];
        for (generic_image, components, expected) in cases {
            assert_eq!(
                bootupd_target_args(generic_image, components),
                expected,
                "{components:?}, generic image: {generic_image}"
            );
        }
    }

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
