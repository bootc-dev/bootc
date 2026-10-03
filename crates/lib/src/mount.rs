//! Explicit, caller-owned mounts of an offline deployment.
//!
//! Conceptually this redoes what the initramfs does at boot
//! (ostree-prepare-root for OSTree, bootc-initramfs-setup for composefs), only
//! for a deployment in an offline sysroot and at a directory the caller picks
//! instead of `/sysroot`: the root is the deployment's composefs image, with
//! `/etc` and `/var` mounted from its state as they will be at boot. Keep it in
//! line with those, and share their code where bootc has it.
//!
//! The deployment is the one the default boot entry would boot, found from the
//! entries on `/boot` and the ESP the same way `bootc status` orders them; that
//! is the offline analogue of the kernel command line a booted system consults.
//!
//! Unlike the `install to-*` commands, this deliberately does not enter a
//! private mount namespace: the assembled tree is left in the caller's
//! namespace, and the caller cleans it up with `umount -R` (or by tearing
//! down its own namespace). bootc keeps no state about the mount.

use std::os::fd::{AsFd, AsRawFd};

use anyhow::{Context, Result, bail, ensure};
use bootc_initramfs_setup::{
    Config as SetupRootConfig, MountType, SETUP_ROOT_CONF_PATH, mount_subdir,
};
use bootc_mount::tempmount::TempMount;
use camino::{Utf8Path, Utf8PathBuf};
use cap_std_ext::{
    cap_std::{ambient_authority, fs::Dir},
    dirext::CapStdExtDirExt,
};
use clap::Args;
use linux_kernel_cmdline::utf8::Cmdline;
use ostree::gio;
use ostree_ext::keyfileext::KeyFileExt;
use ostree_ext::{ostree, ostree_prepareroot};
use rustix::mount::{MoveMountFlags, OpenTreeFlags, move_mount, open_tree};

use crate::bootc_composefs::boot::mount_esp_readonly;
use crate::bootc_composefs::status::{
    BootDirProbe, ComposefsCmdline, get_sorted_grub_uki_boot_entries,
    get_sorted_type1_boot_entries_helper,
};
use crate::composefs_consts::{STATE_DIR_RELATIVE, TYPE1_ENT_PATH, USER_CFG};
use crate::install::ARCH_USES_EFI;
use crate::parsers::bls_config::{BLSConfig, BLSConfigType};
use crate::spec::Bootloader;

const ETC: &str = "etc";
const VAR: &str = "var";
/// Where `/boot` is expected in the sysroot, as OSTree requires.
const BOOT: &str = "boot";
/// Where a mounted ESP is looked for in the sysroot when `--esp` is not
/// given, in order: `/efi` as systemd-gpt-auto-generator mounts it, then the
/// traditional `/boot/efi`.
const DEFAULT_ESP_PATHS: &[&str] = &["efi", "boot/efi"];
/// The kernel argument naming an OSTree deployment's boot symlink.
const OSTREE_KARG: &str = "ostree";

#[derive(Debug, Args, PartialEq, Eq)]
pub(crate) struct MountOpts {
    /// Offline target sysroot.
    #[clap(long, value_parser = crate::cli::parse_absolute_path)]
    pub(crate) sysroot: Utf8PathBuf,

    /// Mount the deployment the default boot entry boots.
    ///
    /// This is required so that other ways to select a deployment can be
    /// added later without changing what an invocation means.
    #[clap(long, required = true)]
    pub(crate) latest: bool,

    /// The mounted EFI System Partition, where systemd-boot keeps its boot entries.
    ///
    /// Defaults to `/efi` or `/boot/efi` if either are mounted, otherwise the ESP will be
    /// discovered (if applicable) from the block device(s) backing the target root.
    #[clap(long, value_parser = crate::cli::parse_absolute_path, hide = !ARCH_USES_EFI)]
    pub(crate) esp: Option<Utf8PathBuf>,

    /// Mount /etc and /var read-only too. The deployment root is always read-only.
    #[clap(long)]
    pub(crate) read_only: bool,

    /// Directory receiving the deployment mount.
    #[clap(value_parser = crate::cli::parse_absolute_path)]
    pub(crate) target: Utf8PathBuf,
}

/// Open the mount target. Like mount(8), this mounts wherever the caller asks;
/// like systemd, it warns when that hides existing content.
fn open_mount_target(target: &Utf8Path) -> Result<Dir> {
    let target_dir = Dir::open_ambient_dir(target, ambient_authority())
        .with_context(|| format!("Opening mount target {target}"))?;
    let mut entries = target_dir
        .entries()
        .with_context(|| format!("Reading mount target {target}"))?;
    if entries.next().is_some() {
        eprintln!("warning: mount target {target} is not empty; its contents will be hidden");
    }
    Ok(target_dir)
}

/// Which backend's deployment a boot entry boots, from its kernel command line.
#[derive(Debug, Clone, PartialEq, Eq)]
enum EntryTarget {
    /// A composefs deployment, by its ID.
    Composefs(String),
    /// An OSTree deployment. Which one is left to OSTree, which orders its
    /// deployments from these same entries.
    Ostree,
}

impl EntryTarget {
    fn from_cmdline(cmdline: &Cmdline) -> Result<Option<Self>> {
        if let Some(composefs) = ComposefsCmdline::find_in_cmdline(cmdline)? {
            return Ok(Some(Self::Composefs(composefs.digest.into())));
        }
        Ok(cmdline.find(OSTREE_KARG).map(|_| Self::Ostree))
    }

    fn from_bls(entry: &BLSConfig) -> Result<Self> {
        let name = || entry.title.as_deref().unwrap_or_default();
        match &entry.cfg_type {
            // bootc names UKIs after the deployment, as `bootc status` relies on.
            BLSConfigType::EFI { .. } => Ok(Self::Composefs(entry.get_verity()?)),
            BLSConfigType::NonEFI { .. } => {
                Self::from_cmdline(entry.get_cmdline()?)?.with_context(|| {
                    format!(
                        "default boot entry {:?} has no composefs or {OSTREE_KARG} kernel argument",
                        name()
                    )
                })
            }
            BLSConfigType::Unknown => bail!("default boot entry {:?} has an unknown type", name()),
        }
    }
}

/// Sorted Type 1 entries of `dir` (not the staged ones, which do not boot).
fn type1_entries(dir: &Dir, bootloader: Bootloader) -> Result<Vec<BLSConfig>> {
    if !dir.try_exists(TYPE1_ENT_PATH)? {
        return Ok(Vec::new());
    }
    get_sorted_type1_boot_entries_helper(dir, true, false, bootloader)
}

/// What the default boot entry on `boot` and `esp` boots, or `None` without entries.
///
/// This orders entries as `bootc status` does; it does not consult EFI variables
/// (such as a one-time boot entry), boot counting, or a configured default.
fn default_entry_target(boot: &Dir, esp: Option<&Dir>) -> Result<Option<EntryTarget>> {
    // Offline there are no EFI variables to ask, only the files.
    let bootloader = BootDirProbe::from_dirs(std::iter::once(boot).chain(esp)).bootloader();
    if bootloader == Bootloader::Systemd {
        // Entries may be on the ESP, or on /boot when that is the ESP.
        let mut entries = type1_entries(boot, bootloader)?;
        if let Some(esp) = esp {
            entries.extend(type1_entries(esp, bootloader)?);
        }
        entries.sort();
        return entries.first().map(EntryTarget::from_bls).transpose();
    }
    // bootc's UKI entries for GRUB, which take precedence as in `bootc status`.
    if boot.try_exists(format!("grub2/{USER_CFG}"))? {
        let mut buf = String::new();
        let menuentries = get_sorted_grub_uki_boot_entries(boot, &mut buf)?;
        return menuentries
            .first()
            .map(|entry| entry.get_verity().map(EntryTarget::Composefs))
            .transpose();
    }
    type1_entries(boot, bootloader)?
        .first()
        .map(EntryTarget::from_bls)
        .transpose()
}

/// Where the ESP was found.
enum Esp<T = TempMount> {
    /// Given by `--esp`, or mounted at one of [`DEFAULT_ESP_PATHS`].
    Mounted(Dir),
    /// Discovered from the block devices backing the sysroot, and mounted
    /// while the boot entries are read.
    Discovered(T),
}

impl Esp {
    fn dir(&self) -> &Dir {
        match self {
            Self::Mounted(dir) => dir,
            Self::Discovered(mount) => &mount.fd,
        }
    }
}

/// The ESP when `--esp` is not given: the first of [`DEFAULT_ESP_PATHS`] in
/// `sysroot` that is a mount point, else whatever `discover` finds.
fn find_esp<T>(
    sysroot: &Dir,
    is_mountpoint: impl Fn(&Dir) -> Result<bool>,
    discover: impl FnOnce() -> Result<Option<T>>,
) -> Result<Option<Esp<T>>> {
    for path in DEFAULT_ESP_PATHS {
        let Some(dir) = sysroot
            .open_dir_optional(path)
            .with_context(|| format!("Opening {path}"))?
        else {
            continue;
        };
        if is_mountpoint(&dir).with_context(|| format!("Checking whether {path} is mounted"))? {
            tracing::debug!("Using the ESP mounted at {path}");
            return Ok(Some(Esp::Mounted(dir)));
        }
    }
    Ok(discover()?.map(Esp::Discovered))
}

/// Find the ESP among the block devices backing `sysroot` as install does,
/// and mount it (or clone its existing mount) to read the boot entries.
fn discover_esp(sysroot: &Dir) -> Result<Option<TempMount>> {
    let esps = bootc_blockdev::list_dev_by_dir(sysroot)?.find_colocated_esps()?;
    let Some(esp) = esps.as_ref().and_then(|esps| esps.first()) else {
        tracing::debug!("No ESP found among the sysroot's block devices");
        return Ok(None);
    };
    let path = esp.path();
    tracing::debug!("Using the ESP discovered at {path}");
    mount_esp_readonly(&path)
        .with_context(|| format!("Mounting ESP {path}"))
        .map(Some)
}

/// The ESP to read boot entries from when `--esp` is not given; none on
/// architectures without one.
fn default_esp(sysroot: &Dir) -> Result<Option<Esp>> {
    if !ARCH_USES_EFI {
        return Ok(None);
    }
    // As install does, a directory is taken as mounted when that is unknown.
    let is_mountpoint = |dir: &Dir| Ok(dir.is_mountpoint(".")?.unwrap_or(true));
    find_esp(sysroot, is_mountpoint, || {
        // The ESP is only needed with systemd-boot, and even then a sole
        // deployment is found without it, so don't fail on sysroots whose
        // devices can't be inspected.
        discover_esp(sysroot).or_else(|e| {
            eprintln!("warning: could not discover the ESP: {e:#}");
            Ok(None)
        })
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeploymentBackend {
    Ostree,
    Composefs,
}

/// Without boot entries to go by, only a sole deployment is unambiguous.
fn select_backend(
    ostree_deployments: usize,
    composefs_deployments: usize,
) -> Result<DeploymentBackend> {
    match (ostree_deployments, composefs_deployments) {
        (1, 0) => Ok(DeploymentBackend::Ostree),
        (0, 1) => Ok(DeploymentBackend::Composefs),
        (0, 0) => bail!("target contains no deployment"),
        (o, c) => bail!(
            "found no boot entries to select among {o} OSTree and {c} composefs deployments; \
             mount /boot at SYSROOT/boot and pass --esp"
        ),
    }
}

/// The deployment selected by `--latest`: the one the default boot entry
/// boots, or without entries the sole deployment. Returns its index in the
/// backend's deployment list.
fn select_deployment(
    target: Option<&EntryTarget>,
    ostree_deployments: usize,
    composefs_deployments: &[String],
) -> Result<(DeploymentBackend, usize)> {
    match target {
        None => {
            let backend = select_backend(ostree_deployments, composefs_deployments.len())?;
            Ok((backend, 0))
        }
        Some(EntryTarget::Composefs(id)) => composefs_deployments
            .iter()
            .position(|d| d == id)
            .map(|i| (DeploymentBackend::Composefs, i))
            .with_context(|| {
                format!(
                    "default boot entry boots composefs deployment {id}, which is not in {STATE_DIR_RELATIVE}"
                )
            }),
        // OSTree loads its deployments from the entries in version order, the
        // default first, as `bootc status` shows them. Don't re-sort them here:
        // e.g. GRUB's file name order differs from that at 10 deployments.
        Some(EntryTarget::Ostree) => {
            ensure!(
                ostree_deployments > 0,
                "default boot entry boots an OSTree deployment, but OSTree found none in /boot"
            );
            Ok((DeploymentBackend::Ostree, 0))
        }
    }
}

pub(crate) async fn mount(opts: MountOpts) -> Result<()> {
    // clap already requires --latest, the only selector so far.
    ensure!(opts.latest, "no deployment selected; pass --latest");
    let target = &opts.target;
    let target_dir = open_mount_target(target)?;
    let sysroot_dir = Dir::open_ambient_dir(&opts.sysroot, ambient_authority())
        .with_context(|| format!("Opening target sysroot {}", opts.sysroot))?;

    // The OSTree lock is held until the mount is assembled, so a concurrent
    // OSTree operation on the offline sysroot cannot prune the deployment from
    // under us.
    let ostree_repo = sysroot_dir.open_dir_optional("ostree/repo")?;
    let ostree_sysroot = if ostree_repo.is_some() {
        // ostree only takes a path; go through the fd we already opened.
        let path = format!("/proc/self/fd/{}", sysroot_dir.as_raw_fd());
        let sysroot = ostree::Sysroot::new(Some(&gio::File::for_path(path)));
        sysroot
            .load(gio::Cancellable::NONE)
            .context("Loading target OSTree sysroot")?;
        Some(ostree_ext::sysroot::SysrootLock::new_from_sysroot(&sysroot).await?)
    } else {
        None
    };
    let ostree_deployments = ostree_sysroot
        .as_ref()
        .map(|s| s.deployments())
        .unwrap_or_default();
    // Check the state directory rather than the repository: OSTree systems
    // using unified storage also have a composefs repository.
    let composefs_deployments = sysroot_dir
        .open_dir_optional(STATE_DIR_RELATIVE)?
        .map(|state| crate::bootc_composefs::gc::list_deployment_state_dirs(&state))
        .transpose()?
        .unwrap_or_default();

    // The boot entries say which deployment boots. OSTree reads /boot at the
    // same place when loading its deployments.
    let boot = sysroot_dir
        .open_dir_optional(BOOT)
        .with_context(|| format!("Opening {}/{BOOT}", opts.sysroot))?;
    let esp = match &opts.esp {
        Some(esp) => Some(Esp::Mounted(
            Dir::open_ambient_dir(esp, ambient_authority())
                .with_context(|| format!("Opening ESP {esp}"))?,
        )),
        None => default_esp(&sysroot_dir)
            .with_context(|| format!("Finding the ESP of {}", opts.sysroot))?,
    };
    let entry_target = boot
        .as_ref()
        .map(|boot| default_entry_target(boot, esp.as_ref().map(Esp::dir)))
        .transpose()
        .context("Finding the default boot entry")?
        .flatten();
    // Unmount a discovered ESP now; it is not part of the deployment mount.
    drop(esp);
    tracing::debug!("Default boot entry boots {entry_target:?}");
    let (backend, index) = select_deployment(
        entry_target.as_ref(),
        ostree_deployments.len(),
        &composefs_deployments,
    )?;

    let (root_tree, state) = match backend {
        DeploymentBackend::Composefs => {
            let id = &composefs_deployments[index];
            let state = sysroot_dir
                .open_dir(format!("{STATE_DIR_RELATIVE}/{id}"))
                .with_context(|| format!("Opening composefs deployment state {id}"))?;
            let repo = crate::bootc_composefs::repo::open_composefs_repo(&sysroot_dir)?;
            let image = repo.mount(id).context("Mounting composefs image")?;
            (image, DeploymentState::Composefs(state))
        }
        DeploymentBackend::Ostree => {
            let sysroot = ostree_sysroot.as_deref().expect("OSTree backend selected");
            let repo = ostree_repo.as_ref().expect("OSTree backend selected");
            let deployment = &ostree_deployments[index];
            let source = sysroot.deployment_dirpath(deployment);
            let deployment_dir = sysroot_dir
                .open_dir(source.as_str())
                .with_context(|| format!("Opening OSTree deployment {source}"))?;
            let var = sysroot_dir
                .open_dir(format!("ostree/deploy/{}/{VAR}", deployment.stateroot()))
                .context("Opening OSTree stateroot /var")?;
            let config = ostree_prepareroot::load_config_from_root(&deployment_dir)
                .context("Loading the deployment's prepare-root.conf")?;
            let etc_transient = config
                .as_ref()
                .map(|config| config.optional_bool("etc", "transient"))
                .transpose()
                .context("Parsing etc.transient")?
                .flatten()
                .unwrap_or_default();
            let composefs = ostree_prepareroot::mount_composefs(
                &deployment_dir,
                repo,
                deployment.csum().as_str(),
                config.as_ref(),
            )?;
            let root_tree = match composefs {
                Some(root_tree) => root_tree,
                // Without composefs, prepare-root uses the checkout itself.
                None => open_tree(
                    &sysroot_dir,
                    source.as_str(),
                    OpenTreeFlags::OPEN_TREE_CLONE | OpenTreeFlags::OPEN_TREE_CLOEXEC,
                )
                .context("Cloning OSTree deployment tree")?,
            };
            (
                root_tree,
                DeploymentState::Ostree {
                    deployment: deployment_dir,
                    var,
                    etc_transient,
                },
            )
        }
    };

    bootc_initramfs_setup::set_mount_readonly(&root_tree)
        .context("Making detached deployment root read-only")?;
    move_mount(
        &root_tree,
        "",
        &target_dir,
        ".",
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )
    .context("Attaching deployment root")?;
    let assembly = (|| -> Result<()> {
        // Reopen by path: target_dir still refers to the directory underneath the new mount.
        let target_root = Dir::open_ambient_dir(target, ambient_authority())
            .context("Opening mounted deployment root")?;
        match &state {
            DeploymentState::Composefs(state) => mount_composefs_state(&target_root, state)?,
            DeploymentState::Ostree {
                deployment,
                var,
                etc_transient,
            } => mount_ostree_state(&target_root, deployment, var, *etc_transient)?,
        }
        if opts.read_only {
            bootc_initramfs_setup::set_mount_tree_readonly(&target_root)
                .context("Making /etc and /var read-only")?;
        }
        Ok(())
    })();
    if let Err(error) = assembly {
        return Err(match bootc_mount::unmount_recursive(target) {
            Ok(()) => error,
            Err(cleanup_error) => {
                error.context(format!("cleanup of {target} also failed: {cleanup_error}"))
            }
        })
        .context("Assembling offline deployment mount");
    }
    Ok(())
}

/// Where the machine-local state of the selected deployment lives.
enum DeploymentState {
    /// The composefs per-deployment state directory.
    Composefs(Dir),
    /// The OSTree deployment directory, its stateroot's `/var`, and whether
    /// prepare-root.conf enables `etc.transient`.
    Ostree {
        deployment: Dir,
        var: Dir,
        etc_transient: bool,
    },
}

/// Mount `/etc` and `/var` as the composefs initramfs does at boot, honoring
/// the image's setup-root configuration (for example a transient `/etc`).
fn mount_composefs_state(root: &Dir, state: &Dir) -> Result<()> {
    let config_path = SETUP_ROOT_CONF_PATH.trim_start_matches('/');
    let config: SetupRootConfig = root
        .read_to_string_optional(config_path)
        .with_context(|| format!("Reading {SETUP_ROOT_CONF_PATH}"))?
        .map(|text| toml::from_str(&text))
        .transpose()
        .with_context(|| format!("Parsing {SETUP_ROOT_CONF_PATH}"))?
        .unwrap_or_default();
    mount_subdir(root, state, ETC, config.etc, MountType::Bind)?;
    mount_subdir(root, state, VAR, config.var, MountType::Bind)?;
    Ok(())
}

/// Mount `/etc` and `/var` as ostree-prepare-root does at boot: `/etc` is the
/// deployment's persistent copy, or a transient overlay of `/usr/etc` when
/// `prepare-root.conf` enables `etc.transient`.
fn mount_ostree_state(root: &Dir, deployment: &Dir, var: &Dir, etc_transient: bool) -> Result<()> {
    if etc_transient {
        let usr_etc = root.open_dir("usr/etc").context("Opening /usr/etc")?;
        let overlay = bootc_initramfs_setup::overlay_transient(&usr_etc, "transient", None)?;
        attach(&overlay, root, ETC)?;
    } else {
        let etc = deployment
            .open_dir(ETC)
            .context("Opening OSTree deployment /etc")?;
        bind(&etc, root, ETC)?;
    }
    bind(var, root, VAR)
}

fn bind(source: &Dir, target: &Dir, name: &str) -> Result<()> {
    let tree = open_tree(
        source,
        ".",
        OpenTreeFlags::OPEN_TREE_CLONE | OpenTreeFlags::OPEN_TREE_CLOEXEC,
    )
    .with_context(|| format!("Cloning /{name}"))?;
    attach(&tree, target, name)
}

fn attach(tree: impl AsFd, target: &Dir, name: &str) -> Result<()> {
    move_mount(
        tree,
        "",
        target,
        name,
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )
    .with_context(|| format!("Attaching /{name}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{InstallOpts, Opt};
    use cap_std_ext::cap_tempfile;
    use clap::Parser;

    // fs-verity SHA-512 digests, as composefs deployment IDs are.
    const DIGEST_A: &str = "7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b67e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6";
    const DIGEST_B: &str = "febdf62805de2ae7b6b597f2a9775d9c8a753ba1e5f09298fc8fbe0b0d13bf01febdf62805de2ae7b6b597f2a9775d9c8a753ba1e5f09298fc8fbe0b0d13bf01";
    const BOOTCSUM: &str = "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9";

    fn composefs_type1(version: &str, sort_key: &str, digest: &str) -> String {
        format!(
            "title bootc {version}\nversion {version}\nsort-key {sort_key}\n\
             linux /bootc_composefs-{digest}/vmlinuz\ninitrd /bootc_composefs-{digest}/initrd\n\
             options root=UUID=abc rw composefs={digest}\n"
        )
    }

    fn uki_type1(version: &str, sort_key: &str, digest: &str) -> String {
        format!(
            "title bootc {version}\nversion {version}\nsort-key {sort_key}\n\
             uki /EFI/Linux/bootc/bootc_composefs-{digest}.efi\n"
        )
    }

    fn ostree_type1(version: &str, serial: u32) -> String {
        format!(
            "title ostree {version}\nversion {version}\n\
             linux /ostree/default-{BOOTCSUM}/vmlinuz\ninitrd /ostree/default-{BOOTCSUM}/initramfs.img\n\
             options root=UUID=abc rw ostree=/ostree/boot.1/default/{BOOTCSUM}/{serial}\n"
        )
    }

    fn grub_uki_menuentry(digest: &str) -> String {
        format!(
            "menuentry \"bootc: ({digest})\" {{\n    insmod fat\n    insmod chain\n    \
             search --no-floppy --set=root --fs-uuid \"${{EFI_PART_UUID}}\"\n    \
             chainloader /EFI/Linux/bootc/bootc_composefs-{digest}.efi\n}}\n"
        )
    }

    #[test]
    fn default_entry_target_follows_bootloader_order() -> Result<()> {
        let composefs = |d: &str| Some(EntryTarget::Composefs(d.into()));
        // (description, files in /boot, files on the ESP, expected)
        let cases: Vec<(&str, Vec<(&str, String)>, Vec<(&str, String)>, _)> = vec![
            ("no entries", vec![], vec![], None),
            (
                // GRUB sorts by file name, highest first, whatever the sort-key.
                "grub type1",
                vec![
                    ("grub2/grub.cfg", String::new()),
                    (
                        "loader/entries/bootc_os-1-0.conf",
                        composefs_type1("1", "0", DIGEST_A),
                    ),
                    (
                        "loader/entries/bootc_os-2-1.conf",
                        composefs_type1("2", "9", DIGEST_B),
                    ),
                ],
                vec![],
                composefs(DIGEST_B),
            ),
            (
                "grub uki",
                vec![(
                    "grub2/user.cfg",
                    grub_uki_menuentry(DIGEST_A) + &grub_uki_menuentry(DIGEST_B),
                )],
                vec![],
                composefs(DIGEST_A),
            ),
            (
                // systemd-boot sorts by sort-key; staged entries do not boot.
                "systemd-boot on the ESP",
                vec![],
                vec![
                    ("loader/entries/a.conf", uki_type1("1", "2", DIGEST_A)),
                    ("loader/entries/b.conf", uki_type1("2", "1", DIGEST_B)),
                    (
                        "loader/entries.staged/c.conf",
                        uki_type1("3", "0", DIGEST_A),
                    ),
                ],
                composefs(DIGEST_B),
            ),
            (
                "systemd-boot with the ESP as /boot",
                vec![
                    ("loader/entries/a.conf", composefs_type1("1", "1", DIGEST_A)),
                    ("loader/entries/b.conf", composefs_type1("2", "2", DIGEST_B)),
                ],
                vec![],
                composefs(DIGEST_A),
            ),
            (
                "ostree on grub",
                vec![
                    ("grub2/grub.cfg", String::new()),
                    ("loader/entries/ostree-1.conf", ostree_type1("1", 1)),
                    ("loader/entries/ostree-2.conf", ostree_type1("2", 0)),
                ],
                vec![],
                Some(EntryTarget::Ostree),
            ),
        ];
        for (desc, boot_files, esp_files, expected) in cases {
            let boot = cap_tempfile::tempdir(ambient_authority())?;
            let esp = cap_tempfile::tempdir(ambient_authority())?;
            for (dir, files) in [(&boot, &boot_files), (&esp, &esp_files)] {
                for (path, contents) in files {
                    dir.create_dir_all(Utf8Path::new(path).parent().unwrap())?;
                    dir.atomic_write(path, contents)?;
                }
            }
            let found =
                default_entry_target(&boot, Some(&esp)).with_context(|| desc.to_string())?;
            assert_eq!(found, expected, "{desc}");
        }
        Ok(())
    }

    #[test]
    fn finds_esp_in_preference_order() -> Result<()> {
        const MOUNTED: &str = "mounted";
        const DISCOVERED: &str = "discovered";
        // (description, directories in the sysroot, those mounted, whether
        // discovery finds an ESP, expected)
        let cases: &[(&str, &[&str], &[&str], bool, Option<&str>)] = &[
            ("nothing", &[], &[], false, None),
            (
                "unmounted directories",
                &["efi", "boot/efi"],
                &[],
                false,
                None,
            ),
            (
                "discovered when nothing is mounted",
                &["efi", "boot/efi"],
                &[],
                true,
                Some(DISCOVERED),
            ),
            ("/efi", &["efi"], &["efi"], true, Some("efi")),
            (
                "/efi over /boot/efi",
                &["efi", "boot/efi"],
                &["efi", "boot/efi"],
                true,
                Some("efi"),
            ),
            (
                "/boot/efi when /efi is not mounted",
                &["efi", "boot/efi"],
                &["boot/efi"],
                true,
                Some("boot/efi"),
            ),
        ];
        for (desc, dirs, mounted, discoverable, expected) in cases {
            let sysroot = cap_tempfile::tempdir(ambient_authority())?;
            for dir in *dirs {
                sysroot.create_dir_all(dir)?;
            }
            // Mark the "mounted" directories with their own path.
            for dir in *mounted {
                sysroot.atomic_write(format!("{dir}/{MOUNTED}"), dir)?;
            }
            let is_mountpoint = |dir: &Dir| Ok(dir.try_exists(MOUNTED)?);
            let found = find_esp(&sysroot, is_mountpoint, || {
                Ok(discoverable.then_some(DISCOVERED))
            })
            .with_context(|| desc.to_string())?;
            let found = match &found {
                None => None,
                Some(Esp::Mounted(dir)) => Some(dir.read_to_string(MOUNTED)?),
                Some(Esp::Discovered(d)) => Some(d.to_string()),
            };
            assert_eq!(found.as_deref(), *expected, "{desc}");
        }
        Ok(())
    }

    #[test]
    fn entry_target_from_cmdline() -> Result<()> {
        let cases = [
            ("root=UUID=abc rw", None),
            (
                &*format!("rw composefs={DIGEST_A}"),
                Some(EntryTarget::Composefs(DIGEST_A.into())),
            ),
            (
                &*format!("rw ostree=/ostree/boot.0/default/{BOOTCSUM}/2"),
                Some(EntryTarget::Ostree),
            ),
        ];
        for (cmdline, expected) in cases {
            let found = EntryTarget::from_cmdline(&Cmdline::from(cmdline))?;
            assert_eq!(found, expected, "{cmdline}");
        }
        Ok(())
    }

    #[test]
    fn selects_deployment_of_default_entry() {
        let composefs = [DIGEST_A.to_string(), DIGEST_B.to_string()];
        // (target, OSTree deployments, expected)
        let cases = [
            (
                Some(EntryTarget::Composefs(DIGEST_B.into())),
                2,
                Some((DeploymentBackend::Composefs, 1)),
            ),
            (Some(EntryTarget::Composefs("missing".into())), 2, None),
            // OSTree's first deployment is its default, however many there are.
            (
                Some(EntryTarget::Ostree),
                12,
                Some((DeploymentBackend::Ostree, 0)),
            ),
            (Some(EntryTarget::Ostree), 0, None),
            // Without boot entries, only a sole deployment is selected.
            (None, 2, None),
            (None, 1, None),
            (None, 0, None),
        ];
        for (target, ostree, expected) in cases {
            let found = select_deployment(target.as_ref(), ostree, &composefs).ok();
            assert_eq!(found, expected, "{target:?} {ostree}");
        }
        assert_eq!(
            select_deployment(None, 0, &composefs[..1]).unwrap(),
            (DeploymentBackend::Composefs, 0)
        );
    }

    #[test]
    fn requires_deployment_selector() {
        let cases: &[(&[&str], bool)] = &[
            (&["--sysroot=/sysroot", "/mnt"], false),
            (&["--sysroot=/sysroot", "--latest", "/mnt"], true),
            (
                &["--sysroot=/sysroot", "--latest", "--read-only", "/mnt"],
                true,
            ),
        ];
        for (args, ok) in cases {
            let argv = ["bootc", "install", "mount"].iter().chain(args.iter());
            match Opt::try_parse_from(argv) {
                Ok(Opt::Install(InstallOpts::Mount(opts))) => {
                    assert!(ok, "{args:?} parsed without a selector");
                    assert!(opts.latest);
                }
                Ok(o) => panic!("{args:?}: expected install mount, got {o:?}"),
                Err(e) => {
                    assert!(!ok, "{args:?}: {e}");
                    assert_eq!(e.kind(), clap::error::ErrorKind::MissingRequiredArgument);
                    assert!(e.to_string().contains("--latest"), "{e}");
                }
            }
        }
    }

    #[test]
    fn selects_only_unambiguous_backend() {
        let cases = [
            (0, 0, None),
            (1, 0, Some(DeploymentBackend::Ostree)),
            (0, 1, Some(DeploymentBackend::Composefs)),
            (1, 1, None),
            (2, 0, None),
            (0, 2, None),
        ];
        for (ostree, composefs, expected) in cases {
            assert_eq!(select_backend(ostree, composefs).ok(), expected);
        }
    }

    #[test]
    fn accepts_any_target_directory() {
        let temp = tempfile::tempdir().unwrap();
        let temp = Utf8Path::from_path(temp.path()).unwrap();
        let target = temp.join("target");
        std::fs::create_dir(&target).unwrap();
        open_mount_target(&target).unwrap();
        // Non-empty only warns, as with systemd.
        std::fs::create_dir(target.join("nested")).unwrap();
        open_mount_target(&target).unwrap();
        assert!(open_mount_target(&temp.join("missing")).is_err());
    }
}
