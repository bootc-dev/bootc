//! Mount helpers for bootc-initramfs

use std::{
    ffi::OsString,
    fmt::Debug,
    io::ErrorKind,
    os::fd::{AsFd, AsRawFd, OwnedFd},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::Parser;
use rustix::{
    fs::{CWD, Mode, OFlags, major, minor, mkdirat, openat, stat, symlink},
    io::Errno,
    mount::{
        FsMountFlags, MountAttrFlags, OpenTreeFlags, UnmountFlags, fsconfig_create,
        fsconfig_set_string, fsmount, open_tree, unmount,
    },
    path,
};

use serde::Deserialize;

use composefs::{
    fsverity::{FsVerityHashValue, Sha512HashValue},
    mount::FsHandle,
    mountcompat::{overlayfs_set_fd, overlayfs_set_lower_and_data_fds, prepare_mount},
    repository::Repository,
};
use composefs_boot::cmdline::ComposefsCmdline;
use composefs_ctl::composefs;
use composefs_ctl::composefs_boot;

use fn_error_context::context;

use linux_kernel_cmdline::utf8::Cmdline;

// mount_setattr syscall support
const MOUNT_ATTR_RDONLY: u64 = 0x00000001;

#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

/// Set mount attributes using mount_setattr syscall
#[context("Setting mount attributes")]
#[allow(unsafe_code)]
fn mount_setattr(fd: impl AsFd, flags: libc::c_int, attr: &MountAttr) -> Result<()> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            fd.as_fd().as_raw_fd(),
            c"".as_ptr(),
            flags,
            attr as *const MountAttr,
            std::mem::size_of::<MountAttr>(),
        )
    };
    if ret == -1 {
        Err(std::io::Error::last_os_error())?;
    }
    Ok(())
}

/// Set mount to readonly
#[context("Setting mount readonly")]
fn set_mount_readonly(fd: impl AsFd) -> Result<()> {
    let attr = MountAttr {
        attr_set: MOUNT_ATTR_RDONLY,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    mount_setattr(fd, libc::AT_EMPTY_PATH, &attr)
}

/// Types of mounts supported by the configuration
#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MountType {
    /// No mount; "root" is an alias meaning this dir is part of the root mount
    #[serde(alias = "root")]
    None,
    /// Bind mount
    Bind,
    /// Overlay mount
    Overlay,
    /// Transient mount; "volatile" is an alias (Unix convention for tmpfs)
    #[serde(alias = "volatile")]
    Transient,
}

#[derive(Debug, Default, Deserialize, PartialEq)]
struct RootConfig {
    #[serde(default)]
    transient: bool,
}

/// Configuration for mount operations
#[derive(Debug, Default, Deserialize, PartialEq)]
pub struct MountConfig {
    /// The type of mount to use
    pub mount: Option<MountType>,
    #[serde(default)]
    /// Whether this mount should be transient (temporary)
    pub transient: bool,
}

#[derive(Debug, Deserialize, Default, PartialEq)]
struct Config {
    #[serde(default)]
    etc: MountConfig,
    #[serde(default)]
    var: MountConfig,
    #[serde(default)]
    root: RootConfig,
}

/// Default path to the setup-root configuration file, relative to the booted root.
pub const SETUP_ROOT_CONF_PATH: &str = "/usr/lib/composefs/setup-root-conf.toml";

/// Returns `true` if the configuration at `path` requests a transient `/etc`
/// overlay.  Used by the systemd generator to decide whether to emit the
/// SELinux relabel unit *before* those mounts exist (the generator runs before
/// `local-fs.target`).
///
/// Returns `false` if the file is absent or unreadable (safe default: no unit
/// emitted for non-transient systems).
pub fn config_has_transient_submounts(path: &std::path::Path) -> bool {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!("Could not read {}: {e:#}", path.display());
            return false;
        }
    };
    let config: Config = match toml::from_str(&text) {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!("Could not parse {}: {e:#}", path.display());
            return false;
        }
    };
    // Only /etc overlay triggers the relabel unit.
    let is_transient = |mc: &MountConfig| match mc.mount {
        Some(mt) => mt == MountType::Transient,
        None => mc.transient,
    };
    is_transient(&config.etc)
}

/// Command-line arguments
#[derive(Parser, Debug)]
pub struct Args {
    #[arg(help = "Execute this command (for testing)")]
    /// Execute this command (for testing)
    pub cmd: Vec<OsString>,

    #[arg(
        long,
        default_value = "/sysroot",
        help = "sysroot directory in initramfs"
    )]
    /// sysroot directory in initramfs
    pub sysroot: PathBuf,

    #[arg(
        long,
        default_value = "/usr/lib/composefs/setup-root-conf.toml",
        help = "Config path (for testing)"
    )]
    /// Config path (for testing)
    pub config: PathBuf,

    // we want to test in a userns, but can't mount erofs there
    #[arg(long, help = "Bind mount root-fs from (for testing)")]
    /// Bind mount root-fs from (for testing)
    pub root_fs: Option<PathBuf>,

    #[arg(long, help = "Kernel commandline args (for testing)")]
    /// Kernel commandline args (for testing)
    pub cmdline: Option<Cmdline<'static>>,

    #[arg(long, help = "Mountpoint (don't replace sysroot, for testing)")]
    /// Mountpoint (don't replace sysroot, for testing)
    pub target: Option<PathBuf>,
}

/// Wrapper around [`composefs::mount::mount_at`]
pub fn mount_at_wrapper(
    fs_fd: impl AsFd,
    dirfd: impl AsFd,
    path: impl path::Arg + Debug + Clone,
) -> Result<()> {
    composefs::mount::mount_at(fs_fd, dirfd, path.clone())
        .with_context(|| format!("Mounting at path {path:?}"))
}

/// Wrapper around [`rustix::fs::openat`]
#[context("Opening dir {name:?}")]
pub fn open_dir(dirfd: impl AsFd, name: impl AsRef<Path> + Debug) -> Result<OwnedFd> {
    let res = openat(
        dirfd,
        name.as_ref(),
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    );

    Ok(res?)
}

#[context("Ensure dir")]
fn ensure_dir(dirfd: impl AsFd, name: &str, mode: Option<rustix::fs::Mode>) -> Result<OwnedFd> {
    match mkdirat(dirfd.as_fd(), name, mode.unwrap_or(0o700.into())) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(err) => Err(err).with_context(|| format!("Creating dir {name}"))?,
    }

    open_dir(dirfd, name)
}

#[context("Bind mounting to path {path}")]
fn bind_mount(fd: impl AsFd, path: &str) -> Result<OwnedFd> {
    let res = open_tree(
        fd.as_fd(),
        path,
        OpenTreeFlags::OPEN_TREE_CLONE
            | OpenTreeFlags::OPEN_TREE_CLOEXEC
            | OpenTreeFlags::AT_EMPTY_PATH,
    );

    Ok(res?)
}

/// Mount a tmpfs to use as the upper layer for an overlay.
///
/// TODO: sync these options with systemd's root mounting, there's some tweaks there for default tmpfs
/// and we may want to make this configurable anyways i nthe future
///
/// See <https://github.com/containers/bootc/issues/1992>.
#[context("Mounting tmpfs for overlay")]
fn mount_tmpfs_for_overlay() -> Result<OwnedFd> {
    let tmpfs = FsHandle::open("tmpfs")?;
    fsconfig_create(tmpfs.as_fd())?;
    Ok(fsmount(
        tmpfs.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::empty(),
    )?)
}

/// Build an overlayfs fsmount fd from an existing state dir (upper+work).
///
/// upper is 0755: the merged view inherits permissions from upperdir, so 0700
/// would make the mountpoint inaccessible to non-root processes.  work is
/// kernel-internal and never visible; 0700 is fine.
/// See: <https://github.com/composefs/composefs-rs/issues/287>
fn build_overlay_fd(
    base: impl AsFd,
    state: impl AsFd,
    source: &str,
    mount_attr_flags: Option<MountAttrFlags>,
) -> Result<OwnedFd> {
    let upper = ensure_dir(state.as_fd(), "upper", Some(0o755.into()))?;
    let work = ensure_dir(state.as_fd(), "work", Some(0o700.into()))?;

    let overlayfs = FsHandle::open("overlay")?;
    fsconfig_set_string(overlayfs.as_fd(), "source", source)?;
    overlayfs_set_fd(overlayfs.as_fd(), "workdir", work.as_fd())?;
    overlayfs_set_fd(overlayfs.as_fd(), "upperdir", upper.as_fd())?;
    overlayfs_set_lower_and_data_fds(&overlayfs, base.as_fd(), None::<OwnedFd>)?;
    fsconfig_create(overlayfs.as_fd())?;
    Ok(fsmount(
        overlayfs.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        mount_attr_flags.unwrap_or(MountAttrFlags::empty()),
    )?)
}

/// Mount a persistent state directory as an overlay on top of `base`,
/// attaching the result immediately at `.` relative to `base`.
#[context("Mounting state as overlay")]
fn overlay_state(
    base: impl AsFd,
    state: impl AsFd,
    source: &str,
    mount_attr_flags: Option<MountAttrFlags>,
) -> Result<()> {
    let fs = build_overlay_fd(&base, state, source, mount_attr_flags)?;
    mount_at_wrapper(fs, base, ".").context("Moving mount")
}

/// Creates a transient overlayfs with the passed-in fd as the lowerdir.
///
/// Returns a detached (not yet attached) `OwnedFd` for the overlay mount.
/// The caller is responsible for attaching it to the filesystem tree.
///
/// `source` is used verbatim as the overlay's `source` fsconfig option and
/// appears in `/proc/self/mountinfo`.  For the composefs root, pass
/// `"transient:composefs=<digest_hex>"` so that `composefs_booted()` can
/// recover the verity digest from the mount source after switch-root.  For
/// non-root transient mounts (e.g. `/usr`, `/var`) pass `"transient"`.
///
/// The SELinux label on `/` is fixed after boot by
/// `bootc-early-overlay-relabel.service`; no initramfs-side xattr write is
/// needed (kernel `fs_use_trans tmpfs` relabeling at policy-load time would
/// overwrite anything written here).
#[context("Creating transient overlayfs")]
pub fn overlay_transient(
    base: impl AsFd,
    source: &str,
    mount_attr_flags: Option<MountAttrFlags>,
) -> Result<OwnedFd> {
    let tmpfs = mount_tmpfs_for_overlay()?;
    let state = prepare_mount(tmpfs)?;
    build_overlay_fd(base, state, source, mount_attr_flags)
}

#[context("Opening rootfs")]
fn open_root_fs(path: &Path) -> Result<OwnedFd> {
    let rootfs = open_tree(
        CWD,
        path,
        OpenTreeFlags::OPEN_TREE_CLONE | OpenTreeFlags::OPEN_TREE_CLOEXEC,
    )?;

    set_mount_readonly(&rootfs)?;

    Ok(rootfs)
}

/// Prepares a floating mount for composefs and returns the fd
///
/// # Arguments
/// * sysroot                - fd for /sysroot
/// * name                   - Name of the EROFS image to be mounted
/// * allow_missing_fsverity - Whether to allow mount without fsverity support
#[context("Mounting composefs image")]
pub fn mount_composefs_image(
    sysroot: &OwnedFd,
    name: &str,
    allow_missing_fsverity: bool,
) -> Result<OwnedFd> {
    // Use open_upgrade to handle upgrades from older composefs-rs versions
    // that lack meta.json: it infers the algorithm and verity mode from
    // existing objects, writes meta.json, and opens normally.
    let (mut repo, _upgraded) = Repository::<Sha512HashValue>::open_upgrade(sysroot, "composefs")?;
    if allow_missing_fsverity {
        repo.set_insecure();
    }
    let rootfs = repo
        .mount(name)
        .context("Failed to mount composefs image")?;

    set_mount_readonly(&rootfs)?;

    Ok(rootfs)
}

/// Mounts a subdirectory with the specified configuration
#[context("Mounting subdirectory")]
pub fn mount_subdir(
    new_root: impl AsFd,
    state: impl AsFd,
    subdir: &str,
    config: MountConfig,
    default: MountType,
) -> Result<()> {
    let mount_type = match config.mount {
        Some(mt) => mt,
        None => match config.transient {
            true => MountType::Transient,
            false => default,
        },
    };

    match mount_type {
        MountType::None => Ok(()),
        MountType::Bind => Ok(mount_at_wrapper(
            bind_mount(&state, subdir)?,
            &new_root,
            subdir,
        )?),
        MountType::Overlay => overlay_state(
            open_dir(&new_root, subdir)?,
            open_dir(&state, subdir)?,
            "overlay",
            None,
        ),
        MountType::Transient => {
            // For subdirectory transient mounts, create the overlay and immediately
            // attach it at the subdirectory path in new_root.
            let subdir_fd = open_dir(&new_root, subdir)?;
            let overlay_fd = overlay_transient(subdir_fd.as_fd(), "transient", None)?;
            mount_at_wrapper(overlay_fd, &new_root, subdir)
        }
    }
}

#[context("GPT workaround")]
/// Workaround for /dev/gpt-auto-root
pub fn gpt_workaround() -> Result<()> {
    // https://github.com/systemd/systemd/issues/35017
    let rootdev = stat("/dev/gpt-auto-root");

    let rootdev = match rootdev {
        Ok(r) => r,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => Err(e)?,
    };

    let target = format!(
        "/dev/block/{}:{}",
        major(rootdev.st_rdev),
        minor(rootdev.st_rdev)
    );
    // Handle the case where the symlink was already created before bootc
    // runs, e.g. by ostree-prepare-root
    // (https://github.com/ostreedev/ostree/pull/3608).
    match symlink(target, "/run/systemd/volatile-root") {
        Ok(()) | Err(Errno::EXIST) => Ok(()),
        Err(err) => Err(err).context("Creating /run/systemd/volatile-root"),
    }
}

/// Sets up /sysroot for switch-root
#[context("Setting up /sysroot")]
pub fn setup_root(args: Args) -> Result<()> {
    let config = match std::fs::read_to_string(args.config) {
        Ok(text) => toml::from_str(&text)?,
        Err(err) if err.kind() == ErrorKind::NotFound => Config::default(),
        Err(err) => Err(err)?,
    };

    let sysroot = open_dir(CWD, &args.sysroot)
        .with_context(|| format!("Failed to open sysroot {:?}", args.sysroot))?;

    let cmdline = args
        .cmdline
        .unwrap_or(Cmdline::from_proc().context("Failed to read cmdline")?);

    // Auto-detect systemd.volatile=state: if the kernel cmdline requests a
    // volatile /var via the systemd fstab-generator, skip our initramfs
    // bind-mount of /var from the deployment state directory.  This leaves
    // /var as an empty directory from the composefs image so that
    // systemd-fstab-generator can mount a fresh tmpfs there at local-fs.target.
    // An explicit `[var] mount = "none"` in setup-root-conf.toml has the same
    // effect; the cmdline check is a convenience so users only need the kargs.d
    // entry without also editing setup-root-conf.toml.
    let config = {
        let mut config = config;
        // value_of returns None for a missing key, Some("") for a bare flag,
        // or Some("state") / Some("overlay") / Some("yes") for key=value form.
        let volatile_val = cmdline.value_of("systemd.volatile");
        let var_volatile = matches!(volatile_val, Some("state") | Some("overlay"));
        if var_volatile && config.var.mount.is_none() && !config.var.transient {
            tracing::debug!(
                "systemd.volatile={} detected; skipping /var state bind-mount",
                volatile_val.unwrap_or("")
            );
            config.var.mount = Some(MountType::None);
        }
        config
    };

    let composefs_info = ComposefsCmdline::<Sha512HashValue>::from_cmdline(&cmdline)
        .context("Failed to parse composefs cmdline")?
        .ok_or_else(|| anyhow::anyhow!("No composefs image in cmdline"))?;

    let new_root = match &args.root_fs {
        Some(path) => open_root_fs(path).context("Failed to clone specified root fs")?,
        None => mount_composefs_image(
            &sysroot,
            &composefs_info.digest().to_hex(),
            composefs_info.is_insecure(),
        )?,
    };

    // we need to clone this before the next step to make sure we get the old one
    let sysroot_clone = bind_mount(&sysroot, "")?;

    set_mount_readonly(&sysroot_clone)?;

    let mount_target = args.target.unwrap_or(args.sysroot.clone());

    // Ideally we build the new root filesystem together before we mount it, but that only works on
    // 6.15 and later.  Before 6.15 we can't mount into a floating tree, so mount it first.  This
    // will leave an abandoned clone of the sysroot mounted under it, but that's OK for now.
    if cfg!(feature = "pre-6.15") {
        mount_at_wrapper(&new_root, CWD, &mount_target)?;
    }

    // When transient root is enabled, place an overlay on top of the composefs.
    // On pre-6.15, since the composefs is already attached at `mount_target`,
    // the overlay is also immediately attached there.  We then open the overlay
    // via its path so that subsequent mounts target the visible merged tree.
    //
    // On 6.15+, the whole tree is assembled in floating mode; `overlay_transient`
    // returns a detached overlay fd that we can directly mount into.
    //
    // `new_root` always refers to the composefs fd; mounting via it after the
    // overlay is in place would land in the hidden lower layer.
    let transient_overlay_fd: Option<OwnedFd> = if config.root.transient {
        let overlay_fd = overlay_transient(
            &new_root,
            &format!("transient:composefs={}", composefs_info.digest().to_hex()),
            None,
        )?;

        if cfg!(feature = "pre-6.15") {
            // In pre-6.15, the composefs is already attached at `mount_target`.
            // Attach the overlay on top of it, then reopen the path to get a
            // dirfd that resolves through the overlay (not the hidden composefs).
            mount_at_wrapper(&overlay_fd, CWD, &mount_target)
                .context("Moving transient overlay onto sysroot")?;
            Some(open_dir(CWD, &mount_target).context("Opening attached overlay root")?)
        } else {
            // On 6.15+ we assemble in floating mode; use the detached overlay fd
            // directly for subsequent mounts into the tree.
            Some(overlay_fd)
        }
    } else {
        None
    };

    // When transient root is active the overlay sits on top of the composefs.
    // Mounts placed via `new_root` would land in the composefs lower layer and
    // be invisible from the running system.  Use the overlay fd for all
    // post-overlay mounts (sysroot, etc, var) so they appear in the merged view.
    let visible_root: &dyn AsFd = transient_overlay_fd
        .as_ref()
        .map_or(&new_root as &dyn AsFd, |fd| fd as &dyn AsFd);

    // Mount the physical sysroot (with the composefs repo) into the new root
    // so that `bootc status` and other tools can find it after switch-root.
    match composefs::mount::mount_at(&sysroot_clone, visible_root, "sysroot") {
        Ok(()) | Err(Errno::NOENT) => {}
        Err(err) => Err(err)?,
    }

    // etc + var
    let state = open_dir(
        open_dir(&sysroot, "state/deploy")?,
        composefs_info.digest().to_hex(),
    )?;
    mount_subdir(visible_root, &state, "etc", config.etc, MountType::Bind)?;
    // /var is bind-mounted from the deployment state directory by default.
    // The systemd.volatile=state cmdline detection above (or an explicit
    // [var] mount = "none" in setup-root-conf.toml) can change this to
    // MountType::None, which skips the bind-mount entirely and leaves /var
    // as an empty directory from the composefs image for systemd to fill.
    mount_subdir(visible_root, &state, "var", config.var, MountType::Bind)?;

    if cfg!(not(feature = "pre-6.15")) {
        // Replace the /sysroot with the new composed root filesystem.
        // When a transient overlay is active, mount it rather than the bare
        // composefs so the running system sees the writable merged view.
        unmount(&args.sysroot, UnmountFlags::DETACH)?;
        mount_at_wrapper(visible_root, CWD, &mount_target)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml: &str) -> Config {
        toml::from_str(toml).expect("TOML parse failed")
    }

    #[test]
    fn test_config_defaults() {
        let config = parse("");
        assert_eq!(
            config,
            Config {
                etc: MountConfig {
                    mount: None,
                    transient: false
                },
                var: MountConfig {
                    mount: None,
                    transient: false
                },
                root: RootConfig { transient: false },
            }
        );
    }

    #[test]
    fn test_mounttype_none() {
        let config = parse("[etc]\nmount = \"none\"");
        assert_eq!(config.etc.mount, Some(MountType::None));
    }

    #[test]
    fn test_mounttype_root_alias() {
        let config = parse("[etc]\nmount = \"root\"");
        assert_eq!(config.etc.mount, Some(MountType::None));
    }

    #[test]
    fn test_etc_transient_flag() {
        let config = parse("[etc]\ntransient = true");
        assert_eq!(config.etc.transient, true);
        assert_eq!(config.etc.mount, None);
    }

    #[test]
    fn test_var_none() {
        // mount = "none" skips the state bind-mount; combine with
        // systemd.volatile=state karg to get a fresh tmpfs on every boot.
        let config = parse("[var]\nmount = \"none\"");
        assert_eq!(config.var.mount, Some(MountType::None));
    }

    #[test]
    fn test_root_transient() {
        let config = parse("[root]\ntransient = true");
        assert_eq!(config.root.transient, true);
    }

    #[test]
    fn test_combined_config() {
        let config = parse("[root]\ntransient = true\n[etc]\nmount = \"root\"");
        assert_eq!(config.root.transient, true);
        assert_eq!(config.etc.mount, Some(MountType::None));
    }
}
