//! Mount helpers for bootc-initramfs

use std::{
    ffi::OsString,
    fmt::Debug,
    io::ErrorKind,
    os::fd::{AsFd, OwnedFd},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::Parser;
use rustix::{
    fs::{major, minor, mkdirat, openat, stat, symlink, Mode, OFlags, CWD},
    io::Errno,
    mount::{
        fsconfig_create, fsconfig_set_string, fsmount, open_tree, unmount, FsMountFlags,
        MountAttrFlags, OpenTreeFlags, UnmountFlags,
    },
    path,
};
use serde::Deserialize;

use composefs::{
    fsverity::{FsVerityHashValue, Sha256HashValue},
    mount::FsHandle,
    mountcompat::{overlayfs_set_fd, overlayfs_set_lower_and_data_fds, prepare_mount},
    repository::Repository,
};
use composefs_boot::cmdline::get_cmdline_composefs;

use fn_error_context::context;

// Config file
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum MountType {
    None,
    Bind,
    Overlay,
    Transient,
}

#[derive(Debug, Default, Deserialize)]
struct RootConfig {
    #[serde(default)]
    transient: bool,
}

#[derive(Debug, Default, Deserialize)]
struct MountConfig {
    mount: Option<MountType>,
    #[serde(default)]
    transient: bool,
}

#[derive(Deserialize, Default)]
struct Config {
    #[serde(default)]
    etc: MountConfig,
    #[serde(default)]
    var: MountConfig,
    #[serde(default)]
    root: RootConfig,
}

/// Command-line arguments
#[derive(Parser, Debug)]
#[command(version)]
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
    pub cmdline: Option<String>,

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

/// Wrapper around [`rustix::openat`]
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
fn ensure_dir(dirfd: impl AsFd, name: &str) -> Result<OwnedFd> {
    match mkdirat(dirfd.as_fd(), name, 0o700.into()) {
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

#[context("Mounting tmpfs")]
fn mount_tmpfs() -> Result<OwnedFd> {
    let tmpfs = FsHandle::open("tmpfs")?;
    fsconfig_create(tmpfs.as_fd())?;
    Ok(fsmount(
        tmpfs.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::empty(),
    )?)
}

#[context("Mounting state as overlay")]
fn overlay_state(base: impl AsFd, state: impl AsFd, source: &str) -> Result<()> {
    let upper = ensure_dir(state.as_fd(), "upper")?;
    let work = ensure_dir(state.as_fd(), "work")?;

    let overlayfs = FsHandle::open("overlay")?;
    fsconfig_set_string(overlayfs.as_fd(), "source", source)?;
    overlayfs_set_fd(overlayfs.as_fd(), "workdir", work.as_fd())?;
    overlayfs_set_fd(overlayfs.as_fd(), "upperdir", upper.as_fd())?;
    overlayfs_set_lower_and_data_fds(&overlayfs, base.as_fd(), None::<OwnedFd>)?;
    fsconfig_create(overlayfs.as_fd())?;
    let fs = fsmount(
        overlayfs.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::empty(),
    )?;

    mount_at_wrapper(fs, base, ".").context("Moving mount")
}

fn overlay_transient(base: impl AsFd) -> Result<()> {
    overlay_state(base, prepare_mount(mount_tmpfs()?)?, "transient")
}

#[context("Opening rootfs")]
fn open_root_fs(path: &Path) -> Result<OwnedFd> {
    let rootfs = open_tree(
        CWD,
        path,
        OpenTreeFlags::OPEN_TREE_CLONE | OpenTreeFlags::OPEN_TREE_CLOEXEC,
    )?;

    // https://github.com/bytecodealliance/rustix/issues/975
    // mount_setattr(rootfs.as_fd()), ..., { ... MountAttrFlags::MOUNT_ATTR_RDONLY ... }, ...)?;

    Ok(rootfs)
}

/// Prepares a floating mount for composefs and returns the fd
///
/// # Arguments
/// * sysroot  - fd for /sysroot
/// * name     - Name of the EROFS image to be mounted
/// * insecure - Whether fsverity is optional or not
#[context("Mounting composefs image")]
pub fn mount_composefs_image(sysroot: &OwnedFd, name: &str, insecure: bool) -> Result<OwnedFd> {
    let mut repo = Repository::<Sha256HashValue>::open_path(sysroot, "composefs")?;
    repo.set_insecure(insecure);
    repo.mount(name).context("Failed to mount composefs image")
}

#[context("Mounting subdirectory")]
fn mount_subdir(
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
        ),
        MountType::Transient => overlay_transient(open_dir(&new_root, subdir)?),
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
    symlink(target, "/run/systemd/volatile-root")?;
    Ok(())
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

    let cmdline = match &args.cmdline {
        Some(cmdline) => cmdline,
        // TODO: Deduplicate this with composefs branch karg parser
        None => &std::fs::read_to_string("/proc/cmdline")?,
    };
    let (image, insecure) = get_cmdline_composefs::<Sha256HashValue>(cmdline)?;

    let new_root = match args.root_fs {
        Some(path) => open_root_fs(&path).context("Failed to clone specified root fs")?,
        None => mount_composefs_image(&sysroot, &image.to_hex(), insecure)?,
    };

    // we need to clone this before the next step to make sure we get the old one
    let sysroot_clone = bind_mount(&sysroot, "")?;

    // Ideally we build the new root filesystem together before we mount it, but that only works on
    // 6.15 and later.  Before 6.15 we can't mount into a floating tree, so mount it first.  This
    // will leave an abandoned clone of the sysroot mounted under it, but that's OK for now.
    if cfg!(feature = "pre-6.15") {
        mount_at_wrapper(&new_root, CWD, &args.sysroot)?;
    }

    if config.root.transient {
        overlay_transient(&new_root)?;
    }

    match composefs::mount::mount_at(&sysroot_clone, &new_root, "sysroot") {
        Ok(()) | Err(Errno::NOENT) => {}
        Err(err) => Err(err)?,
    }

    // etc + var
    let state = open_dir(open_dir(&sysroot, "state/deploy")?, image.to_hex())?;
    mount_subdir(&new_root, &state, "etc", config.etc, MountType::Bind)?;
    mount_subdir(&new_root, &state, "var", config.var, MountType::Bind)?;

    if cfg!(not(feature = "pre-6.15")) {
        // Replace the /sysroot with the new composed root filesystem
        unmount(&args.sysroot, UnmountFlags::DETACH)?;
        mount_at_wrapper(&new_root, CWD, &args.sysroot)?;
    }

    Ok(())
}
