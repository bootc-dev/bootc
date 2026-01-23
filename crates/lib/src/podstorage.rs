//! # bootc-managed instance of containers-storage:
//!
//! The backend for podman and other tools is known as `container-storage:`,
//! with a canonical instance that lives in `/var/lib/containers`.
//!
//! This is a `containers-storage:` instance` which is owned by bootc and
//! is stored at `/sysroot/ostree/bootc`.
//!
//! At the current time, this is only used for Logically Bound Images.

use std::collections::HashSet;
use std::io::{Seek, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::Arc;

use anyhow::{Context, Result};
use bootc_utils::{AsyncCommandRunExt, CommandRunExt, ExitStatusExt};
use camino::{Utf8Path, Utf8PathBuf};
use cap_std_ext::cap_std::fs::Dir;
use cap_std_ext::cap_tempfile::TempDir;
use cap_std_ext::cmdext::CapStdExtCommandExt;
use cap_std_ext::dirext::CapStdExtDirExt;
use cap_std_ext::{cap_std, cap_tempfile};
use fn_error_context::context;
use ostree_ext::ostree::{self};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use tokio::process::Command as AsyncCommand;

// Pass only 100 args at a time just to avoid potentially overflowing argument
// vectors; not that this should happen in reality, but just in case.
const SUBCMD_ARGV_CHUNKING: usize = 100;

/// Global directory path which we use for podman to point
/// it at our storage. Unfortunately we can't yet use the
/// /proc/self/fd/N trick because it currently breaks due
/// to how the untar process is forked in the child.
pub(crate) const STORAGE_ALIAS_DIR: &str = "/run/bootc/storage";
/// We pass this via /proc/self/fd to the child process.
const STORAGE_RUN_FD: i32 = 3;

const LABELED: &str = ".bootc_labeled";

/// The path to the image storage, relative to the bootc root directory.
pub(crate) const SUBPATH: &str = "storage";
/// The path to the "runroot" with transient runtime state; this is
/// relative to the /run directory
const RUNROOT: &str = "bootc/storage";

/// A bootc-owned instance of `containers-storage:`.
pub(crate) struct CStorage {
    /// The root directory
    sysroot: Dir,
    /// The location of container storage
    storage_root: Dir,
    #[allow(dead_code)]
    /// Our runtime state
    run: Dir,
    /// Disallow using this across multiple threads concurrently; while we
    /// have internal locking in podman, in the future we may change how
    /// things work here. And we don't have a use case right now for
    /// concurrent operations.
    _unsync: std::cell::Cell<()>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PullMode {
    /// Pull only if the image is not present
    IfNotExists,
    /// Always check for an update
    #[allow(dead_code)]
    Always,
}

#[allow(unsafe_code)]
#[context("Binding storage roots")]
fn bind_storage_roots(cmd: &mut Command, storage_root: &Dir, run_root: &Dir) -> Result<()> {
    // podman requires an absolute path, for two reasons right now:
    // - It writes the file paths into `db.sql`, a sqlite database for unknown reasons
    // - It forks helper binaries, so just giving it /proc/self/fd won't work as
    //   those helpers may not get the fd passed. (which is also true of skopeo)
    // We create a new mount namespace, which also has the helpful side effect
    // of automatically cleaning up the global bind mount that the storage stack
    // creates.

    let storage_root = Arc::new(storage_root.try_clone().context("Cloning storage root")?);
    let run_root: Arc<OwnedFd> = Arc::new(run_root.try_clone().context("Cloning runroot")?.into());
    // SAFETY: All the APIs we call here are safe to invoke between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            use rustix::fs::{Mode, OFlags};
            // For reasons I don't understand, we can't just `mount("/proc/self/fd/N", "/path/to/target")`
            // but it *does* work to fchdir(fd) + mount(".", "/path/to/target").
            // I think it may be that mount doesn't like operating on the magic links?
            // This trick only works if we set our working directory to the target *before*
            // creating the new namespace too.
            //
            // I think we may be hitting this:
            //
            // "       EINVAL A bind operation (MS_BIND) was requested where source referred a mount namespace magic link (i.e., a /proc/pid/ns/mnt magic link or a bind mount to such a link) and the propagation type of the parent mount of target was
            // MS_SHARED, but propagation of the requested bind mount could lead to a circular dependency that might prevent the mount namespace from ever being freed."
            //
            // But...how did we avoid that circular dependency by using the process cwd?
            //
            // I tried making the mounts recursively private, but that didn't help.
            let oldwd = rustix::fs::open(
                ".",
                OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::RDONLY,
                Mode::empty(),
            )?;
            rustix::process::fchdir(&storage_root)?;
            rustix::thread::unshare_unsafe(rustix::thread::UnshareFlags::NEWNS)?;
            rustix::mount::mount_bind(".", STORAGE_ALIAS_DIR)?;
            rustix::process::fchdir(&oldwd)?;
            Ok(())
        })
    };
    cmd.take_fd_n(run_root, STORAGE_RUN_FD);
    Ok(())
}

// Initialize a `podman` subprocess with:
// - storage overridden to point to to storage_root
// - Authentication (auth.json) using the bootc/ostree owned auth
fn new_podman_cmd_in(sysroot: &Dir, storage_root: &Dir, run_root: &Dir) -> Result<Command> {
    let mut cmd = Command::new("podman");
    bind_storage_roots(&mut cmd, storage_root, run_root)?;
    let run_root = format!("/proc/self/fd/{STORAGE_RUN_FD}");
    cmd.args(["--root", STORAGE_ALIAS_DIR, "--runroot", run_root.as_str()]);

    let tmpd = &cap_std::fs::Dir::open_ambient_dir("/tmp", cap_std::ambient_authority())?;
    let mut tempfile = cap_tempfile::TempFile::new_anonymous(tmpd).map(std::io::BufWriter::new)?;

    // Keep this in sync with https://github.com/bootc-dev/containers-image-proxy-rs/blob/b5e0861ad5065f47eaf9cda0d48da3529cc1bc43/src/imageproxy.rs#L310
    // We always override the auth to match the bootc setup.
    let authfile_fd = ostree_ext::globals::get_global_authfile(sysroot)?.map(|v| v.1);
    if let Some(mut fd) = authfile_fd {
        std::io::copy(&mut fd, &mut tempfile)?;
    } else {
        // Note that if there's no bootc-owned auth, then we force an empty authfile to ensure
        // that podman doesn't fall back to searching the user-owned paths.
        tempfile.write_all(b"{}")?;
    }

    let tempfile = tempfile
        .into_inner()
        .map_err(|e| e.into_error())?
        .into_std();
    let fd: Arc<OwnedFd> = std::sync::Arc::new(tempfile.into());
    let target_fd = fd.as_fd().as_raw_fd();
    cmd.take_fd_n(fd, target_fd);
    cmd.env("REGISTRY_AUTH_FILE", format!("/proc/self/fd/{target_fd}"));

    Ok(cmd)
}

/// Adjust the provided command (skopeo or podman e.g.) to reference
/// the provided path as an additional image store.
pub fn set_additional_image_store<'c>(
    cmd: &'c mut Command,
    ais: impl AsRef<Utf8Path>,
) -> &'c mut Command {
    let ais = ais.as_ref();
    let storage_opt = format!("additionalimagestore={ais}");
    cmd.env("STORAGE_OPTS", storage_opt)
}

/// Ensure that "podman" is the first thing to touch the global storage
/// instance. This is a workaround for <https://github.com/bootc-dev/bootc/pull/1101#issuecomment-2653862974>
/// Basically podman has special upgrade logic for when it is the first thing
/// to initialize the c/storage instance it sets the networking to netavark.
/// If it's not the first thing, then it assumes an upgrade scenario and we
/// may be using CNI.
///
/// But this legacy path is triggered through us using skopeo, turning off netavark
/// by default. Work around this by ensuring that /usr/bin/podman is
/// always the first thing to touch c/storage (at least, when invoked by us).
///
/// Call this function any time we're going to write to containers-storage.
pub(crate) fn ensure_floating_c_storage_initialized() {
    if let Err(e) = Command::new("podman")
        .args(["system", "info"])
        .stdout(Stdio::null())
        .run_capture_stderr()
    {
        // Out of conservatism we don't make this operation fatal right now.
        // If something went wrong, then we'll probably fail on a later operation
        // anyways.
        tracing::warn!("Failed to query podman system info: {e}");
    }
}

impl CStorage {
    /// Create a `podman image` Command instance prepared to operate on our alternative
    /// root.
    pub(crate) fn new_image_cmd(&self) -> Result<Command> {
        let mut r = new_podman_cmd_in(&self.sysroot, &self.storage_root, &self.run)?;
        // We want to limit things to only manipulating images by default.
        r.arg("image");
        Ok(r)
    }

    fn init_globals() -> Result<()> {
        // Ensure our global storage alias dir exists
        std::fs::create_dir_all(STORAGE_ALIAS_DIR)
            .with_context(|| format!("Creating {STORAGE_ALIAS_DIR}"))?;
        Ok(())
    }

    /// Ensure that the LSM (SELinux) labels are set on the bootc-owned
    /// containers-storage: instance. We use a `LABELED` stamp file for
    /// idempotence.
    #[context("Labeling imgstorage dirs")]
    fn ensure_labeled(root: &Dir, sepolicy: Option<&ostree::SePolicy>) -> Result<()> {
        if root.try_exists(LABELED)? {
            return Ok(());
        }
        let Some(sepolicy) = sepolicy else {
            return Ok(());
        };

        // recursively set the labels because they were previously set to usr_t,
        // and there is no policy defined to set them to the c/storage labels
        crate::lsm::relabel_recurse(
            &root,
            ".",
            Some(Utf8Path::new("/var/lib/containers/storage")),
            sepolicy,
        )
        .context("labeling storage root")?;

        root.create(LABELED)?;

        Ok(())
    }

    #[context("Creating imgstorage")]
    pub(crate) fn create(
        sysroot: &Dir,
        run: &Dir,
        sepolicy: Option<&ostree::SePolicy>,
    ) -> Result<Self> {
        Self::init_globals()?;
        let subpath = &Self::subpath();

        // SAFETY: We know there's a parent
        let parent = subpath.parent().unwrap();
        let tmp = format!("{subpath}.tmp");
        if !sysroot
            .try_exists(subpath)
            .with_context(|| format!("Querying {subpath}"))?
        {
            sysroot.remove_all_optional(&tmp).context("Removing tmp")?;
            sysroot
                .create_dir_all(parent)
                .with_context(|| format!("Creating {parent}"))?;
            sysroot.create_dir_all(&tmp).context("Creating tmpdir")?;
            let storage_root = sysroot.open_dir(&tmp).context("Open tmp")?;

            // There's no explicit API to initialize a containers-storage:
            // root, simply passing a path will attempt to auto-create it.
            // We run "podman images" in the new root.
            new_podman_cmd_in(&sysroot, &storage_root, &run)?
                .stdout(Stdio::null())
                .arg("images")
                .run_capture_stderr()
                .context("Initializing images")?;
            Self::ensure_labeled(&storage_root, sepolicy)?;
            drop(storage_root);
            sysroot
                .rename(&tmp, sysroot, subpath)
                .context("Renaming tmpdir")?;
            tracing::debug!("Created image store");
        } else {
            // the storage already exists, make sure it has selinux labels
            let storage_root = sysroot.open_dir(subpath).context("opening storage dir")?;
            Self::ensure_labeled(&storage_root, sepolicy)?;
        }

        Self::open(sysroot, run)
    }

    #[context("Opening imgstorage")]
    pub(crate) fn open(sysroot: &Dir, run: &Dir) -> Result<Self> {
        tracing::trace!("Opening container image store");
        Self::init_globals()?;
        let subpath = &Self::subpath();
        let storage_root = sysroot
            .open_dir(subpath)
            .with_context(|| format!("Opening {subpath}"))?;
        // Always auto-create this if missing
        run.create_dir_all(RUNROOT)
            .with_context(|| format!("Creating {RUNROOT}"))?;
        let run = run.open_dir(RUNROOT)?;
        Ok(Self {
            sysroot: sysroot.try_clone()?,
            storage_root,
            run,
            _unsync: Default::default(),
        })
    }

    #[context("Listing images")]
    pub(crate) async fn list_images(&self) -> Result<Vec<crate::podman::ImageListEntry>> {
        let mut cmd = self.new_image_cmd()?;
        cmd.args(["list", "--format=json"]);
        cmd.stdin(Stdio::null());
        // It's maximally convenient for us to just pipe the whole output to a tempfile
        let mut stdout = tempfile::tempfile()?;
        cmd.stdout(stdout.try_clone()?);
        // Allocate stderr, which is passed to the status checker
        let stderr = tempfile::tempfile()?;
        cmd.stderr(stderr.try_clone()?);

        // Spawn the child and wait
        AsyncCommand::from(cmd)
            .status()
            .await?
            .check_status_with_stderr(stderr)?;
        // Spawn a helper thread to avoid blocking the main thread
        // parsing JSON.
        tokio::task::spawn_blocking(move || -> Result<_> {
            stdout.seek(std::io::SeekFrom::Start(0))?;
            let stdout = std::io::BufReader::new(stdout);
            let r = serde_json::from_reader(stdout)?;
            Ok(r)
        })
        .await?
    }

    #[context("Pruning")]
    pub(crate) async fn prune_except_roots(&self, roots: &HashSet<&str>) -> Result<Vec<String>> {
        let all_images = self.list_images().await?;
        tracing::debug!("Images total: {}", all_images.len(),);
        let mut garbage = Vec::new();
        for image in all_images {
            if image
                .names
                .iter()
                .flatten()
                .all(|name| !roots.contains(name.as_str()))
            {
                garbage.push(image.id);
            }
        }
        tracing::debug!("Images to prune: {}", garbage.len());
        for garbage in garbage.chunks(SUBCMD_ARGV_CHUNKING) {
            let mut cmd = self.new_image_cmd()?;
            cmd.stdin(Stdio::null());
            cmd.stdout(Stdio::null());
            cmd.arg("rm");
            cmd.args(garbage);
            AsyncCommand::from(cmd).run().await?;
        }
        Ok(garbage)
    }

    /// Return true if the image exists in the storage.
    pub(crate) async fn exists(&self, image: &str) -> Result<bool> {
        // Sadly https://docs.rs/containers-image-proxy/latest/containers_image_proxy/struct.ImageProxy.html#method.open_image_optional
        // doesn't work with containers-storage yet
        let mut cmd = AsyncCommand::from(self.new_image_cmd()?);
        cmd.args(["exists", image]);
        Ok(cmd.status().await?.success())
    }

    /// Fetch the image if it is not already present; return whether
    /// or not the image was fetched.
    pub(crate) async fn pull(&self, image: &str, mode: PullMode) -> Result<bool> {
        match mode {
            PullMode::IfNotExists => {
                if self.exists(image).await? {
                    tracing::debug!("Image is already present: {image}");
                    return Ok(false);
                }
            }
            PullMode::Always => {}
        };
        let mut cmd = self.new_image_cmd()?;
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::null());
        cmd.args(["pull", image]);
        tracing::debug!("Pulling image: {image}");
        let mut cmd = AsyncCommand::from(cmd);
        cmd.run().await.context("Failed to pull image")?;
        Ok(true)
    }

    /// Copy an image from the default container storage (/var/lib/containers/)
    /// to this storage.
    #[context("Pulling from host storage: {image}")]
    pub(crate) async fn pull_from_host_storage(&self, image: &str) -> Result<()> {
        let mut cmd = Command::new("podman");
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::null());
        // An ephemeral place for the transient state;
        let temp_runroot = TempDir::new(cap_std::ambient_authority())?;
        bind_storage_roots(&mut cmd, &self.storage_root, &temp_runroot)?;

        // The destination (target stateroot) + container storage dest
        let storage_dest = &format!(
            "containers-storage:[overlay@{STORAGE_ALIAS_DIR}+/proc/self/fd/{STORAGE_RUN_FD}]"
        );
        cmd.args(["image", "push", "--remove-signatures", image])
            .arg(format!("{storage_dest}{image}"));
        let mut cmd = AsyncCommand::from(cmd);
        cmd.run().await?;
        temp_runroot.close()?;
        Ok(())
    }

    pub(crate) fn subpath() -> Utf8PathBuf {
        Utf8Path::new(crate::store::BOOTC_ROOT).join(SUBPATH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    static_assertions::assert_not_impl_any!(CStorage: Sync);
}
