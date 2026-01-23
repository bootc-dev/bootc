//! This module handles finishing/completion after an ostree-based
//! install from e.g. Anaconda.

use std::io;
use std::os::fd::AsFd;
use std::process::Command;

use anyhow::{Context, Result};
use bootc_utils::CommandRunExt;
use camino::Utf8Path;
use cap_std_ext::{cap_std::fs::Dir, dirext::CapStdExtDirExt};
use fn_error_context::context;
use ostree_ext::{gio, ostree};
use rustix::fs::Mode;
use rustix::fs::OFlags;

use crate::podstorage::CStorage;
use crate::utils::deployment_fd;

use super::config;

/// An environment variable set by anaconda that hints
/// we are running as part of that environment.
const ANACONDA_ENV_HINT: &str = "ANA_INSTALL_PATH";
/// The path where Anaconda sets up the target.
/// <https://anaconda-installer.readthedocs.io/en/latest/mount-points.html#mnt-sysroot>
const ANACONDA_SYSROOT: &str = "mnt/sysroot";
/// Global flag to signal we're in a booted ostree system
const OSTREE_BOOTED: &str = "run/ostree-booted";
/// The very well-known DNS resolution file
const RESOLVCONF: &str = "etc/resolv.conf";
/// A renamed file
const RESOLVCONF_ORIG: &str = "etc/resolv.conf.bootc-original";
/// The root filesystem for pid 1
const PROC1_ROOT: &str = "proc/1/root";
/// The cgroupfs mount point, which we may propagate from the host if needed
const CGROUPFS: &str = "sys/fs/cgroup";
/// The path to the temporary global ostree pull secret
const RUN_OSTREE_AUTH: &str = "run/ostree/auth.json";
/// A sub path of /run which is used to ensure idempotency
pub(crate) const RUN_BOOTC_INSTALL_RECONCILED: &str = "run/bootc-install-reconciled";

/// Assuming that the current root is an ostree deployment, pull kargs
/// from it and inject them.
fn reconcile_kargs(sysroot: &ostree::Sysroot, deployment: &ostree::Deployment) -> Result<()> {
    let deployment_root = &crate::utils::deployment_fd(sysroot, deployment)?;
    let cancellable = gio::Cancellable::NONE;

    let current_kargs = deployment
        .bootconfig()
        .expect("bootconfig for deployment")
        .get("options");
    let current_kargs = current_kargs
        .as_ref()
        .map(|s| s.as_str())
        .unwrap_or_default();
    tracing::debug!("current_kargs={current_kargs}");
    let current_kargs = ostree::KernelArgs::from_string(&current_kargs);

    // Keep this in sync with install_container
    let install_config = config::load_config()?;
    let install_config_kargs = install_config
        .as_ref()
        .and_then(|c| c.kargs.as_ref())
        .into_iter()
        .flatten()
        .map(|s| s.as_str())
        .collect::<Vec<_>>();
    let kargsd = crate::bootc_kargs::get_kargs_in_root(deployment_root, std::env::consts::ARCH)?;
    let kargsd_strs = kargsd.iter_str().collect::<Vec<_>>();

    current_kargs.append_argv(&install_config_kargs);
    current_kargs.append_argv(&kargsd_strs);
    let new_kargs = current_kargs.to_string();
    tracing::debug!("new_kargs={new_kargs}");

    sysroot.deployment_set_kargs_in_place(deployment, Some(&new_kargs), cancellable)?;
    Ok(())
}

/// A little helper struct which on drop renames a file. Used for putting back /etc/resolv.conf.
#[must_use]
struct Renamer<'d> {
    dir: &'d Dir,
    from: &'static Utf8Path,
    to: &'static Utf8Path,
}

impl Renamer<'_> {
    fn _impl_drop(&mut self) -> Result<()> {
        self.dir
            .rename(self.from, self.dir, self.to)
            .map_err(Into::into)
    }

    fn consume(mut self) -> Result<()> {
        self._impl_drop()
    }
}

impl Drop for Renamer<'_> {
    fn drop(&mut self) {
        let _ = self._impl_drop();
    }
}
/// Work around <https://github.com/containers/buildah/issues/4242#issuecomment-2492480586>
/// among other things. We unconditionally replace the contents of `/etc/resolv.conf`
/// in the target root with whatever the host uses (in Fedora 41+, that's systemd-resolved for Anaconda).
#[context("Copying host resolv.conf")]
fn ensure_resolvconf<'d>(rootfs: &'d Dir, proc1_root: &Dir) -> Result<Option<Renamer<'d>>> {
    // Now check the state of etc/resolv.conf in the target root
    let meta = rootfs
        .symlink_metadata_optional(RESOLVCONF)
        .context("stat")?;
    let renamer = if meta.is_some() {
        rootfs
            .rename(RESOLVCONF, &rootfs, RESOLVCONF_ORIG)
            .context("Renaming")?;
        Some(Renamer {
            dir: &rootfs,
            from: RESOLVCONF_ORIG.into(),
            to: RESOLVCONF.into(),
        })
    } else {
        None
    };
    // If we got here, /etc/resolv.conf either didn't exist or we removed it.
    // Copy the host data into it (note this will follow symlinks; e.g.
    // Anaconda in Fedora 41+ defaults to systemd-resolved)
    proc1_root
        .copy(RESOLVCONF, rootfs, RESOLVCONF)
        .context("Copying new resolv.conf")?;
    Ok(renamer)
}

/// Bind a mount point from the host namespace into our root
fn bind_from_host(
    rootfs: &Dir,
    src: impl AsRef<Utf8Path>,
    target: impl AsRef<Utf8Path>,
) -> Result<()> {
    fn bind_from_host_impl(rootfs: &Dir, src: &Utf8Path, target: &Utf8Path) -> Result<()> {
        rootfs.create_dir_all(target)?;
        if rootfs.is_mountpoint(target)?.unwrap_or_default() {
            return Ok(());
        }
        let target = format!("/{ANACONDA_SYSROOT}/{target}");
        tracing::debug!("Binding {src} to {target}");
        // We're run in a mount namespace, but not a pid namespace; use nsenter
        // via the pid namespace to escape to the host's mount namespace and
        // perform a mount there.
        Command::new("nsenter")
            .args(["-m", "-t", "1", "--", "mount", "--bind"])
            .arg(src)
            .arg(&target)
            .run_capture_stderr()?;
        Ok(())
    }

    bind_from_host_impl(rootfs, src.as_ref(), target.as_ref())
}

/// Anaconda doesn't mount /sys/fs/cgroup in /mnt/sysroot
#[context("Ensuring cgroupfs")]
fn ensure_cgroupfs(rootfs: &Dir) -> Result<()> {
    bind_from_host(rootfs, CGROUPFS, CGROUPFS)
}

/// If we have /etc/ostree/auth.json in the Anaconda environment then propagate
/// it into /run/ostree/auth.json
#[context("Propagating ostree auth")]
fn ensure_ostree_auth(rootfs: &Dir, host_root: &Dir) -> Result<()> {
    let Some((authpath, authfd)) =
        ostree_ext::globals::get_global_authfile(&host_root).context("Querying authfiles")?
    else {
        tracing::debug!("No auth found in host");
        return Ok(());
    };
    tracing::debug!("Discovered auth in host: {authpath}");
    let mut authfd = io::BufReader::new(authfd);
    let run_ostree_auth = Utf8Path::new(RUN_OSTREE_AUTH);
    rootfs.create_dir_all(run_ostree_auth.parent().unwrap())?;
    rootfs.atomic_replace_with(run_ostree_auth, |w| std::io::copy(&mut authfd, w))?;
    Ok(())
}

#[context("Opening {PROC1_ROOT}")]
fn open_proc1_root(rootfs: &Dir) -> Result<Dir> {
    let proc1_root = rustix::fs::openat(
        &rootfs.as_fd(),
        PROC1_ROOT,
        OFlags::CLOEXEC | OFlags::DIRECTORY,
        Mode::empty(),
    )?;
    Dir::reopen_dir(&proc1_root.as_fd()).map_err(Into::into)
}

/// Core entrypoint invoked when we are likely being invoked from inside Anaconda as a `%post`.
pub(crate) async fn run_from_anaconda(rootfs: &Dir) -> Result<()> {
    // unshare our mount namespace, so any *further* mounts aren't leaked.
    // Note that because this does a re-exec, anything *before* this point
    // should be idempotent.
    crate::cli::require_root(false)?;
    crate::cli::ensure_self_unshared_mount_namespace()?;

    if std::env::var_os(ANACONDA_ENV_HINT).is_none() {
        anyhow::bail!("Missing environment variable {ANACONDA_ENV_HINT}");
    } else {
        // In the way Anaconda sets up the bind mounts today, this doesn't exist. Later
        // code expects it to exist, so do so.
        if !rootfs.try_exists(OSTREE_BOOTED)? {
            tracing::debug!("Writing {OSTREE_BOOTED}");
            rootfs.atomic_write(OSTREE_BOOTED, b"")?;
        }
    }

    // Get access to the real root by opening /proc/1/root
    let proc1_root = &open_proc1_root(rootfs)?;

    if proc1_root
        .try_exists(RUN_BOOTC_INSTALL_RECONCILED)
        .context("Querying reconciliation")?
    {
        println!("Reconciliation already completed.");
        return Ok(());
    }

    ensure_cgroupfs(rootfs)?;
    // Sometimes Anaconda may not initialize networking in the target root?
    let resolvconf = ensure_resolvconf(rootfs, proc1_root)?;
    // Propagate an injected authfile for pulling logically bound images
    ensure_ostree_auth(rootfs, proc1_root)?;

    let sysroot = ostree::Sysroot::new(Some(&gio::File::for_path("/")));
    sysroot
        .load(gio::Cancellable::NONE)
        .context("Loading sysroot")?;
    impl_completion(rootfs, &sysroot, None).await?;

    proc1_root
        .write(RUN_BOOTC_INSTALL_RECONCILED, b"")
        .with_context(|| format!("Writing {RUN_BOOTC_INSTALL_RECONCILED}"))?;
    if let Some(resolvconf) = resolvconf {
        resolvconf.consume()?;
    }
    Ok(())
}

/// From ostree-rs-ext, run through the rest of bootc install functionality
pub async fn run_from_ostree(rootfs: &Dir, sysroot: &Utf8Path, stateroot: &str) -> Result<()> {
    crate::cli::require_root(false)?;
    // Load sysroot from the provided path
    let sysroot = ostree::Sysroot::new(Some(&gio::File::for_path(sysroot)));
    sysroot.load(gio::Cancellable::NONE)?;

    impl_completion(rootfs, &sysroot, Some(stateroot)).await?;

    // In this case we write the completion directly to /run as we're running from
    // the host context.
    rootfs
        .write(RUN_BOOTC_INSTALL_RECONCILED, b"")
        .with_context(|| format!("Writing {RUN_BOOTC_INSTALL_RECONCILED}"))?;
    Ok(())
}

/// Core entrypoint for completion of an ostree-based install to a bootc one:
///
/// - kernel argument handling
/// - logically bound images
///
/// We could also do other things here, such as write an aleph file or
/// ensure the repo config is synchronized, but these two are the most important
/// for now.
pub(crate) async fn impl_completion(
    rootfs: &Dir,
    sysroot: &ostree::Sysroot,
    stateroot: Option<&str>,
) -> Result<()> {
    // Log the completion operation to systemd journal
    const COMPLETION_JOURNAL_ID: &str = "0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4";
    tracing::info!(
        message_id = COMPLETION_JOURNAL_ID,
        bootc.stateroot = stateroot.unwrap_or("default"),
        "Starting bootc installation completion"
    );

    let deployment = &sysroot
        .merge_deployment(stateroot)
        .ok_or_else(|| anyhow::anyhow!("Failed to find deployment (stateroot={stateroot:?})"))?;
    let sysroot_dir = crate::utils::sysroot_dir(&sysroot)?;

    // Create a subdir in /run
    let rundir = "run/bootc-install";
    rootfs.create_dir_all(rundir)?;
    let rundir = &rootfs.open_dir(rundir)?;

    // ostree-ext doesn't do kargs, so handle that now
    reconcile_kargs(&sysroot, deployment)?;

    // ostree-ext doesn't do logically bound images
    let bound_images = crate::boundimage::query_bound_images_for_deployment(sysroot, deployment)?;

    if !bound_images.is_empty() {
        // Log bound images found
        tracing::info!(
            message_id = COMPLETION_JOURNAL_ID,
            bootc.bound_images_count = bound_images.len(),
            "Found {} bound images for completion",
            bound_images.len()
        );

        // load the selinux policy from the target ostree deployment
        let deployment_fd = deployment_fd(sysroot, deployment)?;
        let sepolicy = crate::lsm::new_sepolicy_at(deployment_fd)?;

        // When we're run through ostree, we only lazily initialize the podman storage to avoid
        // having a hard dependency on it.
        let imgstorage = &CStorage::create(&sysroot_dir, &rundir, sepolicy.as_ref())?;
        crate::boundimage::pull_images_impl(imgstorage, bound_images)
            .await
            .context("pulling bound images")?;
    }

    // Log completion success
    tracing::info!(
        message_id = COMPLETION_JOURNAL_ID,
        bootc.stateroot = stateroot.unwrap_or("default"),
        "Successfully completed bootc installation"
    );

    Ok(())
}
