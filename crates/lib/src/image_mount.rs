//! Read-only access to the image content of a booted or staged deployment.
//!
//! This deliberately does not assemble deployment state: in particular, it
//! never bind-mounts `/var` or the deployment's mutable `/etc` over the image.

use std::os::unix::fs::MetadataExt;
use std::{
    os::fd::{AsFd, AsRawFd, OwnedFd},
    path::PathBuf,
    thread,
};

use anyhow::{Context, Result, bail, ensure};
use camino::{Utf8Path, Utf8PathBuf};
use cap_std_ext::cap_std::{ambient_authority, fs::Dir};
use clap::{Args, ValueEnum};
use composefs_ctl::composefs::fsverity::{FsVerityHashValue, Sha512HashValue};
use ostree::gio;
use ostree_ext::{ostree, ostree_prepareroot, sysroot::SysrootLock};
use rustix::fs::{AtFlags, CWD, Mode, OFlags, StatxFlags, openat, statx};
use rustix::mount::{
    MoveMountFlags, OpenTreeFlags, UnmountFlags, move_mount, open_tree, unmount as unmount_path,
};
use rustix::{
    mount::{MountPropagationFlags, mount_change},
    thread::{UnshareFlags, unshare_unsafe},
};

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
#[clap(rename_all = "lowercase")]
pub(crate) enum Deployment {
    Booted,
    Staged,
}

#[derive(Debug, Args, PartialEq, Eq)]
pub(crate) struct MountOpts {
    /// Select exactly the booted deployment or the pending staged deployment.
    #[arg(long, value_enum)]
    pub(crate) deployment: Deployment,

    /// Absolute directory path inside the selected image to expose (`/` selects its root when
    /// supported). OSTree checkout fallback rejects `/` and maps `/etc` to pristine `/usr/etc`.
    /// No path component may be a symlink.
    #[arg(long, value_parser = crate::cli::parse_absolute_path)]
    pub(crate) source: Utf8PathBuf,

    /// Existing empty absolute directory to mount the selected image content on.
    #[arg(long, value_parser = crate::cli::parse_absolute_path)]
    pub(crate) target: Utf8PathBuf,
}

#[derive(Debug, Args, PartialEq, Eq)]
pub(crate) struct UnmountOpts {
    /// Named mountpoint to unmount (non-recursive; bootc provenance is not checked).
    #[arg(value_parser = crate::cli::parse_absolute_path)]
    pub(crate) target: Utf8PathBuf,
}

struct MountedImageRoot {
    tree: OwnedFd,
    // Keep the repository/sysroot locked while cloning and attaching its tree.
    _storage: StorageGuard,
    // A non-composefs OSTree checkout has deployment-local /etc. Source
    // selection maps /etc to pristine image content in /usr/etc instead.
    checkout: bool,
}

enum StorageGuard {
    Composefs {
        _repo: crate::store::ComposefsRepository,
    },
    Ostree {
        // Drop the lock before closing the detached mount it was opened through.
        _sysroot: SysrootLock,
        _mount: OwnedFd,
    },
}

pub(crate) async fn mount(opts: MountOpts) -> Result<()> {
    source_relative_path(&opts.source)?;
    let composefs_booted = crate::bootc_composefs::status::composefs_booted()?;
    // Select only from the active backend. These lookups are deliberately
    // narrower than `status::get_host()`: they do not initialize storage,
    // migrate repository metadata, configure the ESP, or change namespaces.
    let image = if let Some(booted) = composefs_booted {
        let (id, allow_missing_fsverity) = match opts.deployment {
            Deployment::Booted => (booted.digest.to_string(), booted.allow_missing_fsverity),
            Deployment::Staged => (
                staged_composefs_deployment_id(&booted.digest)?,
                booted.allow_missing_fsverity,
            ),
        };
        mount_composefs_image(&opts, id, allow_missing_fsverity)?
    } else {
        mount_ostree_image(&opts).await?
    };
    let MountedImageRoot {
        tree,
        _storage,
        checkout,
    } = image;

    let source_path = select_source_path(checkout, &opts.source)?;
    bootc_initramfs_setup::set_mount_tree_readonly(&tree)
        .context("Making selected deployment image read-only")?;

    let image_root = Dir::reopen_dir(&tree).context("Opening selected image root")?;
    let source = open_source(&image_root, &source_path)?;
    // Open once and retain this descriptor through validation and attachment.
    // This avoids checking one pathname and mounting on a replacement object.
    let (target, target_parent) = open_mount_target(&opts.target)?;
    ensure_not_root_target(&target, &opts.target)?;
    let source_metadata = source.metadata().context("Inspecting image source")?;
    let target_metadata = target
        .metadata()
        .with_context(|| format!("Inspecting mount target {}", opts.target))?;
    ensure!(
        source_metadata.is_dir() && target_metadata.is_dir(),
        "image source {} and target {} must both be directories",
        opts.source,
        opts.target
    );

    // `tree` is a detached mount. Kernel 6.12 rejects open_tree() paths which
    // resolve through a directory fd inside an unattached mount. Attach it in
    // an isolated worker namespace before cloning the already-validated source
    // fd; never change mount visibility in the caller's namespace.
    drop(image_root);
    let source_tree = clone_source_in_staging_namespace(tree, source)
        .with_context(|| format!("Cloning image source {}", opts.source))?;
    bootc_initramfs_setup::set_mount_tree_readonly_nosymfollow(&source_tree)
        .context("Making selected image content read-only and preventing symlink traversal")?;

    // Check immediately before attachment so a changed target cannot silently
    // hide newly-added contents or stack another mount.
    ensure_directory_empty(&target, &opts.target)?;
    if let Some(parent) = target_parent.as_ref() {
        ensure_not_mountpoint(&target, parent, &opts.target)?;
    }

    move_mount(
        &source_tree,
        "",
        &target,
        "",
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH | MoveMountFlags::MOVE_MOUNT_T_EMPTY_PATH,
    )
    .with_context(|| format!("Attaching image source {} at {}", opts.source, opts.target))?;

    Ok(())
}

/// Temporarily attach a detached image mount in a private worker namespace so
/// that the kernel can clone a validated directory fd from inside it.
#[allow(unsafe_code)]
fn clone_source_in_staging_namespace(tree: OwnedFd, source: std::fs::File) -> Result<OwnedFd> {
    thread::Builder::new()
        .name("bootc-image-mount-stage".to_owned())
        .spawn(move || -> Result<OwnedFd> {
            // A dedicated OS thread is required because mount namespace
            // unsharing applies to the calling thread, not the whole process.
            // SAFETY: This is a dedicated worker thread and only CLONE_NEWNS
            // is requested (not CLONE_FILES), so the operation cannot alter
            // the calling thread's namespace or invalidate shared fd tables.
            unsafe { unshare_unsafe(UnshareFlags::NEWNS) }
                .context("Unsharing image mount staging thread namespace")?;
            mount_change(
                c"/",
                MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
            )
            .context("Making image mount staging namespace private")?;

            let directory =
                tempfile::tempdir().context("Creating image mount staging directory")?;
            let mut attachment = TemporaryMountAttachment {
                path: directory.path().to_owned(),
                _directory: directory,
                mounted: false,
            };
            move_mount(
                &tree,
                "",
                CWD,
                attachment.path.as_path(),
                MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
            )
            .context("Attaching image mount in staging namespace")?;
            attachment.mounted = true;

            // Use AT_EMPTY_PATH only after the fd has a path in this namespace.
            // Do not recurse: image-mount source selection has always cloned
            // only the selected mount, not its mounted children.
            let cloned = open_tree(
                &source,
                "",
                OpenTreeFlags::OPEN_TREE_CLONE
                    | OpenTreeFlags::OPEN_TREE_CLOEXEC
                    | OpenTreeFlags::AT_EMPTY_PATH,
            )
            .context("Cloning validated image source fd");

            // Drop all handles into the attached mount before its synchronous,
            // non-recursive unmount. The detached clone (if successful) remains
            // alive independently and is returned to the caller.
            drop(source);
            drop(tree);
            let unmounted = attachment.unmount();
            match (cloned, unmounted) {
                (Ok(cloned), Ok(())) => Ok(cloned),
                (Err(error), Ok(())) => Err(error),
                (Ok(_), Err(error)) => Err(error),
                (Err(error), Err(unmount_error)) => Err(error.context(format!(
                    "Also failed to unmount staging attachment: {unmount_error:#}"
                ))),
            }
        })
        .context("Starting image mount staging thread")?
        .join()
        .map_err(|_| anyhow::anyhow!("Image mount staging thread panicked"))?
}

/// Normal-unmount guard for the temporary staging attachment. Drop retries
/// synchronously during error unwinding; it intentionally never lazy-detaches.
struct TemporaryMountAttachment {
    path: PathBuf,
    _directory: tempfile::TempDir,
    mounted: bool,
}

impl TemporaryMountAttachment {
    fn unmount(&mut self) -> Result<()> {
        if self.mounted {
            unmount_path(&self.path, UnmountFlags::empty())
                .context("Unmounting image mount staging attachment")?;
            self.mounted = false;
        }
        Ok(())
    }
}

impl Drop for TemporaryMountAttachment {
    fn drop(&mut self) {
        if let Err(error) = self.unmount() {
            tracing::error!("Failed to unmount image staging attachment: {error:#}");
        }
    }
}

/// Read the composefs staged selector without constructing `BootedStorage`.
/// The staged ID is valid only when it names a distinct deployment with local
/// composefs state and a parseable origin file.
fn staged_composefs_deployment_id(booted_id: &str) -> Result<String> {
    use crate::composefs_consts::{
        COMPOSEFS_STAGED_DEPLOYMENT_FNAME, COMPOSEFS_TRANSIENT_STATE_DIR,
    };

    let staged_path =
        format!("{COMPOSEFS_TRANSIENT_STATE_DIR}/{COMPOSEFS_STAGED_DEPLOYMENT_FNAME}");
    let staged_json = std::fs::read_to_string(&staged_path)
        .with_context(|| format!("Reading staged composefs deployment selector {staged_path}"))?;
    let id = staged_composefs_id_from_json(&staged_json, booted_id)?;

    let sysroot = Dir::open_ambient_dir("/sysroot", ambient_authority())
        .context("Opening booted system sysroot")?;
    let origin = crate::bootc_composefs::state::read_origin(&sysroot, &id)?.ok_or_else(|| {
        anyhow::anyhow!("No composefs state or origin for staged deployment {id}")
    })?;
    let boot_type = origin
        .get::<String>(
            crate::composefs_consts::ORIGIN_KEY_BOOT,
            crate::composefs_consts::ORIGIN_KEY_BOOT_TYPE,
        )
        .ok_or_else(|| {
            anyhow::anyhow!("Staged composefs deployment {id} has no boot type in its origin")
        })?;
    crate::bootc_composefs::boot::BootType::try_from(boot_type.as_str())
        .context("Parsing staged composefs deployment boot type")?;
    Ok(id)
}

fn staged_composefs_id_from_json(contents: &str, booted_id: &str) -> Result<String> {
    let staged: crate::bootc_composefs::status::StagedDeployment =
        serde_json::from_str(contents).context("Parsing staged composefs deployment selector")?;
    let id = Sha512HashValue::from_hex(&staged.depl_id)
        .context("Parsing staged composefs deployment ID")?
        .to_hex();
    ensure!(id != booted_id, "No staged composefs deployment found");
    Ok(id)
}

fn mount_composefs_image(
    opts: &MountOpts,
    id: String,
    allow_missing_fsverity: bool,
) -> Result<MountedImageRoot> {
    let sysroot = Dir::open_ambient_dir("/sysroot", ambient_authority())
        .context("Opening booted system sysroot")?;
    let mut repo = crate::bootc_composefs::repo::open_composefs_repo(&sysroot)
        .context("Opening existing composefs repository")?;
    if allow_missing_fsverity {
        repo.set_insecure();
    }
    let tree = repo
        .mount(&id)
        .with_context(|| format!("Mounting {:?} composefs deployment {id}", opts.deployment))?;
    Ok(MountedImageRoot {
        tree,
        _storage: StorageGuard::Composefs { _repo: repo },
        checkout: false,
    })
}

async fn mount_ostree_image(opts: &MountOpts) -> Result<MountedImageRoot> {
    // OSTree's sysroot lock creates/opens a lock file, but /sysroot is normally
    // mounted read-only. Clone the mount so that only this private mount view
    // can be made writable; never call prepare_for_write(), which changes the
    // mount namespace and would hide the image mount from the caller.
    let sysroot_dir = Dir::open_ambient_dir("/sysroot", ambient_authority())
        .context("Opening booted system sysroot")?;
    let sysroot_mount = open_tree(
        &sysroot_dir,
        ".",
        OpenTreeFlags::OPEN_TREE_CLONE
            | OpenTreeFlags::AT_RECURSIVE
            | OpenTreeFlags::OPEN_TREE_CLOEXEC,
    )
    .context("Cloning booted system sysroot mount")?;
    bootc_initramfs_setup::clear_mount_readonly(&sysroot_mount)
        .context("Making cloned booted system sysroot writable for OSTree locking")?;

    // OSTree opens the supplied path during load and uses its resulting
    // directory fd for the genuine inter-process lock. Keep sysroot_mount
    // alive for that fd and lock's full lifetime.
    let path = format!("/proc/self/fd/{}", sysroot_mount.as_raw_fd());
    let sysroot_file = gio::File::for_path(path);
    let sysroot = ostree::Sysroot::new(Some(&sysroot_file));
    sysroot
        .load(gio::Cancellable::NONE)
        .context("Loading booted OSTree sysroot")?;
    let sysroot = SysrootLock::new_from_sysroot(&sysroot)
        .await
        .context("Locking booted OSTree sysroot")?;
    sysroot
        .load(gio::Cancellable::NONE)
        .context("Reloading locked booted OSTree sysroot")?;

    // libostree identifies the booted deployment only when its Sysroot points
    // at the current root (/), not the physical backing sysroot (/sysroot).
    // Read that identity while holding the lock above, then resolve it against
    // the deployments from the locked backing sysroot below.
    let booted_sysroot = ostree::Sysroot::new_default();
    booted_sysroot
        .load(gio::Cancellable::NONE)
        .context("Loading current OSTree root")?;
    let selected_deployment = match opts.deployment {
        Deployment::Booted => booted_sysroot
            .require_booted_deployment()
            .context("No booted OSTree deployment found")?
            .clone(),
        Deployment::Staged => {
            let booted = booted_sysroot
                .require_booted_deployment()
                .context("No booted OSTree deployment found")?;
            booted_sysroot
                .deployments()
                .into_iter()
                .find(|deployment| deployment.is_staged() && deployment.osname() == booted.osname())
                .ok_or_else(|| anyhow::anyhow!("No staged OSTree deployment found"))?
        }
    };
    let deployments = sysroot.deployments();
    let deployment = resolve_locked_deployment(&selected_deployment, &deployments)?;
    // Keep composefs lower/data paths rooted on the attached /sysroot mount.
    // On older supported kernels (including 6.12), overlayfs cannot clone a
    // lowerpath reached through the detached mount used for OSTree locking.
    let deployment_path = sysroot.deployment_dirpath(&deployment);
    let deployment_dir = sysroot_dir
        .open_dir(deployment_path.as_str())
        .with_context(|| format!("Opening selected OSTree deployment {deployment_path}"))?;
    let repo = sysroot_dir
        .open_dir("ostree/repo")
        .context("Opening booted OSTree repository")?;
    let config = ostree_prepareroot::load_config_from_root(&deployment_dir)
        .context("Loading selected deployment's prepare-root.conf")?;
    let (tree, checkout) = match ostree_prepareroot::mount_composefs(
        &deployment_dir,
        &repo,
        deployment.csum().as_str(),
        config.as_ref(),
    )
    .context("Mounting selected OSTree deployment image")?
    {
        Some(tree) => (tree, false),
        None => (
            open_tree(
                &sysroot_dir,
                deployment_path.as_str(),
                OpenTreeFlags::OPEN_TREE_CLONE | OpenTreeFlags::OPEN_TREE_CLOEXEC,
            )
            .context("Cloning selected OSTree deployment checkout")?,
            true,
        ),
    };
    Ok(MountedImageRoot {
        tree,
        _storage: StorageGuard::Ostree {
            _sysroot: sysroot,
            _mount: sysroot_mount,
        },
        checkout,
    })
}

/// Resolve the deployment selected from the current-root view to its matching
/// object in the locked backing sysroot. Deployment indexes and staged flags
/// can differ between these views, so use only the stable OSTree identity.
fn resolve_locked_deployment(
    selected: &ostree::Deployment,
    locked_deployments: &[ostree::Deployment],
) -> Result<ostree::Deployment> {
    let identity = deployment_identity(selected);
    let identities = locked_deployments
        .iter()
        .map(deployment_identity)
        .collect::<Vec<_>>();
    let index = matching_deployment_index(&identity, &identities)?;
    Ok(locked_deployments[index].clone())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeploymentIdentity {
    osname: String,
    checksum: String,
    deploy_serial: i32,
}

fn deployment_identity(deployment: &ostree::Deployment) -> DeploymentIdentity {
    DeploymentIdentity {
        osname: deployment.osname().to_string(),
        checksum: deployment.csum().to_string(),
        deploy_serial: deployment.deployserial(),
    }
}

fn matching_deployment_index(
    selected: &DeploymentIdentity,
    candidates: &[DeploymentIdentity],
) -> Result<usize> {
    let mut matches = candidates
        .iter()
        .enumerate()
        .filter(|(_, candidate)| *candidate == selected);
    let (index, _) = matches.next().ok_or_else(|| {
        anyhow::anyhow!("Selected OSTree deployment is absent from locked sysroot")
    })?;
    ensure!(
        matches.next().is_none(),
        "Selected OSTree deployment is ambiguous in locked sysroot"
    );
    Ok(index)
}

fn select_source_path(checkout: bool, source: &Utf8Path) -> Result<Utf8PathBuf> {
    if !checkout {
        return Ok(source.to_owned());
    }
    ensure!(
        source != Utf8Path::new("/"),
        "OSTree checkout fallback does not support --source /: refusing to expose deployment-local /etc"
    );
    if source == Utf8Path::new("/etc") || source.starts_with("/etc/") {
        let suffix = source
            .strip_prefix("/etc")
            .expect("/etc source prefix was checked");
        let mut selected = Utf8PathBuf::from("/usr/etc");
        if !suffix.as_str().is_empty() {
            selected.push(suffix);
        }
        return Ok(selected);
    }
    Ok(source.to_owned())
}

fn open_source(root: &Dir, source: &Utf8Path) -> Result<std::fs::File> {
    let relative = source_relative_path(source)?;
    let components = relative
        .components()
        .filter_map(|component| match component {
            camino::Utf8Component::Normal(component) => Some(component),
            _ => None,
        })
        .collect::<Vec<_>>();

    let mut parent: Option<OwnedFd> = None;
    if components.is_empty() {
        let fd = openat(
            root,
            ".",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .context("Opening image root")?;
        return Ok(std::fs::File::from(fd));
    }

    for (index, component) in components.iter().enumerate() {
        let fd = match &parent {
            Some(parent) => openat(
                parent,
                *component,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ),
            None => openat(
                root,
                *component,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ),
        }
        .with_context(|| format!("Opening image source component {component} in {source}"))?;
        let file = std::fs::File::from(fd);
        let metadata = file
            .metadata()
            .with_context(|| format!("Inspecting image source component {component}"))?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "image source path components must not be symlinks: {source}"
        );
        if index + 1 < components.len() {
            ensure!(
                metadata.is_dir(),
                "image source path component {component} is not a directory"
            );
            parent = Some(file.into());
        } else {
            return Ok(file);
        }
    }
    unreachable!("non-empty component list returns from the loop")
}

fn source_relative_path(source: &Utf8Path) -> Result<Utf8PathBuf> {
    ensure!(
        source.is_absolute(),
        "image source must be absolute: {source}"
    );
    for component in source.components() {
        if matches!(component, camino::Utf8Component::ParentDir) {
            bail!("image source must not contain `..`: {source}");
        }
    }
    source
        .strip_prefix("/")
        .map(|path| path.to_owned())
        .with_context(|| format!("Invalid absolute image source {source}"))
}

pub(crate) fn unmount(opts: UnmountOpts) -> Result<()> {
    // Resolve through directory descriptors so parent path components cannot
    // be swapped for symlinks. Keep the parent, but close the target before
    // unmounting: an open descriptor to the mount root makes it busy.
    let (target, parent) = open_path_no_symlinks(&opts.target, false)?;
    ensure_not_root_target(&target, &opts.target)?;
    let parent = parent.ok_or_else(|| anyhow::anyhow!("Cannot unmount filesystem root"))?;
    ensure!(
        mount_id(&target)? != mount_id(&parent)?,
        "{} is not a mountpoint",
        opts.target
    );
    let name = opts
        .target
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Invalid unmount target {}", opts.target))?;
    let fd_path = format!("/proc/self/fd/{}/{}", parent.as_raw_fd(), name);
    drop(target);
    unmount_path(fd_path.as_str(), UnmountFlags::NOFOLLOW)
        .with_context(|| format!("Unmounting {}", opts.target))?;
    Ok(())
}

fn open_mount_target(path: &Utf8Path) -> Result<(std::fs::File, Option<std::fs::File>)> {
    open_path_no_symlinks(path, true)
}

/// Resolve an absolute path one component at a time, retaining the parent
/// descriptor so checks and mount attachment refer to the same directory.
fn open_path_no_symlinks(
    path: &Utf8Path,
    final_directory: bool,
) -> Result<(std::fs::File, Option<std::fs::File>)> {
    ensure!(path.is_absolute(), "target path must be absolute: {path}");
    ensure!(
        path.components().all(|component| !matches!(
            component,
            camino::Utf8Component::ParentDir | camino::Utf8Component::Prefix(_)
        )),
        "target path must not contain `..`: {path}"
    );
    let components = path
        .components()
        .filter_map(|component| match component {
            camino::Utf8Component::RootDir => None,
            camino::Utf8Component::Normal(component) => Some(component.to_owned()),
            camino::Utf8Component::CurDir => None,
            camino::Utf8Component::ParentDir | camino::Utf8Component::Prefix(_) => unreachable!(),
        })
        .collect::<Vec<_>>();

    let root = openat(
        CWD,
        "/",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context("Opening filesystem root")?;
    let mut parent = std::fs::File::from(root);
    if components.is_empty() {
        ensure!(!final_directory, "mount target must not be filesystem root");
        return Ok((parent, None));
    }

    for (index, component) in components.iter().enumerate() {
        let final_component = index + 1 == components.len();
        let mut flags = OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        if !final_component || final_directory {
            flags |= OFlags::DIRECTORY;
        }
        let fd = openat(&parent, component.as_str(), flags, Mode::empty())
            .with_context(|| format!("Opening target path component {component} in {path}"))?;
        let current = std::fs::File::from(fd);
        let metadata = current
            .metadata()
            .with_context(|| format!("Inspecting target path component {component} in {path}"))?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "target path components must not be symlinks: {path}"
        );
        if final_component {
            return Ok((current, Some(parent)));
        }
        parent = current;
    }
    unreachable!("non-empty component list returns from the loop")
}

fn ensure_directory_empty(target: &impl AsFd, path: &Utf8Path) -> Result<()> {
    let mut entries = Dir::reopen_dir(target)
        .with_context(|| format!("Opening mount target directory {path}"))?
        .entries()?;
    ensure!(
        entries.next().is_none(),
        "mount target {path} must be empty"
    );
    Ok(())
}

/// Compare Linux mount IDs for a directory and its parent. A different ID
/// means the target is already a mountpoint, including an overmount.
fn ensure_not_mountpoint(target: &impl AsFd, parent: &impl AsFd, path: &Utf8Path) -> Result<()> {
    let target_mount_id = mount_id(target)?;
    let parent_mount_id = mount_id(parent)?;
    ensure!(
        target_mount_id == parent_mount_id,
        "mount target {path} is already a mountpoint"
    );
    Ok(())
}

fn mount_id(fd: &impl AsFd) -> Result<u64> {
    let stat = statx(fd.as_fd(), "", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID)
        .context("Reading mount ID with statx")?;
    ensure!(
        stat.stx_mask & StatxFlags::MNT_ID.bits() == StatxFlags::MNT_ID.bits(),
        "kernel did not provide mount IDs via statx (STATX_MNT_ID is required)"
    );
    Ok(stat.stx_mnt_id)
}

fn ensure_not_root_target(target: &std::fs::File, path: &Utf8Path) -> Result<()> {
    let root = openat(CWD, "/", OFlags::PATH | OFlags::CLOEXEC, Mode::empty())
        .context("Opening filesystem root")?;
    let root = std::fs::File::from(root);
    let target_metadata = target
        .metadata()
        .with_context(|| format!("Inspecting target {path}"))?;
    let root_metadata = root.metadata().context("Inspecting filesystem root")?;
    ensure!(
        target_metadata.dev() != root_metadata.dev()
            || target_metadata.ino() != root_metadata.ino(),
        "Refusing to mount or unmount the root filesystem"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        Deployment, DeploymentIdentity, MountOpts, UnmountOpts, ensure_directory_empty,
        ensure_not_mountpoint, ensure_not_root_target, open_mount_target, open_path_no_symlinks,
        open_source, select_source_path, source_relative_path,
    };
    use crate::cli::{ImageOpts, InstallOpts, Opt};
    use camino::{Utf8Path, Utf8PathBuf};
    use cap_std_ext::cap_std::{ambient_authority, fs::Dir};
    use clap::Parser;
    use std::os::unix::fs::symlink;

    #[test]
    fn parses_image_mount_and_unmount_without_changing_install_mount() {
        let parsed = Opt::try_parse_from([
            "bootc",
            "image",
            "mount",
            "--deployment",
            "staged",
            "--source",
            "/usr",
            "--target",
            "/mnt/image",
        ])
        .unwrap();
        assert!(matches!(
            parsed,
            Opt::Image(ImageOpts::Mount(MountOpts {
                deployment: Deployment::Staged,
                ..
            }))
        ));
        assert!(matches!(
            Opt::try_parse_from(["bootc", "image", "unmount", "/mnt/image"]).unwrap(),
            Opt::Image(ImageOpts::Unmount(UnmountOpts { .. }))
        ));
        assert!(matches!(
            Opt::try_parse_from([
                "bootc",
                "install",
                "mount",
                "--sysroot",
                "/sysroot",
                "--latest",
                "/mnt/installed"
            ])
            .unwrap(),
            Opt::Install(InstallOpts::Mount(_))
        ));
    }

    #[test]
    fn source_paths_must_stay_beneath_image_root() {
        for path in ["relative", "/usr/../etc", "/../../etc"] {
            assert!(source_relative_path(Utf8Path::new(path)).is_err(), "{path}");
        }
        assert_eq!(
            source_relative_path(Utf8Path::new("/usr/bin"))
                .unwrap()
                .as_str(),
            "usr/bin"
        );
        assert_eq!(
            source_relative_path(Utf8Path::new("/")).unwrap().as_str(),
            ""
        );
    }

    #[test]
    fn refuses_root_as_mount_or_unmount_target() {
        let (root, _) = open_path_no_symlinks(Utf8Path::new("/"), false).unwrap();
        assert!(ensure_not_root_target(&root, Utf8Path::new("/")).is_err());

        let temp = tempfile::tempdir().unwrap();
        let target = Utf8PathBuf::from_path_buf(temp.path().to_owned()).unwrap();
        let (target_fd, _) = open_path_no_symlinks(&target, false).unwrap();
        assert!(ensure_not_root_target(&target_fd, &target).is_ok());

        let root_alias = temp.path().join("root-alias");
        symlink("/", &root_alias).unwrap();
        let root_alias = Utf8PathBuf::from_path_buf(root_alias).unwrap();
        assert!(open_path_no_symlinks(&root_alias, false).is_err());
    }

    #[test]
    fn source_lookup_rejects_symlink_components_and_preserves_file_directory_matches() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("real-dir")).unwrap();
        std::fs::write(temp.path().join("real-file"), b"image").unwrap();
        symlink("/", temp.path().join("absolute-link")).unwrap();
        symlink("real-file", temp.path().join("file-link")).unwrap();
        let root =
            cap_std_ext::cap_std::fs::Dir::open_ambient_dir(temp.path(), ambient_authority())
                .unwrap();

        assert!(open_source(&root, Utf8Path::new("/absolute-link/etc")).is_err());
        assert!(open_source(&root, Utf8Path::new("/file-link")).is_err());
        assert!(
            open_source(&root, Utf8Path::new("/real-file"))
                .unwrap()
                .metadata()
                .unwrap()
                .is_file()
        );
        assert!(
            open_source(&root, Utf8Path::new("/real-dir"))
                .unwrap()
                .metadata()
                .unwrap()
                .is_dir()
        );
        assert!(
            open_source(&root, Utf8Path::new("/"))
                .unwrap()
                .metadata()
                .unwrap()
                .is_dir()
        );
    }

    #[test]
    fn checkout_sources_map_etc_to_pristine_image_content() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::create_dir_all(root.join("etc/subdir")).unwrap();
        std::fs::create_dir_all(root.join("usr/etc/subdir")).unwrap();
        std::fs::create_dir_all(root.join("etc-other")).unwrap();
        std::fs::create_dir_all(root.join("usr/lib")).unwrap();
        std::fs::write(root.join("etc/marker"), b"deployment-local").unwrap();
        std::fs::write(root.join("usr/etc/marker"), b"image-pristine").unwrap();
        std::fs::write(root.join("etc/subdir/marker"), b"deployment-local-child").unwrap();
        std::fs::write(root.join("usr/etc/subdir/marker"), b"image-pristine-child").unwrap();
        std::fs::write(root.join("etc-other/marker"), b"etc-other").unwrap();

        let image = Dir::open_ambient_dir(root, ambient_authority()).unwrap();
        assert_eq!(image.read("etc/marker").unwrap(), b"deployment-local");
        // Resolve through open_source as the mount path does, then read the
        // marker relative to that selected source directory.
        let read_source_marker = |source: &str| {
            let selected = select_source_path(true, Utf8Path::new(source)).unwrap();
            let dir = Dir::reopen_dir(&image).unwrap();
            let source = open_source(&dir, &selected).unwrap();
            let source = Dir::reopen_dir(&source).unwrap();
            source.read("marker").unwrap()
        };
        assert_eq!(read_source_marker("/etc"), b"image-pristine");
        assert_eq!(read_source_marker("/etc/subdir"), b"image-pristine-child");
        assert_eq!(read_source_marker("/etc-other"), b"etc-other");
        assert_eq!(
            select_source_path(true, Utf8Path::new("/usr")).unwrap(),
            Utf8Path::new("/usr")
        );
        assert_eq!(
            select_source_path(false, Utf8Path::new("/etc")).unwrap(),
            Utf8Path::new("/etc")
        );
        assert_eq!(
            select_source_path(false, Utf8Path::new("/")).unwrap(),
            Utf8Path::new("/")
        );
        assert!(select_source_path(true, Utf8Path::new("/")).is_err());
    }

    #[test]
    fn mount_target_must_be_empty_and_have_no_symlink_components() {
        let temp = tempfile::tempdir().unwrap();
        let target_path = Utf8PathBuf::from_path_buf(temp.path().join("empty")).unwrap();
        std::fs::create_dir(&target_path).unwrap();
        let (target, parent) = open_mount_target(&target_path).unwrap();
        ensure_directory_empty(&target, &target_path).unwrap();
        ensure_not_mountpoint(&target, parent.as_ref().unwrap(), &target_path).unwrap();

        std::fs::write(target_path.join("existing"), b"content").unwrap();
        assert!(ensure_directory_empty(&target, &target_path).is_err());

        let linked_target = temp.path().join("linked-target");
        symlink(&target_path, &linked_target).unwrap();
        let linked_target = Utf8PathBuf::from_path_buf(linked_target).unwrap();
        assert!(open_mount_target(&linked_target).is_err());

        let linked_parent = temp.path().join("linked-parent");
        symlink(temp.path(), &linked_parent).unwrap();
        let nested_target = Utf8PathBuf::from_path_buf(linked_parent.join("empty")).unwrap();
        assert!(open_mount_target(&nested_target).is_err());
    }

    #[test]
    fn staged_composefs_selector_requires_a_valid_distinct_digest() {
        let booted = "aa".repeat(64);
        let staged = "bb".repeat(64);
        let valid_json = format!(r#"{{"depl_id":"{staged}","finalization_locked":false}}"#);
        assert_eq!(
            super::staged_composefs_id_from_json(&valid_json, &booted).unwrap(),
            staged
        );
        assert!(super::staged_composefs_id_from_json(&valid_json, &staged).is_err());
        assert!(super::staged_composefs_id_from_json("{}", &booted).is_err());
        assert!(
            super::staged_composefs_id_from_json(
                r#"{"depl_id":"not-a-digest","finalization_locked":false}"#,
                &booted
            )
            .is_err()
        );
    }

    #[test]
    fn locked_deployment_resolution_requires_one_exact_identity_match() {
        let identity = |osname: &str, checksum: &str, deploy_serial: i32| DeploymentIdentity {
            osname: osname.to_owned(),
            checksum: checksum.to_owned(),
            deploy_serial,
        };
        let selected = identity("default", &"aa".repeat(32), 3);
        let candidates = [
            identity("other", &"aa".repeat(32), 3),
            identity("default", &"bb".repeat(32), 3),
            identity("default", &"aa".repeat(32), 4),
            selected.clone(),
        ];

        assert_eq!(
            super::matching_deployment_index(&selected, &candidates).unwrap(),
            3
        );
        assert!(super::matching_deployment_index(&selected, &[]).is_err());
        let ambiguous = [selected.clone(), selected.clone()];
        assert!(super::matching_deployment_index(&selected, &ambiguous).is_err());
    }
}
