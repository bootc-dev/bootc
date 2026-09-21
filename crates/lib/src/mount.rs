//! Explicit, caller-owned mounts of an offline deployment.
//!
//! Conceptually this redoes what the initramfs does at boot
//! (ostree-prepare-root for OSTree, bootc-initramfs-setup for composefs), only
//! for a deployment in an offline sysroot and at a directory the caller picks
//! instead of `/sysroot`: the root is the deployment's composefs image, with
//! `/etc` and `/var` mounted from its state as they will be at boot. Keep it in
//! line with those, and share their code where bootc has it.
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
use camino::{Utf8Path, Utf8PathBuf};
use cap_std_ext::{
    cap_std::{ambient_authority, fs::Dir},
    dirext::CapStdExtDirExt,
};
use clap::Args;
use ostree::gio;
use ostree_ext::keyfileext::KeyFileExt;
use ostree_ext::{ostree, ostree_prepareroot};
use rustix::mount::{MoveMountFlags, OpenTreeFlags, move_mount, open_tree};

use crate::composefs_consts::STATE_DIR_RELATIVE;

const ETC: &str = "etc";
const VAR: &str = "var";

#[derive(Debug, Args, PartialEq, Eq)]
pub(crate) struct MountOpts {
    /// Offline target sysroot.
    #[clap(long, value_parser = crate::cli::parse_absolute_path)]
    pub(crate) sysroot: Utf8PathBuf,

    /// Mount the latest deployment. Currently the sysroot must contain exactly one.
    ///
    /// This is required so that other ways to select a deployment can be
    /// added later without changing what an invocation means.
    #[clap(long, required = true)]
    pub(crate) latest: bool,

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeploymentBackend {
    Ostree,
    Composefs,
}

fn select_backend(
    ostree_deployments: usize,
    composefs_deployments: usize,
) -> Result<DeploymentBackend> {
    match (ostree_deployments, composefs_deployments) {
        (1, 0) => Ok(DeploymentBackend::Ostree),
        (0, 1) => Ok(DeploymentBackend::Composefs),
        (0, 0) => bail!("target contains no deployment"),
        (o, c) => bail!(
            "target must contain exactly one deployment (found {o} OSTree, {c} composefs); refusing ambiguous selection"
        ),
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

    let (root_tree, state) =
        match select_backend(ostree_deployments.len(), composefs_deployments.len())? {
            DeploymentBackend::Composefs => {
                let id = &composefs_deployments[0];
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
                let deployment = &ostree_deployments[0];
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
    use super::{DeploymentBackend, open_mount_target, select_backend};
    use crate::cli::{InstallOpts, Opt};
    use camino::Utf8Path;
    use clap::Parser;

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
