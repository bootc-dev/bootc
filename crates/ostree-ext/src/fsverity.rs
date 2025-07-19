//! Integration with fsverity

use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};
use cap_std::fs::Dir;
use cap_std_ext::cap_std;
use composefs::fsverity as composefs_fsverity;
use composefs_fsverity::Sha256HashValue;
use ostree::gio;

use crate::keyfileext::KeyFileExt;
use crate::ostree_prepareroot::Tristate;

/// The relative path to the repository config file.
const CONFIG_PATH: &str = "config";

/// The ostree integrity config section
pub const INTEGRITY_SECTION: &str = "ex-integrity";
/// The ostree repo config option to enable fsverity
pub const INTEGRITY_FSVERITY: &str = "fsverity";

/// State of fsverity in a repo
#[derive(Debug, Clone)]
pub struct RepoVerityState {
    /// True if fsverity is desired to be enabled
    pub desired: Tristate,
    /// True if fsverity is known to be enabled on all objects
    pub enabled: bool,
}

/// Check if fsverity is fully enabled for the target repository.
pub fn is_verity_enabled(repo: &ostree::Repo) -> Result<RepoVerityState> {
    let desired = repo
        .config()
        .optional_string(INTEGRITY_SECTION, INTEGRITY_FSVERITY)?
        .map(|s| Tristate::from_str(s.as_str()))
        .transpose()?
        .unwrap_or_default();
    let repo_dir = &Dir::reopen_dir(&repo.dfd_borrow())?;
    let config = repo_dir
        .open(CONFIG_PATH)
        .with_context(|| format!("Opening repository {CONFIG_PATH}"))?;
    // We use the flag of having fsverity set on the repository config as a flag to say that
    // fsverity is fully enabled; all objects have it.
    let enabled = composefs_fsverity::measure_verity::<Sha256HashValue>(config.as_fd()).is_ok();
    Ok(RepoVerityState { desired, enabled })
}

/// Enable fsverity on regular file objects in this directory.
fn enable_fsverity_in_objdir(d: &Dir) -> anyhow::Result<()> {
    for ent in d.entries()? {
        let ent = ent?;
        if !ent.file_type()?.is_file() {
            continue;
        }
        let name = ent.file_name();
        let Some(b"file") = Path::new(&name).extension().map(|e| e.as_bytes()) else {
            continue;
        };
        let f = d.open(&name)?;
        let enabled =
            composefs::fsverity::measure_verity_opt::<Sha256HashValue>(f.as_fd())?.is_some();
        if !enabled {
            composefs_fsverity::enable_verity_raw::<Sha256HashValue>(&f)?;
        }
    }
    Ok(())
}

/// Ensure that fsverity is enabled on this repository.
///
/// - Walk over all regular file objects and ensure that fsverity is enabled on them
/// - Update the repo config if necessary to ensure that future objects have it by default
/// - Update the repo config to enable fsverity on the file itself as a completion flag
pub async fn ensure_verity(repo: &ostree::Repo) -> Result<()> {
    let state = is_verity_enabled(repo)?;
    // If we're already enabled, then we're done.
    if state.enabled {
        return Ok(());
    }

    // Limit concurrency here
    const MAX_CONCURRENT: usize = 3;

    let repodir = Dir::reopen_dir(&repo.dfd_borrow())?;

    // It's convenient here to reuse tokio's spawn_blocking as a threadpool basically.
    let mut joinset = tokio::task::JoinSet::new();

    // Walk over all objects
    for ent in repodir.read_dir("objects")? {
        // Block here if the queue is full
        while joinset.len() >= MAX_CONCURRENT {
            // SAFETY: We just checked the length so we know there's something pending
            let _: () = joinset.join_next().await.unwrap()??;
        }
        let ent = ent?;
        if !ent.file_type()?.is_dir() {
            continue;
        }
        let objdir = ent.open_dir()?;
        // Spawn a thread for each object directory just on general principle
        // of doing multi-threading.
        joinset.spawn_blocking(move || enable_fsverity_in_objdir(&objdir));
    }

    // Drain the remaining tasks.
    while let Some(output) = joinset.join_next().await {
        let _: () = output??;
    }

    // Ensure the flag is set in the config file, which is what libostree parses.
    if state.desired != Tristate::Enabled {
        let config = repo.copy_config();
        config.set_boolean(INTEGRITY_SECTION, INTEGRITY_FSVERITY, true);
        repo.write_config(&config)?;
        repo.reload_config(gio::Cancellable::NONE)?;
    }
    // And finally, enable fsverity as a flag that we have successfully
    // enabled fsverity on all objects.
    let f = repodir.open(CONFIG_PATH)?;
    match composefs_fsverity::enable_verity_raw::<Sha256HashValue>(f.as_fd()) {
        Ok(()) => Ok(()),
        Err(composefs_fsverity::EnableVerityError::AlreadyEnabled) => Ok(()),
        Err(e) => Err(e.into()),
    }
}
