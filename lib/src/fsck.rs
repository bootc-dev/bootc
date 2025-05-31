//! # Perform consistency checking.
//!
//! This is an internal module, backing the experimental `bootc internals fsck`
//! command.

// Unfortunately needed here to work with linkme
#![allow(unsafe_code)]

use std::fmt::Write as _;
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;

use bootc_utils::collect_until;
use camino::Utf8PathBuf;
use cap_std::fs::{Dir, MetadataExt as _};
use cap_std_ext::cap_std;
use cap_std_ext::dirext::CapStdExtDirExt;
use fn_error_context::context;
use linkme::distributed_slice;
use ostree_ext::ostree_prepareroot::Tristate;
use ostree_ext::{composefs, ostree};
use serde::{Deserialize, Serialize};

use crate::store::Storage;

use std::os::fd::AsFd;

/// A lint check has failed.
#[derive(thiserror::Error, Debug)]
struct FsckError(String);

/// The outer error is for unexpected fatal runtime problems; the
/// inner error is for the check failing in an expected way.
type FsckResult = anyhow::Result<std::result::Result<(), FsckError>>;

/// Everything is OK - we didn't encounter a runtime error, and
/// the targeted check passed.
fn fsck_ok() -> FsckResult {
    Ok(Ok(()))
}

/// We successfully found a failure.
fn fsck_err(msg: impl AsRef<str>) -> FsckResult {
    Ok(Err(FsckError::new(msg)))
}

impl std::fmt::Display for FsckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl FsckError {
    fn new(msg: impl AsRef<str>) -> Self {
        Self(msg.as_ref().to_owned())
    }
}

type FsckFn = fn(&Storage) -> FsckResult;
type AsyncFsckFn = fn(&Storage) -> Pin<Box<dyn Future<Output = FsckResult> + '_>>;
#[derive(Debug)]
enum FsckFnImpl {
    Sync(FsckFn),
    Async(AsyncFsckFn),
}

impl From<FsckFn> for FsckFnImpl {
    fn from(value: FsckFn) -> Self {
        Self::Sync(value)
    }
}

impl From<AsyncFsckFn> for FsckFnImpl {
    fn from(value: AsyncFsckFn) -> Self {
        Self::Async(value)
    }
}

#[derive(Debug)]
struct FsckCheck {
    name: &'static str,
    ordering: u16,
    f: FsckFnImpl,
}

#[distributed_slice]
pub(crate) static FSCK_CHECKS: [FsckCheck];

impl FsckCheck {
    pub(crate) const fn new(name: &'static str, ordering: u16, f: FsckFnImpl) -> Self {
        FsckCheck { name, ordering, f }
    }
}

#[distributed_slice(FSCK_CHECKS)]
static CHECK_RESOLVCONF: FsckCheck =
    FsckCheck::new("etc-resolvconf", 5, FsckFnImpl::Sync(check_resolvconf));
/// See https://github.com/bootc-dev/bootc/pull/1096 and https://github.com/containers/bootc/pull/1167
/// Basically verify that if /usr/etc/resolv.conf exists, it is not a zero-sized file that was
/// probably injected by buildah and that bootc should have removed.
///
/// Note that this fsck check can fail for systems upgraded from old bootc right now, as
/// we need the *new* bootc to fix it.
///
/// But at the current time fsck is an experimental feature that we should only be running
/// in our CI.
fn check_resolvconf(storage: &Storage) -> FsckResult {
    // For now we only check the booted deployment.
    if storage.booted_deployment().is_none() {
        return fsck_ok();
    }
    // Read usr/etc/resolv.conf directly.
    let usr = Dir::open_ambient_dir("/usr", cap_std::ambient_authority())?;
    let Some(meta) = usr.symlink_metadata_optional("etc/resolv.conf")? else {
        return fsck_ok();
    };
    if meta.is_file() && meta.size() == 0 {
        return fsck_err("Found usr/etc/resolv.conf as zero-sized file");
    }
    fsck_ok()
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum VerityState {
    Enabled,
    Disabled,
    Inconsistent((u64, u64)),
}

#[derive(Debug, Default)]
struct ObjectsVerityState {
    /// Count of objects with fsverity
    enabled: u64,
    /// Count of objects without fsverity
    disabled: u64,
    /// Objects which should have fsverity but do not
    missing: Vec<String>,
}

/// Check the fsverity state of all regular files in this object directory.
#[context("Computing verity state")]
fn verity_state_of_objects(
    d: &Dir,
    prefix: &str,
    expected: bool,
) -> anyhow::Result<ObjectsVerityState> {
    let mut enabled = 0;
    let mut disabled = 0;
    let mut missing = Vec::new();
    for ent in d.entries()? {
        let ent = ent?;
        if !ent.file_type()?.is_file() {
            continue;
        }
        let name = ent.file_name();
        let name = name
            .into_string()
            .map(Utf8PathBuf::from)
            .map_err(|_| anyhow::anyhow!("Invalid UTF-8"))?;
        let Some("file") = name.extension() else {
            continue;
        };
        let f = d.open(&name)?;
        let r: Option<composefs::fsverity::Sha256HashValue> =
            composefs::fsverity::measure_verity_opt(f.as_fd())?;
        drop(f);
        if r.is_some() {
            enabled += 1;
        } else {
            disabled += 1;
            if expected {
                missing.push(format!("{prefix}{name}"));
            }
        }
    }
    let r = ObjectsVerityState {
        enabled,
        disabled,
        missing,
    };
    Ok(r)
}

async fn verity_state_of_all_objects(
    repo: &ostree::Repo,
    expected: bool,
) -> anyhow::Result<ObjectsVerityState> {
    // Limit concurrency here
    const MAX_CONCURRENT: usize = 3;

    let repodir = Dir::reopen_dir(&repo.dfd_borrow())?;

    // It's convenient here to reuse tokio's spawn_blocking as a threadpool basically.
    let mut joinset = tokio::task::JoinSet::new();
    let mut results = Vec::new();

    for ent in repodir.read_dir("objects")? {
        // Block here if the queue is full
        while joinset.len() >= MAX_CONCURRENT {
            results.push(joinset.join_next().await.unwrap()??);
        }
        let ent = ent?;
        if !ent.file_type()?.is_dir() {
            continue;
        }
        let name = ent.file_name();
        let name = name
            .into_string()
            .map(Utf8PathBuf::from)
            .map_err(|_| anyhow::anyhow!("Invalid UTF-8"))?;

        let objdir = ent.open_dir()?;
        let expected = expected.clone();
        joinset.spawn_blocking(move || verity_state_of_objects(&objdir, name.as_str(), expected));
    }

    // Drain the remaining tasks.
    while let Some(output) = joinset.join_next().await {
        results.push(output??);
    }
    // Fold the results.
    let r = results
        .into_iter()
        .fold(ObjectsVerityState::default(), |mut acc, v| {
            acc.enabled += v.enabled;
            acc.disabled += v.disabled;
            acc.missing.extend(v.missing);
            acc
        });
    Ok(r)
}

#[distributed_slice(FSCK_CHECKS)]
static CHECK_FSVERITY: FsckCheck =
    FsckCheck::new("fsverity", 10, FsckFnImpl::Async(check_fsverity));
fn check_fsverity(storage: &Storage) -> Pin<Box<dyn Future<Output = FsckResult> + '_>> {
    Box::pin(check_fsverity_inner(storage))
}

async fn check_fsverity_inner(storage: &Storage) -> FsckResult {
    let repo = &storage.repo();
    let verity_state = ostree_ext::fsverity::is_verity_enabled(repo)?;
    tracing::debug!(
        "verity: expected={:?} found={:?}",
        verity_state.desired,
        verity_state.enabled
    );

    let verity_found_state =
        verity_state_of_all_objects(&storage.repo(), verity_state.desired == Tristate::Enabled)
            .await?;
    let Some((missing, rest)) = collect_until(
        verity_found_state.missing.iter(),
        const { NonZeroUsize::new(5).unwrap() },
    ) else {
        return fsck_ok();
    };
    let mut err = String::from("fsverity enabled, but objects without fsverity:\n");
    for obj in missing {
        // SAFETY: Writing into a String
        writeln!(err, "  {obj}").unwrap();
    }
    if rest > 0 {
        // SAFETY: Writing into a String
        writeln!(err, "  ...and {rest} more").unwrap();
    }
    fsck_err(err)
}

pub(crate) async fn fsck(storage: &Storage, mut output: impl std::io::Write) -> anyhow::Result<()> {
    let mut checks = FSCK_CHECKS.static_slice().iter().collect::<Vec<_>>();
    checks.sort_by(|a, b| a.ordering.cmp(&b.ordering));

    let mut errors = false;
    for check in checks.iter() {
        let name = check.name;
        let r = match check.f {
            FsckFnImpl::Sync(f) => f(&storage),
            FsckFnImpl::Async(f) => f(&storage).await,
        };
        match r {
            Ok(Ok(())) => {
                println!("ok: {name}");
            }
            Ok(Err(e)) => {
                errors = true;
                writeln!(output, "fsck error: {name}: {e}")?;
            }
            Err(e) => {
                errors = true;
                writeln!(output, "Unexpected runtime error in check {name}: {e}")?;
            }
        }
    }
    if errors {
        anyhow::bail!("Encountered errors")
    }

    // Run an `ostree fsck` (yes, ostree exposes enough APIs
    // that we could reimplement this in Rust, but eh)
    // TODO: Fix https://github.com/bootc-dev/bootc/issues/1216 so we can
    // do this.
    // let st = Command::new("ostree")
    //     .arg("fsck")
    //     .stdin(std::process::Stdio::inherit())
    //     .status()?;
    // if !st.success() {
    //     anyhow::bail!("ostree fsck failed");
    // }

    Ok(())
}
