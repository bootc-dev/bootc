//! # Live application of staged content
//!
//! This module implements `bootc apply-live`, which makes content from the
//! staged deployment visible on the running system without a reboot.
//! See <https://github.com/bootc-dev/bootc/issues/76>.
//!
//! The only scope supported today is logically bound images
//! (`bootc apply-live bound-images`). The image bytes are already shared
//! between deployments via the bootc-owned container storage; what is
//! pinned to a deployment is only the *definition*: the symlink in
//! `/usr/lib/bootc/bound-images.d` and the quadlet file it references.
//!
//! Applying these live therefore does not require mounting anything.
//! Changed quadlet files are written to `/run/containers/systemd/`, which
//! podman gives precedence over `/etc` and `/usr`, and the affected units
//! are restarted. Because `/run` is transient, the override disappears on
//! the next boot, at which point the staged deployment's own `/usr` content
//! applies and the system converges without any further action. (A soft
//! reboot preserves `/run`, so the override is explicitly cleared when one
//! is prepared.)
//!
//! The state file is written *before* any units are touched: it describes
//! what is on disk, and each unit is marked `pending` until it has been
//! restarted successfully. Re-running the command retries pending units.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::process::Command;

use anyhow::{Context, Result, ensure};
use bootc_utils::CommandRunExt;
use camino::{Utf8Path, Utf8PathBuf};
use cap_std_ext::cap_std::{self, fs::Dir};
use cap_std_ext::dirext::CapStdExtDirExt;
use fn_error_context::context;
use ostree_ext::diff::FileTreeDiff;

use crate::boundimage::{BOUND_IMAGE_DIR, BoundImageSpec};
use crate::cli::ApplyLiveBoundImagesOpts;
use crate::spec::{LiveBoundImage, LiveBoundImages};
use crate::store::{BootedOstree, Storage};

/// Directory (relative to `/run`) holding apply-live state.
const STATE_DIR: &str = "bootc/apply-live";
/// State file (relative to `/run`) describing live-applied bound images.
const BOUND_IMAGES_STATE: &str = "bootc/apply-live/bound-images.json";
/// Podman's highest-precedence quadlet search directory, relative to `/`.
/// Paths are relative to the root (not `/run`) so that SELinux labels are
/// computed for the real absolute path.
const QUADLET_RUN_DIR: &str = "run/containers/systemd";
/// Quadlet search directories relative to a deployment root, in decreasing
/// precedence (excluding `/run`, which is what we write to).
const QUADLET_SEARCH_DIRS: &[&str] = &["etc/containers/systemd", "usr/share/containers/systemd"];
/// Directories which may be added/removed/changed in an ostree commit diff
/// while still being in scope for `apply-live bound-images`. Note that
/// `/etc` is stored as `/usr/etc` in ostree commits. The contents of an
/// added or removed directory are checked separately, since the diff does
/// not enumerate them.
const SCOPE_DIRS: &[&str] = &[
    "/usr/lib/bootc",
    "/usr/lib/bootc/bound-images.d",
    "/usr/share/containers",
    "/usr/share/containers/systemd",
    "/usr/etc/containers",
    "/usr/etc/containers/systemd",
];
/// Maximum number of out-of-scope paths to include in an error message.
const MAX_REPORTED_PATHS: usize = 10;
/// Journal message ID for apply-live operations.
const APPLY_LIVE_JOURNAL_ID: &str = "4c9e2b7d1f0a4e8b9c6d3a2f5e7b1c0d";

/// How a bound image definition differs between the booted and staged deployments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChangeKind {
    /// Present in the staged deployment only
    Added,
    /// Present in both, with different quadlet contents
    Updated,
    /// Present in the booted deployment only, and the quadlet file
    /// no longer exists in the staged deployment
    Removed,
}

impl std::fmt::Display for ChangeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ChangeKind::Added => "added",
            ChangeKind::Updated => "updated",
            ChangeKind::Removed => "removed",
        };
        f.write_str(s)
    }
}

/// A single bound image definition change to apply.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct QuadletChange {
    pub(crate) kind: ChangeKind,
    /// The staged spec for `Added`/`Updated`, the booted spec for `Removed`.
    pub(crate) spec: BoundImageSpec,
    /// Path of the quadlet relative to its search directory, if it lives in
    /// one podman will find. Definitions outside a search directory are only
    /// used as pull specs and have nothing to materialize.
    pub(crate) quadlet: Option<Utf8PathBuf>,
    /// The systemd unit to restart, if any.
    pub(crate) unit: Option<String>,
}

/// If `path` (relative to a root) is inside a quadlet search directory,
/// return the remainder relative to that directory.
pub(crate) fn quadlet_relpath(path: &Utf8Path) -> Option<&Utf8Path> {
    QUADLET_SEARCH_DIRS
        .iter()
        .find_map(|d| path.strip_prefix(d).ok())
        .filter(|p| !p.as_str().is_empty())
}

/// Compute the systemd service unit that quadlet generates for a `.container`
/// file. Returns `None` for other quadlet types; a `.image` unit is a oneshot
/// pull which we don't need to run since bootc pulls the image itself.
pub(crate) fn quadlet_unit_name(relpath: &Utf8Path, contents: &str) -> Result<Option<String>> {
    if relpath.extension() != Some("container") {
        return Ok(None);
    }
    let ini = tini::Ini::from_string(contents).context("Parse to ini")?;
    let name = ini
        .get::<String>("Container", "ServiceName")
        .or_else(|| relpath.file_stem().map(ToOwned::to_owned))
        .ok_or_else(|| anyhow::anyhow!("Invalid quadlet name: {relpath}"))?;
    Ok(Some(format!("{name}.service")))
}

/// Convert a deployment-relative path to the form used in an ostree commit
/// (and hence [`FileTreeDiff`]): absolute, with `/etc` stored as `/usr/etc`.
fn commit_path(path: &Utf8Path) -> Utf8PathBuf {
    if let Ok(rest) = path.strip_prefix("etc") {
        Utf8Path::new("/usr/etc").join(rest)
    } else {
        Utf8Path::new("/").join(path)
    }
}

/// Compute the set of definition changes between the booted and staged
/// bound image specs.
pub(crate) fn compute_changes(
    booted: &[BoundImageSpec],
    staged: &[BoundImageSpec],
    staged_root: &Dir,
) -> Result<Vec<QuadletChange>> {
    let booted: BTreeMap<_, _> = booted.iter().map(|s| (s.path.as_path(), s)).collect();
    let staged: BTreeMap<_, _> = staged.iter().map(|s| (s.path.as_path(), s)).collect();
    let mut changes = Vec::new();

    let mk = |kind, spec: &BoundImageSpec| -> Result<QuadletChange> {
        let quadlet = quadlet_relpath(&spec.path).map(ToOwned::to_owned);
        let unit = quadlet
            .as_deref()
            .map(|q| quadlet_unit_name(q, &spec.contents))
            .transpose()?
            .flatten();
        Ok(QuadletChange {
            kind,
            spec: spec.clone(),
            quadlet,
            unit,
        })
    };

    for (path, spec) in staged.iter() {
        match booted.get(path) {
            Some(b) if b.contents == spec.contents => {}
            Some(_) => changes.push(mk(ChangeKind::Updated, spec)?),
            None => changes.push(mk(ChangeKind::Added, spec)?),
        }
    }
    for (path, spec) in booted.iter() {
        if staged.contains_key(path) {
            continue;
        }
        if staged_root.try_exists(path)? {
            // The quadlet still exists, it's just no longer a bound image;
            // there's nothing to change on the running system.
            tracing::debug!("No longer bound, but still present: {path}");
            continue;
        }
        changes.push(mk(ChangeKind::Removed, spec)?);
    }
    Ok(changes)
}

/// Recursively collect the files under `dir` (a commit-form absolute path)
/// in the given root, as commit-form absolute paths.
fn walk_files(root: &Dir, dir: &str, out: &mut Vec<String>) -> Result<()> {
    let rel = dir.trim_start_matches('/');
    let Some(d) = root.open_dir_optional(rel)? else {
        return Ok(());
    };
    for entry in d.entries()? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid non-UTF8 filename: {name:?} in {dir}"))?;
        let path = format!("{dir}/{name}");
        if entry.file_type()?.is_dir() {
            walk_files(root, &path, out)?;
        } else {
            out.push(path);
        }
    }
    Ok(())
}

/// Verify that every path which differs between the booted and staged commits
/// is accounted for by the bound image changes we are going to apply. Any other
/// change means the staged deployment is not just a bound image update, and a
/// reboot is required.
///
/// The ostree diff does not enumerate the contents of added or removed
/// directories, so those are walked in the staged (respectively booted)
/// deployment root and checked file by file.
pub(crate) fn check_diff_scope(
    diff: &FileTreeDiff,
    changes: &[QuadletChange],
    booted_root: &Dir,
    staged_root: &Dir,
) -> Result<()> {
    let bound_dir = format!("/{BOUND_IMAGE_DIR}/");
    let allowed_files: BTreeSet<_> = changes.iter().map(|c| commit_path(&c.spec.path)).collect();
    let file_in_scope =
        |p: &str| -> bool { p.starts_with(&bound_dir) || allowed_files.contains(Utf8Path::new(p)) };
    let dir_in_scope = |p: &str| -> bool { SCOPE_DIRS.contains(&p) };

    let mut out_of_scope: Vec<String> = diff
        .added_files
        .iter()
        .chain(&diff.removed_files)
        .chain(&diff.changed_files)
        .filter(|p| !file_in_scope(p))
        .chain(diff.changed_dirs.iter().filter(|p| !dir_in_scope(p)))
        .cloned()
        .collect();
    for (dirs, root) in [
        (&diff.added_dirs, staged_root),
        (&diff.removed_dirs, booted_root),
    ] {
        for d in dirs {
            if !dir_in_scope(d) {
                out_of_scope.push(d.clone());
                continue;
            }
            let mut files = Vec::new();
            walk_files(root, d, &mut files)?;
            out_of_scope.extend(files.into_iter().filter(|p| !file_in_scope(p)));
        }
    }
    if out_of_scope.is_empty() {
        return Ok(());
    }
    out_of_scope.sort();
    let n = out_of_scope.len();
    let mut msg = String::from(
        "Staged deployment contains changes outside of bound image definitions; a reboot is required to apply it:\n",
    );
    for p in out_of_scope.iter().take(MAX_REPORTED_PATHS) {
        msg.push_str("  ");
        msg.push_str(p);
        msg.push('\n');
    }
    if n > MAX_REPORTED_PATHS {
        msg.push_str(&format!("  ...and {} more\n", n - MAX_REPORTED_PATHS));
    }
    anyhow::bail!("{}", msg.trim_end())
}

/// Read the live bound image state from `/run`, if any.
pub(crate) fn read_state(run: &Dir) -> Result<Option<LiveBoundImages>> {
    let Some(f) = run.open_optional(BOUND_IMAGES_STATE)? else {
        return Ok(None);
    };
    let r = serde_json::from_reader(std::io::BufReader::new(f))
        .with_context(|| format!("Parsing /run/{BOUND_IMAGES_STATE}"))?;
    Ok(Some(r))
}

/// Read the live bound image state from the host `/run`, if any.
pub(crate) fn read_state_from_host() -> Result<Option<LiveBoundImages>> {
    let run =
        Dir::open_ambient_dir("/run", cap_std::ambient_authority()).context("Opening /run")?;
    read_state(&run)
}

fn write_state(run: &Dir, state: &LiveBoundImages) -> Result<()> {
    run.create_dir_all(STATE_DIR)?;
    run.atomic_replace_with(BOUND_IMAGES_STATE, |w| {
        serde_json::to_writer_pretty(w, state).map_err(anyhow::Error::from)
    })
    .with_context(|| format!("Writing /run/{BOUND_IMAGES_STATE}"))
}

/// Remove any live-applied bound image overrides and state. This is used when
/// preparing a soft reboot, which preserves `/run` but must boot into the
/// target deployment's own definitions.
#[context("Clearing live bound image state")]
pub(crate) fn clear_state_from_host() -> Result<()> {
    let run =
        Dir::open_ambient_dir("/run", cap_std::ambient_authority()).context("Opening /run")?;
    let Some(state) = read_state(&run)? else {
        return Ok(());
    };
    let rootfs = Dir::open_ambient_dir("/", cap_std::ambient_authority()).context("Opening /")?;
    for q in state.images.iter().filter_map(|i| i.quadlet.as_deref()) {
        rootfs.remove_file_optional(Utf8Path::new(QUADLET_RUN_DIR).join(q))?;
    }
    run.remove_file_optional(BOUND_IMAGES_STATE)?;
    println!("Cleared live-applied bound image definitions");
    Ok(())
}

#[context("Running systemctl {}", args.join(" "))]
fn systemctl(args: &[&str]) -> Result<()> {
    Command::new("systemctl").args(args).run_capture_stderr()
}

/// Create `path` and any missing ancestors below `/run`, labeling only the
/// directories we create; existing ones (e.g. podman's `/run/containers`)
/// are left alone.
fn ensure_quadlet_dir(
    rootfs: &Dir,
    path: &Utf8Path,
    sepolicy: Option<&ostree_ext::ostree::SePolicy>,
) -> Result<()> {
    let mode = rustix::fs::Mode::from_raw_mode(0o755);
    let ancestors: Vec<_> = path
        .ancestors()
        .take_while(|p| p.as_str().len() > "run".len())
        .collect();
    for dir in ancestors.into_iter().rev() {
        if rootfs.try_exists(dir)? {
            continue;
        }
        crate::lsm::ensure_dir_labeled(rootfs, dir, None, mode, sepolicy)?;
    }
    Ok(())
}

/// Restart every unit still marked pending in `state`, updating the state
/// file as each one succeeds so a failure part way through can be retried.
fn restart_pending(run: &Dir, state: &mut LiveBoundImages) -> Result<()> {
    let mut r = Ok(());
    for img in state.images.iter_mut().filter(|i| i.pending) {
        let Some(unit) = img.unit.as_deref() else {
            img.pending = false;
            continue;
        };
        // `restart` also starts a unit which is not running (the added case).
        if let Err(e) = systemctl(&["restart", unit]) {
            r = Err(e);
            break;
        }
        img.pending = false;
    }
    write_state(run, state)?;
    r
}

/// Implementation of `bootc apply-live bound-images`.
#[context("Applying bound images live")]
pub(crate) async fn apply_bound_images(
    storage: &Storage,
    booted: &BootedOstree<'_>,
    opts: &ApplyLiveBoundImagesOpts,
) -> Result<()> {
    let sysroot = booted.sysroot;
    let booted_deployment = &booted.deployment;
    let staged = sysroot.staged_deployment().ok_or_else(|| {
        anyhow::anyhow!("No staged deployment; run `bootc upgrade` or `bootc switch` first")
    })?;
    ensure!(
        staged.osname() == booted_deployment.osname(),
        "Staged deployment is in a different stateroot"
    );
    let booted_csum = booted_deployment.csum();
    let staged_csum = staged.csum();

    let run =
        &Dir::open_ambient_dir("/run", cap_std::ambient_authority()).context("Opening /run")?;
    let rootfs = &Dir::open_ambient_dir("/", cap_std::ambient_authority()).context("Opening /")?;
    let previous = read_state(run)?;

    // The definitions from this staged deployment are already on disk; all
    // that may be left is restarting units (after `--no-restart`, or a failure).
    if let Some(mut previous) = previous
        .as_ref()
        .filter(|p| p.checksum == staged_csum)
        .cloned()
    {
        let pending: Vec<_> = previous
            .images
            .iter()
            .filter(|i| i.pending)
            .filter_map(|i| i.unit.as_deref())
            .collect();
        if pending.is_empty() {
            println!("Bound images from staged deployment are already applied");
            return Ok(());
        }
        for unit in pending {
            println!("restart pending: {unit}");
        }
        if opts.dry_run || opts.no_restart {
            return Ok(());
        }
        systemctl(&["daemon-reload"])?;
        return restart_pending(run, &mut previous);
    }

    let booted_root = crate::utils::deployment_fd(sysroot, booted_deployment)?;
    let staged_root = crate::utils::deployment_fd(sysroot, &staged)?;
    let booted_specs = crate::boundimage::query_bound_image_specs(&booted_root)?;
    let staged_specs = crate::boundimage::query_bound_image_specs(&staged_root)?;
    let changes = compute_changes(&booted_specs, &staged_specs, &staged_root)?;

    if booted_csum != staged_csum {
        let diff =
            ostree_ext::diff::diff(&sysroot.repo(), &booted_csum, &staged_csum, None::<&str>)?;
        tracing::debug!("Diff booted -> staged: {diff}");
        check_diff_scope(&diff, &changes, &booted_root, &staged_root)?;
    }

    // Overrides written by a previous apply-live which are not part of this
    // one need to be removed so the running system converges on the staged
    // definitions rather than a mix of the two.
    let previous_quadlets: BTreeMap<&Utf8Path, &LiveBoundImage> = previous
        .iter()
        .flat_map(|p| &p.images)
        .filter_map(|i| i.quadlet.as_deref().map(|q| (Utf8Path::new(q), i)))
        .collect();
    let current_quadlets: BTreeSet<&Utf8Path> = changes
        .iter()
        .filter_map(|c| c.quadlet.as_deref())
        .collect();
    let stale: Vec<(&Utf8Path, &LiveBoundImage)> = previous_quadlets
        .iter()
        .filter(|(q, _)| !current_quadlets.contains(*q))
        .map(|(q, i)| (*q, *i))
        .collect();

    if changes.is_empty() && stale.is_empty() {
        println!("No bound image changes to apply");
        return Ok(());
    }

    for c in changes.iter() {
        let unit = c.unit.as_deref().unwrap_or("(no unit)");
        println!("{}: {} ({unit})", c.kind, c.spec.image.image);
    }
    for (q, _) in stale.iter() {
        println!("reverting stale override: {q}");
    }
    if opts.dry_run {
        return Ok(());
    }

    tracing::info!(
        message_id = APPLY_LIVE_JOURNAL_ID,
        bootc.deployment.checksum = staged_csum.as_str(),
        bootc.bound_images_changes = changes.len(),
        "Applying bound image definitions live from staged deployment"
    );

    // Ensure all images referenced by the staged deployment are present. They
    // normally were pulled when the deployment was staged, but this also acts
    // as a retry if that failed.
    let staged_images = staged_specs.iter().map(|s| s.image.clone()).collect();
    crate::boundimage::pull_images(storage, staged_images).await?;

    // Materialize the definitions into /run. A definition may already be live
    // from a previous apply, in which case its unit doesn't need a restart.
    let quadlet_run_dir = Utf8Path::new(QUADLET_RUN_DIR);
    let sepolicy = crate::lsm::new_sepolicy_at(&booted_root)?;
    let filemode = rustix::fs::Mode::from_raw_mode(0o644);
    let mut written = BTreeMap::new();
    for c in changes.iter() {
        let Some(quadlet) = c.quadlet.as_deref() else {
            continue;
        };
        let dest = quadlet_run_dir.join(quadlet);
        match c.kind {
            ChangeKind::Added | ChangeKind::Updated => {
                let already_live = previous_quadlets
                    .get(quadlet)
                    .is_some_and(|prev| !prev.pending)
                    && rootfs.read_to_string_optional(&dest)?.as_deref()
                        == Some(c.spec.contents.as_str());
                if !already_live {
                    // SAFETY: We know there's a parent
                    ensure_quadlet_dir(rootfs, dest.parent().unwrap(), sepolicy.as_ref())?;
                    crate::lsm::atomic_replace_labeled(
                        rootfs,
                        &dest,
                        filemode,
                        sepolicy.as_ref(),
                        |w| w.write_all(c.spec.contents.as_bytes()).map_err(Into::into),
                    )?;
                }
                written.insert(quadlet, !already_live);
            }
            ChangeKind::Removed => {
                rootfs.remove_file_optional(&dest)?;
            }
        }
    }
    for (q, _) in stale.iter() {
        rootfs.remove_file_optional(quadlet_run_dir.join(q))?;
    }

    // Record all bound images of the staged deployment, not just the changed
    // ones: the state file protects them from garbage collection even if the
    // staged deployment is later discarded (e.g. by `bootc rollback`).
    let images = staged_specs
        .iter()
        .map(|s| {
            let quadlet = quadlet_relpath(&s.path).filter(|q| written.contains_key(q));
            let unit = quadlet
                .map(|q| quadlet_unit_name(q, &s.contents))
                .transpose()?
                .flatten();
            let pending = unit.is_some() && quadlet.is_some_and(|q| written[q]);
            Ok(LiveBoundImage {
                image: s.image.image.clone(),
                quadlet: quadlet.map(|q| q.to_string()),
                unit,
                pending,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut state = LiveBoundImages {
        checksum: staged_csum.to_string(),
        deploy_serial: staged.deployserial() as u32,
        images,
    };
    write_state(run, &state)?;

    if opts.no_restart {
        println!("Skipping unit restart; re-run without --no-restart to restart pending units");
        return Ok(());
    }

    // Units for removed definitions must be stopped before the daemon reload
    // which makes them disappear from systemd's view.
    let removed_units = changes
        .iter()
        .filter(|c| c.kind == ChangeKind::Removed)
        .filter_map(|c| c.unit.as_deref())
        .chain(stale.iter().filter_map(|(_, img)| img.unit.as_deref()));
    for unit in removed_units {
        systemctl(&["stop", unit])?;
    }
    systemctl(&["daemon-reload"])?;
    // A stale override reverts to the booted deployment's definition if
    // there is one, otherwise the unit is simply gone.
    for (q, img) in stale.iter() {
        let Some(unit) = img.unit.as_deref() else {
            continue;
        };
        let booted_has = booted_specs
            .iter()
            .any(|s| quadlet_relpath(&s.path) == Some(q));
        if booted_has {
            systemctl(&["start", unit])?;
        }
    }
    restart_pending(run, &mut state)?;

    println!(
        "Applied {} bound image definition change(s) from staged deployment",
        changes.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundimage::BoundImage;

    fn spec(path: &str, image: &str, contents: &str) -> BoundImageSpec {
        BoundImageSpec {
            image: BoundImage {
                image: image.into(),
                auth_file: None,
            },
            path: path.into(),
            contents: contents.into(),
        }
    }

    fn tempdir() -> Result<cap_std_ext::cap_tempfile::TempDir> {
        Ok(cap_std_ext::cap_tempfile::TempDir::new(
            cap_std::ambient_authority(),
        )?)
    }

    #[test]
    fn test_quadlet_relpath() {
        assert_eq!(
            quadlet_relpath("usr/share/containers/systemd/foo.container".into()),
            Some("foo.container".into())
        );
        assert_eq!(
            quadlet_relpath("etc/containers/systemd/sub/foo.image".into()),
            Some("sub/foo.image".into())
        );
        assert_eq!(quadlet_relpath("usr/lib/foo/foo.container".into()), None);
        assert_eq!(quadlet_relpath("usr/share/containers/systemd".into()), None);
    }

    #[test]
    fn test_quadlet_unit_name() -> Result<()> {
        let c = "[Container]\nImage=quay.io/foo/foo:latest\n";
        assert_eq!(
            quadlet_unit_name("foo.container".into(), c)?.as_deref(),
            Some("foo.service")
        );
        assert_eq!(
            quadlet_unit_name("sub/foo.container".into(), c)?.as_deref(),
            Some("foo.service")
        );
        let c = "[Container]\nImage=quay.io/foo/foo:latest\nServiceName=bar\n";
        assert_eq!(
            quadlet_unit_name("foo.container".into(), c)?.as_deref(),
            Some("bar.service")
        );
        let c = "[Image]\nImage=quay.io/foo/foo:latest\n";
        assert_eq!(quadlet_unit_name("foo.image".into(), c)?, None);
        Ok(())
    }

    #[test]
    fn test_commit_path() {
        assert_eq!(
            commit_path("etc/containers/systemd/a.container".into()),
            Utf8PathBuf::from("/usr/etc/containers/systemd/a.container")
        );
        assert_eq!(
            commit_path("usr/share/containers/systemd/a.container".into()),
            Utf8PathBuf::from("/usr/share/containers/systemd/a.container")
        );
    }

    #[test]
    fn test_compute_changes() -> Result<()> {
        let staged_root = &tempdir()?;
        const Q: &str = "usr/share/containers/systemd";
        let v1 = "[Container]\nImage=quay.io/foo/foo:v1\n";
        let v2 = "[Container]\nImage=quay.io/foo/foo:v2\n";
        let bar = "[Image]\nImage=quay.io/foo/bar:latest\n";
        let unbound = "[Container]\nImage=quay.io/foo/unbound:latest\n";
        let gone = "[Container]\nImage=quay.io/foo/gone:latest\n";

        let booted = [
            spec(&format!("{Q}/foo.container"), "quay.io/foo/foo:v1", v1),
            spec(&format!("{Q}/bar.image"), "quay.io/foo/bar:latest", bar),
            spec(
                &format!("{Q}/unbound.container"),
                "quay.io/foo/unbound:latest",
                unbound,
            ),
            spec(
                &format!("{Q}/gone.container"),
                "quay.io/foo/gone:latest",
                gone,
            ),
        ];
        let staged = [
            spec(&format!("{Q}/foo.container"), "quay.io/foo/foo:v2", v2),
            spec(&format!("{Q}/bar.image"), "quay.io/foo/bar:latest", bar),
            spec("usr/lib/misc/new.container", "quay.io/foo/new:latest", v1),
        ];
        // The unbound quadlet still exists in the staged root
        staged_root.create_dir_all(Q)?;
        staged_root.write(format!("{Q}/unbound.container"), unbound)?;

        let changes = compute_changes(&booted, &staged, staged_root)?;
        let summary: Vec<_> = changes
            .iter()
            .map(|c| {
                (
                    c.kind,
                    c.spec.path.as_str(),
                    c.quadlet.as_deref().map(|q| q.as_str()),
                    c.unit.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                (ChangeKind::Added, "usr/lib/misc/new.container", None, None),
                (
                    ChangeKind::Updated,
                    "usr/share/containers/systemd/foo.container",
                    Some("foo.container"),
                    Some("foo.service")
                ),
                (
                    ChangeKind::Removed,
                    "usr/share/containers/systemd/gone.container",
                    Some("gone.container"),
                    Some("gone.service")
                ),
            ]
        );
        Ok(())
    }

    #[test]
    fn test_check_diff_scope() -> Result<()> {
        let booted_root = &tempdir()?;
        let staged_root = &tempdir()?;
        let changes = vec![
            QuadletChange {
                kind: ChangeKind::Updated,
                spec: spec(
                    "usr/share/containers/systemd/foo.container",
                    "quay.io/foo/foo:v2",
                    "",
                ),
                quadlet: Some("foo.container".into()),
                unit: Some("foo.service".into()),
            },
            QuadletChange {
                kind: ChangeKind::Added,
                spec: spec("etc/containers/systemd/bar.image", "quay.io/foo/bar:v1", ""),
                quadlet: Some("bar.image".into()),
                unit: None,
            },
        ];
        let check =
            |diff: &FileTreeDiff| check_diff_scope(diff, &changes, booted_root, staged_root);

        let mut diff = FileTreeDiff::default();
        diff.changed_files
            .insert("/usr/share/containers/systemd/foo.container".into());
        diff.added_files
            .insert("/usr/etc/containers/systemd/bar.image".into());
        diff.added_files
            .insert("/usr/lib/bootc/bound-images.d/bar.image".into());
        diff.added_dirs
            .insert("/usr/lib/bootc/bound-images.d".into());
        check(&diff).unwrap();

        // A bound-images.d symlink target changing isn't visible in the diff
        // as a file change, but the removal of the old link is.
        diff.removed_files
            .insert("/usr/lib/bootc/bound-images.d/old.image".into());
        check(&diff).unwrap();

        // Anything else is out of scope
        diff.changed_files.insert("/usr/bin/bash".into());
        let e = check(&diff).unwrap_err().to_string();
        assert!(e.contains("/usr/bin/bash"), "{e}");
        assert!(!e.contains("foo.container"), "{e}");
        diff.changed_files.remove("/usr/bin/bash");

        // A quadlet we're not going to apply (not bound) is also out of scope
        diff.changed_files
            .insert("/usr/share/containers/systemd/other.container".into());
        assert!(check(&diff).is_err());
        diff.changed_files
            .remove("/usr/share/containers/systemd/other.container");

        // As is a new subdirectory of quadlets, since the diff doesn't recurse into it
        diff.added_dirs
            .insert("/usr/share/containers/systemd/sub".into());
        assert!(check(&diff).is_err());
        diff.added_dirs.remove("/usr/share/containers/systemd/sub");

        // The quadlet dir itself being added is fine when it only contains
        // what we apply (the "first bound image" case)...
        const Q: &str = "usr/etc/containers/systemd";
        staged_root.create_dir_all(Q)?;
        staged_root.write(format!("{Q}/bar.image"), "")?;
        diff.added_dirs.insert("/usr/etc/containers".into());
        diff.added_dirs.insert(format!("/{Q}"));
        check(&diff).unwrap();
        // ...but not when it contains anything else, even nested
        staged_root.create_dir_all(format!("{Q}/sub"))?;
        staged_root.write(format!("{Q}/sub/other.container"), "")?;
        let e = check(&diff).unwrap_err().to_string();
        assert!(e.contains(&format!("/{Q}/sub/other.container")), "{e}");
        staged_root.remove_dir_all(format!("{Q}/sub"))?;
        check(&diff).unwrap();

        // Likewise for a removed directory, which is checked in the booted root
        booted_root.create_dir_all("usr/lib/bootc/bound-images.d")?;
        booted_root.write("usr/lib/bootc/bound-images.d/old.image", "")?;
        diff.removed_dirs.insert("/usr/lib/bootc".into());
        check(&diff).unwrap();
        booted_root.write("usr/lib/bootc/other", "")?;
        let e = check(&diff).unwrap_err().to_string();
        assert!(e.contains("/usr/lib/bootc/other"), "{e}");
        booted_root.remove_file("usr/lib/bootc/other")?;

        // Error message is truncated
        for i in 0..20 {
            diff.added_files.insert(format!("/usr/bin/tool{i}"));
        }
        let e = check(&diff).unwrap_err().to_string();
        assert!(e.contains("and 10 more"), "{e}");
        Ok(())
    }

    #[test]
    fn test_state_roundtrip() -> Result<()> {
        let run = &tempdir()?;
        assert_eq!(read_state(run)?, None);
        let state = LiveBoundImages {
            checksum: "abc".into(),
            deploy_serial: 1,
            images: vec![
                LiveBoundImage {
                    image: "quay.io/foo/foo:v2".into(),
                    quadlet: Some("foo.container".into()),
                    unit: Some("foo.service".into()),
                    pending: true,
                },
                LiveBoundImage {
                    image: "quay.io/foo/bar:v2".into(),
                    quadlet: None,
                    unit: None,
                    pending: false,
                },
            ],
        };
        write_state(run, &state)?;
        assert_eq!(read_state(run)?.as_ref(), Some(&state));
        let raw = run.read_to_string(BOUND_IMAGES_STATE)?;
        assert!(raw.contains("\"pending\": true"), "{raw}");
        assert_eq!(raw.matches("pending").count(), 1, "{raw}");
        Ok(())
    }

    #[test]
    fn test_ensure_quadlet_dir() -> Result<()> {
        let rootfs = &tempdir()?;
        rootfs.create_dir("run")?;
        ensure_quadlet_dir(rootfs, "run/containers/systemd/sub/deeper".into(), None)?;
        assert!(rootfs.is_dir("run/containers/systemd/sub/deeper"));
        // Idempotent
        ensure_quadlet_dir(rootfs, "run/containers/systemd/sub/deeper".into(), None)?;
        Ok(())
    }
}
