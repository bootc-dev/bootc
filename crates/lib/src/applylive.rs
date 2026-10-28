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
//! On the ostree backend, that shared container storage is just a plain
//! directory, so applying a definition change live does not require
//! mounting anything new -- podman already reads the same storage the
//! booted and staged deployments share. (The composefs backend lays out
//! storage differently and is not handled here yet.) Changed quadlet files
//! are written to `/run/containers/systemd/`, which podman gives
//! precedence over `/etc` and `/usr`, and the affected units are restarted.
//! Because `/run` is transient, the override disappears on the next boot,
//! at which point the staged deployment's own `/usr` content applies and
//! the system converges without any further action. (A soft reboot
//! preserves `/run`, so the override is explicitly cleared when one is
//! prepared.)
//!
//! Rather than a separate state file, each quadlet written to
//! `/run/containers/systemd/` carries its own state as a leading comment
//! (see [`marker_line`]): the staged checksum, the image reference, and
//! whether its unit still needs restarting ("pending"). Re-running the
//! command re-derives everything by scanning that directory (see
//! [`scan_live_quadlets`]), so a failure part way through is safe to
//! resume from. The one exception is garbage-collection protection for
//! bound images with no quadlet override (unchanged definitions); see
//! [`write_protected_images`].

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
/// Flat, one-image-reference-per-line list (relative to `/run`) protecting
/// every bound image of an in-progress (or completed) apply-live from
/// garbage collection; see [`write_protected_images`].
const PROTECTED_IMAGES_LIST: &str = "bootc/apply-live/protected-images.list";
/// Prefix of the leading marker comment line bootc writes at the top of
/// each quadlet file it materializes under [`QUADLET_RUN_DIR`]; see
/// [`marker_line`] and [`parse_marker`].
const MARKER_PREFIX: &str = "# X-Bootc-Apply-Live:";
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
    /// For `Updated`, the previous (booted) unit name, if it differs from
    /// `unit` (e.g. `ServiceName=` changed): this needs to be stopped
    /// separately, since restarting `unit` won't touch it.
    pub(crate) old_unit: Option<String>,
}

/// A quadlet file bootc has written to [`QUADLET_RUN_DIR`], parsed back
/// from its marker comment line (see [`marker_line`]/[`parse_marker`]).
/// Recovered by scanning, not persisted elsewhere; see [`scan_live_quadlets`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveQuadlet {
    /// Path relative to [`QUADLET_RUN_DIR`].
    relpath: Utf8PathBuf,
    /// The staged deployment checksum this definition came from.
    checksum: String,
    /// True if the unit has not yet been restarted with this definition.
    pending: bool,
    /// The container image reference, for display purposes.
    image: String,
    /// The quadlet contents, with the marker comment stripped.
    contents: String,
    /// The systemd unit generated from the quadlet, if any.
    unit: Option<String>,
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

    let unit_for = |quadlet: Option<&Utf8Path>, contents: &str| -> Result<Option<String>> {
        quadlet
            .map(|q| quadlet_unit_name(q, contents))
            .transpose()
            .map(Option::flatten)
    };
    let mk = |kind, spec: &BoundImageSpec, old_unit: Option<String>| -> Result<QuadletChange> {
        let quadlet = quadlet_relpath(&spec.path).map(ToOwned::to_owned);
        let unit = unit_for(quadlet.as_deref(), &spec.contents)?;
        Ok(QuadletChange {
            kind,
            spec: spec.clone(),
            quadlet,
            unit,
            old_unit,
        })
    };

    for (path, spec) in staged.iter() {
        match booted.get(path) {
            Some(b) if b.contents == spec.contents => {}
            Some(b) => {
                // The unit name quadlet generates can change (e.g. via
                // `ServiceName=`) even though the file's path didn't; the old
                // unit needs to be stopped separately in that case.
                let quadlet = quadlet_relpath(&spec.path);
                let staged_unit = unit_for(quadlet, &spec.contents)?;
                let booted_unit = unit_for(quadlet, &b.contents)?;
                let old_unit = booted_unit.filter(|u| Some(u) != staged_unit.as_ref());
                changes.push(mk(ChangeKind::Updated, spec, old_unit)?);
            }
            None => changes.push(mk(ChangeKind::Added, spec, None)?),
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
        changes.push(mk(ChangeKind::Removed, spec, None)?);
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
        let ft = entry.file_type()?;
        if ft.is_dir() {
            walk_files(root, &path, out)?;
        } else if ft.is_file() {
            out.push(path);
        }
        // Symlinks (e.g. a unit masked via `-> /dev/null`) and other
        // non-regular entries are neither traversed nor reported: they
        // aren't files bootc itself would have written, and following them
        // can fail cap-std's path resolution for absolute targets.
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

/// Build the leading marker comment for a quadlet file; see [`parse_marker`].
fn marker_line(checksum: &str, pending: bool, image: &str) -> String {
    format!("{MARKER_PREFIX} checksum={checksum} pending={pending} image={image}\n")
}

/// Parse a [`marker_line`] from the start of `contents`, returning
/// `(checksum, pending, image, rest)` where `rest` is the original quadlet
/// contents with the marker removed. Returns `None` if there's no marker,
/// e.g. a quadlet bootc didn't write.
fn parse_marker(contents: &str) -> Option<(String, bool, String, &str)> {
    let (first, rest) = contents.split_once('\n')?;
    let kvs = first.strip_prefix(MARKER_PREFIX)?;
    let (mut checksum, mut pending, mut image) = (None, None, None);
    for kv in kvs.split_whitespace() {
        let (k, v) = kv.split_once('=')?;
        match k {
            "checksum" => checksum = Some(v.to_owned()),
            "pending" => pending = Some(v.parse().ok()?),
            "image" => image = Some(v.to_owned()),
            _ => {}
        }
    }
    Some((checksum?, pending?, image?, rest))
}

/// Scan [`QUADLET_RUN_DIR`] for quadlet files bootc has written, parsing
/// their marker comments back into [`LiveQuadlet`]s. Files with no
/// recognized marker are skipped.
fn scan_live_quadlets(rootfs: &Dir) -> Result<Vec<LiveQuadlet>> {
    let mut paths = Vec::new();
    walk_files(rootfs, &format!("/{QUADLET_RUN_DIR}"), &mut paths)?;
    let prefix = format!("/{QUADLET_RUN_DIR}/");
    let mut out = Vec::new();
    for p in paths {
        let Some(relpath) = p.strip_prefix(prefix.as_str()) else {
            continue;
        };
        let Some(contents) = rootfs.read_to_string_optional(p.trim_start_matches('/'))? else {
            continue;
        };
        let Some((checksum, pending, image, body)) = parse_marker(&contents) else {
            continue;
        };
        let relpath = Utf8PathBuf::from(relpath);
        let unit = quadlet_unit_name(&relpath, body)?;
        out.push(LiveQuadlet {
            relpath,
            checksum,
            pending,
            image,
            contents: body.to_owned(),
            unit,
        });
    }
    Ok(out)
}

/// Add the staged deployment's image references to the protected list (one
/// reference per line), protecting them from garbage collection even if the
/// staged deployment is later discarded (e.g. by `bootc rollback`).
/// Unrelated to the restart state in [`scan_live_quadlets`]: it covers
/// bound images with no quadlet override to carry that state.
///
/// This merges with whatever is already there rather than replacing it: an
/// earlier live-applied deployment's images may still be in use by units
/// that haven't transitioned yet, so they must stay protected too until a
/// reboot (or [`clear_state_from_host`]) resets `/run`.
fn write_protected_images<'a>(run: &Dir, images: impl Iterator<Item = &'a str>) -> Result<()> {
    let mut all: BTreeSet<String> = protected_images_from_host_at(run)?.into_iter().collect();
    all.extend(images.map(ToOwned::to_owned));
    run.create_dir_all(STATE_DIR)?;
    run.atomic_replace_with(PROTECTED_IMAGES_LIST, |w| -> Result<()> {
        for image in &all {
            writeln!(w, "{image}")?;
        }
        Ok(())
    })
    .with_context(|| format!("Writing /run/{PROTECTED_IMAGES_LIST}"))
}

/// Read the image references written by [`write_protected_images`] from an
/// arbitrary directory, if any.
fn protected_images_from_host_at(run: &Dir) -> Result<Vec<String>> {
    let Some(contents) = run.read_to_string_optional(PROTECTED_IMAGES_LIST)? else {
        return Ok(Vec::new());
    };
    Ok(contents.lines().map(ToOwned::to_owned).collect())
}

/// Read back the image references written by [`write_protected_images`], if
/// any, from the host `/run`.
pub(crate) fn protected_images_from_host() -> Result<Vec<String>> {
    let run =
        Dir::open_ambient_dir("/run", cap_std::ambient_authority()).context("Opening /run")?;
    protected_images_from_host_at(&run)
}

/// Build the `bootc status` view of live-applied bound images by scanning
/// [`QUADLET_RUN_DIR`]. Returns `None` if nothing is applied live.
/// `deploy_serial` isn't recorded in the markers, so it's left as `0` for
/// callers to fill in by matching `checksum` against a deployment.
pub(crate) fn status_from_host() -> Result<Option<LiveBoundImages>> {
    let rootfs = Dir::open_ambient_dir("/", cap_std::ambient_authority()).context("Opening /")?;
    let live = scan_live_quadlets(&rootfs)?;
    let Some(checksum) = live.first().map(|q| q.checksum.clone()) else {
        return Ok(None);
    };
    let images = live
        .into_iter()
        .map(|q| LiveBoundImage {
            image: q.image,
            quadlet: Some(q.relpath.to_string()),
            unit: q.unit,
            pending: q.pending,
        })
        .collect();
    Ok(Some(LiveBoundImages {
        checksum,
        deploy_serial: 0,
        images,
    }))
}

/// Remove any live-applied bound image overrides and state. This is used when
/// preparing a soft reboot, which preserves `/run` but must boot into the
/// target deployment's own definitions.
#[context("Clearing live bound image state")]
pub(crate) fn clear_state_from_host() -> Result<()> {
    let rootfs = Dir::open_ambient_dir("/", cap_std::ambient_authority()).context("Opening /")?;
    let live = scan_live_quadlets(&rootfs)?;
    for q in &live {
        rootfs.remove_file_optional(Utf8Path::new(QUADLET_RUN_DIR).join(&q.relpath))?;
    }
    let run =
        Dir::open_ambient_dir("/run", cap_std::ambient_authority()).context("Opening /run")?;
    let had_protected = run.remove_file_optional(PROTECTED_IMAGES_LIST)?;
    if live.is_empty() && !had_protected {
        return Ok(());
    }
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

/// Rewrite the marker on an already-materialized quadlet file, leaving its
/// contents otherwise untouched. Used to flip `pending` to `false` once a
/// unit has been restarted.
fn set_quadlet_pending(
    rootfs: &Dir,
    relpath: &Utf8Path,
    checksum: &str,
    pending: bool,
    image: &str,
    body: &str,
    sepolicy: Option<&ostree_ext::ostree::SePolicy>,
) -> Result<()> {
    let dest = Utf8Path::new(QUADLET_RUN_DIR).join(relpath);
    let filemode = rustix::fs::Mode::from_raw_mode(0o644);
    crate::lsm::atomic_replace_labeled(rootfs, &dest, filemode, sepolicy, |w| {
        w.write_all(marker_line(checksum, pending, image).as_bytes())?;
        w.write_all(body.as_bytes())?;
        Ok(())
    })
}

/// Restart every unit still marked pending among `live`, updating each
/// quadlet's marker as it succeeds so a failure part way through can be
/// retried on the next run.
fn restart_pending(
    rootfs: &Dir,
    live: &[LiveQuadlet],
    sepolicy: Option<&ostree_ext::ostree::SePolicy>,
) -> Result<()> {
    for q in live.iter().filter(|q| q.pending) {
        if let Some(unit) = q.unit.as_deref() {
            // `restart` also starts a unit which is not running (the added case).
            systemctl(&["restart", unit])?;
        }
        set_quadlet_pending(
            rootfs,
            &q.relpath,
            &q.checksum,
            false,
            &q.image,
            &q.contents,
            sepolicy,
        )?;
    }
    Ok(())
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

    let rootfs = &Dir::open_ambient_dir("/", cap_std::ambient_authority()).context("Opening /")?;
    let booted_root = crate::utils::deployment_fd(sysroot, booted_deployment)?;
    let staged_root = crate::utils::deployment_fd(sysroot, &staged)?;
    let sepolicy = crate::lsm::new_sepolicy_at(&booted_root)?;

    let live = scan_live_quadlets(rootfs)?;
    let staged_specs = crate::boundimage::query_bound_image_specs(&staged_root)?;

    // The definitions from this staged deployment are already on disk; all
    // that may be left is restarting units (after `--no-restart`, or a
    // failure). Checking checksums alone isn't enough: if a previous run
    // only got partway through materializing new overrides, the live set
    // may simply be missing some of them. Require every quadlet-bearing
    // staged spec to already have a live entry for this checksum.
    let expected_quadlets: BTreeSet<&Utf8Path> = staged_specs
        .iter()
        .filter_map(|s| quadlet_relpath(&s.path))
        .collect();
    let live_quadlets: BTreeSet<&Utf8Path> = live.iter().map(|q| q.relpath.as_path()).collect();
    if live_quadlets == expected_quadlets && live.iter().all(|q| q.checksum == staged_csum) {
        let pending: Vec<_> = live
            .iter()
            .filter(|q| q.pending)
            .filter_map(|q| q.unit.as_deref())
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
        return restart_pending(rootfs, &live, sepolicy.as_ref());
    }

    let booted_specs = crate::boundimage::query_bound_image_specs(&booted_root)?;
    let changes = compute_changes(&booted_specs, &staged_specs, &staged_root)?;

    if booted_csum != staged_csum {
        let diff =
            ostree_ext::diff::diff(&sysroot.repo(), &booted_csum, &staged_csum, None::<&str>)?;
        tracing::debug!("Diff booted -> staged: {diff}");
        check_diff_scope(&diff, &changes, &booted_root, &staged_root)?;
    }

    // Overrides from a previous apply-live that aren't part of this one
    // need to be removed so the system converges on the current staged
    // definitions rather than a mix of the two.
    let live_by_path: BTreeMap<&Utf8Path, &LiveQuadlet> =
        live.iter().map(|q| (q.relpath.as_path(), q)).collect();
    let current_quadlets: BTreeSet<&Utf8Path> = changes
        .iter()
        .filter_map(|c| c.quadlet.as_deref())
        .collect();
    let stale: Vec<&LiveQuadlet> = live
        .iter()
        .filter(|q| !current_quadlets.contains(q.relpath.as_path()))
        .collect();

    if changes.is_empty() && stale.is_empty() {
        println!("No bound image changes to apply");
        return Ok(());
    }

    for c in changes.iter() {
        let unit = c.unit.as_deref().unwrap_or("(no unit)");
        println!("{}: {} ({unit})", c.kind, c.spec.image.image);
    }
    for q in stale.iter() {
        println!("reverting stale override: {}", q.relpath);
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

    // Protect every bound image of the staged deployment from GC, not just
    // the changed ones. Written first since it's the one piece of state
    // that can't be recovered later by scanning `/run/containers/systemd/`.
    let run =
        &Dir::open_ambient_dir("/run", cap_std::ambient_authority()).context("Opening /run")?;
    write_protected_images(run, staged_specs.iter().map(|s| s.image.image.as_str()))?;

    // A quadlet moving between search dirs (e.g. vendor -> /etc override)
    // produces an Added and a Removed change for the same `/run` destination;
    // the Removed side must not delete what the Added side just wrote.
    let materialized: BTreeSet<&Utf8Path> = changes
        .iter()
        .filter(|c| matches!(c.kind, ChangeKind::Added | ChangeKind::Updated))
        .filter_map(|c| c.quadlet.as_deref())
        .collect();

    // Materialize the definitions into /run, each carrying a marker. A
    // definition may already be live from a previous apply, in which case
    // its unit doesn't need a restart -- but the marker is still refreshed
    // to the current checksum so status and the fast path above stay
    // accurate.
    let quadlet_run_dir = Utf8Path::new(QUADLET_RUN_DIR);
    let filemode = rustix::fs::Mode::from_raw_mode(0o644);
    let mut written: BTreeMap<&Utf8Path, bool> = BTreeMap::new();
    for c in changes.iter() {
        let Some(quadlet) = c.quadlet.as_deref() else {
            continue;
        };
        let dest = quadlet_run_dir.join(quadlet);
        match c.kind {
            ChangeKind::Added | ChangeKind::Updated => {
                let already_live = live_by_path
                    .get(quadlet)
                    .is_some_and(|prev| !prev.pending && prev.contents == c.spec.contents);
                // Refuse to clobber a `/run` quadlet we didn't write.
                if live_by_path.get(quadlet).is_none() && rootfs.try_exists(&dest)? {
                    anyhow::bail!("Refusing to overwrite non-bootc quadlet override at /{dest}");
                }
                // SAFETY: We know there's a parent
                ensure_quadlet_dir(rootfs, dest.parent().unwrap(), sepolicy.as_ref())?;
                let pending = !already_live && c.unit.is_some();
                crate::lsm::atomic_replace_labeled(
                    rootfs,
                    &dest,
                    filemode,
                    sepolicy.as_ref(),
                    |w| {
                        let marker =
                            marker_line(staged_csum.as_str(), pending, c.spec.image.image.as_str());
                        w.write_all(marker.as_bytes())?;
                        w.write_all(c.spec.contents.as_bytes())?;
                        Ok(())
                    },
                )?;
                written.insert(quadlet, pending);
            }
            ChangeKind::Removed => {
                if !materialized.contains(quadlet) {
                    rootfs.remove_file_optional(&dest)?;
                }
            }
        }
    }
    for q in stale.iter() {
        // `stale` is disjoint from `materialized` by construction (it's
        // exactly the live quadlets not touched by any change).
        rootfs.remove_file_optional(quadlet_run_dir.join(&q.relpath))?;
    }

    if opts.no_restart {
        println!("Skipping unit restart; re-run without --no-restart to restart pending units");
        return Ok(());
    }

    // Units for removed definitions, and old units left behind by a rename
    // (e.g. `ServiceName=` changing), must be stopped before the daemon
    // reload which makes them disappear from systemd's view.
    let removed_units = changes
        .iter()
        .filter(|c| c.kind == ChangeKind::Removed)
        .filter_map(|c| c.unit.as_deref())
        .chain(changes.iter().filter_map(|c| c.old_unit.as_deref()))
        .chain(stale.iter().filter_map(|q| q.unit.as_deref()));
    for unit in removed_units {
        systemctl(&["stop", unit])?;
    }
    systemctl(&["daemon-reload"])?;
    // A stale override reverts to the booted deployment's definition if
    // there is one, otherwise the unit is simply gone.
    for q in stale.iter() {
        let Some(unit) = q.unit.as_deref() else {
            continue;
        };
        let booted_has = booted_specs
            .iter()
            .any(|s| quadlet_relpath(&s.path) == Some(q.relpath.as_path()));
        if booted_has {
            systemctl(&["start", unit])?;
        }
    }

    // Restart units for the definitions we just materialized, flipping
    // their markers from pending to applied as each one succeeds.
    let newly_written: Vec<LiveQuadlet> = changes
        .iter()
        .filter(|c| matches!(c.kind, ChangeKind::Added | ChangeKind::Updated))
        .filter_map(|c| {
            let quadlet = c.quadlet.as_deref()?;
            written
                .get(quadlet)
                .copied()
                .unwrap_or(false)
                .then(|| LiveQuadlet {
                    relpath: quadlet.to_owned(),
                    checksum: staged_csum.to_string(),
                    pending: true,
                    image: c.spec.image.image.clone(),
                    contents: c.spec.contents.clone(),
                    unit: c.unit.clone(),
                })
        })
        .collect();
    restart_pending(rootfs, &newly_written, sepolicy.as_ref())?;

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
    fn test_compute_changes_unit_rename() -> Result<()> {
        // Same quadlet path in both, but `ServiceName=` changed: the old
        // unit must still be reported so it gets stopped.
        const Q: &str = "usr/share/containers/systemd";
        let staged_root = &tempdir()?;
        let old = "[Container]\nImage=quay.io/foo/foo:v1\nServiceName=old\n";
        let new = "[Container]\nImage=quay.io/foo/foo:v2\nServiceName=new\n";
        let booted = [spec(
            &format!("{Q}/foo.container"),
            "quay.io/foo/foo:v1",
            old,
        )];
        let staged = [spec(
            &format!("{Q}/foo.container"),
            "quay.io/foo/foo:v2",
            new,
        )];
        let changes = compute_changes(&booted, &staged, staged_root)?;
        assert_eq!(changes.len(), 1);
        let c = &changes[0];
        assert_eq!(c.kind, ChangeKind::Updated);
        assert_eq!(c.unit.as_deref(), Some("new.service"));
        assert_eq!(c.old_unit.as_deref(), Some("old.service"));

        // Same scenario, but the unit name doesn't actually change
        let new_same_name = "[Container]\nImage=quay.io/foo/foo:v2\nServiceName=old\n";
        let staged = [spec(
            &format!("{Q}/foo.container"),
            "quay.io/foo/foo:v2",
            new_same_name,
        )];
        let changes = compute_changes(&booted, &staged, staged_root)?;
        assert_eq!(changes[0].old_unit, None);
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
                old_unit: None,
            },
            QuadletChange {
                kind: ChangeKind::Added,
                spec: spec("etc/containers/systemd/bar.image", "quay.io/foo/bar:v1", ""),
                quadlet: Some("bar.image".into()),
                unit: None,
                old_unit: None,
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
    fn test_marker_roundtrip() {
        let line = marker_line("abc123", true, "quay.io/foo/foo:v2");
        assert_eq!(
            line,
            "# X-Bootc-Apply-Live: checksum=abc123 pending=true image=quay.io/foo/foo:v2\n"
        );
        let contents = format!("{line}[Container]\nImage=quay.io/foo/foo:v2\n");
        let (checksum, pending, image, rest) = parse_marker(&contents).unwrap();
        assert_eq!(checksum, "abc123");
        assert!(pending);
        assert_eq!(image, "quay.io/foo/foo:v2");
        assert_eq!(rest, "[Container]\nImage=quay.io/foo/foo:v2\n");

        // A quadlet bootc didn't write has no marker
        assert_eq!(
            parse_marker("[Container]\nImage=quay.io/foo/foo:v2\n"),
            None
        );
        // Likewise an empty file
        assert_eq!(parse_marker(""), None);
    }

    #[test]
    fn test_scan_live_quadlets() -> Result<()> {
        let rootfs = &tempdir()?;
        rootfs.create_dir_all(QUADLET_RUN_DIR)?;
        let body = "[Container]\nImage=quay.io/foo/foo:v2\n";
        rootfs.write(
            format!("{QUADLET_RUN_DIR}/foo.container"),
            format!(
                "{}{body}",
                marker_line("abc123", true, "quay.io/foo/foo:v2")
            ),
        )?;
        // A sibling file bootc didn't write is ignored
        rootfs.write(
            format!("{QUADLET_RUN_DIR}/unrelated.container"),
            "[Container]\nImage=quay.io/other/other:latest\n",
        )?;
        // A pull-only bound image (no search-dir quadlet) has nothing to
        // scan here; that's covered by `write_protected_images` instead.

        // A unit masked by symlinking it to /dev/null must not break the
        // scan (cap-std rejects resolving absolute symlink targets).
        rootfs.symlink_contents("/dev/null", format!("{QUADLET_RUN_DIR}/masked.container"))?;

        let live = scan_live_quadlets(rootfs)?;
        assert_eq!(live.len(), 1);
        let q = &live[0];
        assert_eq!(q.relpath, Utf8PathBuf::from("foo.container"));
        assert_eq!(q.checksum, "abc123");
        assert!(q.pending);
        assert_eq!(q.image, "quay.io/foo/foo:v2");
        assert_eq!(q.contents, body);
        assert_eq!(q.unit.as_deref(), Some("foo.service"));
        Ok(())
    }

    #[test]
    fn test_protected_images_roundtrip() -> Result<()> {
        let run = &tempdir()?;
        assert_eq!(protected_images_from_host_at(run)?, Vec::<String>::new());
        write_protected_images(
            run,
            ["quay.io/foo/foo:v2", "quay.io/foo/bar:latest"].into_iter(),
        )?;
        assert_eq!(
            protected_images_from_host_at(run)?,
            vec![
                "quay.io/foo/bar:latest".to_string(),
                "quay.io/foo/foo:v2".to_string(),
            ]
        );
        // A later apply (e.g. a subsequent staged deployment) must not drop
        // images still protected from an earlier one.
        write_protected_images(run, ["quay.io/foo/baz:latest"].into_iter())?;
        assert_eq!(
            protected_images_from_host_at(run)?,
            vec![
                "quay.io/foo/bar:latest".to_string(),
                "quay.io/foo/baz:latest".to_string(),
                "quay.io/foo/foo:v2".to_string(),
            ]
        );
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
