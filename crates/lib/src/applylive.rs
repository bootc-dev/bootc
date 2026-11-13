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
//! (see [`marker_line`]): the staged checksum, the image reference and
//! whether its unit still needs restarting ("pending"). Units that have no
//! such override to carry their state -- old units to stop after a
//! removal or a `ServiceName=` rename, and units reverting to the booted
//! definition when a stale override is removed -- are recorded in two
//! small flat lists under `/run/bootc/apply-live/` (see [`UnitActions`]),
//! written before `/run/containers/systemd/` changes; a third one keeps
//! the units an apply stopped (see [`STOPPED_UNITS_LIST`]). Re-running the
//! command re-derives everything from that directory (see
//! [`scan_live_quadlets`]) plus those lists, so a failure part way through
//! -- including a failed stop -- is safe to resume from.
//! Garbage-collection protection for bound images with no quadlet override
//! (unchanged definitions) lives in the same directory; see
//! [`write_protected_images`]. Once every definition is written, the
//! staged checksum is recorded there too (see [`APPLIED_CHECKSUM`]); only
//! then may a re-run skip straight to the pending unit operations.

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
/// Flat, one-unit-per-line list (relative to `/run`) of systemd units that
/// still need to be stopped before `daemon-reload`; see [`UnitActions`].
const PENDING_STOPS_LIST: &str = "bootc/apply-live/pending-stops.list";
/// Flat, one-unit-per-line list (relative to `/run`) of systemd units with
/// no `/run` override that still need restarting after `daemon-reload`;
/// see [`UnitActions`].
const PENDING_RESTARTS_LIST: &str = "bootc/apply-live/pending-restarts.list";
/// Flat, one-unit-per-line list (relative to `/run`) of the units an apply
/// stopped because the staged deployment no longer defined them. Nothing
/// else records them (a removal leaves no override behind), and a later
/// apply whose staged deployment defines one again has to start it.
const STOPPED_UNITS_LIST: &str = "bootc/apply-live/stopped-units.list";
/// The staged checksum (relative to `/run`) whose definitions have all been
/// written to [`QUADLET_RUN_DIR`] and whose unit operations are recorded.
/// Removals and pull-only definitions leave nothing in [`QUADLET_RUN_DIR`],
/// so this is the only proof that an apply of that checksum got that far.
/// Removed before a new apply changes anything.
const APPLIED_CHECKSUM: &str = "bootc/apply-live/applied-checksum";
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
const QUADLET_SEARCH_DIRS: &[&str] = &[ETC_QUADLET_DIR, VENDOR_QUADLET_DIR];
/// The administrator's quadlet search directory, relative to `/`.
const ETC_QUADLET_DIR: &str = "etc/containers/systemd";
/// The vendor quadlet search directory, relative to `/`.
const VENDOR_QUADLET_DIR: &str = "usr/share/containers/systemd";
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
    /// The systemd unit generated from this definition, if any.
    pub(crate) unit: Option<String>,
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
    let mk = |kind, spec: &BoundImageSpec| -> Result<QuadletChange> {
        let quadlet = quadlet_relpath(&spec.path).map(ToOwned::to_owned);
        let unit = unit_for(quadlet.as_deref(), &spec.contents)?;
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
            // A changed unit name (e.g. via `ServiceName=`) is handled by
            // `plan_unit_actions`, which stops the booted unit.
            Some(_) => changes.push(mk(ChangeKind::Updated, spec)?),
            None => changes.push(mk(ChangeKind::Added, spec)?),
        }
    }
    for (path, spec) in booted.iter() {
        if staged.contains_key(path) {
            continue;
        }
        if quadlet_present(staged_root, path)? {
            // The quadlet still exists, it's just no longer a bound image;
            // there's nothing to change on the running system.
            tracing::debug!("No longer bound, but still present: {path}");
            continue;
        }
        changes.push(mk(ChangeKind::Removed, spec)?);
    }
    Ok(changes)
}

/// True if `root` has a quadlet at `path`. Symlinks aren't followed, as
/// cap-std can't resolve an absolute target; one to `/dev/null` masks the
/// quadlet and doesn't count.
fn quadlet_present(root: &Dir, path: &Utf8Path) -> Result<bool> {
    let Some(meta) = root.symlink_metadata_optional(path)? else {
        return Ok(false);
    };
    Ok(!meta.is_symlink() || root.read_link_contents(path)? != std::path::Path::new("/dev/null"))
}

/// Recursively collect every non-directory entry under `dir` (a commit-form
/// absolute path) in the given root, as commit-form absolute paths.
/// Symlinks are included: [`check_diff_scope`] needs them so a symlink
/// inside an added in-scope directory is still reported as out of scope.
/// Callers that only want regular files (e.g. [`scan_live_quadlets`]) must
/// filter themselves.
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
        } else {
            out.push(path);
        }
    }
    Ok(())
}

/// Rootless users' quadlets, which the system generator doesn't read.
const ETC_QUADLET_USERS_DIR: &str = "/etc/containers/systemd/users";

/// Like [`walk_files`], in the order podman's quadlet generator reads a
/// search directory: a directory's own entries by name, then its
/// subdirectories by name, recursively. Of quadlets sharing a file name,
/// podman uses the first in this order. Like the system generator, this
/// skips drop-in (`*.d`) directories and rootless users' quadlets.
fn walk_quadlets(root: &Dir, dir: &str, out: &mut Vec<String>) -> Result<()> {
    let rel = dir.trim_start_matches('/');
    let Some(d) = root.open_dir_optional(rel)? else {
        return Ok(());
    };
    let (mut files, mut dirs) = (Vec::new(), Vec::new());
    for entry in d.entries()? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid non-UTF8 filename: {name:?} in {dir}"))?;
        let path = format!("{dir}/{name}");
        if entry.file_type()?.is_dir() {
            if !name.ends_with(".d") && path != ETC_QUADLET_USERS_DIR {
                dirs.push(path);
            }
        } else {
            files.push(path);
        }
    }
    files.sort();
    dirs.sort();
    out.extend(files);
    for d in dirs {
        walk_quadlets(root, &d, out)?;
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
/// e.g. a quadlet bootc didn't write. Unknown keys are ignored.
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
/// recognized marker are skipped. Symlinks and other non-regular entries
/// (e.g. a unit masked via `-> /dev/null`) are skipped before reading, so
/// cap-std's absolute-symlink resolution can't break `bootc status`.
fn scan_live_quadlets(rootfs: &Dir) -> Result<Vec<LiveQuadlet>> {
    let mut paths = Vec::new();
    walk_files(rootfs, &format!("/{QUADLET_RUN_DIR}"), &mut paths)?;
    let prefix = format!("/{QUADLET_RUN_DIR}/");
    let mut out = Vec::new();
    for p in paths {
        let Some(relpath) = p.strip_prefix(prefix.as_str()) else {
            continue;
        };
        let rel = p.trim_start_matches('/');
        // Don't follow symlinks: an absolute target like `/dev/null` fails
        // cap-std path resolution, and bootc only writes regular files.
        let Some(meta) = rootfs.symlink_metadata_optional(rel)? else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let Some(contents) = rootfs.read_to_string_optional(rel)? else {
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

/// Read a one-entry-per-line list (relative to `/run`), if present.
fn read_list(run: &Dir, path: &str) -> Result<BTreeSet<String>> {
    let Some(contents) = run
        .read_to_string_optional(path)
        .with_context(|| format!("Reading /run/{path}"))?
    else {
        return Ok(BTreeSet::new());
    };
    Ok(contents
        .lines()
        .filter(|l| !l.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

/// Replace a one-entry-per-line list (relative to `/run`), creating the
/// state dir if needed. An empty set removes the file.
fn write_list(run: &Dir, path: &str, entries: &BTreeSet<String>) -> Result<()> {
    if entries.is_empty() {
        run.remove_file_optional(path)?;
        return Ok(());
    }
    run.create_dir_all(STATE_DIR)?;
    run.atomic_replace_with(path, |w| -> Result<()> {
        for entry in entries {
            writeln!(w, "{entry}")?;
        }
        Ok(())
    })
    .with_context(|| format!("Writing /run/{path}"))
}

/// Unit operations still to be carried out, beyond restarting the units of
/// the `/run` overrides marked pending. They are persisted in
/// [`PENDING_STOPS_LIST`] and [`PENDING_RESTARTS_LIST`] before anything in
/// [`QUADLET_RUN_DIR`] changes, and cleared only once they succeed, so
/// `--no-restart`, a failed `systemctl` call or an interrupted run can be
/// resumed by running the command again.
#[derive(Debug, Default, PartialEq, Eq)]
struct UnitActions {
    /// Units to stop before `daemon-reload`: units the staged deployment no
    /// longer defines (removals, the old name of a `ServiceName=` rename).
    stop: BTreeSet<String>,
    /// Units without a `/run` override to restart after `daemon-reload`:
    /// units reverting to the booted definition when a stale override is
    /// removed.
    restart: BTreeSet<String>,
}

impl UnitActions {
    fn load(run: &Dir) -> Result<Self> {
        Ok(Self {
            stop: read_list(run, PENDING_STOPS_LIST)?,
            restart: read_list(run, PENDING_RESTARTS_LIST)?,
        })
    }

    fn store(&self, run: &Dir) -> Result<()> {
        write_list(run, PENDING_STOPS_LIST, &self.stop)?;
        write_list(run, PENDING_RESTARTS_LIST, &self.restart)
    }

    fn is_empty(&self) -> bool {
        self.stop.is_empty() && self.restart.is_empty()
    }
}

/// The unit generated from the quadlet that `specs` define at `relpath`
/// (relative to a search directory), honoring search-directory precedence.
fn unit_at(specs: &[BoundImageSpec], relpath: &Utf8Path) -> Result<Option<String>> {
    for dir in QUADLET_SEARCH_DIRS {
        let path = Utf8Path::new(dir).join(relpath);
        if let Some(spec) = specs.iter().find(|s| s.path == path) {
            return quadlet_unit_name(relpath, &spec.contents);
        }
    }
    Ok(None)
}

/// The units generated by the `.container` quadlets of the deployment at
/// `root`, bound or not: a unit whose quadlet is merely no longer bound
/// still runs after a reboot. Like podman's quadlet generator, this uses
/// one quadlet per file name, wherever in the search directories it is,
/// with `/etc` taking precedence over the vendor directory; a masked one
/// (`-> /dev/null`) or a dangling symlink defines nothing.
fn defined_units(root: &Dir) -> Result<BTreeSet<String>> {
    // Like `query_bound_image_specs`, resolve absolute symlinks in the root.
    let absroot = &root.open_dir_rooted_ext(".")?;
    let mut seen = BTreeSet::new();
    let mut units = BTreeSet::new();
    for dir in QUADLET_SEARCH_DIRS {
        let mut paths = Vec::new();
        walk_quadlets(root, &format!("/{dir}"), &mut paths)?;
        for path in paths {
            let path = Utf8Path::new(path.trim_start_matches('/'));
            let (Some(relpath), Some(name)) = (quadlet_relpath(path), path.file_name()) else {
                continue;
            };
            if !seen.insert(name.to_owned()) || path.extension() != Some("container") {
                continue;
            }
            if root.symlink_metadata(path)?.is_symlink()
                && root.read_link_contents(path)? == std::path::Path::new("/dev/null")
            {
                continue;
            }
            let contents = match absroot.read_to_string(path) {
                Ok(c) => c,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    tracing::debug!("Skipping dangling quadlet {path}");
                    continue;
                }
                Err(e) => return Err(e).with_context(|| format!("Reading {path}")),
            };
            units.extend(quadlet_unit_name(relpath, &contents)?);
        }
    }
    Ok(units)
}

/// Decide which units to stop and restart to move the running system from
/// its current definitions (the booted ones, or a live override where one
/// exists) to the staged ones, which define the units in `defined` (see
/// [`defined_units`]).
///
/// Every unit that may be running from a definition this apply replaces,
/// removes or reverts is a candidate, as are the operations `previous` runs
/// left pending. A candidate the staged deployment no longer defines is
/// stopped; one it still defines is restarted, unless this apply writes a
/// `/run` override for it, whose marker covers its restart (and which must
/// not be stopped, as it keeps running). Units in `stopped` (see
/// [`STOPPED_UNITS_LIST`]) that the staged deployment defines again are
/// restarted too.
fn plan_unit_actions(
    changes: &[QuadletChange],
    stale: &[&LiveQuadlet],
    live_by_path: &BTreeMap<&Utf8Path, &LiveQuadlet>,
    booted_specs: &[BoundImageSpec],
    defined: &BTreeSet<String>,
    previous: UnitActions,
    stopped: &BTreeSet<String>,
) -> Result<UnitActions> {
    // A stop left pending (say by `--no-restart`) of a unit the staged
    // deployment defines again becomes a restart: its override may be gone
    // already, while the unit still runs that definition.
    let mut candidates = previous.stop;
    candidates.extend(previous.restart);
    let relpaths = changes
        .iter()
        .filter_map(|c| c.quadlet.as_deref())
        .chain(stale.iter().map(|q| q.relpath.as_path()));
    for relpath in relpaths {
        if let Some(live) = live_by_path.get(relpath) {
            candidates.extend(live.unit.clone());
        }
        candidates.extend(unit_at(booted_specs, relpath)?);
    }

    // A stopped unit that is still undefined stays stopped, with nothing to do.
    candidates.extend(stopped.intersection(defined).cloned());
    let materialized: BTreeSet<&str> = changes
        .iter()
        .filter(|c| matches!(c.kind, ChangeKind::Added | ChangeKind::Updated))
        .filter_map(|c| c.unit.as_deref())
        .collect();

    let mut actions = UnitActions::default();
    for unit in candidates {
        if !defined.contains(unit.as_str()) {
            actions.stop.insert(unit);
        } else if !materialized.contains(unit.as_str()) {
            actions.restart.insert(unit);
        }
    }
    Ok(actions)
}

/// Build the `bootc status` view of live-applied bound images by scanning
/// [`QUADLET_RUN_DIR`]. Returns `None` if nothing is applied live, or if
/// the markers disagree on the staged checksum (e.g. a partial apply left
/// a mix of deployments) -- status then shows no live state rather than
/// attributing every image to whichever file the scan returned first.
/// `deploy_serial` isn't recorded in the markers, so it's left as `0` for
/// callers to fill in by matching `checksum` against a deployment.
pub(crate) fn status_from_host() -> Result<Option<LiveBoundImages>> {
    let rootfs = Dir::open_ambient_dir("/", cap_std::ambient_authority()).context("Opening /")?;
    let live = scan_live_quadlets(&rootfs)?;
    let Some(checksum) = live.first().map(|q| q.checksum.clone()) else {
        return Ok(None);
    };
    if live.iter().any(|q| q.checksum != checksum) {
        tracing::warn!(
            "Live bound-image markers disagree on staged checksum; omitting liveBoundImages from status"
        );
        return Ok(None);
    }
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
    let had_state = run.remove_all_optional(STATE_DIR)?;
    if live.is_empty() && !had_state {
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
    // Walk parents under `/run` but not `/run` itself (podman owns that).
    let ancestors: Vec<_> = path
        .ancestors()
        .take_while(|p| p.components().count() > 1)
        .collect();
    for dir in ancestors.into_iter().rev() {
        if rootfs.try_exists(dir)? {
            continue;
        }
        crate::lsm::ensure_dir_labeled(rootfs, dir, None, mode, sepolicy)?;
    }
    Ok(())
}

/// Rewrite the marker on an already-materialized quadlet with the given
/// `pending` state, leaving its body untouched.
fn set_quadlet_marker(
    rootfs: &Dir,
    q: &LiveQuadlet,
    pending: bool,
    sepolicy: Option<&ostree_ext::ostree::SePolicy>,
) -> Result<()> {
    let dest = Utf8Path::new(QUADLET_RUN_DIR).join(&q.relpath);
    let filemode = rustix::fs::Mode::from_raw_mode(0o644);
    crate::lsm::atomic_replace_labeled(rootfs, &dest, filemode, sepolicy, |w| {
        w.write_all(marker_line(&q.checksum, pending, &q.image).as_bytes())?;
        w.write_all(q.contents.as_bytes())?;
        Ok(())
    })
}

/// Stop `unit`. A unit systemd doesn't know and isn't running is as
/// stopped as it gets: e.g. the live name of a rename applied with
/// `--no-restart`, whose override no `daemon-reload` ever generated.
fn stop_unit(unit: &str) -> Result<()> {
    let r = systemctl(&["stop", unit]);
    if r.is_err() {
        let state = Command::new("systemctl")
            .args(["show", "--property=LoadState,ActiveState", unit])
            .run_get_string();
        if let Ok(state) = state {
            let state: BTreeSet<&str> = state.lines().collect();
            if state.contains("LoadState=not-found") && state.contains("ActiveState=inactive") {
                tracing::debug!("Not stopping unknown unit {unit}");
                return Ok(());
            }
        }
    }
    r
}

/// Carry out `actions` and restart the units of the overrides in `live`
/// still marked pending, clearing each record only once its operations
/// succeeded, so a failure part way through can be retried on the next run.
/// Keeps [`STOPPED_UNITS_LIST`] up to date along the way.
fn run_unit_actions(
    rootfs: &Dir,
    run: &Dir,
    mut actions: UnitActions,
    live: &[LiveQuadlet],
    sepolicy: Option<&ostree_ext::ostree::SePolicy>,
) -> Result<()> {
    let mut stopped = read_list(run, STOPPED_UNITS_LIST)?;
    // Stop before reloading, while the old definitions are still loaded.
    for unit in &actions.stop {
        stop_unit(unit)?;
        // Right away: if a later stop fails, this one still happened.
        if stopped.insert(unit.clone()) {
            write_list(run, STOPPED_UNITS_LIST, &stopped)?;
        }
    }
    actions.stop.clear();
    actions.store(run)?;
    systemctl(&["daemon-reload"])?;
    for unit in &actions.restart {
        systemctl(&["restart", unit])?;
        stopped.remove(unit);
    }
    actions.restart.clear();
    write_list(run, STOPPED_UNITS_LIST, &stopped)?;
    actions.store(run)?;
    for q in live.iter().filter(|q| q.pending) {
        if let Some(unit) = q.unit.as_deref() {
            // `restart` also starts a unit which is not running (the added case).
            systemctl(&["restart", unit])?;
            if stopped.remove(unit) {
                write_list(run, STOPPED_UNITS_LIST, &stopped)?;
            }
        }
        set_quadlet_marker(rootfs, q, false, sepolicy)?;
    }
    Ok(())
}

/// True when every Added/Updated change already has a live `/run` override
/// matching `staged_csum` and contents, and every Removed change's
/// destination (that isn't also being replaced) is gone.
fn materialization_complete(
    changes: &[QuadletChange],
    live_by_path: &BTreeMap<&Utf8Path, &LiveQuadlet>,
    staged_csum: &str,
    rootfs: &Dir,
) -> Result<bool> {
    let materialized: BTreeSet<&Utf8Path> = changes
        .iter()
        .filter(|c| matches!(c.kind, ChangeKind::Added | ChangeKind::Updated))
        .filter_map(|c| c.quadlet.as_deref())
        .collect();
    for c in changes {
        let Some(quadlet) = c.quadlet.as_deref() else {
            continue;
        };
        match c.kind {
            ChangeKind::Added | ChangeKind::Updated => {
                let Some(prev) = live_by_path.get(quadlet) else {
                    return Ok(false);
                };
                if prev.checksum != staged_csum || prev.contents != c.spec.contents {
                    return Ok(false);
                }
            }
            ChangeKind::Removed => {
                if materialized.contains(quadlet) {
                    continue;
                }
                if rootfs.try_exists(Utf8Path::new(QUADLET_RUN_DIR).join(quadlet))? {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

/// True if a previous run already wrote every definition of `staged_csum`
/// (see [`APPLIED_CHECKSUM`]) and nothing has changed in `/run` since, so
/// all that may be left is carrying out the recorded unit operations.
/// Without the record, a removal-only or pull-only change set would look
/// complete before anything was done, as none of it leaves an override.
fn already_materialized(
    run: &Dir,
    rootfs: &Dir,
    staged_csum: &str,
    changes: &[QuadletChange],
    live_by_path: &BTreeMap<&Utf8Path, &LiveQuadlet>,
) -> Result<bool> {
    let applied = run
        .read_to_string_optional(APPLIED_CHECKSUM)
        .with_context(|| format!("Reading /run/{APPLIED_CHECKSUM}"))?;
    if applied.as_deref().map(str::trim) != Some(staged_csum) {
        return Ok(false);
    }
    // Every live override must belong to this change set; anything else
    // is stale and still needs reverting.
    let current: BTreeSet<&Utf8Path> = changes
        .iter()
        .filter_map(|c| c.quadlet.as_deref())
        .collect();
    if live_by_path.keys().any(|p| !current.contains(p)) {
        return Ok(false);
    }
    materialization_complete(changes, live_by_path, staged_csum, rootfs)
}

/// Map each file name in the quadlet search directory `dir` (relative to
/// `/`, subdirectories included) to the path of the file podman uses for
/// it, skipping the paths `skip` accepts.
fn quadlets_by_name(
    rootfs: &Dir,
    dir: &str,
    skip: impl Fn(&Utf8Path) -> bool,
) -> Result<BTreeMap<String, String>> {
    let mut paths = Vec::new();
    walk_quadlets(rootfs, &format!("/{dir}"), &mut paths)?;
    let mut ret = BTreeMap::new();
    for path in paths {
        let Some(name) = Utf8Path::new(&path).file_name() else {
            continue;
        };
        if !skip(Utf8Path::new(&path)) {
            ret.entry(name.to_owned()).or_insert(path);
        }
    }
    Ok(ret)
}

/// Refuse changes whose result on the running system would differ from
/// what a reboot into the staged deployment gives. Runs before any pull or
/// write so a conflict can't leave a half-applied `/run` state.
///
/// Podman's quadlet generator uses one quadlet per file name, whichever
/// subdirectory it is in, so quadlets are matched by file name:
///
/// - A `/run` quadlet bootc didn't write, where a change would write or
///   remove one, belongs to someone else and is left alone.
/// - A vendor definition with an `/etc` quadlet of the same name: the
///   administrator's definition wins in `/etc`, and keeps winning after a
///   reboot, but a copy of the vendor one in `/run` would override it, and
///   removing the vendor one would stop the unit the `/etc` one defines.
fn check_destinations(
    rootfs: &Dir,
    changes: &[QuadletChange],
    live_by_path: &BTreeMap<&Utf8Path, &LiveQuadlet>,
) -> Result<()> {
    let run_prefix = format!("/{QUADLET_RUN_DIR}/");
    // Symlinks included: a quadlet masked with `-> /dev/null` is just as
    // much someone else's.
    let foreign_run = quadlets_by_name(rootfs, QUADLET_RUN_DIR, |p| {
        p.as_str()
            .strip_prefix(&run_prefix)
            .is_some_and(|rel| live_by_path.contains_key(Utf8Path::new(rel)))
    })?;
    let etc = quadlets_by_name(rootfs, ETC_QUADLET_DIR, |_| false)?;
    for c in changes {
        let Some(name) = c.quadlet.as_deref().and_then(Utf8Path::file_name) else {
            continue;
        };
        if let Some(path) = foreign_run.get(name) {
            anyhow::bail!("Refusing to change non-bootc quadlet override at {path}");
        }
        if !c.spec.path.starts_with(VENDOR_QUADLET_DIR) {
            continue;
        }
        let Some(etc_path) = etc.get(name) else {
            continue;
        };
        // The bound definition moving from /etc to the vendor directory
        // removes the /etc one in the same deployment.
        let moved_from_etc = changes
            .iter()
            .any(|r| r.kind == ChangeKind::Removed && format!("/{}", r.spec.path) == *etc_path);
        if !moved_from_etc {
            anyhow::bail!(
                "{etc_path} overrides the bound definition /{}; a reboot is required to apply it",
                c.spec.path
            );
        }
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
    let run =
        &Dir::open_ambient_dir("/run", cap_std::ambient_authority()).context("Opening /run")?;
    let booted_root = crate::utils::deployment_fd(sysroot, booted_deployment)?;
    let staged_root = crate::utils::deployment_fd(sysroot, &staged)?;
    let sepolicy = crate::lsm::new_sepolicy_at(&booted_root)?;

    let live = scan_live_quadlets(rootfs)?;
    let live_by_path: BTreeMap<&Utf8Path, &LiveQuadlet> =
        live.iter().map(|q| (q.relpath.as_path(), q)).collect();
    let staged_specs = crate::boundimage::query_bound_image_specs(&staged_root)?;
    let booted_specs = crate::boundimage::query_bound_image_specs(&booted_root)?;
    let changes = compute_changes(&booted_specs, &staged_specs, &staged_root)?;

    // Overrides from a previous apply-live that aren't part of this one
    // need to be removed so the system converges on the current staged
    // definitions rather than a mix of the two.
    let current_quadlets: BTreeSet<&Utf8Path> = changes
        .iter()
        .filter_map(|c| c.quadlet.as_deref())
        .collect();
    let stale: Vec<&LiveQuadlet> = live
        .iter()
        .filter(|q| !current_quadlets.contains(q.relpath.as_path()))
        .collect();

    let previous = UnitActions::load(run)?;

    // Fast path: a previous run already wrote every definition for this
    // staged checksum (it passed the scope check then). All that may be
    // left is the unit operations it recorded (after `--no-restart` or a
    // failed `systemctl` call).
    if already_materialized(run, rootfs, &staged_csum, &changes, &live_by_path)? {
        let pending_restarts = live.iter().filter(|q| q.pending).count();
        if previous.is_empty() && pending_restarts == 0 {
            println!("Bound images from staged deployment are already applied");
            return Ok(());
        }
        // Again, as an administrator may have added a conflicting quadlet
        // since (e.g. after `--no-restart`).
        check_destinations(rootfs, &changes, &live_by_path)?;
        for unit in &previous.stop {
            println!("stop pending: {unit}");
        }
        let restarts = live
            .iter()
            .filter(|q| q.pending)
            .filter_map(|q| q.unit.as_deref());
        for unit in previous.restart.iter().map(String::as_str).chain(restarts) {
            println!("restart pending: {unit}");
        }
        if opts.dry_run || opts.no_restart {
            return Ok(());
        }
        return run_unit_actions(rootfs, run, previous, &live, sepolicy.as_ref());
    }

    if booted_csum != staged_csum {
        let diff =
            ostree_ext::diff::diff(&sysroot.repo(), &booted_csum, &staged_csum, None::<&str>)?;
        tracing::debug!("Diff booted -> staged: {diff}");
        check_diff_scope(&diff, &changes, &booted_root, &staged_root)?;
    }

    let stopped = read_list(run, STOPPED_UNITS_LIST)?;
    let actions = plan_unit_actions(
        &changes,
        &stale,
        &live_by_path,
        &booted_specs,
        &defined_units(&staged_root)?,
        previous,
        &stopped,
    )?;
    if changes.is_empty() && stale.is_empty() && actions.is_empty() {
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
    for unit in &actions.stop {
        println!("stop: {unit}");
    }
    for unit in &actions.restart {
        println!("restart: {unit}");
    }
    // Before any pull/write: a conflict must not leave a half-applied
    // `/run` state that an unrelated daemon-reload could pick up.
    check_destinations(rootfs, &changes, &live_by_path)?;
    if opts.dry_run {
        return Ok(());
    }

    // From here on `/run` changes, so until this apply is complete a re-run
    // must take the full path again.
    run.remove_file_optional(APPLIED_CHECKSUM)?;

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
    write_protected_images(run, staged_specs.iter().map(|s| s.image.image.as_str()))?;

    // Record the unit operations before changing any definition: once an
    // override is replaced or removed, nothing else remembers which unit
    // was running from it.
    actions.store(run)?;

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
    run.atomic_write(APPLIED_CHECKSUM, staged_csum.as_bytes())
        .with_context(|| format!("Writing /run/{APPLIED_CHECKSUM}"))?;

    if opts.no_restart {
        println!(
            "Skipping unit stop/restart; re-run without --no-restart to apply pending unit changes"
        );
        return Ok(());
    }

    let live = scan_live_quadlets(rootfs)?;
    run_unit_actions(rootfs, run, actions, &live, sepolicy.as_ref())?;

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

        // A symlink inside an added in-scope dir is also out of scope
        // (walk_files must report non-directory entries, not only regular
        // files -- otherwise a masked/unbound symlink would slip through).
        staged_root.symlink_contents("/dev/null", format!("{Q}/masked.container"))?;
        let e = check(&diff).unwrap_err().to_string();
        assert!(e.contains(&format!("/{Q}/masked.container")), "{e}");
        staged_root.remove_file(format!("{Q}/masked.container"))?;
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

        // Unknown keys are ignored
        let contents = format!(
            "{MARKER_PREFIX} checksum=abc123 pending=false image=quay.io/foo/foo:v2 other=x\n"
        );
        let (_, pending, _, rest) = parse_marker(&contents).unwrap();
        assert!(!pending);
        assert_eq!(rest, "");

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
    fn test_unit_actions_roundtrip() -> Result<()> {
        let run = &tempdir()?;
        assert!(UnitActions::load(run)?.is_empty());
        let actions = UnitActions {
            stop: BTreeSet::from(["foo.service".to_string(), "bar.service".to_string()]),
            restart: BTreeSet::from(["baz.service".to_string()]),
        };
        actions.store(run)?;
        assert_eq!(UnitActions::load(run)?, actions);
        UnitActions::default().store(run)?;
        assert!(UnitActions::load(run)?.is_empty());
        assert!(!run.try_exists(PENDING_STOPS_LIST)?);
        assert!(!run.try_exists(PENDING_RESTARTS_LIST)?);
        Ok(())
    }

    #[test]
    fn test_defined_units() -> Result<()> {
        let root = &tempdir()?;
        for dir in QUADLET_SEARCH_DIRS {
            root.create_dir_all(format!("{dir}/sub"))?;
        }
        let renamed = "[Container]\nImage=quay.io/foo/foo:v1\nServiceName=renamed\n";
        let plain = "[Container]\nImage=quay.io/foo/foo:v1\n";
        root.write(format!("{VENDOR_QUADLET_DIR}/foo.container"), plain)?;
        // /etc shadows the vendor quadlet of the same name
        root.write(format!("{VENDOR_QUADLET_DIR}/bar.container"), plain)?;
        root.write(format!("{ETC_QUADLET_DIR}/bar.container"), renamed)?;
        root.write(format!("{VENDOR_QUADLET_DIR}/sub/baz.container"), plain)?;
        // Only .container quadlets generate the units we manage
        root.write(format!("{VENDOR_QUADLET_DIR}/img.image"), "[Image]\n")?;
        // A masked quadlet defines nothing
        root.symlink_contents("/dev/null", format!("{ETC_QUADLET_DIR}/masked.container"))?;
        root.write(format!("{VENDOR_QUADLET_DIR}/masked.container"), plain)?;
        // Within a search directory, a top-level quadlet wins over one of
        // the same name in a subdirectory
        let sub_top = "[Container]\nImage=quay.io/foo/foo:v1\nServiceName=subtop\n";
        root.create_dir_all(format!("{VENDOR_QUADLET_DIR}/a"))?;
        root.write(format!("{VENDOR_QUADLET_DIR}/a/top.container"), sub_top)?;
        root.write(format!("{VENDOR_QUADLET_DIR}/top.container"), plain)?;
        // Drop-in directories and rootless users' quadlets aren't quadlets
        // of the system generator
        root.create_dir_all(format!("{ETC_QUADLET_DIR}/users"))?;
        root.write(format!("{ETC_QUADLET_DIR}/users/foo.container"), sub_top)?;
        root.create_dir_all(format!("{ETC_QUADLET_DIR}/foo.container.d"))?;
        root.write(
            format!("{ETC_QUADLET_DIR}/foo.container.d/x.container"),
            sub_top,
        )?;
        // Quadlets are matched by file name, across subdirectories
        let etc_qux = "[Container]\nImage=quay.io/foo/foo:v1\nServiceName=etcqux\n";
        root.write(format!("{ETC_QUADLET_DIR}/sub/qux.container"), etc_qux)?;
        root.write(format!("{VENDOR_QUADLET_DIR}/qux.container"), plain)?;
        // An absolute symlink resolves within the root; a dangling one is skipped
        root.create_dir_all("usr/lib/example")?;
        root.write("usr/lib/example/link.container", plain)?;
        root.symlink_contents(
            "/usr/lib/example/link.container",
            format!("{VENDOR_QUADLET_DIR}/link.container"),
        )?;
        root.symlink_contents(
            "/usr/lib/example/gone.container",
            format!("{VENDOR_QUADLET_DIR}/gone.container"),
        )?;
        let expected: BTreeSet<String> = [
            "foo.service",
            "renamed.service",
            "baz.service",
            "etcqux.service",
            "link.service",
            "top.service",
        ]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect();
        assert_eq!(defined_units(root)?, expected);
        Ok(())
    }

    #[test]
    fn test_revert_unbound_symlinked_quadlet() -> Result<()> {
        // The staged deployment keeps the quadlet, as an absolute symlink,
        // but no longer binds it: reverting the live override restarts
        // the unit rather than stopping it.
        let v1 = "[Container]\nImage=quay.io/foo/foo:v1\n";
        let v2 = "[Container]\nImage=quay.io/foo/foo:v2\n";
        let path = format!("{VENDOR_QUADLET_DIR}/foo.container");
        let staged_root = &tempdir()?;
        staged_root.create_dir_all(VENDOR_QUADLET_DIR)?;
        staged_root.create_dir_all("usr/lib/example")?;
        staged_root.write("usr/lib/example/foo.container", v1)?;
        staged_root.symlink_contents("/usr/lib/example/foo.container", &path)?;
        let booted = [spec(&path, "quay.io/foo/foo:v1", v1)];
        let changes = compute_changes(&booted, &[], staged_root)?;
        assert!(changes.is_empty(), "{changes:?}");
        let live = LiveQuadlet {
            relpath: "foo.container".into(),
            checksum: "abc123".into(),
            pending: false,
            image: "quay.io/foo/foo:v2".into(),
            contents: v2.into(),
            unit: Some("foo.service".into()),
        };
        let live_by_path = BTreeMap::from([(live.relpath.as_path(), &live)]);
        let actions = plan_unit_actions(
            &changes,
            &[&live],
            &live_by_path,
            &booted,
            &defined_units(staged_root)?,
            UnitActions::default(),
            &BTreeSet::new(),
        )?;
        assert!(actions.stop.is_empty(), "{actions:?}");
        assert_eq!(actions.restart, BTreeSet::from(["foo.service".to_string()]));

        // A mask, though, removes it
        staged_root.remove_file(&path)?;
        staged_root.symlink_contents("/dev/null", &path)?;
        let changes = compute_changes(&booted, &[], staged_root)?;
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, ChangeKind::Removed);
        Ok(())
    }

    #[test]
    fn test_plan_unit_actions() -> Result<()> {
        const USR: &str = "usr/share/containers/systemd";
        const ETC: &str = "etc/containers/systemd";
        // A `foo.container` definition in `dir`, optionally renaming its unit.
        let def = |dir: &str, tag: &str, service: Option<&str>| {
            let mut contents = format!("[Container]\nImage=quay.io/foo/foo:{tag}\n");
            if let Some(service) = service {
                contents.push_str(&format!("ServiceName={service}\n"));
            }
            spec(
                &format!("{dir}/foo.container"),
                &format!("quay.io/foo/foo:{tag}"),
                &contents,
            )
        };
        let live = |tag: &str, service: Option<&str>| {
            let d = def(USR, tag, service);
            LiveQuadlet {
                relpath: "foo.container".into(),
                checksum: "abc123".into(),
                pending: false,
                image: d.image.image.clone(),
                unit: quadlet_unit_name("foo.container".into(), &d.contents).unwrap(),
                contents: d.contents,
            }
        };
        let units =
            |names: &[&str]| -> BTreeSet<String> { names.iter().map(|s| s.to_string()).collect() };

        struct Case {
            name: &'static str,
            booted: Vec<BoundImageSpec>,
            staged: Vec<BoundImageSpec>,
            /// Quadlets in the staged deployment that aren't bound
            unbound: Vec<BoundImageSpec>,
            live: Option<LiveQuadlet>,
            previous: UnitActions,
            stopped: &'static [&'static str],
            stop: &'static [&'static str],
            restart: &'static [&'static str],
        }
        let cases = [
            Case {
                name: "update keeps the unit: the marker restarts it",
                booted: vec![def(USR, "v1", None)],
                staged: vec![def(USR, "v2", None)],
                unbound: vec![],
                live: None,
                previous: UnitActions::default(),
                stopped: &[],
                stop: &[],
                restart: &[],
            },
            Case {
                name: "rename stops the booted unit",
                booted: vec![def(USR, "v1", None)],
                staged: vec![def(USR, "v2", Some("bar"))],
                unbound: vec![],
                live: None,
                previous: UnitActions::default(),
                stopped: &[],
                stop: &["foo.service"],
                restart: &[],
            },
            Case {
                name: "rename over a live rename stops the live unit too",
                booted: vec![def(USR, "v1", None)],
                staged: vec![def(USR, "v3", Some("baz"))],
                unbound: vec![],
                live: Some(live("v2", Some("bar"))),
                previous: UnitActions::default(),
                stopped: &[],
                stop: &["bar.service", "foo.service"],
                restart: &[],
            },
            Case {
                name: "removal stops the booted unit",
                booted: vec![def(USR, "v1", None)],
                staged: vec![],
                unbound: vec![],
                live: None,
                previous: UnitActions::default(),
                stopped: &[],
                stop: &["foo.service"],
                restart: &[],
            },
            Case {
                name: "removal of a live rename stops both units",
                booted: vec![def(USR, "v1", None)],
                staged: vec![],
                unbound: vec![],
                live: Some(live("v2", Some("bar"))),
                previous: UnitActions::default(),
                stopped: &[],
                stop: &["bar.service", "foo.service"],
                restart: &[],
            },
            Case {
                name: "reverting a stale override restarts the booted unit",
                booted: vec![def(USR, "v1", None)],
                staged: vec![def(USR, "v1", None)],
                unbound: vec![],
                live: Some(live("v2", None)),
                previous: UnitActions::default(),
                stopped: &[],
                stop: &[],
                restart: &["foo.service"],
            },
            Case {
                name: "reverting a stale rename starts the booted unit by its own name",
                booted: vec![def(USR, "v1", None)],
                staged: vec![def(USR, "v1", None)],
                unbound: vec![],
                live: Some(live("v2", Some("bar"))),
                previous: UnitActions::default(),
                stopped: &[],
                stop: &["bar.service"],
                restart: &["foo.service"],
            },
            Case {
                name: "a move to /etc keeps an already live unit running",
                booted: vec![def(USR, "v2", None)],
                staged: vec![def(ETC, "v2", None)],
                unbound: vec![],
                live: Some(live("v2", None)),
                previous: UnitActions::default(),
                stopped: &[],
                stop: &[],
                restart: &[],
            },
            Case {
                name: "a stop left pending for a unit staged defines again becomes a restart",
                booted: vec![def(USR, "v1", None)],
                staged: vec![def(USR, "v1", None)],
                unbound: vec![],
                live: None,
                previous: UnitActions {
                    stop: units(&["foo.service"]),
                    restart: BTreeSet::new(),
                },
                stopped: &[],
                stop: &[],
                restart: &["foo.service"],
            },
            Case {
                name: "a restart left pending for a unit staged removes becomes a stop",
                booted: vec![def(USR, "v1", None)],
                staged: vec![],
                unbound: vec![],
                live: None,
                previous: UnitActions {
                    stop: BTreeSet::new(),
                    restart: units(&["foo.service"]),
                },
                stopped: &[],
                stop: &["foo.service"],
                restart: &[],
            },
            Case {
                name: "reverting an override whose quadlet is no longer bound restarts it",
                booted: vec![def(USR, "v1", None)],
                staged: vec![],
                unbound: vec![def(USR, "v1", None)],
                live: Some(live("v2", None)),
                previous: UnitActions::default(),
                stopped: &[],
                stop: &[],
                restart: &["foo.service"],
            },
            Case {
                name: "a unit an earlier removal stopped is started once staged defines it again",
                booted: vec![def(USR, "v1", None)],
                staged: vec![def(USR, "v1", None)],
                unbound: vec![],
                live: None,
                previous: UnitActions::default(),
                stopped: &["foo.service"],
                stop: &[],
                restart: &["foo.service"],
            },
            Case {
                name: "a unit an earlier removal stopped stays stopped while undefined",
                booted: vec![def(USR, "v1", None)],
                staged: vec![],
                unbound: vec![],
                live: None,
                previous: UnitActions::default(),
                stopped: &["bar.service"],
                stop: &["foo.service"],
                restart: &[],
            },
        ];
        for case in cases {
            let staged_root = &tempdir()?;
            staged_root.create_dir_all(USR)?;
            staged_root.create_dir_all(ETC)?;
            for s in case.staged.iter().chain(&case.unbound) {
                staged_root.write(&s.path, &s.contents)?;
            }
            let changes = compute_changes(&case.booted, &case.staged, staged_root)?;
            let live_by_path: BTreeMap<&Utf8Path, &LiveQuadlet> =
                case.live.iter().map(|q| (q.relpath.as_path(), q)).collect();
            let current: BTreeSet<&Utf8Path> = changes
                .iter()
                .filter_map(|c| c.quadlet.as_deref())
                .collect();
            let stale: Vec<&LiveQuadlet> = case
                .live
                .iter()
                .filter(|q| !current.contains(q.relpath.as_path()))
                .collect();
            let actions = plan_unit_actions(
                &changes,
                &stale,
                &live_by_path,
                &case.booted,
                &defined_units(staged_root)?,
                case.previous,
                &units(case.stopped),
            )?;
            assert_eq!(actions.stop, units(case.stop), "{}", case.name);
            assert_eq!(actions.restart, units(case.restart), "{}", case.name);
        }
        Ok(())
    }

    #[test]
    fn test_materialization_complete() -> Result<()> {
        let rootfs = &tempdir()?;
        rootfs.create_dir_all(QUADLET_RUN_DIR)?;
        const Q: &str = "usr/share/containers/systemd";
        let body = "[Container]\nImage=quay.io/foo/foo:v2\n";
        let changes = vec![QuadletChange {
            kind: ChangeKind::Updated,
            spec: spec(&format!("{Q}/foo.container"), "quay.io/foo/foo:v2", body),
            quadlet: Some("foo.container".into()),
            unit: Some("foo.service".into()),
        }];
        let live_by_path = BTreeMap::new();
        assert!(!materialization_complete(
            &changes,
            &live_by_path,
            "abc123",
            rootfs
        )?);

        rootfs.write(
            format!("{QUADLET_RUN_DIR}/foo.container"),
            format!(
                "{}{body}",
                marker_line("abc123", true, "quay.io/foo/foo:v2")
            ),
        )?;
        let live = scan_live_quadlets(rootfs)?;
        let live_by_path: BTreeMap<&Utf8Path, &LiveQuadlet> =
            live.iter().map(|q| (q.relpath.as_path(), q)).collect();
        assert!(materialization_complete(
            &changes,
            &live_by_path,
            "abc123",
            rootfs
        )?);
        // Wrong checksum => not complete
        assert!(!materialization_complete(
            &changes,
            &live_by_path,
            "other",
            rootfs
        )?);
        Ok(())
    }

    #[test]
    fn test_already_materialized() -> Result<()> {
        let rootfs = &tempdir()?;
        let run = &tempdir()?;
        rootfs.create_dir_all(QUADLET_RUN_DIR)?;
        run.create_dir_all(STATE_DIR)?;
        const Q: &str = "usr/share/containers/systemd";
        let gone = "[Container]\nImage=quay.io/foo/gone:latest\n";
        let removed = QuadletChange {
            kind: ChangeKind::Removed,
            spec: spec(
                &format!("{Q}/gone.container"),
                "quay.io/foo/gone:latest",
                gone,
            ),
            quadlet: Some("gone.container".into()),
            unit: Some("gone.service".into()),
        };
        let pull_only = QuadletChange {
            kind: ChangeKind::Added,
            spec: spec("usr/lib/misc/new.container", "quay.io/foo/new:latest", gone),
            quadlet: None,
            unit: None,
        };
        let no_live = BTreeMap::new();
        // Neither a removal nor a pull-only change leaves anything in /run,
        // so without the record they must not look applied...
        for changes in [vec![removed], vec![pull_only], vec![]] {
            assert!(!already_materialized(
                run, rootfs, "abc123", &changes, &no_live
            )?);
            // ...until a run records this checksum, and only this one
            run.write(APPLIED_CHECKSUM, "abc123")?;
            assert!(already_materialized(
                run, rootfs, "abc123", &changes, &no_live
            )?);
            assert!(!already_materialized(
                run, rootfs, "other", &changes, &no_live
            )?);
            run.remove_file(APPLIED_CHECKSUM)?;
        }

        // A live override outside the change set is stale, so not applied
        // even with the record.
        let body = "[Container]\nImage=quay.io/foo/foo:v2\n";
        rootfs.write(
            format!("{QUADLET_RUN_DIR}/foo.container"),
            format!(
                "{}{body}",
                marker_line("abc123", false, "quay.io/foo/foo:v2")
            ),
        )?;
        let live = scan_live_quadlets(rootfs)?;
        let live_by_path: BTreeMap<&Utf8Path, &LiveQuadlet> =
            live.iter().map(|q| (q.relpath.as_path(), q)).collect();
        run.write(APPLIED_CHECKSUM, "abc123")?;
        assert!(!already_materialized(
            run,
            rootfs,
            "abc123",
            &[],
            &live_by_path
        )?);
        Ok(())
    }

    #[test]
    fn test_check_destinations() -> Result<()> {
        let contents = "[Container]\nImage=quay.io/foo/foo:v2\n";
        let change = |kind, dir: &str| QuadletChange {
            kind,
            spec: spec(
                &format!("{dir}/foo.container"),
                "quay.io/foo/foo:v2",
                contents,
            ),
            quadlet: Some("foo.container".into()),
            unit: Some("foo.service".into()),
        };
        let run_quadlet = format!("{QUADLET_RUN_DIR}/foo.container");
        let etc_quadlet = format!("{ETC_QUADLET_DIR}/foo.container");
        let owned = format!(
            "{}{contents}",
            marker_line("abc123", false, "quay.io/foo/foo:v2")
        );
        enum File {
            /// A quadlet bootc wrote
            Owned,
            Regular(&'static str),
            Symlink(&'static str),
        }
        // (description, changes, files on the host, expected error)
        let cases: Vec<(&str, Vec<QuadletChange>, Vec<(&str, File)>, Option<&str>)> = vec![
            (
                "nothing in the way",
                vec![change(ChangeKind::Updated, VENDOR_QUADLET_DIR)],
                vec![],
                None,
            ),
            (
                "our own override",
                vec![change(ChangeKind::Updated, VENDOR_QUADLET_DIR)],
                vec![(run_quadlet.as_str(), File::Owned)],
                None,
            ),
            (
                "someone else's override",
                vec![change(ChangeKind::Updated, VENDOR_QUADLET_DIR)],
                vec![(run_quadlet.as_str(), File::Regular("[Container]\n"))],
                Some("non-bootc quadlet override"),
            ),
            (
                "someone else's override of a removed quadlet",
                vec![change(ChangeKind::Removed, VENDOR_QUADLET_DIR)],
                vec![(run_quadlet.as_str(), File::Regular("[Container]\n"))],
                Some("non-bootc quadlet override"),
            ),
            (
                "a masked override",
                vec![change(ChangeKind::Added, VENDOR_QUADLET_DIR)],
                vec![(run_quadlet.as_str(), File::Symlink("/dev/null"))],
                Some("non-bootc quadlet override"),
            ),
            (
                "an /etc quadlet shadowing the vendor one",
                vec![change(ChangeKind::Updated, VENDOR_QUADLET_DIR)],
                vec![(etc_quadlet.as_str(), File::Regular("[Container]\n"))],
                Some("a reboot is required"),
            ),
            (
                "someone else's override of the same name in a subdirectory",
                vec![change(ChangeKind::Updated, VENDOR_QUADLET_DIR)],
                vec![(
                    "run/containers/systemd/sub/foo.container",
                    File::Regular("[Container]\n"),
                )],
                Some("non-bootc quadlet override"),
            ),
            (
                "an /etc quadlet of the same name in a subdirectory",
                vec![change(ChangeKind::Updated, VENDOR_QUADLET_DIR)],
                vec![(
                    "etc/containers/systemd/sub/foo.container",
                    File::Regular("[Container]\n"),
                )],
                Some("a reboot is required"),
            ),
            (
                "unrelated quadlets in /etc and /run",
                vec![change(ChangeKind::Updated, VENDOR_QUADLET_DIR)],
                vec![
                    (
                        "etc/containers/systemd/bar.container",
                        File::Regular("[Container]\n"),
                    ),
                    (
                        "run/containers/systemd/bar.container",
                        File::Regular("[Container]\n"),
                    ),
                ],
                None,
            ),
            (
                "an /etc quadlet shadowing a removed vendor one",
                vec![change(ChangeKind::Removed, VENDOR_QUADLET_DIR)],
                vec![(etc_quadlet.as_str(), File::Regular("[Container]\n"))],
                Some("a reboot is required"),
            ),
            (
                "an /etc mask shadowing the vendor one",
                vec![change(ChangeKind::Added, VENDOR_QUADLET_DIR)],
                vec![(etc_quadlet.as_str(), File::Symlink("/dev/null"))],
                Some("a reboot is required"),
            ),
            (
                "the bound definition moving from /etc to the vendor directory",
                vec![
                    change(ChangeKind::Added, VENDOR_QUADLET_DIR),
                    change(ChangeKind::Removed, ETC_QUADLET_DIR),
                ],
                vec![(etc_quadlet.as_str(), File::Regular("[Container]\n"))],
                None,
            ),
            (
                "the bound definition itself in /etc",
                vec![change(ChangeKind::Updated, ETC_QUADLET_DIR)],
                vec![(etc_quadlet.as_str(), File::Regular("[Container]\n"))],
                None,
            ),
        ];
        for (name, changes, files, expected) in cases {
            let rootfs = &tempdir()?;
            rootfs.create_dir_all(QUADLET_RUN_DIR)?;
            rootfs.create_dir_all(ETC_QUADLET_DIR)?;
            for (path, file) in files {
                if let Some(parent) = Utf8Path::new(path).parent() {
                    rootfs.create_dir_all(parent)?;
                }
                match file {
                    File::Owned => rootfs.write(path, &owned)?,
                    File::Regular(contents) => rootfs.write(path, contents)?,
                    File::Symlink(target) => rootfs.symlink_contents(target, path)?,
                }
            }
            let live = scan_live_quadlets(rootfs)?;
            let live_by_path: BTreeMap<&Utf8Path, &LiveQuadlet> =
                live.iter().map(|q| (q.relpath.as_path(), q)).collect();
            let r = check_destinations(rootfs, &changes, &live_by_path);
            match expected {
                None => r.unwrap_or_else(|e| panic!("{name}: {e:#}")),
                Some(msg) => {
                    let e = format!("{:#}", r.unwrap_err());
                    assert!(e.contains(msg), "{name}: {e}");
                }
            }
        }
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
