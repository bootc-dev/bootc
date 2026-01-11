//! # Implementation of container build lints
//!
//! This module implements `bootc container lint`.

// Unfortunately needed here to work with linkme
#![allow(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::env::consts::ARCH;
use std::fmt::{Display, Write as WriteFmt};
use std::num::NonZeroUsize;
use std::ops::ControlFlow;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use anyhow::Result;
use bootc_utils::PathQuotedDisplay;
use camino::{Utf8Path, Utf8PathBuf};
use cap_std::fs::Dir;
use cap_std_ext::cap_std;
use cap_std_ext::cap_std::fs::MetadataExt;
use cap_std_ext::dirext::WalkConfiguration;
use cap_std_ext::dirext::{CapStdExtDirExt as _, WalkComponent};
use fn_error_context::context;
use indoc::indoc;
use linkme::distributed_slice;
use ostree_ext::ostree_prepareroot;
use serde::Serialize;

use crate::bootc_composefs::boot::EFI_LINUX;

/// Reference to embedded default baseimage content that should exist.
const BASEIMAGE_REF: &str = "usr/share/doc/bootc/baseimage/base";
// https://systemd.io/API_FILE_SYSTEMS/ with /var added for us
const API_DIRS: &[&str] = &["dev", "proc", "sys", "run", "tmp", "var"];

/// Only output this many items by default
const DEFAULT_TRUNCATED_OUTPUT: NonZeroUsize = const { NonZeroUsize::new(5).unwrap() };

/// A lint check has failed.
#[derive(thiserror::Error, Debug)]
struct LintError(String);

/// The outer error is for unexpected fatal runtime problems; the
/// inner error is for the lint failing in an expected way.
type LintResult = Result<std::result::Result<(), LintError>>;

/// Everything is OK - we didn't encounter a runtime error, and
/// the targeted check passed.
fn lint_ok() -> LintResult {
    Ok(Ok(()))
}

/// We successfully found a lint failure.
fn lint_err(msg: impl AsRef<str>) -> LintResult {
    Ok(Err(LintError::new(msg)))
}

impl std::fmt::Display for LintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl LintError {
    fn new(msg: impl AsRef<str>) -> Self {
        Self(msg.as_ref().to_owned())
    }
}

#[derive(Debug, Default)]
struct LintExecutionConfig {
    no_truncate: bool,
}

type LintFn = fn(&Dir, config: &LintExecutionConfig) -> LintResult;
type LintRecursiveResult = LintResult;
type LintRecursiveFn = fn(&WalkComponent, config: &LintExecutionConfig) -> LintRecursiveResult;
/// A lint can either operate as it pleases on a target root, or it
/// can be recursive.
#[derive(Debug)]
enum LintFnTy {
    /// A lint that doesn't traverse the whole filesystem
    Regular(LintFn),
    /// A recursive lint
    Recursive(LintRecursiveFn),
}
#[distributed_slice]
pub(crate) static LINTS: [Lint];

/// The classification of a lint type.
#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
enum LintType {
    /// If this fails, it is known to be fatal - the system will not install or
    /// is effectively guaranteed to fail at runtime.
    Fatal,
    /// This is not a fatal problem, but something you likely want to fix.
    Warning,
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum WarningDisposition {
    AllowWarnings,
    FatalWarnings,
}

#[derive(Debug, Copy, Clone, Serialize, PartialEq, Eq)]
pub(crate) enum RootType {
    Running,
    Alternative,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
struct Lint {
    name: &'static str,
    #[serde(rename = "type")]
    ty: LintType,
    #[serde(skip)]
    f: LintFnTy,
    description: &'static str,
    // Set if this only applies to a specific root type.
    #[serde(skip_serializing_if = "Option::is_none")]
    root_type: Option<RootType>,
}

// We require lint names to be unique, so we can just compare based on those.
impl PartialEq for Lint {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}
impl Eq for Lint {}

impl std::hash::Hash for Lint {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
}

impl PartialOrd for Lint {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Lint {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.name.cmp(other.name)
    }
}

impl Lint {
    pub(crate) const fn new_fatal(
        name: &'static str,
        description: &'static str,
        f: LintFn,
    ) -> Self {
        Lint {
            name,
            ty: LintType::Fatal,
            f: LintFnTy::Regular(f),
            description,
            root_type: None,
        }
    }

    pub(crate) const fn new_warning(
        name: &'static str,
        description: &'static str,
        f: LintFn,
    ) -> Self {
        Lint {
            name,
            ty: LintType::Warning,
            f: LintFnTy::Regular(f),
            description,
            root_type: None,
        }
    }

    const fn set_root_type(mut self, v: RootType) -> Self {
        self.root_type = Some(v);
        self
    }
}

pub(crate) fn lint_list(output: impl std::io::Write) -> Result<()> {
    // Dump in yaml format by default, it's readable enough
    serde_yaml::to_writer(output, &*LINTS)?;
    Ok(())
}

#[derive(Debug)]
struct LintExecutionResult {
    warnings: usize,
    passed: usize,
    skipped: usize,
    fatal: usize,
}

// Helper function to format items with optional truncation
fn format_items<T>(
    config: &LintExecutionConfig,
    header: &str,
    items: impl Iterator<Item = T>,
    o: &mut String,
) -> Result<()>
where
    T: Display,
{
    let mut items = items.into_iter();
    if config.no_truncate {
        let Some(first) = items.next() else {
            return Ok(());
        };
        writeln!(o, "{header}:")?;
        writeln!(o, "  {first}")?;
        for item in items {
            writeln!(o, "  {item}")?;
        }
        return Ok(());
    } else {
        let Some((samples, rest)) = bootc_utils::collect_until(items, DEFAULT_TRUNCATED_OUTPUT)
        else {
            return Ok(());
        };
        writeln!(o, "{header}:")?;
        for item in samples {
            writeln!(o, "  {item}")?;
        }
        if rest > 0 {
            writeln!(o, "  ...and {rest} more")?;
        }
    }
    Ok(())
}

// Helper to build a lint error message from multiple sections.
// The closure `build_message_fn` is responsible for calling `format_items`
// to populate the message buffer.
fn format_lint_err_from_items<T>(
    config: &LintExecutionConfig,
    header: &str,
    items: impl Iterator<Item = T>,
) -> LintResult
where
    T: Display,
{
    let mut msg = String::new();
    // SAFETY: Writing to a string can't fail
    format_items(config, header, items, &mut msg).unwrap();
    lint_err(msg)
}

fn lint_inner<'skip>(
    root: &Dir,
    root_type: RootType,
    config: &LintExecutionConfig,
    skip: impl IntoIterator<Item = &'skip str>,
    mut output: impl std::io::Write,
) -> Result<LintExecutionResult> {
    let mut fatal = 0usize;
    let mut warnings = 0usize;
    let mut passed = 0usize;
    let skip: std::collections::HashSet<_> = skip.into_iter().collect();
    let (mut applicable_lints, skipped_lints): (Vec<_>, Vec<_>) = LINTS.iter().partition(|lint| {
        if skip.contains(lint.name) {
            return false;
        }
        if let Some(lint_root_type) = lint.root_type {
            if lint_root_type != root_type {
                return false;
            }
        }
        true
    });
    // SAFETY: Length must be smaller.
    let skipped = skipped_lints.len();
    // Default to predictablility here
    applicable_lints.sort_by(|a, b| a.name.cmp(b.name));
    // Split the lints by type
    let (nonrec_lints, recursive_lints): (Vec<_>, Vec<_>) = applicable_lints
        .into_iter()
        .partition(|lint| matches!(lint.f, LintFnTy::Regular(_)));
    let mut results = Vec::new();
    for lint in nonrec_lints {
        let f = match lint.f {
            LintFnTy::Regular(f) => f,
            LintFnTy::Recursive(_) => unreachable!(),
        };
        results.push((lint, f(&root, &config)));
    }

    let mut recursive_lints = BTreeSet::from_iter(recursive_lints);
    let mut recursive_errors = BTreeMap::new();
    root.walk(
        &WalkConfiguration::default()
            .noxdev()
            .path_base(Path::new("/")),
        |e| -> std::io::Result<_> {
            // If there's no recursive lints, we're done!
            if recursive_lints.is_empty() {
                return Ok(ControlFlow::Break(()));
            }
            // Keep track of any errors we caught while iterating over
            // the recursive lints.
            let mut this_iteration_errors = Vec::new();
            // Call each recursive lint on this directory entry.
            for &lint in recursive_lints.iter() {
                let f = match &lint.f {
                    // SAFETY: We know this set only holds recursive lints
                    LintFnTy::Regular(_) => unreachable!(),
                    LintFnTy::Recursive(f) => f,
                };
                // Keep track of the error if we found one
                match f(e, &config) {
                    Ok(Ok(())) => {}
                    o => this_iteration_errors.push((lint, o)),
                }
            }
            // For each recursive lint that errored, remove it from
            // the set that we will continue running.
            for (lint, err) in this_iteration_errors {
                recursive_lints.remove(lint);
                recursive_errors.insert(lint, err);
            }
            Ok(ControlFlow::Continue(()))
        },
    )?;
    // Extend our overall result set with the recursive-lint errors.
    results.extend(recursive_errors);
    // Any recursive lint still in this list succeeded.
    results.extend(recursive_lints.into_iter().map(|lint| (lint, lint_ok())));
    for (lint, r) in results {
        let name = lint.name;
        let r = match r {
            Ok(r) => r,
            Err(e) => anyhow::bail!("Unexpected runtime error running lint {name}: {e}"),
        };

        if let Err(e) = r {
            match lint.ty {
                LintType::Fatal => {
                    writeln!(output, "Failed lint: {name}: {e}")?;
                    fatal += 1;
                }
                LintType::Warning => {
                    writeln!(output, "Lint warning: {name}: {e}")?;
                    warnings += 1;
                }
            }
        } else {
            // We'll be quiet for now
            tracing::debug!("OK {name} (type={:?})", lint.ty);
            passed += 1;
        }
    }

    Ok(LintExecutionResult {
        passed,
        skipped,
        warnings,
        fatal,
    })
}

#[context("Linting")]
pub(crate) fn lint<'skip>(
    root: &Dir,
    warning_disposition: WarningDisposition,
    root_type: RootType,
    skip: impl IntoIterator<Item = &'skip str>,
    mut output: impl std::io::Write,
    no_truncate: bool,
) -> Result<()> {
    let config = LintExecutionConfig { no_truncate };
    let r = lint_inner(root, root_type, &config, skip, &mut output)?;
    writeln!(output, "Checks passed: {}", r.passed)?;
    if r.skipped > 0 {
        writeln!(output, "Checks skipped: {}", r.skipped)?;
    }
    let fatal = if matches!(warning_disposition, WarningDisposition::FatalWarnings) {
        r.fatal + r.warnings
    } else {
        r.fatal
    };
    if r.warnings > 0 {
        writeln!(output, "Warnings: {}", r.warnings)?;
    }
    if fatal > 0 {
        anyhow::bail!("Checks failed: {}", fatal)
    }
    Ok(())
}

/// check for the existence of the /var/run directory
/// if it exists we need to check that it links to /run if not error
#[distributed_slice(LINTS)]
static LINT_VAR_RUN: Lint = Lint::new_fatal(
    "var-run",
    "Check for /var/run being a physical directory; this is always a bug.",
    check_var_run,
);
fn check_var_run(root: &Dir, _config: &LintExecutionConfig) -> LintResult {
    if let Some(meta) = root.symlink_metadata_optional("var/run")? {
        if !meta.is_symlink() {
            return lint_err("Not a symlink: var/run");
        }
    }
    lint_ok()
}

#[distributed_slice(LINTS)]
static LINT_BUILDAH_INJECTED: Lint = Lint::new_warning(
    "buildah-injected",
    indoc::indoc! { "
        Check for an invalid /etc/hostname or /etc/resolv.conf that may have been injected by
        a container build system." },
    check_buildah_injected,
)
// This one doesn't make sense to run looking at the running root,
// because we do expect /etc/hostname to be injected as
.set_root_type(RootType::Alternative);
fn check_buildah_injected(root: &Dir, _config: &LintExecutionConfig) -> LintResult {
    const RUNTIME_INJECTED: &[&str] = &["etc/hostname", "etc/resolv.conf"];
    for ent in RUNTIME_INJECTED {
        if let Some(meta) = root.symlink_metadata_optional(ent)? {
            if meta.is_file() && meta.size() == 0 {
                return lint_err(format!(
                    "/{ent} is an empty file; this may have been synthesized by a container runtime."
                ));
            }
        }
    }
    lint_ok()
}

#[distributed_slice(LINTS)]
static LINT_ETC_USRUSETC: Lint = Lint::new_fatal(
    "etc-usretc",
    indoc! { r#"
Verify that only one of /etc or /usr/etc exist. You should only have /etc
in a container image. It will cause undefined behavior to have both /etc
and /usr/etc.
"# },
    check_usretc,
);
fn check_usretc(root: &Dir, _config: &LintExecutionConfig) -> LintResult {
    let etc_exists = root.symlink_metadata_optional("etc")?.is_some();
    // For compatibility/conservatism don't bomb out if there's no /etc.
    if !etc_exists {
        return lint_ok();
    }
    // But having both /etc and /usr/etc is not something we want to support.
    if root.symlink_metadata_optional("usr/etc")?.is_some() {
        return lint_err(
            "Found /usr/etc - this is a bootc implementation detail and not supported to use in containers",
        );
    }
    lint_ok()
}

/// Validate that we can parse the /usr/lib/bootc/kargs.d files.
#[distributed_slice(LINTS)]
static LINT_KARGS: Lint = Lint::new_fatal(
    "bootc-kargs",
    "Verify syntax of /usr/lib/bootc/kargs.d.",
    check_parse_kargs,
);
fn check_parse_kargs(root: &Dir, _config: &LintExecutionConfig) -> LintResult {
    let args = crate::bootc_kargs::get_kargs_in_root(root, ARCH)?;
    tracing::debug!("found kargs: {args:?}");
    lint_ok()
}

#[distributed_slice(LINTS)]
static LINT_KERNEL: Lint = Lint::new_fatal(
    "kernel",
    indoc! { r#"
             Check for multiple kernels, i.e. multiple directories of the form /usr/lib/modules/$kver.
             Only one kernel is supported in an image.
     "# },
    check_kernel,
);
fn check_kernel(root: &Dir, _config: &LintExecutionConfig) -> LintResult {
    let result = ostree_ext::bootabletree::find_kernel_dir_fs(&root)?;
    tracing::debug!("Found kernel: {:?}", result);
    lint_ok()
}

// This one can be lifted in the future, see https://github.com/bootc-dev/bootc/issues/975
#[distributed_slice(LINTS)]
static LINT_UTF8: Lint = Lint {
    name: "utf8",
    description: indoc! { r#"
Check for non-UTF8 filenames. Currently, the ostree backend of bootc only supports
UTF-8 filenames. Non-UTF8 filenames will cause a fatal error.
"#},
    ty: LintType::Fatal,
    root_type: None,
    f: LintFnTy::Recursive(check_utf8),
};
fn check_utf8(e: &WalkComponent, _config: &LintExecutionConfig) -> LintRecursiveResult {
    let path = e.path;
    let filename = e.filename;
    let dirname = path.parent().unwrap_or(Path::new("/"));
    if filename.to_str().is_none() {
        // This escapes like "abc\xFFdéf"
        return lint_err(format!(
            "{}: Found non-utf8 filename {filename:?}",
            PathQuotedDisplay::new(&dirname)
        ));
    };

    if e.file_type.is_symlink() {
        let target = e.dir.read_link_contents(filename)?;
        if target.to_str().is_none() {
            return lint_err(format!(
                "{}: Found non-utf8 symlink target",
                PathQuotedDisplay::new(&path)
            ));
        }
    }
    lint_ok()
}

fn check_prepareroot_composefs_norecurse(dir: &Dir) -> LintResult {
    let path = ostree_ext::ostree_prepareroot::CONF_PATH;
    let Some(config) = ostree_prepareroot::load_config_from_root(dir)? else {
        return lint_err(format!("{path} is not present to enable composefs"));
    };
    if !ostree_prepareroot::overlayfs_enabled_in_config(&config)? {
        return lint_err(format!("{path} does not have composefs enabled"));
    }
    lint_ok()
}

#[distributed_slice(LINTS)]
static LINT_API_DIRS: Lint = Lint::new_fatal(
    "api-base-directories",
    indoc! { r#"
Verify that expected base API directories exist. For more information
on these, see <https://systemd.io/API_FILE_SYSTEMS/>.

Note that in addition, bootc requires that `/var` exist as a directory.
"#},
    check_api_dirs,
);
fn check_api_dirs(root: &Dir, _config: &LintExecutionConfig) -> LintResult {
    for d in API_DIRS {
        let Some(meta) = root.symlink_metadata_optional(d)? else {
            return lint_err(format!("Missing API filesystem base directory: /{d}"));
        };
        if !meta.is_dir() {
            return lint_err(format!(
                "Expected directory for API filesystem base directory: /{d}"
            ));
        }
    }
    lint_ok()
}

#[distributed_slice(LINTS)]
static LINT_COMPOSEFS: Lint = Lint::new_warning(
    "baseimage-composefs",
    indoc! { r#"
Check that composefs is enabled for ostree. More in
<https://ostreedev.github.io/ostree/composefs/>.
"#},
    check_composefs,
);
fn check_composefs(dir: &Dir, _config: &LintExecutionConfig) -> LintResult {
    if let Err(e) = check_prepareroot_composefs_norecurse(dir)? {
        return Ok(Err(e));
    }
    // If we have our own documentation with the expected root contents
    // embedded, then check that too! Mostly just because recursion is fun.
    if let Some(dir) = dir.open_dir_optional(BASEIMAGE_REF)? {
        if let Err(e) = check_prepareroot_composefs_norecurse(&dir)? {
            return Ok(Err(e));
        }
    }
    lint_ok()
}

/// Check for a few files and directories we expect in the base image.
fn check_baseimage_root_norecurse(dir: &Dir, _config: &LintExecutionConfig) -> LintResult {
    // Check /sysroot
    let meta = dir.symlink_metadata_optional("sysroot")?;
    match meta {
        Some(meta) if !meta.is_dir() => return lint_err("Expected a directory for /sysroot"),
        None => return lint_err("Missing /sysroot"),
        _ => {}
    }

    // Check /ostree -> sysroot/ostree
    let Some(meta) = dir.symlink_metadata_optional("ostree")? else {
        return lint_err("Missing ostree -> sysroot/ostree link");
    };
    if !meta.is_symlink() {
        return lint_err("/ostree should be a symlink");
    }
    let link = dir.read_link_contents("ostree")?;
    let expected = "sysroot/ostree";
    if link.as_os_str().as_bytes() != expected.as_bytes() {
        return lint_err(format!("Expected /ostree -> {expected}, not {link:?}"));
    }

    lint_ok()
}

/// Check ostree-related base image content.
#[distributed_slice(LINTS)]
static LINT_BASEIMAGE_ROOT: Lint = Lint::new_fatal(
    "baseimage-root",
    indoc! { r#"
Check that expected files are present in the root of the filesystem; such
as /sysroot and a composefs configuration for ostree. More in
<https://bootc-dev.github.io/bootc/bootc-images.html#standard-image-content>.
"#},
    check_baseimage_root,
);
fn check_baseimage_root(dir: &Dir, config: &LintExecutionConfig) -> LintResult {
    if let Err(e) = check_baseimage_root_norecurse(dir, config)? {
        return Ok(Err(e));
    }
    // If we have our own documentation with the expected root contents
    // embedded, then check that too! Mostly just because recursion is fun.
    if let Some(dir) = dir.open_dir_optional(BASEIMAGE_REF)? {
        if let Err(e) = check_baseimage_root_norecurse(&dir, config)? {
            return Ok(Err(e));
        }
    }
    lint_ok()
}

fn collect_nonempty_regfiles(
    root: &Dir,
    path: &Utf8Path,
    out: &mut BTreeSet<Utf8PathBuf>,
) -> Result<()> {
    for entry in root.entries_utf8()? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let path = path.join(entry.file_name()?);
        if ty.is_file() {
            let meta = entry.metadata()?;
            if meta.size() > 0 {
                out.insert(path);
            }
        } else if ty.is_dir() {
            let d = entry.open_dir()?;
            collect_nonempty_regfiles(d.as_cap_std(), &path, out)?;
        }
    }
    Ok(())
}

#[distributed_slice(LINTS)]
static LINT_VARLOG: Lint = Lint::new_warning(
    "var-log",
    indoc! { r#"
Check for non-empty regular files in `/var/log`. It is often undesired
to ship log files in container images. Log files in general are usually
per-machine state in `/var`. Additionally, log files often include
timestamps, causing unreproducible container images, and may contain
sensitive build system information.
"#},
    check_varlog,
);
fn check_varlog(root: &Dir, config: &LintExecutionConfig) -> LintResult {
    let Some(d) = root.open_dir_optional("var/log")? else {
        return lint_ok();
    };
    let mut nonempty_regfiles = BTreeSet::new();
    collect_nonempty_regfiles(&d, "/var/log".into(), &mut nonempty_regfiles)?;

    if nonempty_regfiles.is_empty() {
        return lint_ok();
    }

    let header = "Found non-empty logfiles";
    let items = nonempty_regfiles.iter().map(PathQuotedDisplay::new);
    format_lint_err_from_items(config, header, items)
}

#[distributed_slice(LINTS)]
static LINT_VAR_TMPFILES: Lint = Lint::new_warning(
    "var-tmpfiles",
    indoc! { r#"
Check for content in /var that does not have corresponding systemd tmpfiles.d entries.
This can cause a problem across upgrades because content in /var from the container
image will only be applied on the initial provisioning.

Instead, it's recommended to have /var effectively empty in the container image,
and use systemd tmpfiles.d to generate empty directories and compatibility symbolic links
as part of each boot.
"#},
    check_var_tmpfiles,
)
.set_root_type(RootType::Running);

fn check_var_tmpfiles(_root: &Dir, config: &LintExecutionConfig) -> LintResult {
    let r = bootc_tmpfiles::find_missing_tmpfiles_current_root()?;
    if r.tmpfiles.is_empty() && r.unsupported.is_empty() {
        return lint_ok();
    }
    let mut msg = String::new();
    let header = "Found content in /var missing systemd tmpfiles.d entries";
    format_items(config, header, r.tmpfiles.iter().map(|v| v as &_), &mut msg)?;
    let header = "Found non-directory/non-symlink files in /var";
    let items = r.unsupported.iter().map(PathQuotedDisplay::new);
    format_items(config, header, items, &mut msg)?;
    lint_err(msg)
}

#[distributed_slice(LINTS)]
static LINT_SYSUSERS: Lint = Lint::new_warning(
    "sysusers",
    indoc! { r#"
Check for users in /etc/passwd and groups in /etc/group that do not have corresponding
systemd sysusers.d entries in /usr/lib/sysusers.d.
This can cause a problem across upgrades because if /etc is not transient and is locally
modified (commonly due to local user additions), then the contents of /etc/passwd in the new container
image may not be visible.

Using systemd-sysusers to allocate users and groups will ensure that these are allocated
on system startup alongside other users.

More on this topic in <https://bootc-dev.github.io/bootc/building/users-and-groups.html>
"# },
    check_sysusers,
);
fn check_sysusers(rootfs: &Dir, config: &LintExecutionConfig) -> LintResult {
    let r = bootc_sysusers::analyze(rootfs)?;
    if r.is_empty() {
        return lint_ok();
    }
    let mut msg = String::new();
    let header = "Found /etc/passwd entry without corresponding systemd sysusers.d";
    let items = r.missing_users.iter().map(|v| v as &dyn std::fmt::Display);
    format_items(config, header, items, &mut msg)?;
    let header = "Found /etc/group entry without corresponding systemd sysusers.d";
    format_items(config, header, r.missing_groups.into_iter(), &mut msg)?;
    lint_err(msg)
}

#[distributed_slice(LINTS)]
static LINT_NONEMPTY_BOOT: Lint = Lint::new_warning(
    "nonempty-boot",
    indoc! { r#"
The `/boot` directory should be present, but empty. The kernel
content should be in /usr/lib/modules instead in the container image.
Any content here in the container image will be masked at runtime.
"#},
    check_boot,
);
fn check_boot(root: &Dir, config: &LintExecutionConfig) -> LintResult {
    let Some(d) = root.open_dir_optional("boot")? else {
        return lint_err("Missing /boot directory");
    };

    // First collect all entries to determine if the directory is empty
    let entries: Result<BTreeSet<_>, _> = d
        .entries()?
        .into_iter()
        .map(|v| {
            let v = v?;
            anyhow::Ok(v.file_name())
        })
        .collect();
    let mut entries = entries?;
    {
        // Work around https://github.com/containers/composefs-rs/issues/131
        let efidir = Utf8Path::new(EFI_LINUX)
            .parent()
            .map(|b| b.as_std_path())
            .unwrap();
        entries.remove(efidir.as_os_str());
    }
    if entries.is_empty() {
        return lint_ok();
    }

    let header = "Found non-empty /boot";
    let items = entries.iter().map(PathQuotedDisplay::new);
    format_lint_err_from_items(config, header, items)
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use super::*;

    static ALTROOT_LINTS: LazyLock<usize> = LazyLock::new(|| {
        LINTS
            .iter()
            .filter(|lint| lint.root_type != Some(RootType::Running))
            .count()
    });

    fn fixture() -> Result<cap_std_ext::cap_tempfile::TempDir> {
        // Create a new temporary directory for test fixtures.
        let tempdir = cap_std_ext::cap_tempfile::tempdir(cap_std::ambient_authority())?;
        Ok(tempdir)
    }

    fn passing_fixture() -> Result<cap_std_ext::cap_tempfile::TempDir> {
        // Create a temporary directory fixture that is expected to pass most lints.
        let root = cap_std_ext::cap_tempfile::tempdir(cap_std::ambient_authority())?;
        for d in API_DIRS {
            root.create_dir(d)?;
        }
        root.create_dir_all("usr/lib/modules/5.7.2")?;
        root.write("usr/lib/modules/5.7.2/vmlinuz", "vmlinuz")?;

        root.create_dir("boot")?;
        root.create_dir("sysroot")?;
        root.symlink_contents("sysroot/ostree", "ostree")?;

        const PREPAREROOT_PATH: &str = "usr/lib/ostree/prepare-root.conf";
        const PREPAREROOT: &str =
            include_str!("../../../baseimage/base/usr/lib/ostree/prepare-root.conf");
        root.create_dir_all(Utf8Path::new(PREPAREROOT_PATH).parent().unwrap())?;
        root.atomic_write(PREPAREROOT_PATH, PREPAREROOT)?;

        Ok(root)
    }

    #[test]
    fn test_var_run() -> Result<()> {
        let root = &fixture()?;
        let config = &LintExecutionConfig::default();
        // This one should pass
        check_var_run(root, config).unwrap().unwrap();
        root.create_dir_all("var/run/foo")?;
        assert!(check_var_run(root, config).unwrap().is_err());
        root.remove_dir_all("var/run")?;
        // Now we should pass again
        check_var_run(root, config).unwrap().unwrap();
        Ok(())
    }

    #[test]
    fn test_api() -> Result<()> {
        let root = &passing_fixture()?;
        let config = &LintExecutionConfig::default();
        // This one should pass
        check_api_dirs(root, config).unwrap().unwrap();
        root.remove_dir("var")?;
        assert!(check_api_dirs(root, config).unwrap().is_err());
        root.write("var", "a file for var")?;
        assert!(check_api_dirs(root, config).unwrap().is_err());
        Ok(())
    }

    #[test]
    fn test_lint_main() -> Result<()> {
        let root = &passing_fixture()?;
        let config = &LintExecutionConfig::default();
        let mut out = Vec::new();
        let warnings = WarningDisposition::FatalWarnings;
        let root_type = RootType::Alternative;
        lint(root, warnings, root_type, [], &mut out, config.no_truncate).unwrap();
        root.create_dir_all("var/run/foo")?;
        let mut out = Vec::new();
        assert!(lint(root, warnings, root_type, [], &mut out, config.no_truncate).is_err());
        Ok(())
    }

    #[test]
    fn test_lint_inner() -> Result<()> {
        let root = &passing_fixture()?;
        let config = &LintExecutionConfig::default();

        // Verify that all lints run
        let mut out = Vec::new();
        let root_type = RootType::Alternative;
        let r = lint_inner(root, root_type, config, [], &mut out).unwrap();
        let running_only_lints = LINTS.len().checked_sub(*ALTROOT_LINTS).unwrap();
        assert_eq!(r.warnings, 0);
        assert_eq!(r.fatal, 0);
        assert_eq!(r.skipped, running_only_lints);
        assert_eq!(r.passed, *ALTROOT_LINTS);

        let r = lint_inner(root, root_type, config, ["var-log"], &mut out).unwrap();
        // Trigger a failure in var-log by creating a non-empty log file.
        root.create_dir_all("var/log/dnf")?;
        root.write("var/log/dnf/dnf.log", b"dummy dnf log")?;
        assert_eq!(r.passed, ALTROOT_LINTS.checked_sub(1).unwrap());
        assert_eq!(r.fatal, 0);
        assert_eq!(r.skipped, running_only_lints + 1);
        assert_eq!(r.warnings, 0);

        // But verify that not skipping it results in a warning
        let mut out = Vec::new();
        let r = lint_inner(root, root_type, config, [], &mut out).unwrap();
        assert_eq!(r.passed, ALTROOT_LINTS.checked_sub(1).unwrap());
        assert_eq!(r.fatal, 0);
        assert_eq!(r.skipped, running_only_lints);
        assert_eq!(r.warnings, 1);
        Ok(())
    }

    #[test]
    fn test_kernel_lint() -> Result<()> {
        let root = &fixture()?;
        let config = &LintExecutionConfig::default();
        // This one should pass
        check_kernel(root, config).unwrap().unwrap();
        root.create_dir_all("usr/lib/modules/5.7.2")?;
        root.write("usr/lib/modules/5.7.2/vmlinuz", "old vmlinuz")?;
        root.create_dir_all("usr/lib/modules/6.3.1")?;
        root.write("usr/lib/modules/6.3.1/vmlinuz", "new vmlinuz")?;
        assert!(check_kernel(root, config).is_err());
        root.remove_dir_all("usr/lib/modules/5.7.2")?;
        // Now we should pass again
        check_kernel(root, config).unwrap().unwrap();
        Ok(())
    }

    #[test]
    fn test_kargs() -> Result<()> {
        let root = &fixture()?;
        let config = &LintExecutionConfig::default();
        check_parse_kargs(root, config).unwrap().unwrap();
        root.create_dir_all("usr/lib/bootc")?;
        root.write("usr/lib/bootc/kargs.d", "not a directory")?;
        assert!(check_parse_kargs(root, config).is_err());
        Ok(())
    }

    #[test]
    fn test_usr_etc() -> Result<()> {
        let root = &fixture()?;
        let config = &LintExecutionConfig::default();
        // This one should pass
        check_usretc(root, config).unwrap().unwrap();
        root.create_dir_all("etc")?;
        root.create_dir_all("usr/etc")?;
        assert!(check_usretc(root, config).unwrap().is_err());
        root.remove_dir_all("etc")?;
        // Now we should pass again
        check_usretc(root, config).unwrap().unwrap();
        Ok(())
    }

    #[test]
    fn test_varlog() -> Result<()> {
        let root = &fixture()?;
        let config = &LintExecutionConfig::default();
        check_varlog(root, config).unwrap().unwrap();
        root.create_dir_all("var/log")?;
        check_varlog(root, config).unwrap().unwrap();
        root.symlink_contents("../../usr/share/doc/systemd/README.logs", "var/log/README")?;
        check_varlog(root, config).unwrap().unwrap();

        root.atomic_write("var/log/somefile.log", "log contents")?;
        let Err(e) = check_varlog(root, config).unwrap() else {
            unreachable!()
        };
        similar_asserts::assert_eq!(
            e.to_string(),
            "Found non-empty logfiles:\n  /var/log/somefile.log\n"
        );
        root.create_dir_all("var/log/someproject")?;
        root.atomic_write("var/log/someproject/audit.log", "audit log")?;
        root.atomic_write("var/log/someproject/info.log", "info")?;
        let Err(e) = check_varlog(root, config).unwrap() else {
            unreachable!()
        };
        similar_asserts::assert_eq!(
            e.to_string(),
            indoc! { r#"
                Found non-empty logfiles:
                  /var/log/somefile.log
                  /var/log/someproject/audit.log
                  /var/log/someproject/info.log
                "# }
        );

        Ok(())
    }

    #[test]
    fn test_boot() -> Result<()> {
        let root = &passing_fixture()?;
        let config = &LintExecutionConfig::default();
        check_boot(&root, config).unwrap().unwrap();

        // Verify creating EFI doesn't error
        root.create_dir_all("EFI/Linux")?;
        root.write("EFI/Linux/foo.efi", b"some dummy efi")?;
        check_boot(&root, config).unwrap().unwrap();

        root.create_dir("boot/somesubdir")?;
        let Err(e) = check_boot(&root, config).unwrap() else {
            unreachable!()
        };
        assert!(e.to_string().contains("somesubdir"));

        Ok(())
    }

    fn run_recursive_lint(
        root: &Dir,
        f: LintRecursiveFn,
        config: &LintExecutionConfig,
    ) -> LintResult {
        // Helper function to execute a recursive lint function over a directory.
        let mut result = lint_ok();
        root.walk(
            &WalkConfiguration::default()
                .noxdev()
                .path_base(Path::new("/")),
            |e| -> Result<_> {
                let r = f(e, config)?;
                match r {
                    Ok(()) => Ok(ControlFlow::Continue(())),
                    Err(e) => {
                        result = Ok(Err(e));
                        Ok(ControlFlow::Break(()))
                    }
                }
            },
        )?;
        result
    }

    #[test]
    fn test_non_utf8() {
        use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

        let root = &fixture().unwrap();
        let config = &LintExecutionConfig::default();

        // Try to create some adversarial symlink situations to ensure the walk doesn't crash
        root.create_dir("subdir").unwrap();
        // Self-referential symlinks
        root.symlink("self", "self").unwrap();
        // Infinitely looping dir symlinks
        root.symlink("..", "subdir/parent").unwrap();
        // Broken symlinks
        root.symlink("does-not-exist", "broken").unwrap();
        // Out-of-scope symlinks
        root.symlink("../../x", "escape").unwrap();
        // Should be fine
        run_recursive_lint(root, check_utf8, config)
            .unwrap()
            .unwrap();

        // But this will cause an issue
        let baddir = OsStr::from_bytes(b"subdir/2/bad\xffdir");
        root.create_dir("subdir/2").unwrap();
        root.create_dir(baddir).unwrap();
        let Err(err) = run_recursive_lint(root, check_utf8, config).unwrap() else {
            unreachable!("Didn't fail");
        };
        assert_eq!(
            err.to_string(),
            r#"/subdir/2: Found non-utf8 filename "bad\xFFdir""#
        );
        root.remove_dir(baddir).unwrap(); // Get rid of the problem
        run_recursive_lint(root, check_utf8, config)
            .unwrap()
            .unwrap(); // Check it

        // Create a new problem in the form of a regular file
        let badfile = OsStr::from_bytes(b"regular\xff");
        root.write(badfile, b"Hello, world!\n").unwrap();
        let Err(err) = run_recursive_lint(root, check_utf8, config).unwrap() else {
            unreachable!("Didn't fail");
        };
        assert_eq!(
            err.to_string(),
            r#"/: Found non-utf8 filename "regular\xFF""#
        );
        root.remove_file(badfile).unwrap(); // Get rid of the problem
        run_recursive_lint(root, check_utf8, config)
            .unwrap()
            .unwrap(); // Check it

        // And now test invalid symlink targets
        root.symlink(badfile, "subdir/good-name").unwrap();
        let Err(err) = run_recursive_lint(root, check_utf8, config).unwrap() else {
            unreachable!("Didn't fail");
        };
        assert_eq!(
            err.to_string(),
            r#"/subdir/good-name: Found non-utf8 symlink target"#
        );
        root.remove_file("subdir/good-name").unwrap(); // Get rid of the problem
        run_recursive_lint(root, check_utf8, config)
            .unwrap()
            .unwrap(); // Check it

        // Finally, test a self-referential symlink with an invalid name.
        // We should spot the invalid name before we check the target.
        root.symlink(badfile, badfile).unwrap();
        let Err(err) = run_recursive_lint(root, check_utf8, config).unwrap() else {
            unreachable!("Didn't fail");
        };
        assert_eq!(
            err.to_string(),
            r#"/: Found non-utf8 filename "regular\xFF""#
        );
        root.remove_file(badfile).unwrap(); // Get rid of the problem
        run_recursive_lint(root, check_utf8, config)
            .unwrap()
            .unwrap(); // Check it
    }

    #[test]
    fn test_baseimage_root() -> Result<()> {
        let td = fixture()?;
        let config = &LintExecutionConfig::default();

        // An empty root should fail our test
        assert!(check_baseimage_root(&td, config).unwrap().is_err());

        drop(td);
        let td = passing_fixture()?;
        check_baseimage_root(&td, config).unwrap().unwrap();
        Ok(())
    }

    #[test]
    fn test_composefs() -> Result<()> {
        let td = fixture()?;
        let config = &LintExecutionConfig::default();

        // An empty root should fail our test
        assert!(check_composefs(&td, config).unwrap().is_err());

        drop(td);
        let td = passing_fixture()?;
        // This should pass as the fixture includes a valid composefs config.
        check_composefs(&td, config).unwrap().unwrap();

        td.write(
            "usr/lib/ostree/prepare-root.conf",
            b"[composefs]\nenabled = false",
        )?;
        // Now it should fail because composefs is explicitly disabled.
        assert!(check_composefs(&td, config).unwrap().is_err());

        Ok(())
    }

    #[test]
    fn test_buildah_injected() -> Result<()> {
        let td = fixture()?;
        let config = &LintExecutionConfig::default();
        td.create_dir("etc")?;
        assert!(check_buildah_injected(&td, config).unwrap().is_ok());
        td.write("etc/hostname", b"")?;
        assert!(check_buildah_injected(&td, config).unwrap().is_err());
        td.write("etc/hostname", b"some static hostname")?;
        assert!(check_buildah_injected(&td, config).unwrap().is_ok());
        Ok(())
    }

    #[test]
    fn test_list() {
        let mut r = Vec::new();
        lint_list(&mut r).unwrap();
        let lints: Vec<serde_yaml::Value> = serde_yaml::from_slice(&r).unwrap();
        assert_eq!(lints.len(), LINTS.len());
    }

    #[test]
    fn test_format_items_no_truncate() -> Result<()> {
        let config = LintExecutionConfig { no_truncate: true };
        let header = "Test Header";
        let mut output_str = String::new();

        // Test case 1: Empty iterator
        let items_empty: Vec<String> = vec![];
        format_items(&config, header, items_empty.iter(), &mut output_str)?;
        assert_eq!(output_str, "");
        output_str.clear();

        // Test case 2: Iterator with one item
        let items_one = ["item1"];
        format_items(&config, header, items_one.iter(), &mut output_str)?;
        assert_eq!(output_str, "Test Header:\n  item1\n");
        output_str.clear();

        // Test case 3: Iterator with multiple items
        let items_multiple = (1..=3).map(|v| format!("item{v}")).collect::<Vec<_>>();
        format_items(&config, header, items_multiple.iter(), &mut output_str)?;
        assert_eq!(output_str, "Test Header:\n  item1\n  item2\n  item3\n");
        output_str.clear();

        // Test case 4: Iterator with items > DEFAULT_TRUNCATED_OUTPUT
        let items_multiple = (1..=8).map(|v| format!("item{v}")).collect::<Vec<_>>();
        format_items(&config, header, items_multiple.iter(), &mut output_str)?;
        assert_eq!(
            output_str,
            "Test Header:\n  item1\n  item2\n  item3\n  item4\n  item5\n  item6\n  item7\n  item8\n"
        );
        output_str.clear();

        Ok(())
    }

    #[test]
    fn test_format_items_truncate() -> Result<()> {
        let config = LintExecutionConfig::default();
        let header = "Test Header";
        let mut output_str = String::new();

        // Test case 1: Empty iterator
        let items_empty: Vec<String> = vec![];
        format_items(&config, header, items_empty.iter(), &mut output_str)?;
        assert_eq!(output_str, "");
        output_str.clear();

        // Test case 2: Iterator with fewer items than DEFAULT_TRUNCATED_OUTPUT
        let items_few = ["item1", "item2"];
        format_items(&config, header, items_few.iter(), &mut output_str)?;
        assert_eq!(output_str, "Test Header:\n  item1\n  item2\n");
        output_str.clear();

        // Test case 3: Iterator with exactly DEFAULT_TRUNCATED_OUTPUT items
        let items_exact: Vec<_> = (0..DEFAULT_TRUNCATED_OUTPUT.get())
            .map(|i| format!("item{}", i + 1))
            .collect();
        format_items(&config, header, items_exact.iter(), &mut output_str)?;
        let mut expected_output = String::from("Test Header:\n");
        for i in 0..DEFAULT_TRUNCATED_OUTPUT.get() {
            writeln!(expected_output, "  item{}", i + 1)?;
        }
        assert_eq!(output_str, expected_output);
        output_str.clear();

        // Test case 4: Iterator with more items than DEFAULT_TRUNCATED_OUTPUT
        let items_many: Vec<_> = (0..(DEFAULT_TRUNCATED_OUTPUT.get() + 2))
            .map(|i| format!("item{}", i + 1))
            .collect();
        format_items(&config, header, items_many.iter(), &mut output_str)?;
        let mut expected_output = String::from("Test Header:\n");
        for i in 0..DEFAULT_TRUNCATED_OUTPUT.get() {
            writeln!(expected_output, "  item{}", i + 1)?;
        }
        writeln!(expected_output, "  ...and 2 more")?;
        assert_eq!(output_str, expected_output);
        output_str.clear();

        // Test case 5: Iterator with one more item than DEFAULT_TRUNCATED_OUTPUT
        let items_one_more: Vec<_> = (0..(DEFAULT_TRUNCATED_OUTPUT.get() + 1))
            .map(|i| format!("item{}", i + 1))
            .collect();
        format_items(&config, header, items_one_more.iter(), &mut output_str)?;
        let mut expected_output = String::from("Test Header:\n");
        for i in 0..DEFAULT_TRUNCATED_OUTPUT.get() {
            writeln!(expected_output, "  item{}", i + 1)?;
        }
        writeln!(expected_output, "  ...and 1 more")?;
        assert_eq!(output_str, expected_output);
        output_str.clear();

        Ok(())
    }

    #[test]
    fn test_format_items_display_impl() -> Result<()> {
        let config = LintExecutionConfig::default();
        let header = "Numbers";
        let mut output_str = String::new();

        let items_numbers = [1, 2, 3];
        format_items(&config, header, items_numbers.iter(), &mut output_str)?;
        similar_asserts::assert_eq!(output_str, "Numbers:\n  1\n  2\n  3\n");

        Ok(())
    }
}
