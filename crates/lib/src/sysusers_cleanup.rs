//! Remove orphaned and duplicate entries from `/etc/shadow` and `/etc/gshadow`
//! before `systemd-sysusers` runs, preventing fatal "already exists" errors.
//!
//! The canonical trigger for this problem is the ublue/rechunk tooling, which
//! resets `/etc/group` (and optionally `/etc/passwd`) but leaves the shadow
//! files untouched, producing stale entries.  When `systemd-sysusers` then
//! tries to create those users/groups it finds them already in the shadow files
//! and fatally errors, causing subsequent entries to be skipped.
//!
//! This module is invoked as `bootc internals sysusers-sync` by the static
//! `bootc-sysusers-shadow-sync.service` unit, which the generator symlinks into
//! `sysinit.target.wants/` and which runs `Before=systemd-sysusers.service`.

// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::HashSet;
use std::io::Write;

use anyhow::{Context, Result};
use cap_std_ext::cap_std;
use cap_std_ext::cap_std::fs::Dir;
use cap_std_ext::dirext::CapStdExtDirExt;
use fn_error_context::context;
use ostree_ext::ostree;

// ── helpers ──────────────────────────────────────────────────────────────────

/// Load usernames from a passwd-format file at `path` within `root`, returning
/// an empty set if the file doesn't exist.
fn load_usernames(root: &Dir, path: &str) -> Result<HashSet<String>> {
    use bootc_sysusers::nameservice::passwd::parse_passwd_content;
    let mut names = HashSet::new();
    if let Some(f) = root
        .open_optional(path)
        .with_context(|| format!("Opening {path}"))?
    {
        let entries = parse_passwd_content(std::io::BufReader::new(f))
            .with_context(|| format!("Parsing {path}"))?;
        names.extend(entries.into_iter().map(|e| e.name));
    }
    Ok(names)
}

/// Load group names from a group-format file at `path` within `root`, returning
/// an empty set if the file doesn't exist.
fn load_groupnames(root: &Dir, path: &str) -> Result<HashSet<String>> {
    use bootc_sysusers::nameservice::group::parse_group_content;
    let mut names = HashSet::new();
    if let Some(f) = root
        .open_optional(path)
        .with_context(|| format!("Opening {path}"))?
    {
        let entries = parse_group_content(std::io::BufReader::new(f))
            .with_context(|| format!("Parsing {path}"))?;
        names.extend(entries.into_iter().map(|e| e.name));
    }
    Ok(names)
}

// ── RemovedEntries ────────────────────────────────────────────────────────────

/// Entries removed from a shadow-style file, split by reason.
#[derive(Debug, Default)]
struct RemovedEntries {
    orphaned: Vec<String>,
    duplicates: Vec<String>,
}

impl RemovedEntries {
    fn is_empty(&self) -> bool {
        self.orphaned.is_empty() && self.duplicates.is_empty()
    }
}

// ── filter_shadow_file ────────────────────────────────────────────────────────

/// Remove entries from a shadow-style file whose name is not in `valid_names`
/// or which are duplicates (keeping first occurrence). Returns the sets of
/// removed entry names, or `None` if the file does not exist. Logging is left
/// to the caller.
///
/// When `sepolicy` is provided the rewritten file is labeled according to the
/// policy (using the file's canonical absolute path, e.g. `/etc/shadow`). This
/// preserves the correct SELinux label (`shadow_t` / `gshadow_t`) on the
/// atomically replaced tempfile, which would otherwise inherit `etc_t` from the
/// directory's default transition rules.
fn filter_shadow_file<T>(
    root: &Dir,
    path: &str,
    valid_names: &HashSet<String>,
    name_fn: impl Fn(&T) -> &str,
    serialize_fn: impl Fn(&T, &mut Vec<u8>) -> Result<()>,
    parse_fn: impl Fn(std::io::BufReader<cap_std::fs::File>) -> Result<Vec<T>>,
    sepolicy: Option<&ostree::SePolicy>,
) -> Result<Option<RemovedEntries>> {
    let Some(f) = root
        .open_optional(path)
        .with_context(|| format!("Opening {path}"))?
    else {
        return Ok(None);
    };
    let meta = f.metadata().with_context(|| format!("Stat {path}"))?;
    use cap_std::fs::MetadataExt as _;
    let mode = rustix::fs::Mode::from_raw_mode(meta.mode());
    let entries = parse_fn(std::io::BufReader::new(f))?;

    let mut seen = HashSet::new();
    let mut removed = RemovedEntries::default();

    let filtered: Vec<T> = entries
        .into_iter()
        .filter(|e| {
            let name = name_fn(e);
            if !valid_names.contains(name) {
                removed.orphaned.push(name.to_string());
                return false;
            }
            if !seen.insert(name.to_string()) {
                removed.duplicates.push(name.to_string());
                return false;
            }
            true
        })
        .collect();

    if removed.is_empty() {
        return Ok(Some(removed));
    }

    let mut buf = Vec::new();
    for entry in &filtered {
        serialize_fn(entry, &mut buf)?;
    }
    crate::lsm::atomic_replace_labeled(root, path, mode, sepolicy, |w| {
        w.write_all(&buf).map_err(Into::into)
    })
    .with_context(|| format!("Rewriting {path}"))?;

    Ok(Some(removed))
}

// ── PwdLock ───────────────────────────────────────────────────────────────────

/// RAII guard that holds the shadow-utils password-file lock (`/etc/.pwd.lock`)
/// for the duration of its lifetime, matching the locking convention used by
/// `shadow-utils` (`lckpwdf(3)`) and `systemd-sysusers`.
///
/// `locked` tracks whether `lckpwdf` was actually called so that `Drop` only
/// calls `ulckpwdf` when the lock is genuinely held.
struct PwdLock {
    locked: bool,
}

impl PwdLock {
    /// Acquire the lock only when `root` is the real root filesystem.
    /// When operating on a tempdir (unit tests, image builds) lckpwdf would
    /// try to lock the *host* `/etc/.pwd.lock`, which is wrong, so we skip it.
    fn acquire_for_root(root: &Dir) -> Result<Self> {
        #[allow(unsafe_code)]
        unsafe extern "C" {
            fn lckpwdf() -> libc::c_int;
        }
        // Check if this Dir refers to the real root by comparing its device/inode
        // to that of "/". If it doesn't, skip locking.
        let root_meta = root.dir_metadata()?;
        let real_root_meta = std::fs::metadata("/")?;
        use cap_std_ext::cap_primitives::fs::MetadataExt as CapMetadataExt;
        use std::os::unix::fs::MetadataExt;
        if root_meta.dev() != real_root_meta.dev() || root_meta.ino() != real_root_meta.ino() {
            tracing::trace!("skipping lckpwdf: not operating on real root");
            return Ok(PwdLock { locked: false });
        }
        // lckpwdf() blocks up to 15 seconds then returns -1 on timeout.
        #[allow(unsafe_code)]
        let r = unsafe { lckpwdf() };
        if r != 0 {
            anyhow::bail!("lckpwdf() failed: could not acquire /etc/.pwd.lock");
        }
        Ok(PwdLock { locked: true })
    }
}

impl Drop for PwdLock {
    fn drop(&mut self) {
        if !self.locked {
            return;
        }
        #[allow(unsafe_code)]
        unsafe extern "C" {
            fn ulckpwdf() -> libc::c_int;
        }
        #[allow(unsafe_code)]
        let _ = unsafe { ulckpwdf() };
    }
}

// ── public entry point ────────────────────────────────────────────────────────

/// Remove orphaned and duplicate entries from `/etc/shadow` and `/etc/gshadow`.
///
/// For `/etc/shadow`: an entry is orphaned if the username does not appear in
/// `/etc/passwd` OR `/usr/lib/passwd`. Both are checked because nss-altfiles
/// places real system users in `/usr/lib/passwd` and those users legitimately
/// have shadow entries for local PAM authentication.
///
/// For `/etc/gshadow`: an entry is orphaned if the group name does not appear
/// in `/etc/group` OR `/usr/lib/group`. The symmetry with shadow/passwd is
/// intentional: nss-altfiles places groups in `/usr/lib/group` and those groups
/// legitimately have gshadow entries. A gshadow entry is only stale when the
/// group has dropped from *both* locations (the rechunk scenario).
///
/// This runs as `bootc-sysusers-shadow-sync.service` before
/// `systemd-sysusers.service` to prevent fatal "already exists" errors when
/// sysusers tries to create users/groups whose shadow entries are stale.
#[context("Fixing orphaned/duplicate entries in /etc/shadow and /etc/gshadow")]
pub(crate) fn run(root: &Dir) -> Result<()> {
    use bootc_sysusers::nameservice::gshadow::{GshadowEntry, parse_gshadow_content};
    use bootc_sysusers::nameservice::shadow::{ShadowEntry, parse_shadow_content};

    // Acquire the shadow-utils/systemd-sysusers lock (/etc/.pwd.lock) for the
    // duration of this function so our read-modify-write is atomic with respect
    // to any other process that honours the same locking convention.
    let _lock = PwdLock::acquire_for_root(root)?;

    // Load the SELinux policy for this root so that rewritten shadow files get
    // the correct label (e.g. `shadow_t` / `gshadow_t`) rather than inheriting
    // the directory default (`etc_t`) from the atomically created tempfile.
    // Returns None on non-SELinux systems or when no policy csum is found.
    let sepolicy = crate::lsm::new_sepolicy_at(root)?;
    let sepolicy = sepolicy.as_ref();

    // Build valid user set from both /etc/passwd and /usr/lib/passwd.
    // nss-altfiles users in /usr/lib/passwd legitimately have shadow entries.
    let mut valid_users = load_usernames(root, "etc/passwd")?;
    valid_users.extend(load_usernames(root, "usr/lib/passwd")?);

    // Build valid group set from both /etc/group and /usr/lib/group.
    // nss-altfiles groups in /usr/lib/group legitimately have gshadow entries.
    // A gshadow entry is only orphaned when the group is absent from both.
    let mut valid_groups = load_groupnames(root, "etc/group")?;
    valid_groups.extend(load_groupnames(root, "usr/lib/group")?);

    // If we couldn't find any valid users at all, skip to avoid
    // incorrectly wiping shadow on a minimal/unusual system.
    if valid_users.is_empty() {
        tracing::debug!("No /etc/passwd or /usr/lib/passwd found, skipping shadow fixup");
        return Ok(());
    }

    if let Some(removed) = filter_shadow_file(
        root,
        "etc/shadow",
        &valid_users,
        |e: &ShadowEntry| e.namp.as_str(),
        |e, buf| e.to_writer(buf),
        parse_shadow_content,
        sepolicy,
    )? {
        if !removed.is_empty() {
            tracing::info!(
                "etc/shadow: removed {} orphaned ({}), {} duplicate ({}) entries",
                removed.orphaned.len(),
                removed.orphaned.join(", "),
                removed.duplicates.len(),
                removed.duplicates.join(", "),
            );
        }
    }

    // Guard: if we found no groups at all from either file, skip to avoid
    // wiping gshadow on an unusual system where group files are absent.
    if !valid_groups.is_empty() {
        if let Some(removed) = filter_shadow_file(
            root,
            "etc/gshadow",
            &valid_groups,
            |e: &GshadowEntry| e.name.as_str(),
            |e, buf| e.to_writer(buf),
            parse_gshadow_content,
            sepolicy,
        )? {
            if !removed.is_empty() {
                tracing::info!(
                    "etc/gshadow: removed {} orphaned ({}), {} duplicate ({}) entries",
                    removed.orphaned.len(),
                    removed.orphaned.join(", "),
                    removed.duplicates.len(),
                    removed.duplicates.join(", "),
                );
            }
        }
    }

    Ok(())
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use cap_std_ext::cap_std;
    use cap_std_ext::dirext::CapStdExtDirExt;

    use super::*;

    fn setup_etc(td: &cap_std::fs::Dir) -> Result<()> {
        td.create_dir_all("etc")?;
        Ok(())
    }

    #[test]
    fn test_fixup_shadow_no_orphans() -> Result<()> {
        let td = cap_std_ext::cap_tempfile::tempdir(cap_std::ambient_authority())?;
        setup_etc(&td)?;
        td.atomic_write(
            "etc/passwd",
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n",
        )?;
        td.atomic_write(
            "etc/shadow",
            "root:*:18912:0:99999:7:::\ndaemon:*:18474:0:99999:7:::\n",
        )?;
        td.atomic_write("etc/group", "root:x:0:\ndaemon:x:1:\n")?;
        td.atomic_write("etc/gshadow", "root:*::\ndaemon:*::\n")?;

        run(&td)?;

        assert_eq!(
            td.read_to_string("etc/shadow")?,
            "root:*:18912:0:99999:7:::\ndaemon:*:18474:0:99999:7:::\n"
        );
        assert_eq!(td.read_to_string("etc/gshadow")?, "root:*::\ndaemon:*::\n");
        Ok(())
    }

    #[test]
    fn test_fixup_shadow_orphaned_entry() -> Result<()> {
        let td = cap_std_ext::cap_tempfile::tempdir(cap_std::ambient_authority())?;
        setup_etc(&td)?;
        td.atomic_write("etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")?;
        // plocate is in shadow but NOT in passwd or usr/lib/passwd
        td.atomic_write(
            "etc/shadow",
            "root:*:18912:0:99999:7:::\nplocate:!!:::::::\n",
        )?;
        td.atomic_write("etc/group", "root:x:0:\n")?;
        td.atomic_write("etc/gshadow", "root:*::\nplocate:!::\n")?;

        run(&td)?;

        // plocate removed from both
        assert_eq!(
            td.read_to_string("etc/shadow")?,
            "root:*:18912:0:99999:7:::\n"
        );
        assert_eq!(td.read_to_string("etc/gshadow")?, "root:*::\n");
        Ok(())
    }

    #[test]
    fn test_fixup_shadow_nss_altfiles_group_gshadow_kept() -> Result<()> {
        // plocate is in /usr/lib/group (nss-altfiles) but NOT in /etc/group.
        // Its /etc/gshadow entry must be KEPT — the group is legitimately present
        // in the system via nss-altfiles, so the gshadow entry is valid.
        // Only when the group drops from BOTH /etc/group and /usr/lib/group is
        // the gshadow entry considered orphaned.
        let td = cap_std_ext::cap_tempfile::tempdir(cap_std::ambient_authority())?;
        td.create_dir_all("etc")?;
        td.create_dir_all("usr/lib")?;
        td.atomic_write("etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")?;
        td.atomic_write("etc/shadow", "root:*:18912:0:99999:7:::\n")?;
        td.atomic_write("etc/group", "root:x:0:\n")?;
        // plocate in usr/lib/group (nss-altfiles) but not in etc/group
        td.atomic_write("usr/lib/group", "plocate:x:999:\n")?;
        td.atomic_write("etc/gshadow", "root:*::\nplocate:!::\n")?;

        run(&td)?;

        // plocate gshadow entry must be KEPT — group is valid via /usr/lib/group
        assert_eq!(td.read_to_string("etc/gshadow")?, "root:*::\nplocate:!::\n");
        Ok(())
    }

    #[test]
    fn test_fixup_shadow_nss_altfiles_group_gshadow_removed() -> Result<()> {
        // The core rechunk/ublue scenario: plocate dropped from BOTH /etc/group
        // and /usr/lib/group, but the stale gshadow entry remains.
        // It must be removed so systemd-sysusers can re-create the group cleanly.
        let td = cap_std_ext::cap_tempfile::tempdir(cap_std::ambient_authority())?;
        td.create_dir_all("etc")?;
        td.create_dir_all("usr/lib")?;
        td.atomic_write("etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")?;
        td.atomic_write("etc/shadow", "root:*:18912:0:99999:7:::\n")?;
        td.atomic_write("etc/group", "root:x:0:\n")?;
        // plocate absent from both /etc/group and /usr/lib/group
        td.atomic_write("etc/gshadow", "root:*::\nplocate:!::\n")?;

        run(&td)?;

        // plocate gshadow entry must be REMOVED — absent from both group files
        assert_eq!(td.read_to_string("etc/gshadow")?, "root:*::\n");
        Ok(())
    }

    #[test]
    fn test_fixup_shadow_nss_altfiles_passwd_user_kept() -> Result<()> {
        // Users in /usr/lib/passwd (nss-altfiles) legitimately have shadow entries
        // because /etc/shadow is always local. Their shadow entries must be preserved.
        let td = cap_std_ext::cap_tempfile::tempdir(cap_std::ambient_authority())?;
        td.create_dir_all("etc")?;
        td.create_dir_all("usr/lib")?;
        // bin is in /usr/lib/passwd (nss-altfiles), not in /etc/passwd
        td.atomic_write("etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")?;
        td.atomic_write("usr/lib/passwd", "bin:x:1:1:bin:/bin:/sbin/nologin\n")?;
        // bin has a shadow entry — this is valid and must be preserved
        td.atomic_write("etc/shadow", "root:*:18912:0:99999:7:::\nbin:!!:::::::\n")?;
        td.atomic_write("etc/group", "root:x:0:\nbin:x:1:\n")?;
        td.atomic_write("etc/gshadow", "root:*::\nbin:*::\n")?;

        run(&td)?;

        // bin shadow entry preserved (bin is in /usr/lib/passwd)
        assert_eq!(
            td.read_to_string("etc/shadow")?,
            "root:*:18912:0:99999:7:::\nbin:!!:::::::\n"
        );
        Ok(())
    }

    #[test]
    fn test_fixup_shadow_duplicate_removed() -> Result<()> {
        let td = cap_std_ext::cap_tempfile::tempdir(cap_std::ambient_authority())?;
        setup_etc(&td)?;
        td.atomic_write("etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")?;
        // root appears twice in shadow
        td.atomic_write(
            "etc/shadow",
            "root:*:18912:0:99999:7:::\nroot:*:18912:0:99999:7:::\n",
        )?;
        td.atomic_write("etc/group", "root:x:0:\n")?;
        td.atomic_write("etc/gshadow", "root:*::\n")?;

        run(&td)?;

        // duplicate removed, first kept
        assert_eq!(
            td.read_to_string("etc/shadow")?,
            "root:*:18912:0:99999:7:::\n"
        );
        Ok(())
    }

    #[test]
    fn test_fixup_shadow_no_passwd_skips() -> Result<()> {
        // No /etc/passwd at all => skip shadow fixup entirely (safety guard)
        let td = cap_std_ext::cap_tempfile::tempdir(cap_std::ambient_authority())?;
        setup_etc(&td)?;
        td.atomic_write(
            "etc/shadow",
            "root:*:18912:0:99999:7:::\nplocate:!!:::::::\n",
        )?;
        td.atomic_write("etc/gshadow", "root:*::\nplocate:!::\n")?;

        run(&td)?;

        // Files unchanged — we didn't know what's valid
        assert_eq!(
            td.read_to_string("etc/shadow")?,
            "root:*:18912:0:99999:7:::\nplocate:!!:::::::\n"
        );
        Ok(())
    }
}
