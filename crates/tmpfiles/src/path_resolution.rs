//! Generic primitives for resolving a path against real symlinks in a
//! `cap_std::fs::Dir`-rooted filesystem.

use std::ffi::OsString;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use cap_std::fs::{Dir, MetadataExt as _};
use cap_std_ext::RootDir;
use cap_std_ext::cap_std;

use crate::{Error, Result};

/// The physical identity of a resolved path: the `(dev, ino)` of its
/// (symlink-resolved) parent directory, paired with its own leaf filename.
///
/// The leaf is never dereferenced (see [`PathResolver::resolve_parent_identity`]),
/// so it's kept as a plain filename rather than being folded into the parent
/// identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct PathIdentity {
    parent_dev: u64,
    parent_ino: u64,
    leaf: OsString,
}

impl PathIdentity {
    pub(crate) fn new(parent_dev: u64, parent_ino: u64, leaf: OsString) -> Self {
        Self {
            parent_dev,
            parent_ino,
            leaf,
        }
    }
}

/// Resolves the symlinks in the *parent* (intermediate) components of a
/// declared tmpfiles.d path against the physical rootfs, so that it matches
/// what the `/var` walker in `convert_path_to_tmpfiles_d_recurse` actually
/// encounters on disk.
///
/// For example, systemd's `provision.conf` declares `d /root/.ssh ...`, but
/// on a stateless/immutable-root system `/root` is a symlink to the physical
/// `/var/roothome`, so the walker only ever sees `/var/roothome/.ssh`.
/// Resolving `/root/.ssh` here to the *identity* of `/var/roothome/.ssh`
/// lets a plain map lookup recognize it as covered, without the walker
/// having to do a bidirectional alias lookup at every node.
///
/// The **leaf** (final) component of a path is never dereferenced, even if
/// it happens to be a symlink itself: it's the thing being declared by the
/// tmpfiles.d line, may not exist yet, and its own target is irrelevant to
/// resolving its *location*. Only the parent directory is ever opened.
///
/// Resolution of the parent is delegated entirely to the kernel via
/// `openat2(RESOLVE_IN_ROOT)` (through [`cap_std_ext::RootDir`]), which
/// correctly and safely handles arbitrary symlink chains, absolute symlink
/// targets (chroot-style reinterpreted against the rootfs, e.g. a top-level
/// `/home -> /var/home`), and symlink loops (surfaced as a standard `ELOOP`
/// I/O error), without this crate needing to reimplement any of that itself.
///
/// Since the kernel has already done the real work of resolving the parent
/// down to a live, open file descriptor, the result is reported as that
/// descriptor's `(dev, ino)` identity (via `fstat`). Querying identity
/// directly on an already-open fd is kernel-authoritative and immune to
/// concurrent path mutations (renames of ancestors, etc.).
///
/// If any component of the parent doesn't exist, `Ok(None)` is returned:
/// nothing can physically exist beneath a missing directory either, so the
/// `/var` walker will never encounter (and thus never need to match) such a
/// path in the first place.
pub(crate) struct PathResolver {
    root_dir: RootDir,
    /// The `(dev, ino)` identity of the rootfs root itself, captured once so
    /// that resolving a bare top-level entry (whose "parent" is the rootfs
    /// root, which can't itself be a symlink) doesn't need a separate lookup.
    root_dev: u64,
    root_ino: u64,
}

impl PathResolver {
    pub(crate) fn new(rootfs: &Dir) -> Result<Self> {
        let root_dir = RootDir::new(rootfs, ".")?;
        let root_meta = rootfs.dir_metadata()?;
        Ok(Self {
            root_dir,
            root_dev: root_meta.dev(),
            root_ino: root_meta.ino(),
        })
    }

    /// See the module-level docs on [`PathResolver`] for the full contract.
    pub(crate) fn resolve_parent_identity(&self, path: &Path) -> Result<Option<PathIdentity>> {
        let to_err = |err| Error::PathIo {
            path: path.to_owned(),
            err,
        };

        let relpath = path.strip_prefix("/").unwrap_or(path);
        // The leaf is never dereferenced. Paths with no leaf at all (i.e.
        // "/", or an empty path) fall through to an empty leaf below; such a
        // path can never match a real entry encountered by the `/var`
        // walker, so this is harmless.
        let leaf = relpath.file_name().map(OsString::from).unwrap_or_default();
        // A bare top-level entry (e.g. "/root") has no parent component to
        // resolve; the rootfs root itself can't be a symlink, so it (and the
        // "no leaf at all" case above) resolve directly against the cached
        // rootfs-root identity.
        let parent = relpath.parent().unwrap_or_else(|| Path::new(""));
        if parent.as_os_str().is_empty() {
            return Ok(Some(PathIdentity::new(self.root_dev, self.root_ino, leaf)));
        }

        let parent_file = match self.root_dir.open_optional(parent) {
            Ok(Some(f)) => f,
            Ok(None) => return Ok(None),
            // Tolerate inaccessible paths (EACCES in rootless containers).
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return Ok(None),
            Err(e) => return Err(to_err(e)),
        };
        let parent_meta = parent_file.metadata().map_err(to_err)?;
        Ok(Some(PathIdentity::new(
            parent_meta.dev(),
            parent_meta.ino(),
            leaf,
        )))
    }
}

#[cfg(test)]
mod tests {
    use cap_std::fs::PermissionsExt as _;

    use super::*;

    fn newroot() -> Result<cap_std_ext::cap_tempfile::TempDir> {
        cap_std_ext::cap_tempfile::tempdir(cap_std::ambient_authority()).map_err(Error::Io)
    }

    /// Create a chain of `n` symlinks named `{prefix}0..{prefix}(n-1)`, each
    /// pointing to the next, with the last one pointing to a real `target`
    /// directory (which must already exist).
    fn make_symlink_chain(rootfs: &Dir, prefix: &str, n: u32) -> Result<()> {
        for i in 0..n {
            let target = if i + 1 < n {
                format!("{prefix}{}", i + 1)
            } else {
                "target".to_string()
            };
            rootfs.symlink(target, format!("{prefix}{i}"))?;
        }
        Ok(())
    }

    /// Compute the identity that `resolve_parent_identity` *should* return
    /// for a given `input` path, by directly `fstat`-ing the real, known
    /// physical location (`expected_parent_relpath`, or `""` for the rootfs
    /// root itself) in the test fixture. This lets the test assert two
    /// dynamically-derived values against each other, rather than hardcoding
    /// meaningless raw `(dev, ino)` numbers.
    fn expected_identity(rootfs: &Dir, input: &str, expected_parent_relpath: &str) -> PathIdentity {
        let meta = if expected_parent_relpath.is_empty() {
            rootfs.dir_metadata().unwrap()
        } else {
            rootfs.metadata(expected_parent_relpath).unwrap()
        };
        let leaf = Path::new(input).file_name().unwrap_or_default().to_owned();
        PathIdentity::new(meta.dev(), meta.ino(), leaf)
    }

    #[test]
    fn test_resolve_parent_identity() -> anyhow::Result<()> {
        let rootfs = &newroot()?;

        // No symlinks involved: the path resolves to its own real parent.
        rootfs.create_dir_all("var/lib/plain")?;
        // The conventional top-level `/root -> var/roothome` alias.
        rootfs.create_dir_all("var/roothome/.ssh")?;
        rootfs.symlink("var/roothome", "root")?;
        // A symlink nested two levels deep under /var.
        rootfs.create_dir_all("var/lib/machines")?;
        rootfs.symlink("machines", "var/lib/portables")?;
        // An absolute-target top-level symlink (e.g. the conventional
        // `/home -> /var/home`), proving absolute targets are correctly
        // chroot-reinterpreted against the rootfs rather than rejected.
        rootfs.create_dir_all("var/home")?;
        rootfs.symlink_contents("/var/home", "home")?;
        // A leaf that is itself a symlink; it must never be dereferenced.
        rootfs.symlink("var/roothome", "leaf-is-a-symlink")?;
        // A symlink pointing exactly at the rootfs root, with further
        // pending components after it that *do* exist, so the successful
        // resolution path is actually exercised.
        rootfs.symlink_contents("/", "root-link")?;
        rootfs.create_dir_all("foo/bar")?;
        // A chain that switches from a relative target to an absolute one
        // midway through resolution.
        rootfs.create_dir_all("c")?;
        rootfs.symlink("b", "a")?;
        rootfs.symlink_contents("/c", "b")?;
        // A dangling intermediate symlink: the target itself doesn't exist
        // (as opposed to a plain missing path component).
        rootfs.symlink_contents("/var/nonexistent-target", "var/dangling")?;
        // A real symlink hop, followed by a path that doesn't exist only
        // *after* the hop.
        rootfs.create_dir_all("real")?;
        rootfs.symlink("real", "alias")?;

        // `expected_parent`, when `Some`, is the rootfs-relative path of the
        // real physical directory the parent should resolve to (`""` for
        // the rootfs root itself). `None` means the parent can't be
        // resolved at all (some component missing), so `Ok(None)` is
        // expected.
        let cases: &[(&str, Option<&str>)] = &[
            // Identity: no symlinks anywhere in the path.
            ("/var/lib/plain/file", Some("var/lib/plain")),
            // A single top-level symlink.
            ("/root/.ssh", Some("var/roothome")),
            // A symlink nested more than one level deep.
            ("/var/lib/portables/myimage", Some("var/lib/machines")),
            // An absolute-target top-level symlink.
            ("/home/testuser", Some("var/home")),
            // A dangling/missing intermediate component: nothing on disk,
            // so no identity can be resolved.
            ("/nonexistent/deep/path", None),
            // The leaf itself is a symlink, but must not be dereferenced;
            // its parent is the rootfs root itself.
            ("/leaf-is-a-symlink", Some("")),
            // A symlink pointing exactly at the root, with pending
            // components after it that fully exist.
            ("/root-link/foo/bar", Some("foo")),
            // A relative-then-absolute symlink chain.
            ("/a/x", Some("c")),
            // A dangling intermediate symlink: the parent can't be fully
            // resolved (its target doesn't exist). This is harmless: no
            // real, physically-walked path can ever match `None`.
            ("/var/dangling/sub/leaf", None),
            // A real symlink hop, then a missing component that only
            // becomes apparent after following it: likewise unresolved.
            ("/alias/missing/leaf", None),
        ];
        let resolver = PathResolver::new(rootfs)?;
        for (input, expected_parent) in cases.iter().copied() {
            let resolved = resolver.resolve_parent_identity(Path::new(input))?;
            let expected = expected_parent.map(|relpath| expected_identity(rootfs, input, relpath));
            assert_eq!(resolved, expected, "input: {input}");
        }

        Ok(())
    }

    #[test]
    fn test_resolve_parent_identity_symlink_loop() -> anyhow::Result<()> {
        let rootfs = &newroot()?;
        rootfs.create_dir_all("var")?;

        // A mutual A <-> B loop.
        rootfs.symlink_contents("/var/b", "var/a")?;
        rootfs.symlink_contents("/var/a", "var/b")?;
        let resolver = PathResolver::new(rootfs)?;
        let err = resolver
            .resolve_parent_identity(Path::new("/var/a/file"))
            .unwrap_err();
        assert!(matches!(err, Error::PathIo { .. }), "{err:?}");

        // A symlink pointing directly at itself.
        rootfs.symlink("self", "var/self")?;
        let err = resolver
            .resolve_parent_identity(Path::new("/var/self/file"))
            .unwrap_err();
        assert!(matches!(err, Error::PathIo { .. }), "{err:?}");

        Ok(())
    }

    #[test]
    fn test_resolve_parent_identity_permission_denied() -> anyhow::Result<()> {
        if rustix::process::getuid().is_root() {
            return Ok(());
        }
        let rootfs = &newroot()?;
        rootfs.create_dir("noaccess")?;
        rootfs.set_permissions("noaccess", cap_std::fs::Permissions::from_mode(0o000))?;
        let resolver = PathResolver::new(rootfs)?;
        let resolved = resolver.resolve_parent_identity(Path::new("/noaccess/child/leaf"))?;
        assert_eq!(resolved, None, "EACCES parent should resolve to None");

        // Restore permissions so the temp dir can be cleaned up.
        rootfs.set_permissions("noaccess", cap_std::fs::Permissions::from_mode(0o755))?;
        Ok(())
    }

    #[test]
    fn test_resolve_parent_identity_chain() -> anyhow::Result<()> {
        let rootfs = &newroot()?;
        rootfs.create_dir_all("target")?;
        // The leaf needs to actually exist, since a chain hop only succeeds
        // once the *entire* parent (the whole chain) resolves.
        rootfs.create_dir_all("target/leaf")?;

        // A reasonably long chain of symlinks resolves correctly end to end,
        // proving multi-hop chains are followed (loop detection itself is
        // the kernel's job and is covered separately).
        const CHAIN_LEN: u32 = 25;
        make_symlink_chain(rootfs, "chain", CHAIN_LEN)?;
        let resolver = PathResolver::new(rootfs)?;
        let resolved = resolver.resolve_parent_identity(Path::new("/chain0/leaf/subpath"))?;
        let expected = expected_identity(rootfs, "/chain0/leaf/subpath", "target/leaf");
        assert_eq!(resolved, Some(expected));

        Ok(())
    }
}
