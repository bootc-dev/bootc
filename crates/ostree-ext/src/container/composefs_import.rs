//! Synthesize an ostree commit directly from a composefs OCI repository.
//!
//! This is the inverse of the existing ostree→composefs flow in libostree.
//! Rather than importing OCI layers through the tar pipeline, we walk the
//! composefs `FileSystem` tree and write each entry as an ostree object.
//!
//! For external regular files we bypass the ostree C library's `write_content`
//! API and instead write content objects directly to disk.  This lets us
//! attempt `FICLONE` (reflink) from the composefs object fd, falling back to
//! `copy_file_range` / read-write.  The ostree SHA256 content checksum is
//! still computed via the C library's `checksum_file_from_input` (a pure,
//! repo-independent function) so the serialisation format is never
//! reimplemented.
//!
//! Metadata objects (dirmeta, dirtree, commit) and small inline files continue
//! to use the ostree C API — they are tiny and benefit from the existing
//! validation.
//!
//! # Why reflink, not hardlink
//!
//! A composefs object is content-addressed by its SHA-512 fsverity digest.
//! Multiple filesystem paths with identical content share a single composefs
//! object (inode).  In ostree bare mode, however, every content object carries
//! its own per-inode metadata: uid, gid, mode, and *all* xattrs including
//! `security.selinux`.  The same composefs object can be referenced by two
//! ostree objects that need different SELinux labels — for example
//! `/etc/sudo.conf` (label `etc_t`) and
//! `/usr/share/doc/sudo/examples/sudo.conf` (label `usr_t`).  Because a
//! single inode can hold only one `security.selinux` value, hardlinking both
//! ostree objects to the shared composefs inode is impossible: the second
//! `setxattr` would overwrite the first, causing `ostree fsck` to report a
//! checksum mismatch.
//!
//! Reflinks (FICLONE) solve this: each ostree object gets its own inode and
//! therefore its own metadata, while the underlying disk extents are shared
//! with the composefs object — zero copy, same space on the wire.
//!
//! # Filesystem requirements
//!
//! FICLONE requires a reflink-capable filesystem such as XFS or btrfs.  On
//! these filesystems the ostree and composefs repositories share disk blocks
//! so installing the OS adds no extra space for the ostree content objects.
//! On ext4 (and other filesystems without reflink support) FICLONE fails with
//! `EOPNOTSUPP` and the code falls back to a byte copy; installation succeeds
//! but no block sharing occurs between the two repositories.
//!
//! # SELinux labels and the NUL-terminator fix
//!
//! `selabel()` from composefs-rs applies SELinux labels in-memory to the
//! filesystem tree before ostree synthesis begins.  On SELinux-disabled hosts
//! (such as a container used for `bootc install`) the `fsetxattr` call for
//! `security.selinux` is a no-op; labels are applied by the kernel at first
//! boot during auto-relabeling.  The ostree checksums are computed with the
//! correct label values (because `checksum_file_from_input` sees them from the
//! in-memory tree), so `ostree fsck` passes after boot.
//!
//! One subtlety: composefs-rs `selabel()` stores SELinux values *without* a
//! trailing NUL, but the kernel stores them *with* one.  `xattrs_to_variant`
//! appends the NUL when computing the ostree checksum so that it matches what
//! `ostree fsck` reads back from the live filesystem.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd};
use std::os::unix::ffi::OsStrExt as _;

use anyhow::{Context as _, Result};

use composefs_ctl::composefs::fsverity::Sha512HashValue;
use composefs_ctl::composefs::generic_tree::{Inode, Stat};
use composefs_ctl::composefs::repository::Repository;
use composefs_ctl::composefs::tree::{Directory, Leaf, LeafContent, RegularFile};
use composefs_ctl::composefs_boot::selabel::selabel;
use composefs_ctl::composefs_oci;

use crate::container::store::{
    META_COMPOSEFS_SYNTHESIZED, META_CONFIG, META_MANIFEST, META_MANIFEST_DIGEST,
};
use crate::prelude::{Cast as _, ToVariant as _};
use crate::{gio, glib};

type ComposefsRepo = Repository<Sha512HashValue>;

/// Tracks per-import statistics and FICLONE capability for the composefs→ostree
/// object copy loop.
///
/// # Why reflink, not hardlink
///
/// A composefs object is a content-addressed file identified by its SHA-512
/// fsverity digest.  Multiple filesystem paths with identical content share the
/// same composefs object (inode).  In ostree's bare repo mode, however, each
/// content object carries its own metadata — uid, gid, mode, and **all xattrs
/// including `security.selinux`** — directly on the inode.
///
/// The same composefs object can be referenced by ostree objects that need
/// different metadata.  For example `/etc/sudo.conf` and
/// `/usr/share/doc/sudo/examples/sudo.conf` have identical bytes but different
/// SELinux labels (`etc_t` vs `usr_t`), producing different ostree content
/// checksums.  A single inode can carry only one `security.selinux` value, so
/// hardlinking both ostree objects to the shared composefs inode is impossible:
/// whichever metadata is written second silently overwrites the first, causing
/// `ostree fsck` to report a checksum mismatch.
///
/// Reflinks (FICLONE) solve this cleanly: each ostree object gets its own
/// inode (its own metadata) while the underlying disk extents are shared with
/// the composefs object — zero copy, same space efficiency.  If the filesystem
/// does not support reflinks (e.g. ext4) we fall back to a byte copy; unified
/// storage is not possible in that configuration.
struct DirectImportContext {
    /// `true` after FICLONE has failed on this device pair.
    ficlone_failed: bool,
    /// Count of files reflinked (FICLONE succeeded — blocks shared with composefs object).
    reflinked: u64,
    /// Count of files written via byte copy fallback (filesystem lacks reflink support).
    copied: u64,
    /// Count of objects that already existed in the repo (skipped).
    existing: u64,
    /// When `true`, any FICLONE failure is returned as a hard error instead of
    /// silently falling back to byte copy.  Set by the caller when it has already
    /// confirmed that reflinks are supported on the storage (e.g. via a probe).
    reflinks_required: bool,
}

/// Convert composefs xattrs (`BTreeMap`) to the ostree GVariant format (`a(ayay)`).
///
/// The ostree on-disk format stores xattr names as NUL-terminated C strings inside
/// `ay` (byte array) GVariant values — matching the C library's use of
/// `g_variant_new_bytestring(name)`.  The validation function in libostree reads
/// names back with the `"(^&ay@ay)"` format specifier, which returns a raw pointer
/// into the GVariant buffer, and then calls `strcmp` on it — so the trailing NUL
/// *must* be present.  Without it the first byte of the *value* would be treated as
/// part of the name, and if that byte happens to be `0x00` the validator throws
/// "Invalid xattr name (empty or missing NUL)".
fn xattrs_to_variant(xattrs: &BTreeMap<Box<OsStr>, Box<[u8]>>) -> Option<glib::Variant> {
    if xattrs.is_empty() {
        return None;
    }
    let children = xattrs.iter().map(|(k, v)| {
        // Append NUL so that ostree's C validator can read the name as a C string.
        let mut name_bytes = k.as_bytes().to_vec();
        name_bytes.push(b'\0');
        // SELinux stores label values as NUL-terminated strings on the filesystem.
        // The composefs selabel() function strips the NUL, but ostree fsck reads
        // xattrs back from disk (where the kernel always stores them with NUL) when
        // verifying checksums.  Ensure our checksum matches by adding the NUL here
        // for security.selinux values that are missing it.
        let value: &[u8] = v.as_ref();
        let value_owned;
        let value = if k.as_bytes() == b"security.selinux"
            && !value.last().copied().map_or(true, |b| b == 0)
        {
            value_owned = [value, &[0u8]].concat();
            value_owned.as_slice()
        } else {
            value
        };
        glib::Variant::tuple_from_iter([name_bytes.as_slice().to_variant(), value.to_variant()])
    });
    Some(glib::Variant::array_from_iter::<(&[u8], &[u8])>(children))
}

/// Build an ostree `DirMeta` GVariant from a composefs `Stat`.
fn create_dirmeta(stat: &Stat) -> glib::Variant {
    let finfo = gio::FileInfo::new();
    finfo.set_attribute_uint32("unix::uid", stat.st_uid);
    finfo.set_attribute_uint32("unix::gid", stat.st_gid);
    // ostree's create_directory_metadata requires the full mode word including
    // the S_IFDIR type bits.  The composefs Stat only stores the permission
    // bits, so we must OR in S_IFDIR ourselves.
    let mode = libc::S_IFDIR | stat.st_mode;
    finfo.set_attribute_uint32("unix::mode", mode);
    let xattrs = xattrs_to_variant(&stat.xattrs);
    crate::ostree::create_directory_metadata(&finfo, xattrs.as_ref())
}

/// Top-level paths from the OCI image that are API/virtual filesystems at runtime.
///
/// These paths (`/proc`, `/sys`, etc.) must NOT have their children written into
/// the ostree commit — they are mounted as kernel-provided virtual filesystems at
/// boot time and any content baked into the image is irrelevant (and in the case
/// of device nodes, actively harmful).  The directory entries themselves are
/// written as empty directories so that the mount points exist.
///
/// This mirrors the `EXCLUDED_TOPLEVEL_PATHS` list and the filtering logic in
/// `crate::tar::write::normalize_validate_path()`.
const EXCLUDED_TOPLEVEL_PATHS: &[&str] = &["run", "tmp", "proc", "sys", "dev"];

/// Walk the composefs root directory, applying ostree path normalization:
///
/// - `/etc` → `usr/etc` (ostree's deployment mechanism expects config here)
/// - Children of API/virtual-filesystem mounts (`/proc`, `/sys`, `/dev`, `/run`,
///   `/tmp`) are **omitted** — the directory entries are written as empty mount
///   points but their content is never part of the commit.
///
/// This matches the filtering that the tar import pipeline applies via
/// `normalize_validate_path()` in `tar/write.rs`.
fn write_dir_to_mtree_remap_etc(
    orepo: &crate::ostree::Repo,
    crepo: &ComposefsRepo,
    dir: &Directory<Sha512HashValue>,
    leaves: &[Leaf<Sha512HashValue>],
    mtree: &crate::ostree::MutableTree,
    ctx: &mut DirectImportContext,
) -> Result<()> {
    // Write the root dirmeta first
    let dirmeta = create_dirmeta(&dir.stat);
    let meta_csum = orepo
        .write_metadata(
            crate::ostree::ObjectType::DirMeta,
            None,
            &dirmeta,
            gio::Cancellable::NONE,
        )
        .context("Writing root dirmeta")?;
    mtree.set_metadata_checksum(&meta_csum.to_hex());

    // Collect the `etc` directory entry (if any) for deferred processing
    let mut etc_dir: Option<&Directory<Sha512HashValue>> = None;

    for (name, inode) in dir.sorted_entries() {
        let name = name
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Non-UTF8 entry name: {:?}", name))?;

        // Intercept `etc` at the root and defer it — we'll write it
        // as `usr/etc` after processing everything else.
        if name == "etc" {
            match inode {
                Inode::Directory(child) => {
                    etc_dir = Some(child);
                    continue;
                }
                _ => {
                    // Unusual: /etc is not a directory (e.g. symlink).
                    // Write it as-is — the deployment code will handle it
                    // or fail later with a more specific error.
                }
            }
        }

        // API/virtual-filesystem mount points: include the empty directory itself
        // (so the mount point exists at runtime) but skip all children.  This
        // mirrors the tar importer's EXCLUDED_TOPLEVEL_PATHS handling.
        if EXCLUDED_TOPLEVEL_PATHS.contains(&name) {
            if let Inode::Directory(child) = inode {
                let child_mtree = mtree.ensure_dir(name)?;
                // Write only the dirmeta (permissions/xattrs) — no children.
                let child_dirmeta = create_dirmeta(&child.stat);
                let child_meta_csum = orepo
                    .write_metadata(
                        crate::ostree::ObjectType::DirMeta,
                        None,
                        &child_dirmeta,
                        gio::Cancellable::NONE,
                    )
                    .with_context(|| format!("Writing dirmeta for excluded path {name}"))?;
                child_mtree.set_metadata_checksum(&child_meta_csum.to_hex());
                tracing::debug!("Composefs import: skipping children of excluded path /{name}");
                continue;
            }
            // Non-directory at an excluded path (e.g. a symlink for /tmp)?
            // Skip it entirely.
            tracing::debug!("Composefs import: skipping non-directory excluded path /{name}");
            continue;
        }

        match inode {
            Inode::Directory(child) => {
                let child_mtree = mtree.ensure_dir(name)?;
                write_dir_to_mtree(orepo, crepo, child, leaves, &child_mtree, ctx)?;
            }
            Inode::Leaf(leaf_id, _) => {
                let leaf = &leaves[leaf_id.0];
                let csum = write_leaf(orepo, crepo, &leaf.stat, &leaf.content, ctx)?;
                mtree
                    .replace_file(name, &csum)
                    .with_context(|| format!("Inserting {name} into mtree"))?;
            }
        }
    }

    // Now write the deferred `/etc` directory as `usr/etc`.
    if let Some(etc) = etc_dir {
        let usr_mtree = mtree.ensure_dir("usr")?;
        let usr_etc_mtree = usr_mtree.ensure_dir("etc")?;
        write_dir_to_mtree(orepo, crepo, etc, leaves, &usr_etc_mtree, ctx)
            .context("Writing /etc as usr/etc")?;
    }

    Ok(())
}

/// Recursively walk a composefs directory, writing each entry into `mtree`.
fn write_dir_to_mtree(
    orepo: &crate::ostree::Repo,
    crepo: &ComposefsRepo,
    dir: &Directory<Sha512HashValue>,
    leaves: &[Leaf<Sha512HashValue>],
    mtree: &crate::ostree::MutableTree,
    ctx: &mut DirectImportContext,
) -> Result<()> {
    let dirmeta = create_dirmeta(&dir.stat);
    let meta_csum = orepo
        .write_metadata(
            crate::ostree::ObjectType::DirMeta,
            None,
            &dirmeta,
            gio::Cancellable::NONE,
        )
        .context("Writing dirmeta")?;
    mtree.set_metadata_checksum(&meta_csum.to_hex());

    for (name, inode) in dir.sorted_entries() {
        let name = name
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Non-UTF8 entry name: {:?}", name))?;
        match inode {
            Inode::Directory(child) => {
                let child_mtree = mtree.ensure_dir(name)?;
                write_dir_to_mtree(orepo, crepo, child, leaves, &child_mtree, ctx)?;
            }
            Inode::Leaf(leaf_id, _) => {
                let leaf = &leaves[leaf_id.0];
                let csum = write_leaf(orepo, crepo, &leaf.stat, &leaf.content, ctx)?;
                mtree
                    .replace_file(name, &csum)
                    .with_context(|| format!("Inserting {name} into mtree"))?;
            }
        }
    }
    Ok(())
}

/// Write a single composefs leaf (regular file or symlink) to the ostree repo.
/// Returns the hex content checksum.
fn write_leaf(
    orepo: &crate::ostree::Repo,
    crepo: &ComposefsRepo,
    stat: &Stat,
    content: &LeafContent<Sha512HashValue>,
    ctx: &mut DirectImportContext,
) -> Result<String> {
    let xattrs = xattrs_to_variant(&stat.xattrs);
    match content {
        LeafContent::Symlink(target) => {
            let target = target
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Non-UTF8 symlink target"))?;
            let csum = orepo
                .write_symlink(
                    None,
                    stat.st_uid,
                    stat.st_gid,
                    xattrs.as_ref(),
                    target,
                    gio::Cancellable::NONE,
                )
                .context("Writing symlink")?;
            Ok(csum.to_string())
        }
        LeafContent::Regular(file) => {
            write_regular_file(orepo, crepo, stat, file, xattrs.as_ref(), ctx)
        }
        other => anyhow::bail!(
            "Unsupported composefs leaf (device/fifo/socket): {:?}",
            std::mem::discriminant(other)
        ),
    }
}

/// Write a regular file into the ostree repo.
///
/// Inline files use the ostree C API directly.  External files bypass the C
/// `write_content` path and instead write content objects directly to disk,
/// attempting FICLONE (reflink) first and falling back to a byte copy.
///
/// The ostree content checksum is computed via the C library's
/// `checksum_file_from_input` to guarantee format compatibility.
fn write_regular_file(
    orepo: &crate::ostree::Repo,
    crepo: &ComposefsRepo,
    stat: &Stat,
    file: &RegularFile<Sha512HashValue>,
    xattrs: Option<&glib::Variant>,
    ctx: &mut DirectImportContext,
) -> Result<String> {
    // ostree requires the full mode word including S_IFREG
    let mode = libc::S_IFREG | stat.st_mode;

    match file {
        RegularFile::Inline(data) => {
            let csum = orepo
                .write_regfile_inline(
                    None,
                    stat.st_uid,
                    stat.st_gid,
                    mode,
                    xattrs,
                    data,
                    gio::Cancellable::NONE,
                )
                .context("Writing inline file")?;
            Ok(csum.to_string())
        }
        RegularFile::External(object_id, size) => {
            write_external_file_direct(orepo, crepo, stat, object_id, *size, xattrs, mode, ctx)
        }
    }
}

/// Compute the ostree content checksum for a regular file using the C API.
///
/// This calls `ostree_checksum_file_from_input()` which is a pure,
/// repo-independent function.  It constructs the standard file header
/// GVariant (uid/gid/mode/xattrs) and hashes `header || content`.
fn compute_content_checksum(
    stat: &Stat,
    xattrs: Option<&glib::Variant>,
    fd: BorrowedFd<'_>,
    size: u64,
    mode: u32,
) -> Result<String> {
    let finfo = gio::FileInfo::new();
    finfo.set_attribute_uint32("unix::uid", stat.st_uid);
    finfo.set_attribute_uint32("unix::gid", stat.st_gid);
    finfo.set_attribute_uint32("unix::mode", mode);
    finfo.set_size(size as i64);
    finfo.set_file_type(gio::FileType::Regular);

    // Dup the fd so we can hand an owned File to ReadInputStream without
    // touching the caller's fd or using unsafe.
    let file = std::fs::File::from(fd.try_clone_to_owned().context("Dup fd for checksum")?);
    let istream = gio::ReadInputStream::new(file);
    let csum = crate::ostree::checksum_file_from_input(
        &finfo,
        xattrs,
        Some(&istream),
        crate::ostree::ObjectType::File,
        gio::Cancellable::NONE,
    )
    .map_err(|e| anyhow::anyhow!("Computing content checksum: {e}"))?;

    Ok(csum.to_string())
}

/// Build the `user.ostreemeta` GVariant `(uuu@a(ayay))` for bare-user mode.
///
/// This matches the C function `create_file_metadata()` in ostree-repo-commit.c.
fn build_bareuser_metadata(
    uid: u32,
    gid: u32,
    mode: u32,
    xattrs: Option<&glib::Variant>,
) -> glib::Variant {
    let empty_xattrs;
    let xattrs = match xattrs {
        Some(v) => v.clone(),
        None => {
            empty_xattrs = glib::Variant::array_from_iter::<(&[u8], &[u8])>(std::iter::empty());
            empty_xattrs
        }
    };
    // ostree stores these as big-endian u32 values
    glib::Variant::tuple_from_iter([
        uid.to_be().to_variant(),
        gid.to_be().to_variant(),
        mode.to_be().to_variant(),
        xattrs,
    ])
}

/// Apply file metadata to an fd according to the ostree repo mode.
///
/// For `Bare`: sets real uid/gid, mode, and xattrs via syscalls.
/// For `BareUser`: stores metadata in a `user.ostreemeta` xattr and
/// applies a masked mode suitable for non-root operation.
fn apply_file_metadata(
    fd: BorrowedFd<'_>,
    stat: &Stat,
    mode: u32,
    xattrs: Option<&glib::Variant>,
    repo_mode: crate::ostree::RepoMode,
) -> Result<()> {
    use rustix::fs::{Mode, Timestamps, XattrFlags, fchmod, fchown, fsetxattr, futimens};

    match repo_mode {
        crate::ostree::RepoMode::Bare => {
            fchown(
                fd,
                Some(rustix::process::Uid::from_raw(stat.st_uid)),
                Some(rustix::process::Gid::from_raw(stat.st_gid)),
            )
            .context("fchown")?;
            fchmod(fd, Mode::from_raw_mode(mode)).context("fchmod")?;
            // Set real xattrs on the file.  For security.selinux the composefs
            // selabel() function stores values without the NUL terminator that
            // the kernel expects; add it here so the on-disk value matches what
            // xattrs_to_variant() (and thus the ostree checksum) sees.
            for (name, value) in &stat.xattrs {
                let value: &[u8] = value.as_ref();
                let value_with_nul;
                let value = if name.as_bytes() == b"security.selinux"
                    && !value.last().copied().map_or(true, |b| b == 0)
                {
                    value_with_nul = [value, &[0u8]].concat();
                    value_with_nul.as_slice()
                } else {
                    value
                };
                fsetxattr(fd, name.as_bytes(), value, XattrFlags::empty())
                    .with_context(|| format!("fsetxattr({:?})", name))?;
            }
        }
        crate::ostree::RepoMode::BareUser => {
            // Write the user.ostreemeta xattr
            let meta = build_bareuser_metadata(stat.st_uid, stat.st_gid, mode, xattrs);
            let meta_bytes = meta.data_as_bytes();
            fsetxattr(
                fd,
                c"user.ostreemeta",
                meta_bytes.as_ref(),
                XattrFlags::empty(),
            )
            .context("fsetxattr(user.ostreemeta)")?;
            // Mask mode for non-root safety (matches libostree)
            let content_mode = (mode & (libc::S_IFREG | 0o775)) | libc::S_IRUSR;
            fchmod(fd, Mode::from_raw_mode(content_mode)).context("fchmod (bare-user)")?;
        }
        other => anyhow::bail!("Unsupported ostree repo mode for direct write: {other:?}"),
    }

    // Set mtime to OSTREE_TIMESTAMP (0), matching libostree behavior.
    // UTIME_OMIT for atime means "leave atime unchanged".
    futimens(
        fd,
        &Timestamps {
            last_access: rustix::fs::Timespec {
                tv_sec: 0,
                tv_nsec: rustix::fs::UTIME_OMIT,
            },
            last_modification: rustix::fs::Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
        },
    )
    .context("futimens")?;

    Ok(())
}

/// Ensure the `objects/XX/` directory exists under the repo.
fn ensure_object_dir(repo_dfd: BorrowedFd<'_>, prefix: &str) -> Result<()> {
    use rustix::fs::{Mode, mkdirat};

    let objects_dir = format!("objects/{prefix}");
    match mkdirat(repo_dfd, objects_dir.as_str(), Mode::from_raw_mode(0o777)) {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::EXIST) => Ok(()),
        Err(e) => Err(e).context(format!("Creating {objects_dir}"))?,
    }
}

/// Write a composefs external regular file directly into the ostree repo.
///
/// # Sharing strategy: FICLONE (reflink) → byte copy
///
/// Each ostree content object is written as a fresh inode (via `O_TMPFILE`)
/// and populated from the composefs object using `FICLONE` (reflink) when the
/// filesystem supports it, falling back to `copy_file_range` / `std::io::copy`.
///
/// **Why not hardlink?**  A composefs object is identified by its SHA-512
/// fsverity digest of raw content.  The same object can be referenced by
/// multiple ostree content objects that carry different metadata — in
/// particular different `security.selinux` xattrs assigned by the SELinux
/// policy relabeling step.  Ostree bare mode stores metadata (uid/gid/mode/
/// xattrs) on the inode, so a single shared inode cannot satisfy two different
/// metadata requirements.  FICLONE shares the underlying disk extents while
/// keeping inodes independent, giving each ostree object its own metadata.
///
/// On filesystems without reflink support (ext4, etc.) FICLONE fails with
/// `EOPNOTSUPP` and we fall back to a full byte copy.  Unified storage
/// (space-sharing between the composefs and ostree repos) requires a
/// reflink-capable filesystem (XFS, btrfs, …).
///
/// Returns the hex SHA256 content checksum.
#[allow(clippy::too_many_arguments)]
fn write_external_file_direct(
    orepo: &crate::ostree::Repo,
    crepo: &ComposefsRepo,
    stat: &Stat,
    object_id: &Sha512HashValue,
    size: u64,
    xattrs: Option<&glib::Variant>,
    mode: u32,
    ctx: &mut DirectImportContext,
) -> Result<String> {
    use rustix::fs::{AtFlags, Mode, OFlags, linkat, openat};
    use std::io::{Seek, SeekFrom};

    let cfs_fd = crepo
        .open_object(object_id)
        .context("Opening composefs object")?;

    // Compute the ostree content checksum using the C API.
    let checksum = compute_content_checksum(stat, xattrs, cfs_fd.as_fd(), size, mode)
        .context("Computing content checksum")?;

    // Check if the object already exists — skip if so.
    if orepo
        .has_object(
            crate::ostree::ObjectType::File,
            &checksum,
            gio::Cancellable::NONE,
        )
        .context("Checking for existing object")?
    {
        ctx.existing += 1;
        return Ok(checksum);
    }

    let repo_dfd = orepo.dfd_borrow();
    let repo_mode = orepo.mode();

    // Ensure objects/XX/ directory exists.
    let (prefix, _rest) = checksum.split_at(2);
    ensure_object_dir(repo_dfd, prefix)?;

    let obj_path = format!("objects/{prefix}/{}.file", &checksum[2..]);

    // Create an O_TMPFILE in the repo's tmp/ directory.  This gives us an
    // anonymous inode we can populate before atomically linking it into place,
    // avoiding partial writes visible to concurrent readers.
    let tmp_fd = openat(
        repo_dfd,
        c"tmp",
        OFlags::WRONLY | OFlags::TMPFILE | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o644),
    )
    .context("Creating tmpfile in ostree repo/tmp")?;

    // Seek the source fd back to the start (compute_content_checksum consumed it).
    let mut src_file = std::fs::File::from(cfs_fd);
    src_file
        .seek(SeekFrom::Start(0))
        .context("Seeking composefs fd to start")?;

    // --- Primary path: FICLONE (reflink) ---
    //
    // Shares the underlying disk extents with the composefs object while giving
    // the ostree object its own inode (and thus its own metadata).  On XFS this
    // is a near-zero-cost operation.  After the first failure we stop trying.
    let mut reflinked = false;
    if !ctx.ficlone_failed {
        match rustix::fs::ioctl_ficlone(&tmp_fd, &src_file) {
            Ok(()) => {
                reflinked = true;
            }
            Err(e @ (rustix::io::Errno::OPNOTSUPP | rustix::io::Errno::XDEV)) => {
                if ctx.reflinks_required {
                    return Err(anyhow::anyhow!(
                        "FICLONE failed ({e}) but reflinks were confirmed supported \
                         by the storage probe — cannot safely continue import"
                    ));
                }
                tracing::debug!(
                    "FICLONE not supported on this filesystem; \
                     falling back to copy for all remaining objects"
                );
                ctx.ficlone_failed = true;
            }
            Err(e) => {
                if ctx.reflinks_required {
                    return Err(anyhow::anyhow!(
                        "FICLONE failed unexpectedly ({e}); reflinks are required"
                    ));
                }
                tracing::debug!("FICLONE failed unexpectedly ({e}); falling back to copy");
                ctx.ficlone_failed = true;
            }
        }
    }

    if reflinked {
        ctx.reflinked += 1;
    } else {
        // --- Fallback: byte copy via copy_file_range ---
        let mut dst_file = std::fs::File::from(tmp_fd.try_clone().context("Cloning tmpfile fd")?);
        let n = std::io::copy(&mut src_file, &mut dst_file).context("Copying file content")?;
        anyhow::ensure!(
            n == size,
            "Size mismatch: expected {size} bytes but copied {n}"
        );
        ctx.copied += 1;
    }

    // Apply metadata (uid/gid/mode/xattrs/mtime) to the new inode.
    apply_file_metadata(tmp_fd.as_fd(), stat, mode, xattrs, repo_mode)?;

    // Atomically link the tmpfile into place at objects/XX/rest.file.
    let proc_path = format!("/proc/self/fd/{}", tmp_fd.as_raw_fd());
    match linkat(
        rustix::fs::CWD,
        proc_path.as_str(),
        repo_dfd,
        obj_path.as_str(),
        AtFlags::SYMLINK_FOLLOW,
    ) {
        Ok(()) => {}
        Err(rustix::io::Errno::EXIST) => {
            // A concurrent writer (or an earlier call) already wrote this object.
        }
        Err(e) => {
            return Err(e).with_context(|| format!("Linking tmpfile to {obj_path}"));
        }
    }

    Ok(checksum)
}

/// Synthesize an ostree commit from a composefs repository that has already
/// pulled an OCI image.
///
/// This is the inverse of the ostree→composefs path in libostree: instead of
/// reading an ostree commit to build an EROFS image, we walk the composefs
/// `FileSystem` tree and write each entry as an ostree object.
///
/// The resulting commit carries the same OCI metadata as a commit produced by
/// the standard `ostree-container` import pipeline:
/// - `ostree.container.image-config`
/// - `ostree.manifest`
/// - `ostree.manifest-digest`
///
/// External regular files are written directly to disk with FICLONE (reflink)
/// attempted first, falling back to a byte copy.  On the same filesystem this
/// avoids copying data entirely.
pub fn import_from_composefs_repo(
    ostree_repo: &crate::ostree::Repo,
    composefs_repo: &ComposefsRepo,
    config_digest: &composefs_oci::OciDigest,
    manifest_digest: &str,
    image_manifest: &crate::oci_spec::image::ImageManifest,
    image_config: &crate::oci_spec::image::ImageConfiguration,
    reflinks_required: bool,
) -> Result<String> {
    let cancellable = gio::Cancellable::NONE;

    // Reconstruct the merged filesystem tree from the composefs store
    let mut fs = composefs_oci::image::create_filesystem(composefs_repo, config_digest, None)
        .context("Reconstructing composefs filesystem tree")?;

    // Apply SELinux labels in-memory before writing any objects.
    // selabel walks the FileSystem tree and reads policy files directly from
    // the composefs object store — no file copies are made.
    let labeled = selabel(&mut fs, composefs_repo)
        .context("Applying SELinux labels from composefs image policy")?;
    tracing::debug!(
        labeled,
        total_leaves = fs.leaves.len(),
        "SELinux labeling complete"
    );

    let txn = ostree_repo
        .auto_transaction(cancellable)
        .context("Beginning ostree transaction")?;

    let mut ctx = DirectImportContext {
        ficlone_failed: false,
        reflinked: 0,
        copied: 0,
        existing: 0,
        reflinks_required,
    };

    // Walk and write all objects.
    //
    // The composefs filesystem tree uses the OCI image layout where `/etc`
    // lives at the tree root. However, ostree's deployment mechanism expects
    // configuration to be at `usr/etc` (it copies `usr/etc` → `etc` during
    // deployment initialization and performs a 3-way merge). The old
    // `ImageImporter` tar pipeline applies this `/etc` → `usr/etc` remap
    // via `normalize_validate_path()` in `tar/write.rs`.
    //
    // We replicate that remapping here: if the composefs root has an `etc`
    // directory, we write it into the ostree tree as `usr/etc` instead of
    // a top-level `etc`.
    let root_mtree = crate::ostree::MutableTree::new();
    write_dir_to_mtree_remap_etc(
        ostree_repo,
        composefs_repo,
        &fs.root,
        &fs.leaves,
        &root_mtree,
        &mut ctx,
    )
    .context("Writing composefs tree into ostree")?;

    tracing::info!(
        reflinked = ctx.reflinked,
        copied = ctx.copied,
        existing = ctx.existing,
        "Composefs→ostree import complete: reflinked={} copied={} existing={}",
        ctx.reflinked,
        ctx.copied,
        ctx.existing,
    );

    // Seal the tree
    let root = ostree_repo
        .write_mtree(&root_mtree, cancellable)
        .context("Sealing MutableTree")?;
    let root = root
        .downcast::<crate::ostree::RepoFile>()
        .map_err(|_| anyhow::anyhow!("BUG: write_mtree did not return a RepoFile"))?;

    // Attach OCI metadata so the commit looks like a normal ostree-container import,
    // plus a flag indicating this commit was synthesized from a composefs repository
    // (so per-layer blob refs do not exist).
    let meta = glib::VariantDict::new(None);
    meta.insert(
        META_CONFIG,
        &serde_json::to_string(image_config).context("Serializing image config")?,
    );
    meta.insert(
        META_MANIFEST,
        &serde_json::to_string(image_manifest).context("Serializing manifest")?,
    );
    meta.insert(META_MANIFEST_DIGEST, &manifest_digest);
    meta.insert(crate::ostree::METADATA_KEY_BOOTABLE.as_ref(), &true);
    meta.insert(META_COMPOSEFS_SYNTHESIZED, &true);
    let meta = meta.to_variant();

    // Use the image creation timestamp for the ostree commit, matching the
    // behaviour of the old ImageImporter pipeline.  This is important because
    // rpm-ostree unconditionally expects a non-zero timestamp in the deployment
    // metadata; a zero (epoch) timestamp can cause `rpm-ostree status` to abort.
    let timestamp =
        crate::container::store::timestamp_of_manifest_or_config(image_manifest, image_config)
            .unwrap_or_else(|| chrono::offset::Utc::now().timestamp() as u64);

    let commit = ostree_repo
        .write_commit_with_time(None, None, None, Some(&meta), &root, timestamp, cancellable)
        .context("Writing ostree commit")?;

    txn.commit(cancellable).context("Committing transaction")?;

    Ok(commit.to_string())
}

#[cfg(test)]
mod tests {
    use rustix::fd::AsRawFd as _;
    use rustix::fs::{AtFlags, Mode, OFlags, linkat, openat};
    use std::os::fd::AsFd as _;

    /// Verify that O_TMPFILE can be materialized via /proc/self/fd/N without
    /// root (the linkat+SYMLINK_FOLLOW approach used by write_external_file_direct).
    #[test]
    fn test_otmpfile_materialize_via_proc() {
        let dir = tempfile::tempdir_in("/var/tmp").unwrap();
        let dir_fd = rustix::fs::open(
            dir.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();

        // Create O_TMPFILE — anonymous inode in the directory
        let tmp_fd = openat(
            &dir_fd,
            c".",
            OFlags::WRONLY | OFlags::TMPFILE | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o644),
        )
        .expect("O_TMPFILE");

        rustix::io::write(&tmp_fd, b"hello").unwrap();

        // Materialize via /proc/self/fd/N with SYMLINK_FOLLOW
        let proc_path = format!("/proc/self/fd/{}", tmp_fd.as_fd().as_raw_fd());
        linkat(
            rustix::fs::CWD,
            proc_path.as_str(),
            &dir_fd,
            "materialized.txt",
            AtFlags::SYMLINK_FOLLOW,
        )
        .expect("linkat via /proc/self/fd should work without root");

        let contents = std::fs::read(dir.path().join("materialized.txt")).unwrap();
        assert_eq!(contents, b"hello");
    }

    /// Verify FICLONE (reflink) works between two files in /var/tmp.
    /// This will return EOPNOTSUPP on filesystems that don't support it
    /// (e.g. ext4), which is acceptable — we just need to confirm the
    /// ioctl itself is reachable and returns a meaningful error code.
    #[test]
    fn test_ficlone_or_enotsup() {
        let dir = tempfile::tempdir_in("/var/tmp").unwrap();
        let dir_fd = rustix::fs::open(
            dir.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();

        // Source file with some content
        let src_fd = openat(
            &dir_fd,
            c"src",
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o644),
        )
        .unwrap();
        rustix::io::write(&src_fd, b"reflink-test-content").unwrap();

        // Destination — O_TMPFILE
        let dst_fd = openat(
            &dir_fd,
            c".",
            OFlags::WRONLY | OFlags::TMPFILE | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o644),
        )
        .unwrap();

        match rustix::fs::ioctl_ficlone(&dst_fd, &src_fd) {
            Ok(()) => {
                // Reflinks supported — verify content matches
                let proc_path = format!("/proc/self/fd/{}", dst_fd.as_fd().as_raw_fd());
                linkat(
                    rustix::fs::CWD,
                    proc_path.as_str(),
                    &dir_fd,
                    "dst",
                    AtFlags::SYMLINK_FOLLOW,
                )
                .unwrap();
                let contents = std::fs::read(dir.path().join("dst")).unwrap();
                assert_eq!(contents, b"reflink-test-content");
                eprintln!("FICLONE: supported on this filesystem");
            }
            Err(rustix::io::Errno::OPNOTSUPP) | Err(rustix::io::Errno::XDEV) => {
                eprintln!(
                    "FICLONE: not supported on this filesystem (EOPNOTSUPP/EXDEV) — fallback to copy is correct"
                );
            }
            Err(e) => panic!("Unexpected FICLONE error: {e}"),
        }
    }

    /// Verify that user.ostreemeta xattr can be set on a regular file
    /// without root in /var/tmp.
    #[test]
    fn test_user_ostreemeta_xattr() {
        use rustix::fs::{XattrFlags, fgetxattr, fsetxattr};

        let dir = tempfile::tempdir_in("/var/tmp").unwrap();
        let f = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        let fd = rustix::fs::open(f.path(), OFlags::RDWR | OFlags::CLOEXEC, Mode::empty()).unwrap();

        let meta_bytes = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xed\x00\x00\x00\x00";
        fsetxattr(&fd, c"user.ostreemeta", meta_bytes, XattrFlags::empty())
            .expect("setting user.ostreemeta should work without root");

        let mut buf = vec![0u8; 256];
        let n = fgetxattr(&fd, c"user.ostreemeta", &mut buf).unwrap();
        assert_eq!(&buf[..n], meta_bytes);
    }
}
