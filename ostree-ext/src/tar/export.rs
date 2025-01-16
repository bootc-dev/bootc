//! APIs for creating container images from OSTree commits

use crate::chunking;
use crate::objgv::*;
use anyhow::{anyhow, ensure, Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use fn_error_context::context;
use gio::glib;
use gio::prelude::*;
use gvariant::aligned_bytes::TryAsAligned;
use gvariant::{Marker, Structure};
use ostree::gio;
use std::borrow::Borrow;
use std::borrow::Cow;
use std::collections::HashSet;
use std::ffi::CStr;
use std::io::BufReader;

/// The repository mode generated by a tar export stream.
pub const BARE_SPLIT_XATTRS_MODE: &str = "bare-split-xattrs";

/// The SELinux xattr. Because the ostree xattrs require an embedded NUL, we
/// store that version as a constant.
pub(crate) const SECURITY_SELINUX_XATTR_C: &CStr = c"security.selinux";
/// Then derive a string version (without the NUL) from the above.
pub(crate) const SECURITY_SELINUX_XATTR: &str = const {
    match SECURITY_SELINUX_XATTR_C.to_str() {
        Ok(r) => r,
        Err(_) => unreachable!(),
    }
};

// This is both special in the tar stream *and* it's in the ostree commit.
const SYSROOT: &str = "sysroot";
// This way the default ostree -> sysroot/ostree symlink works.
const OSTREEDIR: &str = "sysroot/ostree";
// The ref added (under ostree/) in the exported OSTree repo pointing at the commit.
#[allow(dead_code)]
const OSTREEREF: &str = "encapsulated";

/// In v0 format, we use this relative path prefix.  I think I chose this by looking
/// at the current Fedora base image tar stream.  However, several others don't do
/// this and have paths be relative by simply omitting `./`, i.e. the tar stream
/// contains `usr/bin/bash` and not `./usr/bin/bash`.  The former looks cleaner
/// to me, so in v1 we drop it.
const TAR_PATH_PREFIX_V0: &str = "./";

/// The base repository configuration that identifies this is a tar export.
// See https://github.com/ostreedev/ostree/issues/2499
const REPO_CONFIG: &str = r#"[core]
repo_version=1
mode=bare-split-xattrs
"#;

/// A decently large buffer, as used by e.g. coreutils `cat`.
/// System calls are expensive.
const BUF_CAPACITY: usize = 131072;

/// Convert /usr/etc back to /etc
fn map_path(p: &Utf8Path) -> std::borrow::Cow<Utf8Path> {
    match p.strip_prefix("./usr/etc") {
        Ok(r) => Cow::Owned(Utf8Path::new("./etc").join(r)),
        _ => Cow::Borrowed(p),
    }
}

/// Convert usr/etc back to etc for the tar stream.
fn map_path_v1(p: &Utf8Path) -> &Utf8Path {
    debug_assert!(!p.starts_with("/") && !p.starts_with("."));
    if p.starts_with("usr/etc") {
        p.strip_prefix("usr/").unwrap()
    } else {
        p
    }
}

/// Given two paths, which may be absolute (starting with /) or
/// start with `./`, return true if they are equal after removing
/// those prefixes. This is effectively "would these paths be equal"
/// when processed as a tar entry.
pub(crate) fn path_equivalent_for_tar(a: impl AsRef<Utf8Path>, b: impl AsRef<Utf8Path>) -> bool {
    fn strip_prefix(p: &Utf8Path) -> &Utf8Path {
        if let Ok(p) = p.strip_prefix("/") {
            return p;
        } else if let Ok(p) = p.strip_prefix("./") {
            return p;
        }
        return p;
    }
    strip_prefix(a.as_ref()) == strip_prefix(b.as_ref())
}

struct OstreeTarWriter<'a, W: std::io::Write> {
    repo: &'a ostree::Repo,
    commit_checksum: &'a str,
    commit_object: glib::Variant,
    out: &'a mut tar::Builder<W>,
    #[allow(dead_code)]
    options: ExportOptions,
    wrote_initdirs: bool,
    /// True if we're only writing directories
    structure_only: bool,
    wrote_vartmp: bool, // Set if the ostree commit contains /var/tmp
    wrote_dirtree: HashSet<String>,
    wrote_dirmeta: HashSet<String>,
    wrote_content: HashSet<String>,
    wrote_xattrs: HashSet<String>,
}

pub(crate) fn object_path(objtype: ostree::ObjectType, checksum: &str) -> Utf8PathBuf {
    let suffix = match objtype {
        ostree::ObjectType::Commit => "commit",
        ostree::ObjectType::CommitMeta => "commitmeta",
        ostree::ObjectType::DirTree => "dirtree",
        ostree::ObjectType::DirMeta => "dirmeta",
        ostree::ObjectType::File => "file",
        o => panic!("Unexpected object type: {:?}", o),
    };
    let (first, rest) = checksum.split_at(2);
    format!("{}/repo/objects/{}/{}.{}", OSTREEDIR, first, rest, suffix).into()
}

fn v1_xattrs_object_path(checksum: &str) -> Utf8PathBuf {
    let (first, rest) = checksum.split_at(2);
    format!("{}/repo/objects/{}/{}.file-xattrs", OSTREEDIR, first, rest).into()
}

fn v1_xattrs_link_object_path(checksum: &str) -> Utf8PathBuf {
    let (first, rest) = checksum.split_at(2);
    format!(
        "{}/repo/objects/{}/{}.file-xattrs-link",
        OSTREEDIR, first, rest
    )
    .into()
}

/// Check for "denormal" symlinks which contain "//"
// See https://github.com/fedora-sysv/chkconfig/pull/67
// [root@cosa-devsh ~]# rpm -qf /usr/lib/systemd/systemd-sysv-install
// chkconfig-1.13-2.el8.x86_64
// [root@cosa-devsh ~]# ll /usr/lib/systemd/systemd-sysv-install
// lrwxrwxrwx. 2 root root 24 Nov 29 18:08 /usr/lib/systemd/systemd-sysv-install -> ../../..//sbin/chkconfig
// [root@cosa-devsh ~]#
fn symlink_is_denormal(target: &str) -> bool {
    target.contains("//")
}

pub(crate) fn tar_append_default_data(
    out: &mut tar::Builder<impl std::io::Write>,
    path: &Utf8Path,
    buf: &[u8],
) -> Result<()> {
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(tar::EntryType::Regular);
    h.set_uid(0);
    h.set_gid(0);
    h.set_mode(0o644);
    h.set_size(buf.len() as u64);
    out.append_data(&mut h, path, buf).map_err(Into::into)
}

impl<'a, W: std::io::Write> OstreeTarWriter<'a, W> {
    fn new(
        repo: &'a ostree::Repo,
        commit_checksum: &'a str,
        out: &'a mut tar::Builder<W>,
        options: ExportOptions,
    ) -> Result<Self> {
        let commit_object = repo.load_commit(commit_checksum)?.0;
        let r = Self {
            repo,
            commit_checksum,
            commit_object,
            out,
            options,
            wrote_initdirs: false,
            structure_only: false,
            wrote_vartmp: false,
            wrote_dirmeta: HashSet::new(),
            wrote_dirtree: HashSet::new(),
            wrote_content: HashSet::new(),
            wrote_xattrs: HashSet::new(),
        };
        Ok(r)
    }

    /// Convert the ostree mode to tar mode.
    /// The ostree mode bits include the format, tar does not.
    /// Historically in format version 0 we injected them, so we need to keep doing so.
    fn filter_mode(&self, mode: u32) -> u32 {
        mode & !libc::S_IFMT
    }

    /// Add a directory entry with default permissions (root/root 0755)
    fn append_default_dir(&mut self, path: &Utf8Path) -> Result<()> {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Directory);
        h.set_uid(0);
        h.set_gid(0);
        h.set_mode(0o755);
        h.set_size(0);
        self.out.append_data(&mut h, path, &mut std::io::empty())?;
        Ok(())
    }

    /// Add a regular file entry with default permissions (root/root 0644)
    fn append_default_data(&mut self, path: &Utf8Path, buf: &[u8]) -> Result<()> {
        tar_append_default_data(self.out, path, buf)
    }

    /// Add an hardlink entry with default permissions (root/root 0644)
    fn append_default_hardlink(&mut self, path: &Utf8Path, link_target: &Utf8Path) -> Result<()> {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Link);
        h.set_uid(0);
        h.set_gid(0);
        h.set_mode(0o644);
        h.set_size(0);
        self.out.append_link(&mut h, path, link_target)?;
        Ok(())
    }

    /// Write the initial /sysroot/ostree/repo structure.
    fn write_repo_structure(&mut self) -> Result<()> {
        if self.wrote_initdirs {
            return Ok(());
        }

        let objdir: Utf8PathBuf = format!("{}/repo/objects", OSTREEDIR).into();
        // Add all parent directories
        let parent_dirs = {
            let mut parts: Vec<_> = objdir.ancestors().collect();
            parts.reverse();
            parts
        };
        for path in parent_dirs {
            match path.as_str() {
                "/" | "" => continue,
                _ => {}
            }
            self.append_default_dir(path)?;
        }
        // Object subdirectories
        for d in 0..=0xFF {
            let path: Utf8PathBuf = format!("{}/{:02x}", objdir, d).into();
            self.append_default_dir(&path)?;
        }
        // Standard repo subdirectories.
        let subdirs = [
            "extensions",
            "refs",
            "refs/heads",
            "refs/mirrors",
            "refs/remotes",
            "state",
            "tmp",
            "tmp/cache",
        ];
        for d in subdirs {
            let path: Utf8PathBuf = format!("{}/repo/{}", OSTREEDIR, d).into();
            self.append_default_dir(&path)?;
        }

        // Repository configuration file.
        {
            let path = format!("{}/repo/config", OSTREEDIR);
            self.append_default_data(Utf8Path::new(&path), REPO_CONFIG.as_bytes())?;
        }

        self.wrote_initdirs = true;
        Ok(())
    }

    /// Recursively serialize a commit object to the target tar stream.
    fn write_commit(&mut self) -> Result<()> {
        let cancellable = gio::Cancellable::NONE;

        let commit_bytes = self.commit_object.data_as_bytes();
        let commit_bytes = commit_bytes.try_as_aligned()?;
        let commit = gv_commit!().cast(commit_bytes);
        let commit = commit.to_tuple();
        let contents = hex::encode(commit.6);
        let metadata_checksum = &hex::encode(commit.7);
        let metadata_v = self
            .repo
            .load_variant(ostree::ObjectType::DirMeta, metadata_checksum)?;
        // Safety: We passed the correct variant type just above
        let metadata = &ostree::DirMetaParsed::from_variant(&metadata_v).unwrap();
        let rootpath = Utf8Path::new(TAR_PATH_PREFIX_V0);

        // We need to write the root directory, before we write any objects.  This should be the very
        // first thing.
        self.append_dir(rootpath, metadata)?;

        // Now, we create sysroot/ and everything under it
        self.write_repo_structure()?;

        self.append_commit_object()?;

        // The ostree dirmeta object for the root.
        self.append(ostree::ObjectType::DirMeta, metadata_checksum, &metadata_v)?;

        // Recurse and write everything else.
        self.append_dirtree(
            Utf8Path::new(TAR_PATH_PREFIX_V0),
            contents,
            true,
            cancellable,
        )?;

        self.append_standard_var(cancellable)?;

        Ok(())
    }

    fn append_commit_object(&mut self) -> Result<()> {
        self.append(
            ostree::ObjectType::Commit,
            self.commit_checksum,
            &self.commit_object.clone(),
        )?;
        if let Some(commitmeta) = self
            .repo
            .read_commit_detached_metadata(self.commit_checksum, gio::Cancellable::NONE)?
        {
            self.append(
                ostree::ObjectType::CommitMeta,
                self.commit_checksum,
                &commitmeta,
            )?;
        }
        Ok(())
    }

    fn append(
        &mut self,
        objtype: ostree::ObjectType,
        checksum: &str,
        v: &glib::Variant,
    ) -> Result<()> {
        let set = match objtype {
            ostree::ObjectType::Commit | ostree::ObjectType::CommitMeta => None,
            ostree::ObjectType::DirTree => Some(&mut self.wrote_dirtree),
            ostree::ObjectType::DirMeta => Some(&mut self.wrote_dirmeta),
            o => panic!("Unexpected object type: {:?}", o),
        };
        if let Some(set) = set {
            if set.contains(checksum) {
                return Ok(());
            }
            let inserted = set.insert(checksum.to_string());
            debug_assert!(inserted);
        }

        let data = v.data_as_bytes();
        let data = data.as_ref();
        self.append_default_data(&object_path(objtype, checksum), data)
            .with_context(|| format!("Writing object {checksum}"))?;
        Ok(())
    }

    /// Export xattrs in ostree-container style format, which is a .xattrs file.
    /// This is different from xattrs which may appear as e.g. PAX metadata, which we don't use
    /// at the moment.
    ///
    /// Return whether content was written.
    #[context("Writing xattrs")]
    fn append_ostree_xattrs(&mut self, checksum: &str, xattrs: &glib::Variant) -> Result<bool> {
        let xattrs_data = xattrs.data_as_bytes();
        let xattrs_data = xattrs_data.as_ref();

        let xattrs_checksum = {
            let digest = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), xattrs_data)?;
            hex::encode(digest)
        };

        let path = v1_xattrs_object_path(&xattrs_checksum);
        // Write xattrs content into a separate `.file-xattrs` object.
        if !self.wrote_xattrs.contains(&xattrs_checksum) {
            let inserted = self.wrote_xattrs.insert(xattrs_checksum);
            debug_assert!(inserted);
            self.append_default_data(&path, xattrs_data)?;
        }
        // Write a `.file-xattrs-link` which links the file object to
        // the corresponding detached xattrs.
        {
            let link_obj_path = v1_xattrs_link_object_path(checksum);
            self.append_default_hardlink(&link_obj_path, &path)?;
        }

        Ok(true)
    }

    /// Append all xattrs to the tar stream *except* security.selinux, because
    /// that one doesn't become visible in `podman run` anyways, so we couldn't
    /// rely on it in some cases.
    /// https://github.com/containers/storage/blob/0d4a8d2aaf293c9f0464b888d932ab5147a284b9/pkg/archive/archive.go#L85
    #[context("Writing tar xattrs")]
    fn append_tarstream_xattrs(&mut self, xattrs: &glib::Variant) -> Result<()> {
        let v = xattrs.data_as_bytes();
        let v = v.try_as_aligned().unwrap();
        let v = gvariant::gv!("a(ayay)").cast(v);
        let mut pax_extensions = Vec::new();
        for entry in v {
            let (k, v) = entry.to_tuple();
            let k = CStr::from_bytes_with_nul(k).unwrap();
            let k = k
                .to_str()
                .with_context(|| format!("Found non-UTF8 xattr: {k:?}"))?;
            if k == SECURITY_SELINUX_XATTR {
                continue;
            }
            pax_extensions.push((format!("SCHILY.xattr.{k}"), v));
        }
        self.out
            .append_pax_extensions(pax_extensions.iter().map(|(k, v)| (k.as_str(), *v)))?;
        Ok(())
    }

    /// Write a content object, returning the path/header that should be used
    /// as a hard link to it in the target path. This matches how ostree checkouts work.
    fn append_content(&mut self, checksum: &str) -> Result<(Utf8PathBuf, tar::Header)> {
        let path = object_path(ostree::ObjectType::File, checksum);

        let (instream, meta, xattrs) = self.repo.load_file(checksum, gio::Cancellable::NONE)?;

        let mut h = tar::Header::new_gnu();
        h.set_uid(meta.attribute_uint32("unix::uid") as u64);
        h.set_gid(meta.attribute_uint32("unix::gid") as u64);
        let mode = meta.attribute_uint32("unix::mode");
        h.set_mode(self.filter_mode(mode));
        if instream.is_some() {
            h.set_size(meta.size() as u64);
        }
        if !self.wrote_content.contains(checksum) {
            let inserted = self.wrote_content.insert(checksum.to_string());
            debug_assert!(inserted);

            // The xattrs objects need to be exported before the regular object they
            // refer to. Otherwise the importing logic won't have the xattrs available
            // when importing file content.
            self.append_ostree_xattrs(checksum, &xattrs)?;
            self.append_tarstream_xattrs(&xattrs)?;

            if let Some(instream) = instream {
                ensure!(meta.file_type() == gio::FileType::Regular);

                h.set_entry_type(tar::EntryType::Regular);
                h.set_size(meta.size() as u64);
                let mut instream = BufReader::with_capacity(BUF_CAPACITY, instream.into_read());
                self.out
                    .append_data(&mut h, &path, &mut instream)
                    .with_context(|| format!("Writing regfile {}", checksum))?;
            } else {
                ensure!(meta.file_type() == gio::FileType::SymbolicLink);

                let target = meta
                    .symlink_target()
                    .ok_or_else(|| anyhow!("Missing symlink target"))?;
                let target = target
                    .to_str()
                    .ok_or_else(|| anyhow!("Invalid UTF-8 symlink target: {target:?}"))?;
                let context = || format!("Writing content symlink: {}", checksum);
                h.set_entry_type(tar::EntryType::Symlink);
                h.set_size(0);
                // Handle //chkconfig, see above
                if symlink_is_denormal(target) {
                    h.set_link_name_literal(target).with_context(context)?;
                    self.out
                        .append_data(&mut h, &path, &mut std::io::empty())
                        .with_context(context)?;
                } else {
                    self.out
                        .append_link(&mut h, &path, target)
                        .with_context(context)?;
                }
            }
        }

        Ok((path, h))
    }

    /// Write a directory using the provided metadata.
    fn append_dir(&mut self, dirpath: &Utf8Path, meta: &ostree::DirMetaParsed) -> Result<()> {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_size(0);
        header.set_uid(meta.uid as u64);
        header.set_gid(meta.gid as u64);
        header.set_mode(self.filter_mode(meta.mode));
        self.out
            .append_data(&mut header, dirpath, std::io::empty())?;
        Ok(())
    }

    /// Given a source object (in e.g. ostree/repo/objects/...), write a hardlink to it
    /// in its expected target path (e.g. `usr/bin/bash`).
    fn append_content_hardlink(
        &mut self,
        srcpath: &Utf8Path,
        mut h: tar::Header,
        dest: &Utf8Path,
    ) -> Result<()> {
        // Query the original size first
        let size = h.size().context("Querying size for hardlink append")?;
        // Don't create hardlinks to zero-sized files, it's much more likely
        // to result in generated tar streams from container builds resulting
        // in a modified linked-to file in /sysroot, which we don't currently handle.
        // And in the case where the input is *not* zero sized, we still output
        // a hardlink of size zero, as this is what is normal.
        h.set_size(0);
        if h.entry_type() == tar::EntryType::Regular && size == 0 {
            self.out.append_data(&mut h, dest, &mut std::io::empty())?;
        } else {
            h.set_entry_type(tar::EntryType::Link);
            h.set_link_name(srcpath)?;
            self.out.append_data(&mut h, dest, &mut std::io::empty())?;
        }
        Ok(())
    }

    /// Write a dirtree object.
    fn append_dirtree<C: IsA<gio::Cancellable>>(
        &mut self,
        dirpath: &Utf8Path,
        checksum: String,
        is_root: bool,
        cancellable: Option<&C>,
    ) -> Result<()> {
        let v = &self
            .repo
            .load_variant(ostree::ObjectType::DirTree, &checksum)?;
        self.append(ostree::ObjectType::DirTree, &checksum, v)?;
        drop(checksum);
        let v = v.data_as_bytes();
        let v = v.try_as_aligned()?;
        let v = gv_dirtree!().cast(v);
        let (files, dirs) = v.to_tuple();

        if let Some(c) = cancellable {
            c.set_error_if_cancelled()?;
        }

        if !self.structure_only {
            for file in files {
                let (name, csum) = file.to_tuple();
                let name = name.to_str();
                let checksum = &hex::encode(csum);
                let (objpath, h) = self.append_content(checksum)?;
                let subpath = &dirpath.join(name);
                let subpath = map_path(subpath);
                self.append_content_hardlink(&objpath, h, &subpath)?;
            }
        }

        // Record if the ostree commit includes /var/tmp; if so we don't need to synthesize
        // it in `append_standard_var()`.
        if path_equivalent_for_tar(dirpath, "var/tmp") {
            self.wrote_vartmp = true;
        }

        for item in dirs {
            let (name, contents_csum, meta_csum) = item.to_tuple();
            let name = name.to_str();
            let metadata = {
                let meta_csum = &hex::encode(meta_csum);
                let meta_v = &self
                    .repo
                    .load_variant(ostree::ObjectType::DirMeta, meta_csum)?;
                self.append(ostree::ObjectType::DirMeta, meta_csum, meta_v)?;
                // Safety: We passed the correct variant type just above
                ostree::DirMetaParsed::from_variant(meta_v).unwrap()
            };
            // Special hack because tar stream for containers can't have duplicates.
            if is_root && name == SYSROOT {
                continue;
            }
            let dirtree_csum = hex::encode(contents_csum);
            let subpath = &dirpath.join(name);
            let subpath = map_path(subpath);
            self.append_dir(&subpath, &metadata)?;
            self.append_dirtree(&subpath, dirtree_csum, false, cancellable)?;
        }

        Ok(())
    }

    /// Generate e.g. `/var/tmp`.
    ///
    /// In the OSTree model we expect `/var` to start out empty, and be populated via
    /// e.g. `systemd-tmpfiles`.  But, systemd doesn't run in Docker-style containers by default.
    ///
    /// So, this function creates a few critical directories in `/var` by default.
    fn append_standard_var(&mut self, cancellable: Option<&gio::Cancellable>) -> Result<()> {
        // If the commit included /var/tmp, then it's already in the tar stream.
        if self.wrote_vartmp {
            return Ok(());
        }
        if let Some(c) = cancellable {
            c.set_error_if_cancelled()?;
        }
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_size(0);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mode(self.filter_mode(libc::S_IFDIR | 0o1777));
        self.out
            .append_data(&mut header, "var/tmp", std::io::empty())?;
        Ok(())
    }
}

/// Recursively walk an OSTree commit and generate data into a `[tar::Builder]`
/// which contains all of the metadata objects, as well as a hardlinked
/// stream that looks like a checkout.  Extended attributes are stored specially out
/// of band of tar so that they can be reliably retrieved.
fn impl_export<W: std::io::Write>(
    repo: &ostree::Repo,
    commit_checksum: &str,
    out: &mut tar::Builder<W>,
    options: ExportOptions,
) -> Result<()> {
    let writer = &mut OstreeTarWriter::new(repo, commit_checksum, out, options)?;
    writer.write_commit()?;
    Ok(())
}

/// Configuration for tar export.
#[derive(Debug, PartialEq, Eq, Default)]
pub struct ExportOptions;

/// Export an ostree commit to an (uncompressed) tar archive stream.
#[context("Exporting commit")]
pub fn export_commit(
    repo: &ostree::Repo,
    rev: &str,
    out: impl std::io::Write,
    options: Option<ExportOptions>,
) -> Result<()> {
    let commit = repo.require_rev(rev)?;
    let mut tar = tar::Builder::new(out);
    let options = options.unwrap_or_default();
    impl_export(repo, commit.as_str(), &mut tar, options)?;
    tar.finish()?;
    Ok(())
}

/// Chunked (or version 1) tar streams don't have a leading `./`.
fn path_for_tar_v1(p: &Utf8Path) -> &Utf8Path {
    debug_assert!(!p.starts_with("."));
    map_path_v1(p.strip_prefix("/").unwrap_or(p))
}

/// Implementation of chunk writing, assumes that the preliminary structure
/// has been written to the tar stream.
fn write_chunk<W: std::io::Write>(
    writer: &mut OstreeTarWriter<W>,
    chunk: chunking::ChunkMapping,
) -> Result<()> {
    for (checksum, (_size, paths)) in chunk.into_iter() {
        let (objpath, h) = writer.append_content(checksum.borrow())?;
        for path in paths.iter() {
            let path = path_for_tar_v1(path);
            let h = h.clone();
            writer.append_content_hardlink(&objpath, h, path)?;
        }
    }
    Ok(())
}

/// Output a chunk to a tar stream.
pub(crate) fn export_chunk<W: std::io::Write>(
    repo: &ostree::Repo,
    commit: &str,
    chunk: chunking::ChunkMapping,
    out: &mut tar::Builder<W>,
) -> Result<()> {
    // For chunking, we default to format version 1
    #[allow(clippy::needless_update)]
    let opts = ExportOptions;
    let writer = &mut OstreeTarWriter::new(repo, commit, out, opts)?;
    writer.write_repo_structure()?;
    write_chunk(writer, chunk)
}

/// Output the last chunk in a chunking.
#[context("Exporting final chunk")]
pub(crate) fn export_final_chunk<W: std::io::Write>(
    repo: &ostree::Repo,
    commit_checksum: &str,
    remainder: chunking::Chunk,
    out: &mut tar::Builder<W>,
) -> Result<()> {
    let options = ExportOptions;
    let writer = &mut OstreeTarWriter::new(repo, commit_checksum, out, options)?;
    // For the final chunk, output the commit object, plus all ostree metadata objects along with
    // the containing directories.
    writer.structure_only = true;
    writer.write_commit()?;
    writer.structure_only = false;
    write_chunk(writer, remainder.content)
}

/// Process an exported tar stream, and update the detached metadata.
#[allow(clippy::while_let_on_iterator)]
#[context("Replacing detached metadata")]
pub(crate) fn reinject_detached_metadata<C: IsA<gio::Cancellable>>(
    src: &mut tar::Archive<impl std::io::Read>,
    dest: &mut tar::Builder<impl std::io::Write>,
    detached_buf: Option<&[u8]>,
    cancellable: Option<&C>,
) -> Result<()> {
    let mut entries = src.entries()?;
    let mut commit_ent = None;
    // Loop through the tar stream until we find the commit object; copy all prior entries
    // such as the baseline directory structure.
    while let Some(entry) = entries.next() {
        if let Some(c) = cancellable {
            c.set_error_if_cancelled()?;
        }
        let entry = entry?;
        let header = entry.header();
        let path = entry.path()?;
        let path: &Utf8Path = (&*path).try_into()?;
        if !(header.entry_type() == tar::EntryType::Regular && path.as_str().ends_with(".commit")) {
            crate::tar::write::copy_entry(entry, dest, None)?;
        } else {
            commit_ent = Some(entry);
            break;
        }
    }
    let commit_ent = commit_ent.ok_or_else(|| anyhow!("Missing commit object"))?;
    let commit_path = commit_ent.path()?;
    let commit_path = Utf8Path::from_path(&commit_path)
        .ok_or_else(|| anyhow!("Invalid non-utf8 path {:?}", commit_path))?;
    let (checksum, objtype) = crate::tar::import::Importer::parse_metadata_entry(commit_path)?;
    assert_eq!(objtype, ostree::ObjectType::Commit); // Should have been verified above
    crate::tar::write::copy_entry(commit_ent, dest, None)?;

    // If provided, inject our new detached metadata object
    if let Some(detached_buf) = detached_buf {
        let detached_path = object_path(ostree::ObjectType::CommitMeta, &checksum);
        tar_append_default_data(dest, &detached_path, detached_buf)?;
    }

    // If the next entry is detached metadata, then drop it since we wrote a new one
    let next_ent = entries
        .next()
        .ok_or_else(|| anyhow!("Expected metadata object after commit"))??;
    let next_ent_path = next_ent.path()?;
    let next_ent_path: &Utf8Path = (&*next_ent_path).try_into()?;
    let objtype = crate::tar::import::Importer::parse_metadata_entry(next_ent_path)?.1;
    if objtype != ostree::ObjectType::CommitMeta {
        crate::tar::write::copy_entry(next_ent, dest, None)?;
    }

    // Finally, copy all remaining entries.
    while let Some(entry) = entries.next() {
        if let Some(c) = cancellable {
            c.set_error_if_cancelled()?;
        }
        crate::tar::write::copy_entry(entry?, dest, None)?;
    }

    Ok(())
}

/// Replace the detached metadata in an tar stream which is an export of an OSTree commit.
pub fn update_detached_metadata<D: std::io::Write, C: IsA<gio::Cancellable>>(
    src: impl std::io::Read,
    dest: D,
    detached_buf: Option<&[u8]>,
    cancellable: Option<&C>,
) -> Result<D> {
    let mut src = tar::Archive::new(src);
    let mut dest = tar::Builder::new(dest);
    reinject_detached_metadata(&mut src, &mut dest, detached_buf, cancellable)?;
    dest.into_inner().map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_equivalent() {
        assert!(path_equivalent_for_tar("var/tmp", "./var/tmp"));
        assert!(path_equivalent_for_tar("./var/tmp", "var/tmp"));
        assert!(path_equivalent_for_tar("/var/tmp", "var/tmp"));
        assert!(!path_equivalent_for_tar("var/tmp", "var"));
    }

    #[test]
    fn test_map_path() {
        assert_eq!(map_path("/".into()), Utf8Path::new("/"));
        assert_eq!(
            map_path("./usr/etc/blah".into()),
            Utf8Path::new("./etc/blah")
        );
        for unchanged in ["boot", "usr/bin", "usr/lib/foo"].iter().map(Utf8Path::new) {
            assert_eq!(unchanged, map_path_v1(unchanged));
        }

        assert_eq!(Utf8Path::new("etc"), map_path_v1(Utf8Path::new("usr/etc")));
        assert_eq!(
            Utf8Path::new("etc/foo"),
            map_path_v1(Utf8Path::new("usr/etc/foo"))
        );
    }

    #[test]
    fn test_denormal_symlink() {
        let normal = ["/", "/usr", "../usr/bin/blah"];
        let denormal = ["../../usr/sbin//chkconfig", "foo//bar/baz"];
        for path in normal {
            assert!(!symlink_is_denormal(path));
        }
        for path in denormal {
            assert!(symlink_is_denormal(path));
        }
    }

    #[test]
    fn test_v1_xattrs_object_path() {
        let checksum = "b8627e3ef0f255a322d2bd9610cfaaacc8f122b7f8d17c0e7e3caafa160f9fc7";
        let expected = "sysroot/ostree/repo/objects/b8/627e3ef0f255a322d2bd9610cfaaacc8f122b7f8d17c0e7e3caafa160f9fc7.file-xattrs";
        let output = v1_xattrs_object_path(checksum);
        assert_eq!(&output, expected);
    }

    #[test]
    fn test_v1_xattrs_link_object_path() {
        let checksum = "b8627e3ef0f255a322d2bd9610cfaaacc8f122b7f8d17c0e7e3caafa160f9fc7";
        let expected = "sysroot/ostree/repo/objects/b8/627e3ef0f255a322d2bd9610cfaaacc8f122b7f8d17c0e7e3caafa160f9fc7.file-xattrs-link";
        let output = v1_xattrs_link_object_path(checksum);
        assert_eq!(&output, expected);
    }
}
