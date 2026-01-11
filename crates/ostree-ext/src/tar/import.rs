//! APIs for extracting OSTree commits from container images

use crate::Result;
use anyhow::{Context, anyhow, bail, ensure};
use camino::Utf8Path;
use camino::Utf8PathBuf;
use fn_error_context::context;
use gio::glib;
use gio::prelude::*;
use glib::Variant;
use ostree::gio;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::io::prelude::*;
use tracing::{Level, event, instrument};

/// Arbitrary limit on xattrs to avoid RAM exhaustion attacks. The actual filesystem limits are often much smaller.
// See https://en.wikipedia.org/wiki/Extended_file_attributes
// For example, XFS limits to 614 KiB.
const MAX_XATTR_SIZE: u32 = 1024 * 1024;
/// Limit on metadata objects (dirtree/dirmeta); this is copied
/// from ostree-core.h.  TODO: Bind this in introspection
const MAX_METADATA_SIZE: u32 = 10 * 1024 * 1024;

/// Upper size limit for "small" regular files.
// https://stackoverflow.com/questions/258091/when-should-i-use-mmap-for-file-access
pub(crate) const SMALL_REGFILE_SIZE: usize = 127 * 1024;

// The prefix for filenames that contain content we actually look at.
pub(crate) const REPO_PREFIX: &str = "sysroot/ostree/repo/";
/// Statistics from import.
#[derive(Debug, Default)]
struct ImportStats {
    dirtree: u32,
    dirmeta: u32,
    regfile_small: u32,
    regfile_large: u32,
    symlinks: u32,
}

enum ImporterMode {
    Commit(Option<String>),
    ObjectSet(BTreeSet<String>),
}

/// Importer machine.
pub(crate) struct Importer {
    repo: ostree::Repo,
    remote: Option<String>,
    verify_text: Option<String>,
    // Cache of xattrs, keyed by their content checksum.
    xattrs: HashMap<String, glib::Variant>,
    // Reusable buffer for xattrs references. It maps a file checksum (.0)
    // to an xattrs checksum (.1) in the `xattrs` cache above.
    next_xattrs: Option<(String, String)>,

    // Reusable buffer for reads.  See also https://github.com/rust-lang/rust/issues/78485
    buf: Vec<u8>,

    stats: ImportStats,

    /// Additional state depending on whether we're importing an object set or a commit.
    data: ImporterMode,
}

/// Validate size/type of a tar header for OSTree metadata object.
fn validate_metadata_header(header: &tar::Header, desc: &str) -> Result<usize> {
    if header.entry_type() != tar::EntryType::Regular {
        return Err(anyhow!("Invalid non-regular metadata object {}", desc));
    }
    let size = header.size()?;
    let max_size = MAX_METADATA_SIZE as u64;
    if size > max_size {
        return Err(anyhow!(
            "object of size {} exceeds {} bytes",
            size,
            max_size
        ));
    }
    Ok(size as usize)
}

fn header_attrs(header: &tar::Header) -> Result<(u32, u32, u32)> {
    let uid: u32 = header.uid()?.try_into()?;
    let gid: u32 = header.gid()?.try_into()?;
    let mode: u32 = header.mode()?;
    Ok((uid, gid, mode))
}

// The C function ostree_object_type_from_string aborts on
// unknown strings, so we have a safe version here.
fn objtype_from_string(t: &str) -> Option<ostree::ObjectType> {
    Some(match t {
        "commit" => ostree::ObjectType::Commit,
        "commitmeta" => ostree::ObjectType::CommitMeta,
        "dirtree" => ostree::ObjectType::DirTree,
        "dirmeta" => ostree::ObjectType::DirMeta,
        "file" => ostree::ObjectType::File,
        _ => return None,
    })
}

/// Given a tar entry, read it all into a GVariant
fn entry_to_variant<R: std::io::Read, T: StaticVariantType>(
    mut entry: tar::Entry<R>,
    desc: &str,
) -> Result<glib::Variant> {
    let header = entry.header();
    let size = validate_metadata_header(header, desc)?;

    let mut buf: Vec<u8> = Vec::with_capacity(size);
    let n = std::io::copy(&mut entry, &mut buf)?;
    assert_eq!(n as usize, size);
    let v = glib::Bytes::from_owned(buf);
    let v = Variant::from_bytes::<T>(&v);
    Ok(v.normal_form())
}

/// Parse an object path into (parent, rest, objtype).
///
/// Normal ostree object paths look like 00/1234.commit.
/// In the tar format, we may also see 00/1234.file.xattrs.
fn parse_object_entry_path(path: &Utf8Path) -> Result<(&str, &Utf8Path, &str)> {
    // The "sharded" commit directory.
    let parentname = path
        .parent()
        .and_then(|p| p.file_name())
        .ok_or_else(|| anyhow!("Invalid path (no parent) {}", path))?;
    #[allow(clippy::needless_as_bytes)]
    if !(parentname.is_ascii() && parentname.as_bytes().len() == 2) {
        return Err(anyhow!("Invalid checksum parent {}", parentname));
    }
    let name = path
        .file_name()
        .map(Utf8Path::new)
        .ok_or_else(|| anyhow!("Invalid path (dir) {}", path))?;
    let objtype = name
        .extension()
        .ok_or_else(|| anyhow!("Invalid objpath {}", path))?;

    Ok((parentname, name, objtype))
}

fn parse_checksum(parent: &str, name: &Utf8Path) -> Result<String> {
    let checksum_rest = name
        .file_stem()
        .ok_or_else(|| anyhow!("Invalid object path part {}", name))?;
    // Also take care of the double extension on `.file.xattrs`.
    let checksum_rest = checksum_rest.trim_end_matches(".file");

    #[allow(clippy::needless_as_bytes)]
    if !(checksum_rest.is_ascii() && checksum_rest.as_bytes().len() == 62) {
        return Err(anyhow!("Invalid checksum part {}", checksum_rest));
    }
    let reassembled = format!("{parent}{checksum_rest}");
    validate_sha256(reassembled)
}

/// Parse a `.file-xattrs-link` link target into the corresponding checksum.
fn parse_xattrs_link_target(path: &Utf8Path) -> Result<String> {
    let (parent, rest, _objtype) = parse_object_entry_path(path)?;
    parse_checksum(parent, rest)
}

impl Importer {
    /// Create an importer which will import an OSTree commit object.
    pub(crate) fn new_for_commit(repo: &ostree::Repo, remote: Option<String>) -> Self {
        Self {
            repo: repo.clone(),
            remote,
            verify_text: None,
            buf: vec![0u8; 16384],
            xattrs: Default::default(),
            next_xattrs: None,
            stats: Default::default(),
            data: ImporterMode::Commit(None),
        }
    }

    /// Create an importer to write an "object set"; a chunk of objects which is
    /// usually streamed from a separate storage system, such as an OCI container image layer.
    pub(crate) fn new_for_object_set(repo: &ostree::Repo) -> Self {
        Self {
            repo: repo.clone(),
            remote: None,
            verify_text: None,
            buf: vec![0u8; 16384],
            xattrs: Default::default(),
            next_xattrs: None,
            stats: Default::default(),
            data: ImporterMode::ObjectSet(Default::default()),
        }
    }

    // Given a tar entry, filter it out if it doesn't look like an object file in
    // `/sysroot/ostree`.
    // It is an error if the filename is invalid UTF-8.  If it is valid UTF-8, return
    // an owned copy of the path.
    fn filter_entry<R: std::io::Read>(
        e: tar::Entry<R>,
    ) -> Result<Option<(tar::Entry<R>, Utf8PathBuf)>> {
        if e.header().entry_type() == tar::EntryType::Directory {
            return Ok(None);
        }
        let orig_path = e.path()?;
        let path = Utf8Path::from_path(&orig_path)
            .ok_or_else(|| anyhow!("Invalid non-utf8 path {:?}", orig_path))?;
        // Ignore the regular non-object file hardlinks we inject
        if let Ok(path) = path.strip_prefix(REPO_PREFIX) {
            // Filter out the repo config file and refs dir
            if path.file_name() == Some("config") || path.starts_with("refs") {
                return Ok(None);
            }
            let path = path.into();
            Ok(Some((e, path)))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn parse_metadata_entry(path: &Utf8Path) -> Result<(String, ostree::ObjectType)> {
        let (parentname, name, objtype) = parse_object_entry_path(path)?;
        let checksum = parse_checksum(parentname, name)?;
        let objtype = objtype_from_string(objtype)
            .ok_or_else(|| anyhow!("Invalid object type {}", objtype))?;
        Ok((checksum, objtype))
    }

    /// Import a metadata object.
    #[context("Importing metadata object")]
    fn import_metadata<R: std::io::Read>(
        &mut self,
        entry: tar::Entry<R>,
        checksum: &str,
        objtype: ostree::ObjectType,
    ) -> Result<()> {
        let v = match objtype {
            ostree::ObjectType::DirTree => {
                self.stats.dirtree += 1;
                entry_to_variant::<_, ostree::TreeVariantType>(entry, checksum)?
            }
            ostree::ObjectType::DirMeta => {
                self.stats.dirmeta += 1;
                entry_to_variant::<_, ostree::DirmetaVariantType>(entry, checksum)?
            }
            o => return Err(anyhow!("Invalid metadata object type; {:?}", o)),
        };
        // FIXME validate here that this checksum was in the set we expected.
        // https://github.com/ostreedev/ostree-rs-ext/issues/1
        let actual =
            self.repo
                .write_metadata(objtype, Some(checksum), &v, gio::Cancellable::NONE)?;
        assert_eq!(actual.to_hex(), checksum);
        Ok(())
    }

    /// Import a content object, large regular file flavour.
    #[context("Importing regfile")]
    fn import_large_regfile_object<R: std::io::Read>(
        &mut self,
        mut entry: tar::Entry<R>,
        size: usize,
        checksum: &str,
        xattrs: glib::Variant,
        cancellable: Option<&gio::Cancellable>,
    ) -> Result<()> {
        let (uid, gid, mode) = header_attrs(entry.header())?;
        let w = self.repo.write_regfile(
            Some(checksum),
            uid,
            gid,
            libc::S_IFREG | mode,
            size as u64,
            Some(&xattrs),
        )?;
        {
            let w = w.clone().upcast::<gio::OutputStream>();
            loop {
                let n = entry
                    .read(&mut self.buf[..])
                    .context("Reading large regfile")?;
                if n == 0 {
                    break;
                }
                w.write(&self.buf[0..n], cancellable)
                    .context("Writing large regfile")?;
            }
        }
        let c = w.finish(cancellable)?;
        debug_assert_eq!(c, checksum);
        self.stats.regfile_large += 1;
        Ok(())
    }

    /// Import a content object, small regular file flavour.
    #[context("Importing regfile small")]
    fn import_small_regfile_object<R: std::io::Read>(
        &mut self,
        mut entry: tar::Entry<R>,
        size: usize,
        checksum: &str,
        xattrs: glib::Variant,
        cancellable: Option<&gio::Cancellable>,
    ) -> Result<()> {
        let (uid, gid, mode) = header_attrs(entry.header())?;
        assert!(size <= SMALL_REGFILE_SIZE);
        let mut buf = vec![0u8; size];
        entry.read_exact(&mut buf[..])?;
        let c = self.repo.write_regfile_inline(
            Some(checksum),
            uid,
            gid,
            libc::S_IFREG | mode,
            Some(&xattrs),
            &buf,
            cancellable,
        )?;
        debug_assert_eq!(c.as_str(), checksum);
        self.stats.regfile_small += 1;
        Ok(())
    }

    /// Import a content object, symlink flavour.
    #[context("Importing symlink")]
    fn import_symlink_object<R: std::io::Read>(
        &mut self,
        entry: tar::Entry<R>,
        checksum: &str,
        xattrs: glib::Variant,
    ) -> Result<()> {
        let (uid, gid, _) = header_attrs(entry.header())?;
        let target = entry
            .link_name()?
            .ok_or_else(|| anyhow!("Invalid symlink"))?;
        let target = target
            .as_os_str()
            .to_str()
            .ok_or_else(|| anyhow!("Non-utf8 symlink"))?;
        let c = self.repo.write_symlink(
            Some(checksum),
            uid,
            gid,
            Some(&xattrs),
            target,
            gio::Cancellable::NONE,
        )?;
        debug_assert_eq!(c.as_str(), checksum);
        self.stats.symlinks += 1;
        Ok(())
    }

    /// Import a content object.
    #[context("Processing content object {}", checksum)]
    fn import_content_object<R: std::io::Read>(
        &mut self,
        entry: tar::Entry<R>,
        checksum: &str,
        cancellable: Option<&gio::Cancellable>,
    ) -> Result<()> {
        let size: usize = entry.header().size()?.try_into()?;

        // Pop the queued xattrs reference.
        let (file_csum, xattrs_csum) = self
            .next_xattrs
            .take()
            .ok_or_else(|| anyhow!("Missing xattrs reference"))?;
        if checksum != file_csum {
            return Err(anyhow!("Object mismatch, found xattrs for {}", file_csum));
        }

        if self
            .repo
            .has_object(ostree::ObjectType::File, checksum, cancellable)?
        {
            return Ok(());
        }

        // Retrieve xattrs content from the cache.
        let xattrs = self
            .xattrs
            .get(&xattrs_csum)
            .cloned()
            .ok_or_else(|| anyhow!("Failed to find xattrs content {}", xattrs_csum,))?;

        match entry.header().entry_type() {
            tar::EntryType::Regular => {
                if size > SMALL_REGFILE_SIZE {
                    self.import_large_regfile_object(entry, size, checksum, xattrs, cancellable)
                } else {
                    self.import_small_regfile_object(entry, size, checksum, xattrs, cancellable)
                }
            }
            tar::EntryType::Symlink => self.import_symlink_object(entry, checksum, xattrs),
            o => Err(anyhow!("Invalid tar entry of type {:?}", o)),
        }
    }

    /// Given a tar entry that looks like an object (its path is under ostree/repo/objects/),
    /// determine its type and import it.
    #[context("Importing object {}", path)]
    fn import_object<R: std::io::Read>(
        &mut self,
        entry: tar::Entry<'_, R>,
        path: &Utf8Path,
        cancellable: Option<&gio::Cancellable>,
    ) -> Result<()> {
        let (parentname, name, suffix) = parse_object_entry_path(path)?;
        let checksum = parse_checksum(parentname, name)?;

        match suffix {
            "commit" => Err(anyhow!("Found multiple commit objects")),
            "file" => {
                self.import_content_object(entry, &checksum, cancellable)?;
                // Track the objects we wrote
                match &mut self.data {
                    ImporterMode::ObjectSet(imported) => {
                        if let Some(p) = imported.replace(checksum) {
                            anyhow::bail!("Duplicate object: {}", p);
                        }
                    }
                    ImporterMode::Commit(_) => {}
                }
                Ok(())
            }
            "file-xattrs" => self.process_file_xattrs(entry, checksum),
            "file-xattrs-link" => self.process_file_xattrs_link(entry, checksum),
            "xattrs" => self.process_xattr_ref(entry, checksum),
            kind => {
                let objtype = objtype_from_string(kind)
                    .ok_or_else(|| anyhow!("Invalid object type {}", kind))?;
                match &mut self.data {
                    ImporterMode::ObjectSet(_) => {
                        anyhow::bail!(
                            "Found metadata object {}.{:?} in object set mode",
                            checksum,
                            objtype
                        );
                    }
                    ImporterMode::Commit(_) => {}
                }
                self.import_metadata(entry, &checksum, objtype)
            }
        }
    }

    /// Process a `.file-xattrs` object (v1).
    #[context("Processing file xattrs")]
    fn process_file_xattrs(
        &mut self,
        entry: tar::Entry<impl std::io::Read>,
        checksum: String,
    ) -> Result<()> {
        self.cache_xattrs_content(entry, Some(checksum))?;
        Ok(())
    }

    /// Process a `.file-xattrs-link` object (v1).
    ///
    /// This is an hardlink that contains extended attributes for a content object.
    /// When the max hardlink count is reached, this object may also be encoded as
    /// a regular file instead.
    #[context("Processing xattrs link")]
    fn process_file_xattrs_link(
        &mut self,
        entry: tar::Entry<impl std::io::Read>,
        checksum: String,
    ) -> Result<()> {
        use tar::EntryType::{Link, Regular};
        if let Some(prev) = &self.next_xattrs {
            bail!(
                "Found previous dangling xattrs for file object '{}'",
                prev.0
            );
        }

        // Extract the xattrs checksum from the link target or from the content (v1).
        // Later, it will be used as the key for a lookup into the `self.xattrs` cache.
        let xattrs_checksum = match entry.header().entry_type() {
            Link => {
                let link_target = entry
                    .link_name()?
                    .ok_or_else(|| anyhow!("No xattrs link content for {}", checksum))?;
                let xattr_target = Utf8Path::from_path(&link_target)
                    .ok_or_else(|| anyhow!("Invalid non-UTF8 xattrs link {}", checksum))?;
                parse_xattrs_link_target(xattr_target)?
            }
            Regular => self.cache_xattrs_content(entry, None)?,
            x => bail!("Unexpected xattrs type '{:?}' found for {}", x, checksum),
        };

        // Now xattrs are properly cached for the next content object in the stream,
        // which should match `checksum`.
        self.next_xattrs = Some((checksum, xattrs_checksum));

        Ok(())
    }

    /// Process a `.file.xattrs` entry (v0).
    ///
    /// This is an hardlink that contains extended attributes for a content object.
    #[context("Processing xattrs reference")]
    fn process_xattr_ref<R: std::io::Read>(
        &mut self,
        entry: tar::Entry<R>,
        target: String,
    ) -> Result<()> {
        if let Some(prev) = &self.next_xattrs {
            bail!(
                "Found previous dangling xattrs for file object '{}'",
                prev.0
            );
        }

        // Parse the xattrs checksum from the link target (v0).
        // Later, it will be used as the key for a lookup into the `self.xattrs` cache.
        let header = entry.header();
        if header.entry_type() != tar::EntryType::Link {
            bail!("Non-hardlink xattrs reference found for {}", target);
        }
        let xattr_target = entry
            .link_name()?
            .ok_or_else(|| anyhow!("No xattrs link content for {}", target))?;
        let xattr_target = Utf8Path::from_path(&xattr_target)
            .ok_or_else(|| anyhow!("Invalid non-UTF8 xattrs link {}", target))?;
        let xattr_target = xattr_target
            .file_name()
            .ok_or_else(|| anyhow!("Invalid xattrs link {}", target))?
            .to_string();
        let xattrs_checksum = validate_sha256(xattr_target)?;

        // Now xattrs are properly cached for the next content object in the stream,
        // which should match `checksum`.
        self.next_xattrs = Some((target, xattrs_checksum));

        Ok(())
    }

    /// Process a special /xattrs/ entry, with checksum of xattrs content (v0).
    fn process_split_xattrs_content<R: std::io::Read>(
        &mut self,
        entry: tar::Entry<R>,
    ) -> Result<()> {
        let checksum = {
            let path = entry.path()?;
            let name = path
                .file_name()
                .ok_or_else(|| anyhow!("Invalid xattrs dir: {:?}", path))?;
            let name = name
                .to_str()
                .ok_or_else(|| anyhow!("Invalid non-UTF8 xattrs name: {:?}", name))?;
            validate_sha256(name.to_string())?
        };
        self.cache_xattrs_content(entry, Some(checksum))?;
        Ok(())
    }

    /// Read an xattrs entry and cache its content, optionally validating its checksum.
    ///
    /// This returns the computed checksum for the successfully cached content.
    fn cache_xattrs_content<R: std::io::Read>(
        &mut self,
        mut entry: tar::Entry<R>,
        expected_checksum: Option<String>,
    ) -> Result<String> {
        let header = entry.header();
        if header.entry_type() != tar::EntryType::Regular {
            return Err(anyhow!(
                "Invalid xattr entry of type {:?}",
                header.entry_type()
            ));
        }
        let n = header.size()?;
        if n > MAX_XATTR_SIZE as u64 {
            return Err(anyhow!("Invalid xattr size {}", n));
        }

        let mut contents = vec![0u8; n as usize];
        entry.read_exact(contents.as_mut_slice())?;
        let data: glib::Bytes = contents.as_slice().into();
        let xattrs_checksum = {
            let digest = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), &data)?;
            hex::encode(digest)
        };
        if let Some(input) = expected_checksum {
            ensure!(
                input == xattrs_checksum,
                "Checksum mismatch, expected '{}' but computed '{}'",
                input,
                xattrs_checksum
            );
        }

        let contents = Variant::from_bytes::<&[(&[u8], &[u8])]>(&data);
        self.xattrs.insert(xattrs_checksum.clone(), contents);
        Ok(xattrs_checksum)
    }

    fn import_objects_impl<'a>(
        &mut self,
        ents: impl Iterator<Item = Result<(tar::Entry<'a, impl Read + Send + Unpin + 'a>, Utf8PathBuf)>>,
        cancellable: Option<&gio::Cancellable>,
    ) -> Result<()> {
        for entry in ents {
            let (entry, path) = entry?;
            if let Ok(p) = path.strip_prefix("objects/") {
                self.import_object(entry, p, cancellable)?;
            } else if path.strip_prefix("xattrs/").is_ok() {
                self.process_split_xattrs_content(entry)?;
            }
        }
        Ok(())
    }

    #[context("Importing objects")]
    pub(crate) fn import_objects(
        &mut self,
        archive: &mut tar::Archive<impl Read + Send + Unpin>,
        cancellable: Option<&gio::Cancellable>,
    ) -> Result<()> {
        let ents = archive.entries()?.filter_map(|e| match e {
            Ok(e) => Self::filter_entry(e).transpose(),
            Err(e) => Some(Err(anyhow::Error::msg(e))),
        });
        self.import_objects_impl(ents, cancellable)
    }

    #[context("Importing commit")]
    pub(crate) fn import_commit(
        &mut self,
        archive: &mut tar::Archive<impl Read + Send + Unpin>,
        cancellable: Option<&gio::Cancellable>,
    ) -> Result<()> {
        // This can only be invoked once
        assert!(matches!(self.data, ImporterMode::Commit(None)));
        // Create an iterator that skips over directories; we just care about the file names.
        let mut ents = archive.entries()?.filter_map(|e| match e {
            Ok(e) => Self::filter_entry(e).transpose(),
            Err(e) => Some(Err(anyhow::Error::msg(e))),
        });
        // Read the commit object.
        let (commit_ent, commit_path) = ents
            .next()
            .ok_or_else(|| anyhow!("Commit object not found"))??;

        if commit_ent.header().entry_type() != tar::EntryType::Regular {
            return Err(anyhow!(
                "Expected regular file for commit object, not {:?}",
                commit_ent.header().entry_type()
            ));
        }
        let (checksum, objtype) = Self::parse_metadata_entry(&commit_path)?;
        if objtype != ostree::ObjectType::Commit {
            return Err(anyhow!("Expected commit object, not {:?}", objtype));
        }
        let commit = entry_to_variant::<_, ostree::CommitVariantType>(commit_ent, &checksum)?;

        let (next_ent, nextent_path) = ents
            .next()
            .ok_or_else(|| anyhow!("End of stream after commit object"))??;
        let (next_checksum, next_objtype) = Self::parse_metadata_entry(&nextent_path)?;

        if let Some(remote) = self.remote.as_deref() {
            if next_objtype != ostree::ObjectType::CommitMeta {
                return Err(anyhow!(
                    "Using remote {} for verification; Expected commitmeta object, not {:?}",
                    remote,
                    next_objtype
                ));
            }
            if next_checksum != checksum {
                return Err(anyhow!(
                    "Expected commitmeta checksum {}, found {}",
                    checksum,
                    next_checksum
                ));
            }
            let commitmeta = entry_to_variant::<_, std::collections::HashMap<String, glib::Variant>>(
                next_ent,
                &next_checksum,
            )?;

            // Now that we have both the commit and detached metadata in memory, verify that
            // the signatures in the detached metadata correctly sign the commit.
            self.verify_text = Some(
                self.repo
                    .signature_verify_commit_data(
                        remote,
                        &commit.data_as_bytes(),
                        &commitmeta.data_as_bytes(),
                        ostree::RepoVerifyFlags::empty(),
                    )
                    .context("Verifying ostree commit in tar stream")?
                    .into(),
            );

            self.repo.mark_commit_partial(&checksum, true)?;

            // Write the commit object, which also verifies its checksum.
            let actual_checksum =
                self.repo
                    .write_metadata(objtype, Some(&checksum), &commit, cancellable)?;
            assert_eq!(actual_checksum.to_hex(), checksum);
            event!(Level::DEBUG, "Imported {}.commit", checksum);

            // Finally, write the detached metadata.
            self.repo
                .write_commit_detached_metadata(&checksum, Some(&commitmeta), cancellable)?;
        } else {
            self.repo.mark_commit_partial(&checksum, true)?;

            // We're not doing any validation of the commit, so go ahead and write it.
            let actual_checksum =
                self.repo
                    .write_metadata(objtype, Some(&checksum), &commit, cancellable)?;
            assert_eq!(actual_checksum.to_hex(), checksum);
            event!(Level::DEBUG, "Imported {}.commit", checksum);

            // Write the next object, whether it's commit metadata or not.
            let (meta_checksum, meta_objtype) = Self::parse_metadata_entry(&nextent_path)?;
            match meta_objtype {
                ostree::ObjectType::CommitMeta => {
                    let commitmeta = entry_to_variant::<
                        _,
                        std::collections::HashMap<String, glib::Variant>,
                    >(next_ent, &meta_checksum)?;
                    self.repo.write_commit_detached_metadata(
                        &checksum,
                        Some(&commitmeta),
                        gio::Cancellable::NONE,
                    )?;
                }
                _ => {
                    self.import_object(next_ent, &nextent_path, cancellable)?;
                }
            }
        }
        match &mut self.data {
            ImporterMode::Commit(c) => {
                c.replace(checksum);
            }
            ImporterMode::ObjectSet(_) => unreachable!(),
        }

        self.import_objects_impl(ents, cancellable)?;

        Ok(())
    }

    pub(crate) fn finish_import_commit(self) -> (String, Option<String>) {
        tracing::debug!("Import stats: {:?}", self.stats);
        match self.data {
            ImporterMode::Commit(c) => (c.unwrap(), self.verify_text),
            ImporterMode::ObjectSet(_) => unreachable!(),
        }
    }

    pub(crate) fn default_dirmeta() -> glib::Variant {
        let finfo = gio::FileInfo::new();
        finfo.set_attribute_uint32("unix::uid", 0);
        finfo.set_attribute_uint32("unix::gid", 0);
        finfo.set_attribute_uint32("unix::mode", libc::S_IFDIR | 0o755);
        // SAFETY: TODO: This is not a nullable return, fix it in ostree
        ostree::create_directory_metadata(&finfo, None)
    }

    pub(crate) fn finish_import_object_set(self) -> Result<String> {
        let objset = match self.data {
            ImporterMode::Commit(_) => unreachable!(),
            ImporterMode::ObjectSet(s) => s,
        };
        tracing::debug!("Imported {} content objects", objset.len());
        let mtree = ostree::MutableTree::new();
        for checksum in objset.into_iter() {
            mtree.replace_file(&checksum, &checksum)?;
        }
        let dirmeta = self.repo.write_metadata(
            ostree::ObjectType::DirMeta,
            None,
            &Self::default_dirmeta(),
            gio::Cancellable::NONE,
        )?;
        mtree.set_metadata_checksum(&dirmeta.to_hex());
        let tree = self.repo.write_mtree(&mtree, gio::Cancellable::NONE)?;
        let commit = self.repo.write_commit_with_time(
            None,
            None,
            None,
            None,
            tree.downcast_ref().unwrap(),
            0,
            gio::Cancellable::NONE,
        )?;
        Ok(commit.to_string())
    }
}

fn validate_sha256(input: String) -> Result<String> {
    if input.len() != 64 {
        return Err(anyhow!("Invalid sha256 checksum (len) {}", input));
    }
    if !input.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
        return Err(anyhow!("Invalid sha256 checksum {}", input));
    }
    Ok(input)
}

/// Configuration for tar import.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct TarImportOptions {
    /// Name of the remote to use for signature verification.
    pub remote: Option<String>,
}

/// Read the contents of a tarball and import the ostree commit inside.
/// Returns the sha256 of the imported commit.
#[instrument(level = "debug", skip_all)]
pub async fn import_tar(
    repo: &ostree::Repo,
    src: impl tokio::io::AsyncRead + Send + Unpin + 'static,
    options: Option<TarImportOptions>,
) -> Result<String> {
    let options = options.unwrap_or_default();
    let src = tokio_util::io::SyncIoBridge::new(src);
    let repo = repo.clone();
    // The tar code we use today is blocking, so we spawn a thread.
    crate::tokio_util::spawn_blocking_cancellable_flatten(move |cancellable| {
        let mut archive = tar::Archive::new(src);
        let txn = repo.auto_transaction(Some(cancellable))?;
        let mut importer = Importer::new_for_commit(&repo, options.remote);
        importer.import_commit(&mut archive, Some(cancellable))?;
        let (checksum, _) = importer.finish_import_commit();
        txn.commit(Some(cancellable))?;
        repo.mark_commit_partial(&checksum, false)?;
        Ok::<_, anyhow::Error>(checksum)
    })
    .await
}

/// Read the contents of a tarball and import the content objects inside.
/// Generates a synthetic commit object referencing them.
#[instrument(level = "debug", skip_all)]
pub async fn import_tar_objects(
    repo: &ostree::Repo,
    src: impl tokio::io::AsyncRead + Send + Unpin + 'static,
) -> Result<String> {
    let src = tokio_util::io::SyncIoBridge::new(src);
    let repo = repo.clone();
    // The tar code we use today is blocking, so we spawn a thread.
    crate::tokio_util::spawn_blocking_cancellable_flatten(move |cancellable| {
        let mut archive = tar::Archive::new(src);
        let mut importer = Importer::new_for_object_set(&repo);
        let txn = repo.auto_transaction(Some(cancellable))?;
        importer.import_objects(&mut archive, Some(cancellable))?;
        let r = importer.finish_import_object_set()?;
        txn.commit(Some(cancellable))?;
        Ok::<_, anyhow::Error>(r)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_metadata_entry() {
        let c = "a8/6d80a3e9ff77c2e3144c787b7769b300f91ffd770221aac27bab854960b964";
        let invalid = format!("{c}.blah");
        for &k in &["", "42", c, &invalid] {
            assert!(Importer::parse_metadata_entry(k.into()).is_err())
        }
        let valid = format!("{c}.commit");
        let r = Importer::parse_metadata_entry(valid.as_str().into()).unwrap();
        assert_eq!(r.0, c.replace('/', ""));
        assert_eq!(r.1, ostree::ObjectType::Commit);
    }

    #[test]
    fn test_validate_sha256() {
        let err_cases = &[
            "a86d80a3e9ff77c2e3144c787b7769b300f91ffd770221aac27bab854960b9644",
            "a86d80a3E9ff77c2e3144c787b7769b300f91ffd770221aac27bab854960b964",
        ];
        for input in err_cases {
            validate_sha256(input.to_string()).unwrap_err();
        }

        validate_sha256(
            "a86d80a3e9ff77c2e3144c787b7769b300f91ffd770221aac27bab854960b964".to_string(),
        )
        .unwrap();
    }

    #[test]
    fn test_parse_object_entry_path() {
        let path = "sysroot/ostree/repo/objects/b8/627e3ef0f255a322d2bd9610cfaaacc8f122b7f8d17c0e7e3caafa160f9fc7.file.xattrs";
        let input = Utf8PathBuf::from(path);
        let expected_parent = "b8";
        let expected_rest =
            "627e3ef0f255a322d2bd9610cfaaacc8f122b7f8d17c0e7e3caafa160f9fc7.file.xattrs";
        let expected_objtype = "xattrs";
        let output = parse_object_entry_path(&input).unwrap();
        assert_eq!(output.0, expected_parent);
        assert_eq!(output.1, expected_rest);
        assert_eq!(output.2, expected_objtype);
    }

    #[test]
    fn test_parse_checksum() {
        let parent = "b8";
        let name = "627e3ef0f255a322d2bd9610cfaaacc8f122b7f8d17c0e7e3caafa160f9fc7.file.xattrs";
        let expected = "b8627e3ef0f255a322d2bd9610cfaaacc8f122b7f8d17c0e7e3caafa160f9fc7";
        let output = parse_checksum(parent, &Utf8PathBuf::from(name)).unwrap();
        assert_eq!(output, expected);
    }

    #[test]
    fn test_parse_xattrs_link_target() {
        let err_cases = &[
            "",
            "b8627e3ef0f255a322d2bd9610cfaaacc8f122b7f8d17c0e7e3caafa160f9fc7.file-xattrs",
            "../b8/62.file-xattrs",
        ];
        for input in err_cases {
            parse_xattrs_link_target(Utf8Path::new(input)).unwrap_err();
        }

        let ok_cases = &[
            "../b8/627e3ef0f255a322d2bd9610cfaaacc8f122b7f8d17c0e7e3caafa160f9fc7.file-xattrs",
            "sysroot/ostree/repo/objects/b8/627e3ef0f255a322d2bd9610cfaaacc8f122b7f8d17c0e7e3caafa160f9fc7.file-xattrs",
        ];
        let expected = "b8627e3ef0f255a322d2bd9610cfaaacc8f122b7f8d17c0e7e3caafa160f9fc7";
        for input in ok_cases {
            let output = parse_xattrs_link_target(Utf8Path::new(input)).unwrap();
            assert_eq!(output, expected);
        }
    }
}
