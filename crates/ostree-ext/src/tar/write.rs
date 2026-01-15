//! APIs to write a tarball stream into an OSTree commit.
//!
//! This functionality already exists in libostree mostly,
//! this API adds a higher level, more ergonomic Rust frontend
//! to it.
//!
//! In the future, this may also evolve into parsing the tar
//! stream in Rust, not in C.

use crate::Result;
use crate::generic_decompress::Decompressor;
use anyhow::{Context, anyhow};
use camino::{Utf8Component, Utf8Path, Utf8PathBuf};

use cap_std::io_lifetimes;
use cap_std_ext::cap_std::fs::Dir;
use cap_std_ext::cmdext::CapStdExtCommandExt;
use cap_std_ext::{cap_std, cap_tempfile};
use containers_image_proxy::oci_spec::image as oci_image;
use fn_error_context::context;
use ostree::gio;
use ostree::prelude::FileExt;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::io::{BufWriter, Seek, Write};
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tracing::instrument;

// Exclude things in https://www.freedesktop.org/wiki/Software/systemd/APIFileSystems/
// from being placed in the rootfs.
const EXCLUDED_TOPLEVEL_PATHS: &[&str] = &["run", "tmp", "proc", "sys", "dev"];

/// Copy a tar entry to a new tar archive, optionally using a different filesystem path.
#[context("Copying entry")]
pub(crate) fn copy_entry(
    mut entry: tar::Entry<impl std::io::Read>,
    dest: &mut tar::Builder<impl std::io::Write>,
    path: Option<&Path>,
) -> Result<()> {
    // Make copies of both the header and path, since that's required for the append APIs
    let path = if let Some(path) = path {
        path.to_owned()
    } else {
        (*entry.path()?).to_owned()
    };
    let mut header = entry.header().clone();
    if let Some(headers) = entry.pax_extensions()? {
        let extensions = headers
            .map(|ext| {
                let ext = ext?;
                Ok((ext.key()?, ext.value_bytes()))
            })
            .collect::<Result<Vec<_>>>()?;
        dest.append_pax_extensions(extensions.as_slice().iter().copied())?;
    }

    // Need to use the entry.link_name() not the header.link_name()
    // api as the header api does not handle long paths:
    // https://github.com/alexcrichton/tar-rs/issues/192
    match entry.header().entry_type() {
        tar::EntryType::Symlink => {
            let target = entry.link_name()?.ok_or_else(|| anyhow!("Invalid link"))?;
            // Sanity check UTF-8 here too.
            let target: &Utf8Path = (&*target).try_into()?;
            dest.append_link(&mut header, path, target)
        }
        tar::EntryType::Link => {
            let target = entry.link_name()?.ok_or_else(|| anyhow!("Invalid link"))?;
            let target: &Utf8Path = (&*target).try_into()?;
            // We need to also normalize the target in order to handle hardlinked files in /etc
            // where we remap /etc to /usr/etc.
            let target = remap_etc_path(target);
            dest.append_link(&mut header, path, &*target)
        }
        _ => dest.append_data(&mut header, path, entry),
    }
    .map_err(Into::into)
}

/// Configuration for tar layer commits.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct WriteTarOptions {
    /// Base ostree commit hash
    pub base: Option<String>,
    /// Enable SELinux labeling from the base commit
    /// Requires the `base` option.
    pub selinux: bool,
    /// Allow content not in /usr; this should be paired with ostree rootfs.transient = true
    pub allow_nonusr: bool,
    /// If true, do not move content in /var to /usr/share/factory/var.  This should be used
    /// with ostree v2024.3 or newer.
    pub retain_var: bool,
}

/// The result of writing a tar stream.
///
/// This includes some basic data on the number of files that were filtered
/// out because they were not in `/usr`.
#[derive(Debug, Default)]
pub struct WriteTarResult {
    /// The resulting OSTree commit SHA-256.
    pub commit: String,
    /// Number of paths in a prefix (e.g. `/var` or `/boot`) which were discarded.
    pub filtered: BTreeMap<String, u32>,
}

// Copy of logic from https://github.com/ostreedev/ostree/pull/2447
// to avoid waiting for backport + releases
fn sepolicy_from_base(repo: &ostree::Repo, base: &str) -> Result<tempfile::TempDir> {
    let cancellable = gio::Cancellable::NONE;
    let policypath = "usr/etc/selinux";
    let tempdir = tempfile::tempdir()?;
    let (root, _) = repo.read_commit(base, cancellable)?;
    let policyroot = root.resolve_relative_path(policypath);
    if policyroot.query_exists(cancellable) {
        let policydest = tempdir.path().join(policypath);
        std::fs::create_dir_all(policydest.parent().unwrap())?;
        let opts = ostree::RepoCheckoutAtOptions {
            mode: ostree::RepoCheckoutMode::User,
            subpath: Some(Path::new(policypath).to_owned()),
            ..Default::default()
        };
        repo.checkout_at(Some(&opts), ostree::AT_FDCWD, policydest, base, cancellable)?;
    }
    Ok(tempdir)
}

#[derive(Debug, PartialEq, Eq)]
enum NormalizedPathResult<'a> {
    Filtered(&'a str),
    Normal(Utf8PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct TarImportConfig {
    allow_nonusr: bool,
    remap_factory_var: bool,
}

// If a path starts with /etc or ./etc or etc, remap it to be usr/etc.
fn remap_etc_path(path: &Utf8Path) -> Cow<'_, Utf8Path> {
    let mut components = path.components();
    let Some(prefix) = components.next() else {
        return Cow::Borrowed(path);
    };
    let (prefix, first) = if matches!(prefix, Utf8Component::CurDir | Utf8Component::RootDir) {
        let Some(next) = components.next() else {
            return Cow::Borrowed(path);
        };
        (Some(prefix), next)
    } else {
        (None, prefix)
    };
    if first.as_str() == "etc" {
        let usr = Utf8Component::Normal("usr");
        Cow::Owned(
            prefix
                .into_iter()
                .chain([usr, first])
                .chain(components)
                .collect(),
        )
    } else {
        Cow::Borrowed(path)
    }
}

fn normalize_validate_path<'a>(
    path: &'a Utf8Path,
    config: &'_ TarImportConfig,
) -> Result<NormalizedPathResult<'a>> {
    // This converts e.g. `foo//bar/./baz` into `foo/bar/baz`.
    let mut components = path
        .components()
        .map(|part| {
            match part {
                // Convert absolute paths to relative
                camino::Utf8Component::RootDir => Ok(camino::Utf8Component::CurDir),
                // Allow ./ and regular parts
                camino::Utf8Component::Normal(_) | camino::Utf8Component::CurDir => Ok(part),
                // Barf on Windows paths as well as Unix path uplinks `..`
                _ => Err(anyhow!("Invalid path: {}", path)),
            }
        })
        .peekable();
    let mut ret = Utf8PathBuf::new();
    // Insert a leading `./` if not present
    if let Some(Ok(camino::Utf8Component::Normal(_))) = components.peek() {
        ret.push(camino::Utf8Component::CurDir);
    }
    let mut found_first = false;
    let mut excluded = false;
    for part in components {
        let part = part?;
        if excluded {
            return Ok(NormalizedPathResult::Filtered(part.as_str()));
        }
        if !found_first {
            if let Utf8Component::Normal(part) = part {
                found_first = true;
                match part {
                    // We expect all the OS content to live in usr in general
                    "usr" => ret.push(part),
                    // ostree has special support for /etc
                    "etc" => {
                        ret.push("usr/etc");
                    }
                    "var" => {
                        // Content in /var will get copied by a systemd tmpfiles.d unit
                        if config.remap_factory_var {
                            ret.push("usr/share/factory/var");
                        } else {
                            ret.push(part)
                        }
                    }
                    o if EXCLUDED_TOPLEVEL_PATHS.contains(&o) => {
                        // We don't want to actually drop the toplevel, but mark
                        // *children* of it as excluded.
                        excluded = true;
                        ret.push(part)
                    }
                    _ if config.allow_nonusr => ret.push(part),
                    _ => {
                        return Ok(NormalizedPathResult::Filtered(part));
                    }
                }
            } else {
                ret.push(part);
            }
        } else {
            ret.push(part);
        }
    }

    Ok(NormalizedPathResult::Normal(ret))
}

/// Perform various filtering on imported tar archives.
///  - Move /etc to /usr/etc
///  - Entirely drop files not in /usr
///
/// This also acts as a Rust "pre-parser" of the tar archive, hopefully
/// catching anything corrupt that might be exploitable from the C libarchive side.
/// Remember that we're parsing this while we're downloading it, and in order
/// to verify integrity we rely on the total sha256 of the blob, so all content
/// written before then must be considered untrusted.
pub(crate) fn filter_tar(
    src: impl std::io::Read,
    dest: impl std::io::Write,
    config: &TarImportConfig,
    tmpdir: &Dir,
) -> Result<BTreeMap<String, u32>> {
    let src = std::io::BufReader::new(src);
    let mut src = tar::Archive::new(src);
    let dest = BufWriter::new(dest);
    let mut dest = tar::Builder::new(dest);
    let mut filtered = BTreeMap::new();

    let ents = src.entries()?;

    tracing::debug!("Filtering tar; config={config:?}");

    // Lookaside data for dealing with hardlinked files into /sysroot; see below.
    let mut changed_sysroot_objects = HashMap::new();
    let mut new_sysroot_link_targets = HashMap::<Utf8PathBuf, Utf8PathBuf>::new();

    for entry in ents {
        let mut entry = entry?;
        let header = entry.header();
        let path = entry.path()?;
        let path: &Utf8Path = (&*path).try_into()?;
        // Force all paths to relative
        let path = path.strip_prefix("/").unwrap_or(path);

        let is_modified = header.mtime().unwrap_or_default() > 0;
        let is_regular = header.entry_type() == tar::EntryType::Regular;
        if path.strip_prefix(crate::tar::REPO_PREFIX).is_ok() {
            // If it's a modified file in /sysroot, it may be a target for future hardlinks.
            // In that case, we copy the data off to a temporary file.  Then the first hardlink
            // to it becomes instead the real file, and any *further* hardlinks refer to that
            // file instead.
            if is_modified && is_regular {
                tracing::debug!("Processing modified sysroot file {path}");
                // Create an O_TMPFILE (anonymous file) to use as a temporary store for the file data
                let mut tmpf = cap_tempfile::TempFile::new_anonymous(tmpdir)
                    .map(BufWriter::new)
                    .context("Creating tmpfile")?;
                let path = path.to_owned();
                let header = header.clone();
                std::io::copy(&mut entry, &mut tmpf)
                    .map_err(anyhow::Error::msg)
                    .context("Copying")?;
                let mut tmpf = tmpf.into_inner()?;
                tmpf.seek(std::io::SeekFrom::Start(0))?;
                // Cache this data, indexed by the file path
                changed_sysroot_objects.insert(path, (header, tmpf));
                continue;
            }
        } else if header.entry_type() == tar::EntryType::Link && is_modified {
            let target = header
                .link_name()?
                .ok_or_else(|| anyhow!("Invalid empty hardlink"))?;
            let target: &Utf8Path = (&*target).try_into()?;
            // Canonicalize to a relative path
            let target = path.strip_prefix("/").unwrap_or(target);
            // If this is a hardlink into /sysroot...
            if target.strip_prefix(crate::tar::REPO_PREFIX).is_ok() {
                // And we found a previously processed modified file there
                if let Some((mut header, data)) = changed_sysroot_objects.remove(target) {
                    tracing::debug!("Making {path} canonical for sysroot link {target}");
                    // Make *this* entry the canonical one, consuming the temporary file data
                    dest.append_data(&mut header, path, data)?;
                    // And cache this file path as the new link target
                    new_sysroot_link_targets.insert(target.to_owned(), path.to_owned());
                } else if let Some(real_target) = new_sysroot_link_targets.get(target) {
                    tracing::debug!("Relinking {path} to {real_target}");
                    // We found a 2nd (or 3rd, etc.) link into /sysroot; rewrite the link
                    // target to be the first file outside of /sysroot we found.
                    let mut header = header.clone();
                    dest.append_link(&mut header, path, real_target)?;
                } else {
                    tracing::debug!("Found unhandled modified link from {path} to {target}");
                }
                continue;
            }
        }

        let normalized = match normalize_validate_path(path, config)? {
            NormalizedPathResult::Filtered(path) => {
                tracing::trace!("Filtered: {path}");
                if let Some(v) = filtered.get_mut(path) {
                    *v += 1;
                } else {
                    filtered.insert(path.to_string(), 1);
                }
                continue;
            }
            NormalizedPathResult::Normal(path) => path,
        };

        copy_entry(entry, &mut dest, Some(normalized.as_std_path()))?;
    }
    dest.into_inner()?.flush()?;
    Ok(filtered)
}

/// Asynchronous wrapper for filter_tar()
#[context("Filtering tar stream")]
async fn filter_tar_async(
    src: impl AsyncRead + Send + 'static,
    media_type: oci_image::MediaType,
    mut dest: impl AsyncWrite + Send + Unpin,
    config: &TarImportConfig,
    repo_tmpdir: Dir,
) -> Result<BTreeMap<String, u32>> {
    let (tx_buf, mut rx_buf) = tokio::io::duplex(8192);
    // The source must be moved to the heap so we know it is stable for passing to the worker thread
    let src = Box::pin(src);
    let config = config.clone();
    let tar_transformer = crate::tokio_util::spawn_blocking_flatten(move || {
        let src = tokio_util::io::SyncIoBridge::new(src);
        let mut src = Decompressor::new(&media_type, src)?;
        let dest = tokio_util::io::SyncIoBridge::new(tx_buf);

        let r = filter_tar(&mut src, dest, &config, &repo_tmpdir);

        src.finish()?;

        Ok(r)
    });
    let copier = tokio::io::copy(&mut rx_buf, &mut dest);
    let (r, v) = tokio::join!(tar_transformer, copier);
    let _v: u64 = v?;
    r?
}

/// Write the contents of a tarball as an ostree commit.
#[allow(unsafe_code)] // For raw fd bits
#[instrument(level = "debug", skip_all)]
pub async fn write_tar(
    repo: &ostree::Repo,
    src: impl tokio::io::AsyncRead + Send + Unpin + 'static,
    media_type: oci_image::MediaType,
    refname: &str,
    options: Option<WriteTarOptions>,
) -> Result<WriteTarResult> {
    let repo = repo.clone();
    let options = options.unwrap_or_default();
    let sepolicy = if options.selinux {
        if let Some(base) = options.base {
            Some(sepolicy_from_base(&repo, &base).context("tar: Preparing sepolicy")?)
        } else {
            None
        }
    } else {
        None
    };
    let mut c = std::process::Command::new("ostree");
    // Unset G_MESSAGES_DEBUG to prevent GLib debug messages from corrupting stdout.
    // When G_MESSAGES_DEBUG is set (e.g., "all"), GLib and OSTree emit debug messages
    // to stdout instead of stderr, which corrupts the commit hash we parse from
    // the subprocess output. This causes derived layer content to be silently lost
    // during container imports.
    c.env_remove("G_MESSAGES_DEBUG");
    let repofd = repo.dfd_as_file()?;
    let repofd: Arc<io_lifetimes::OwnedFd> = Arc::new(repofd.into());
    {
        let c = c
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .args(["commit"]);
        c.take_fd_n(repofd.clone(), 3);
        c.arg("--repo=/proc/self/fd/3");
        if let Some(sepolicy) = sepolicy.as_ref() {
            c.arg("--selinux-policy");
            c.arg(sepolicy.path());
        }
        c.arg(format!(
            "--add-metadata-string=ostree.importer.version={}",
            env!("CARGO_PKG_VERSION")
        ));
        c.args([
            "--no-bindings",
            "--tar-autocreate-parents",
            "--tree=tar=/proc/self/fd/0",
            "--branch",
            refname,
        ]);
    }
    let mut c = tokio::process::Command::from(c);
    c.kill_on_drop(true);
    let mut r = c.spawn()?;
    tracing::trace!("Spawned ostree child process");
    // Safety: We passed piped() for all of these
    let child_stdin = r.stdin.take().unwrap();
    let mut child_stdout = r.stdout.take().unwrap();
    let mut child_stderr = r.stderr.take().unwrap();
    // Copy the filtered tar stream to child stdin
    let import_config = TarImportConfig {
        allow_nonusr: options.allow_nonusr,
        remap_factory_var: !options.retain_var,
    };
    let repo_tmpdir = Dir::reopen_dir(&repo.dfd_borrow())?
        .open_dir("tmp")
        .context("Getting repo tmpdir")?;
    let filtered_result =
        filter_tar_async(src, media_type, child_stdin, &import_config, repo_tmpdir);
    let output_copier = async move {
        // Gather stdout/stderr to buffers
        let mut child_stdout_buf = String::new();
        let mut child_stderr_buf = String::new();
        let (_a, _b) = tokio::try_join!(
            child_stdout.read_to_string(&mut child_stdout_buf),
            child_stderr.read_to_string(&mut child_stderr_buf)
        )?;
        Ok::<_, anyhow::Error>((child_stdout_buf, child_stderr_buf))
    };

    // We must convert the child exit status here to an error to
    // ensure we break out of the try_join! below.
    let status = async move {
        let status = r.wait().await?;
        if !status.success() {
            return Err(anyhow!("Failed to commit tar: {:?}", status));
        }
        anyhow::Ok(())
    };
    tracing::debug!("Waiting on child process");
    let (filtered_result, child_stdout) =
        match tokio::try_join!(status, filtered_result).context("Processing tar") {
            Ok(((), filtered_result)) => {
                let (child_stdout, _) = output_copier.await.context("Copying child output")?;
                (filtered_result, child_stdout)
            }
            Err(e) => {
                if let Ok((_, child_stderr)) = output_copier.await {
                    // Avoid trailing newline
                    let child_stderr = child_stderr.trim();
                    Err(e.context(child_stderr.to_string()))?
                } else {
                    Err(e)?
                }
            }
        };
    drop(sepolicy);

    tracing::trace!("tar written successfully");
    // TODO: trim string in place
    let s = child_stdout.trim();
    Ok(WriteTarResult {
        commit: s.to_string(),
        filtered: filtered_result,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_remap_etc() {
        // These shouldn't change. Test etcc to verify we're not doing string matching.
        let unchanged = ["", "foo", "/etcc/foo", "../etc/baz"];
        for x in unchanged {
            similar_asserts::assert_eq!(x, remap_etc_path(x.into()).as_str());
        }
        // Verify all 3 forms of "./etc", "/etc" and "etc", and also test usage of
        // ".."" (should be unchanged) and "//" (will be normalized).
        for (p, expected) in [
            ("/etc/foo/../bar/baz", "/usr/etc/foo/../bar/baz"),
            ("etc/foo//bar", "usr/etc/foo/bar"),
            ("./etc/foo", "./usr/etc/foo"),
            ("etc", "usr/etc"),
        ] {
            similar_asserts::assert_eq!(remap_etc_path(p.into()).as_str(), expected);
        }
    }

    #[test]
    fn test_normalize_path() {
        let imp_default = &TarImportConfig {
            allow_nonusr: false,
            remap_factory_var: true,
        };
        let allow_nonusr = &TarImportConfig {
            allow_nonusr: true,
            remap_factory_var: true,
        };
        let composefs_and_new_ostree = &TarImportConfig {
            allow_nonusr: true,
            remap_factory_var: false,
        };
        let valid_all = &[
            ("/usr/bin/blah", "./usr/bin/blah"),
            ("usr/bin/blah", "./usr/bin/blah"),
            ("usr///share/.//blah", "./usr/share/blah"),
            ("var/lib/blah", "./usr/share/factory/var/lib/blah"),
            ("./var/lib/blah", "./usr/share/factory/var/lib/blah"),
            ("dev", "./dev"),
            ("/proc", "./proc"),
            ("./", "."),
        ];
        let valid_nonusr = &[("boot", "./boot"), ("opt/puppet/blah", "./opt/puppet/blah")];
        for &(k, v) in valid_all {
            let r = normalize_validate_path(k.into(), imp_default).unwrap();
            let r2 = normalize_validate_path(k.into(), allow_nonusr).unwrap();
            assert_eq!(r, r2);
            match r {
                NormalizedPathResult::Normal(r) => assert_eq!(r, v),
                NormalizedPathResult::Filtered(o) => panic!("Should not have filtered {o}"),
            }
        }
        for &(k, v) in valid_nonusr {
            let strict = normalize_validate_path(k.into(), imp_default).unwrap();
            assert!(
                matches!(strict, NormalizedPathResult::Filtered(_)),
                "Incorrect filter for {k}"
            );
            let nonusr = normalize_validate_path(k.into(), allow_nonusr).unwrap();
            match nonusr {
                NormalizedPathResult::Normal(r) => assert_eq!(r, v),
                NormalizedPathResult::Filtered(o) => panic!("Should not have filtered {o}"),
            }
        }
        let filtered = &["/run/blah", "/sys/foo", "/dev/somedev"];
        for &k in filtered {
            match normalize_validate_path(k.into(), imp_default).unwrap() {
                NormalizedPathResult::Filtered(_) => {}
                NormalizedPathResult::Normal(_) => {
                    panic!("{k} should be filtered")
                }
            }
        }
        let errs = &["usr/foo/../../bar"];
        for &k in errs {
            assert!(normalize_validate_path(k.into(), allow_nonusr).is_err());
            assert!(normalize_validate_path(k.into(), imp_default).is_err());
        }
        assert!(matches!(
            normalize_validate_path("var/lib/foo".into(), composefs_and_new_ostree).unwrap(),
            NormalizedPathResult::Normal(_)
        ));
    }

    #[tokio::test]
    async fn tar_filter() -> Result<()> {
        let tempd = tempfile::tempdir()?;
        let rootfs = &tempd.path().join("rootfs");

        std::fs::create_dir_all(rootfs.join("etc/systemd/system"))?;
        std::fs::write(rootfs.join("etc/systemd/system/foo.service"), "fooservice")?;
        std::fs::write(rootfs.join("blah"), "blah")?;
        let rootfs_tar_path = &tempd.path().join("rootfs.tar");
        let rootfs_tar = std::fs::File::create(rootfs_tar_path)?;
        let mut rootfs_tar = tar::Builder::new(rootfs_tar);
        rootfs_tar.append_dir_all(".", rootfs)?;
        let _ = rootfs_tar.into_inner()?;
        let mut dest = Vec::new();
        let src = tokio::io::BufReader::new(tokio::fs::File::open(rootfs_tar_path).await?);
        let cap_tmpdir = Dir::open_ambient_dir(&tempd, cap_std::ambient_authority())?;
        filter_tar_async(
            src,
            oci_image::MediaType::ImageLayer,
            &mut dest,
            &Default::default(),
            cap_tmpdir,
        )
        .await?;
        let dest = dest.as_slice();
        let mut final_tar = tar::Archive::new(Cursor::new(dest));
        let destdir = &tempd.path().join("destdir");
        final_tar.unpack(destdir)?;
        assert!(destdir.join("usr/etc/systemd/system/foo.service").exists());
        assert!(!destdir.join("blah").exists());
        Ok(())
    }
}
