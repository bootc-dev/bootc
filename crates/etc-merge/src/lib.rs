//! Lib for /etc merge

#![allow(dead_code)]

use fn_error_context::context;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::BufReader;
use std::io::Write;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use anyhow::Context;
use cap_std_ext::cap_std;
use cap_std_ext::cap_std::fs::{Dir as CapStdDir, MetadataExt, Permissions, PermissionsExt};
use cap_std_ext::dirext::CapStdExtDirExt;
use composefs::fsverity::{FsVerityHashValue, Sha256HashValue, Sha512HashValue};
use composefs::generic_tree::{Directory, Inode, Leaf, LeafContent, Stat};
use composefs::tree::ImageError;
use rustix::fs::{
    AtFlags, Gid, Uid, XattrFlags, lgetxattr, llistxattr, lsetxattr, readlinkat, symlinkat,
};

/// Metadata associated with a file, directory, or symlink entry.
#[derive(Debug)]
pub struct CustomMetadata {
    /// A SHA256 sum representing the file contents.
    content_hash: String,
    /// Optional verity for the file
    verity: Option<String>,
}

impl CustomMetadata {
    fn new(content_hash: String, verity: Option<String>) -> Self {
        Self {
            content_hash,
            verity,
        }
    }
}

type Xattrs = RefCell<BTreeMap<Box<OsStr>, Box<[u8]>>>;

struct MyStat(Stat);

impl From<(&cap_std::fs::Metadata, Xattrs)> for MyStat {
    fn from(value: (&cap_std::fs::Metadata, Xattrs)) -> Self {
        Self(Stat {
            st_mode: value.0.mode(),
            st_uid: value.0.uid(),
            st_gid: value.0.gid(),
            st_mtim_sec: value.0.mtime(),
            xattrs: value.1,
        })
    }
}

fn stat_eq_ignore_mtime(this: &Stat, other: &Stat) -> bool {
    if this.st_uid != other.st_uid {
        return false;
    }

    if this.st_gid != other.st_gid {
        return false;
    }

    if this.st_mode != other.st_mode {
        return false;
    }

    if this.xattrs != other.xattrs {
        return false;
    }

    return true;
}

/// Represents the differences between two directory trees.
#[derive(Debug)]
pub struct Diff {
    /// Paths that exist in the current /etc but not in the pristine
    added: Vec<PathBuf>,
    /// Paths that exist in both pristine and current /etc but differ in metadata
    /// (e.g., file contents, permissions, symlink targets)
    modified: Vec<PathBuf>,
    /// Paths that exist in the pristine /etc but not in the current one
    removed: Vec<PathBuf>,
}

fn collect_all_files(
    root: &Directory<CustomMetadata>,
    current_path: PathBuf,
    files: &mut Vec<PathBuf>,
) {
    fn collect(
        root: &Directory<CustomMetadata>,
        mut current_path: PathBuf,
        files: &mut Vec<PathBuf>,
    ) {
        for (path, inode) in root.sorted_entries() {
            current_path.push(path);

            files.push(current_path.clone());

            if let Inode::Directory(dir) = inode {
                collect(dir, current_path.clone(), files);
            }

            current_path.pop();
        }
    }

    collect(root, current_path, files);
}

#[context("Getting deletions")]
fn get_deletions(
    pristine: &Directory<CustomMetadata>,
    current: &Directory<CustomMetadata>,
    mut current_path: PathBuf,
    diff: &mut Diff,
) -> anyhow::Result<()> {
    for (file_name, inode) in pristine.sorted_entries() {
        current_path.push(file_name);

        match inode {
            Inode::Directory(pristine_dir) => {
                match current.get_directory(file_name) {
                    Ok(curr_dir) => {
                        get_deletions(pristine_dir, curr_dir, current_path.clone(), diff)?
                    }

                    Err(ImageError::NotFound(..)) => {
                        // Directory was deleted
                        diff.removed.push(current_path.clone());
                    }

                    Err(ImageError::NotADirectory(..)) => {
                        // Already tracked in modifications
                    }

                    Err(e) => Err(e)?,
                }
            }

            Inode::Leaf(..) => match current.ref_leaf(file_name) {
                Ok(..) => {
                    // Empty as all additions/modifications are tracked earlier in `get_modifications`
                }

                Err(ImageError::NotFound(..)) => {
                    // File was deleted
                    diff.removed.push(current_path.clone());
                }

                Err(ImageError::IsADirectory(..)) => {
                    // Already tracked in modifications
                }

                Err(e) => Err(e).context(format!("{file_name:?}"))?,
            },
        }

        current_path.pop();
    }

    Ok(())
}

// 1. Files in the currently booted deployment’s /etc which were modified from the default /usr/etc (of the same deployment) are retained.
//
// 2. Files in the currently booted deployment’s /etc which were not modified from the default /usr/etc (of the same deployment)
// are upgraded to the new defaults from the new deployment’s /usr/etc.

// Modifications
// 1. File deleted from new /etc
// 2. File added in new /etc
//
// 3. File modified in new /etc
//    a. Content added/deleted
//    b. Permissions/ownership changed
//    c. Was a file but changed to directory/symlink etc or vice versa
//    d. xattrs changed - we don't include this right now
#[context("Getting modifications")]
fn get_modifications(
    pristine: &Directory<CustomMetadata>,
    current: &Directory<CustomMetadata>,
    mut current_path: PathBuf,
    diff: &mut Diff,
) -> anyhow::Result<()> {
    use composefs::generic_tree::LeafContent::*;

    for (path, inode) in current.sorted_entries() {
        current_path.push(path);

        match inode {
            Inode::Directory(curr_dir) => {
                match pristine.get_directory(path) {
                    Ok(old_dir) => {
                        if !stat_eq_ignore_mtime(&curr_dir.stat, &old_dir.stat) {
                            // Directory permissions/owner modified
                            diff.modified.push(current_path.clone());
                        }

                        get_modifications(old_dir, &curr_dir, current_path.clone(), diff)?
                    }

                    Err(ImageError::NotFound(..)) => {
                        // Dir not found in original /etc, dir was added
                        diff.added.push(current_path.clone());

                        // Also add every file inside that dir
                        collect_all_files(&curr_dir, current_path.clone(), &mut diff.added);
                    }

                    Err(ImageError::NotADirectory(..)) => {
                        // Some directory was changed to a file/symlink
                        // This should be counted in the diff, but we don't really merge this
                        diff.modified.push(current_path.clone());
                    }

                    Err(e) => Err(e)?,
                }
            }

            Inode::Leaf(leaf) => match pristine.ref_leaf(path) {
                Ok(old_leaf) => {
                    if !stat_eq_ignore_mtime(&old_leaf.stat, &leaf.stat) {
                        diff.modified.push(current_path.clone());
                        current_path.pop();
                        continue;
                    }

                    match (&old_leaf.content, &leaf.content) {
                        (Regular(old_meta), Regular(current_meta)) => {
                            if old_meta.content_hash != current_meta.content_hash {
                                // File modified in some way
                                diff.modified.push(current_path.clone());
                            }
                        }

                        (Symlink(old_link), Symlink(current_link)) => {
                            if old_link != current_link {
                                // Symlink modified in some way
                                diff.modified.push(current_path.clone());
                            }
                        }

                        (Symlink(..), Regular(..)) | (Regular(..), Symlink(..)) => {
                            // File changed to symlink or vice-versa
                            diff.modified.push(current_path.clone());
                        }

                        (a, b) => {
                            unreachable!("{a:?} modified to {b:?}")
                        }
                    }
                }

                Err(ImageError::IsADirectory(..)) => {
                    // A directory was changed to a file
                    diff.modified.push(current_path.clone());
                }

                Err(ImageError::NotFound(..)) => {
                    // File not found in original /etc, file was added
                    diff.added.push(current_path.clone());
                }

                Err(e) => Err(e).context(format!("{path:?}"))?,
            },
        }

        current_path.pop();
    }

    Ok(())
}

/// Traverses and collects directory trees for three etc states.
///
/// Recursively walks through the given *pristine*, *current*, and *new* etc directories,
/// building filesystem trees that capture files, directories, and symlinks.
/// Device files, sockets, pipes etc are ignored
///
/// It is primarily used to prepare inputs for later diff computations and
/// comparisons between different etc states.
///
/// # Arguments
///
/// * `pristine_etc` - The reference directory representing the unmodified version or current /etc.
/// Usually this will be obtained by remounting the EROFS image to a temporary location
///
/// * `current_etc` - The current `/etc` directory
///
/// * `new_etc` - The directory representing the `/etc` directory for a new deployment. This will
/// again be usually obtained by mounting the new EROFS image to a temporary location. If merging
/// it will be necessary to make the `/etc` for the deployment writeable
///
/// # Returns
///
/// [`anyhow::Result`] containing a tuple of directory trees in the order:
///
/// 1. `pristine_etc_files` – Dirtree of the pristine etc state
/// 2. `current_etc_files` – Dirtree of the current etc state
/// 3. `new_etc_files` – Dirtree of the new etc state
pub fn traverse_etc(
    pristine_etc: &CapStdDir,
    current_etc: &CapStdDir,
    new_etc: &CapStdDir,
) -> anyhow::Result<(
    Directory<CustomMetadata>,
    Directory<CustomMetadata>,
    Directory<CustomMetadata>,
)> {
    let mut pristine_etc_files = Directory::default();
    recurse_dir(pristine_etc, &mut pristine_etc_files)
        .context(format!("Recursing {pristine_etc:?}"))?;

    let mut current_etc_files = Directory::default();
    recurse_dir(current_etc, &mut current_etc_files)
        .context(format!("Recursing {current_etc:?}"))?;

    let mut new_etc_files = Directory::default();
    recurse_dir(new_etc, &mut new_etc_files).context(format!("Recursing {new_etc:?}"))?;

    return Ok((pristine_etc_files, current_etc_files, new_etc_files));
}

/// Computes the differences between two directory snapshots.
#[context("Computing diff")]
pub fn compute_diff(
    pristine_etc_files: &Directory<CustomMetadata>,
    current_etc_files: &Directory<CustomMetadata>,
) -> anyhow::Result<Diff> {
    let mut diff = Diff {
        added: vec![],
        modified: vec![],
        removed: vec![],
    };

    get_modifications(
        &pristine_etc_files,
        &current_etc_files,
        PathBuf::new(),
        &mut diff,
    )?;

    get_deletions(
        &pristine_etc_files,
        &current_etc_files,
        PathBuf::new(),
        &mut diff,
    )?;

    Ok(diff)
}

/// Prints a colorized summary of differences to standard output.
pub fn print_diff(diff: &Diff, writer: &mut impl Write) {
    use owo_colors::OwoColorize;

    for added in &diff.added {
        let _ = writeln!(writer, "{} {added:?}", ModificationType::Added.green());
    }

    for modified in &diff.modified {
        let _ = writeln!(writer, "{} {modified:?}", ModificationType::Modified.cyan());
    }

    for removed in &diff.removed {
        let _ = writeln!(writer, "{} {removed:?}", ModificationType::Removed.red());
    }
}

#[context("Collecting xattrs")]
fn collect_xattrs(etc_fd: &CapStdDir, rel_path: impl AsRef<Path>) -> anyhow::Result<Xattrs> {
    let link = format!("/proc/self/fd/{}", etc_fd.as_fd().as_raw_fd());
    let path = Path::new(&link).join(rel_path);

    const DEFAULT_SIZE: usize = 128;

    // Start with a guess for size
    let mut xattrs_name_buf: Vec<u8> = vec![0; DEFAULT_SIZE];
    let mut size = llistxattr(&path, &mut xattrs_name_buf).context("llistxattr")?;

    if size > xattrs_name_buf.capacity() {
        xattrs_name_buf.resize(size, 0);
        size = llistxattr(&path, &mut xattrs_name_buf).context("llistxattr")?;
    }

    let xattrs: Xattrs = RefCell::new(BTreeMap::new());

    for name_buf in xattrs_name_buf[..size]
        .split(|&b| b == 0)
        .filter(|x| !x.is_empty())
    {
        let name = OsStr::from_bytes(name_buf);

        let mut xattrs_value_buf = vec![0; DEFAULT_SIZE];
        let mut size = lgetxattr(&path, name_buf, &mut xattrs_value_buf).context("lgetxattr")?;

        if size > xattrs_value_buf.capacity() {
            xattrs_value_buf.resize(size, 0);
            size = lgetxattr(&path, name_buf, &mut xattrs_value_buf).context("lgetxattr")?;
        }

        xattrs.borrow_mut().insert(
            Box::<OsStr>::from(name),
            Box::<[u8]>::from(&xattrs_value_buf[..size]),
        );
    }

    Ok(xattrs)
}

#[context("Copying xattrs")]
fn copy_xattrs(xattrs: &Xattrs, new_etc_fd: &CapStdDir, file: &PathBuf) -> anyhow::Result<()> {
    for (attr, value) in xattrs.borrow().iter() {
        let path = Path::new(&format!("/proc/self/fd/{}", new_etc_fd.as_raw_fd())).join(file);

        lsetxattr(path, attr.as_ref(), value, XattrFlags::empty())
            .context(format!("setxattr for {file:?}"))?;
    }

    Ok(())
}

fn recurse_dir(dir: &CapStdDir, root: &mut Directory<CustomMetadata>) -> anyhow::Result<()> {
    for entry in dir.entries()? {
        let entry = entry.context(format!("Getting entry"))?;
        let entry_name = entry.file_name();

        let entry_type = entry.file_type()?;

        let entry_meta = entry
            .metadata()
            .context(format!("Getting metadata for {entry_name:?}"))?;

        let xattrs = collect_xattrs(&dir, &entry_name)?;

        // Do symlinks first as we don't want to follow back up any symlinks
        if entry_type.is_symlink() {
            let readlinkat_result = readlinkat(&dir, &entry_name, vec![])
                .context(format!("readlinkat {entry_name:?}"))?;

            let os_str = OsStr::from_bytes(readlinkat_result.as_bytes());

            root.insert(
                &entry_name,
                Inode::Leaf(Rc::new(Leaf {
                    stat: MyStat::from((&entry_meta, xattrs)).0,
                    content: LeafContent::Symlink(Box::from(os_str)),
                })),
            );

            continue;
        }

        if entry_type.is_dir() {
            let dir = dir
                .open_dir(&entry_name)
                .with_context(|| format!("Opening dir {entry_name:?} inside {dir:?}"))?;

            let mut directory = Directory::new(MyStat::from((&entry_meta, xattrs)).0);

            recurse_dir(&dir, &mut directory)?;

            root.insert(&entry_name, Inode::Directory(Box::new(directory)));

            continue;
        }

        if !(entry_type.is_symlink() || entry_type.is_file()) {
            // We cannot read any other device like socket, pipe, fifo.
            // We shouldn't really find these in /etc in the first place
            tracing::debug!("Ignoring non-regular/non-symlink file: {:?}", entry_name);
            continue;
        }

        // TODO: Another generic here but constrained to Sha256HashValue
        // Regarding this, we'll definitely get DigestMismatch error if SHA512 is being used
        // So we query the verity again if we get a DigestMismatch error
        let measured_verity =
            composefs::fsverity::measure_verity_opt::<Sha256HashValue>(entry.open()?);

        let measured_verity = match measured_verity {
            Ok(mv) => mv.map(|verity| verity.to_hex()),

            Err(composefs::fsverity::MeasureVerityError::InvalidDigestAlgorithm { .. }) => {
                composefs::fsverity::measure_verity_opt::<Sha512HashValue>(entry.open()?)?
                    .map(|verity| verity.to_hex())
            }

            Err(e) => Err(e)?,
        };

        if let Some(measured_verity) = measured_verity {
            root.insert(
                &entry_name,
                Inode::Leaf(Rc::new(Leaf {
                    stat: MyStat::from((&entry_meta, xattrs)).0,
                    content: LeafContent::Regular(CustomMetadata::new(
                        "".into(),
                        Some(measured_verity),
                    )),
                })),
            );

            continue;
        }

        let mut hasher = openssl::hash::Hasher::new(openssl::hash::MessageDigest::sha256())?;

        let file = entry
            .open()
            .context(format!("Opening entry {entry_name:?}"))?;

        let mut reader = BufReader::new(file);
        std::io::copy(&mut reader, &mut hasher)?;

        let content_digest = hex::encode(hasher.finish()?);

        root.insert(
            &entry_name,
            Inode::Leaf(Rc::new(Leaf {
                stat: MyStat::from((&entry_meta, xattrs)).0,
                content: LeafContent::Regular(CustomMetadata::new(content_digest, None)),
            })),
        );
    }

    Ok(())
}

#[derive(Debug)]
enum ModificationType {
    Added,
    Modified,
    Removed,
}

impl std::fmt::Display for ModificationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl ModificationType {
    fn symbol(&self) -> &'static str {
        match self {
            ModificationType::Added => "+",
            ModificationType::Modified => "~",
            ModificationType::Removed => "-",
        }
    }
}

fn create_dir_with_perms(
    new_etc_fd: &CapStdDir,
    dir_name: &PathBuf,
    stat: &Stat,
    new_inode: Option<&Inode<CustomMetadata>>,
) -> anyhow::Result<()> {
    // The new directory is not present in the new_etc, so we create it, else we only copy the
    // metadata
    if new_inode.is_none() {
        // Here we use `create_dir_all` to create every parent as we will set the permissions later
        // on. Due to the fact that we have an ordered (sorted) list of directories and directory
        // entries and we have a DFS traversal, we will aways have directory creation starting from
        // the parent anyway.
        //
        // The exception being, if a directory is modified in the current_etc, and a new directory
        // is added inside the modified directory, say `dir/prems` has its premissions modified and
        // `dir/prems/new` is the new directory created. Since we handle added files/directories first,
        // we will create the directories `perms/new` with directory `new` also getting its
        // permissions set, but `perms` will not. `perms` will have its premissions set up when we
        // handle the modified directories.
        new_etc_fd
            .create_dir_all(&dir_name)
            .context(format!("Failed to create dir {dir_name:?}"))?;
    }

    new_etc_fd
        .set_permissions(&dir_name, Permissions::from_mode(stat.st_mode))
        .context(format!("Changing permissions for dir {dir_name:?}"))?;

    rustix::fs::chownat(
        &new_etc_fd,
        dir_name,
        Some(Uid::from_raw(stat.st_uid)),
        Some(Gid::from_raw(stat.st_gid)),
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .context(format!("chown {dir_name:?}"))?;

    copy_xattrs(&stat.xattrs, new_etc_fd, dir_name)?;

    Ok(())
}

fn merge_leaf(
    current_etc_fd: &CapStdDir,
    new_etc_fd: &CapStdDir,
    leaf: &Rc<Leaf<CustomMetadata>>,
    new_inode: Option<&Inode<CustomMetadata>>,
    file: &PathBuf,
) -> anyhow::Result<()> {
    let symlink = match &leaf.content {
        LeafContent::Regular(..) => None,
        LeafContent::Symlink(target) => Some(target),

        _ => {
            tracing::debug!("Found non file/symlink while merging. Ignoring");
            return Ok(());
        }
    };

    if matches!(new_inode, Some(Inode::Directory(..))) {
        anyhow::bail!("Modified config file {file:?} newly defaults to directory. Cannot merge")
    };

    // If a new file with the same path exists, we delete it
    new_etc_fd
        .remove_all_optional(&file)
        .context(format!("Deleting {file:?}"))?;

    if let Some(target) = symlink {
        // Using rustix's symlinkat here as we might have absolute symlinks which clash with ambient_authority
        symlinkat(&**target, new_etc_fd, file).context(format!("Creating symlink {file:?}"))?;
    } else {
        current_etc_fd
            .copy(&file, new_etc_fd, &file)
            .context(format!("Copying file {file:?}"))?;
    };

    rustix::fs::chownat(
        &new_etc_fd,
        file,
        Some(Uid::from_raw(leaf.stat.st_uid)),
        Some(Gid::from_raw(leaf.stat.st_gid)),
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .context(format!("chown {file:?}"))?;

    copy_xattrs(&leaf.stat.xattrs, new_etc_fd, file)?;

    Ok(())
}

fn merge_modified_files(
    files: &Vec<PathBuf>,
    current_etc_fd: &CapStdDir,
    current_etc_dirtree: &Directory<CustomMetadata>,
    new_etc_fd: &CapStdDir,
    new_etc_dirtree: &Directory<CustomMetadata>,
) -> anyhow::Result<()> {
    for file in files {
        let (dir, filename) = current_etc_dirtree
            .split(OsStr::new(&file))
            .context("Getting directory and file")?;

        let current_inode = dir
            .lookup(filename)
            .ok_or(anyhow::anyhow!("{filename:?} not found"))?;

        // This will error out if some directory in a chain does not exist
        let res = new_etc_dirtree.split(OsStr::new(&file));

        match res {
            Ok((new_dir, filename)) => {
                let new_inode = new_dir.lookup(filename);

                match current_inode {
                    Inode::Directory(..) => {
                        create_dir_with_perms(new_etc_fd, file, current_inode.stat(), new_inode)?;
                    }

                    Inode::Leaf(leaf) => {
                        merge_leaf(current_etc_fd, new_etc_fd, leaf, new_inode, file)?
                    }
                };
            }

            // Directory/File does not exist in the new /etc
            Err(ImageError::NotFound(..)) => match current_inode {
                Inode::Directory(..) => {
                    create_dir_with_perms(new_etc_fd, file, current_inode.stat(), None)?
                }

                Inode::Leaf(leaf) => {
                    merge_leaf(current_etc_fd, new_etc_fd, leaf, None, file)?;
                }
            },

            Err(e) => Err(e)?,
        };
    }

    Ok(())
}

/// Goes through the added, modified, removed files and apply those changes to the new_etc
/// This will overwrite, remove, modify files in new_etc
/// Paths in `diff` are relative to `etc`
#[context("Merging")]
pub fn merge(
    current_etc_fd: &CapStdDir,
    current_etc_dirtree: &Directory<CustomMetadata>,
    new_etc_fd: &CapStdDir,
    new_etc_dirtree: &Directory<CustomMetadata>,
    diff: Diff,
) -> anyhow::Result<()> {
    merge_modified_files(
        &diff.added,
        current_etc_fd,
        current_etc_dirtree,
        new_etc_fd,
        new_etc_dirtree,
    )
    .context("Merging added files")?;

    merge_modified_files(
        &diff.modified,
        current_etc_fd,
        current_etc_dirtree,
        new_etc_fd,
        new_etc_dirtree,
    )
    .context("Merging modified files")?;

    for removed in diff.removed {
        match new_etc_fd.remove_file(&removed) {
            Ok(..) => { /* no-op */ }
            // Removed file's not present in the new etc dir, nothing to do
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => Err(e)?,
        }

        println!("- Removed file {removed:?}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use cap_std::fs::PermissionsExt;
    use cap_std_ext::cap_std::fs::Metadata;

    use super::*;

    const FILES: &[(&str, &str)] = &[
        ("a/file1", "a-file1"),
        ("a/file2", "a-file2"),
        ("a/b/file1", "ab-file1"),
        ("a/b/file2", "ab-file2"),
        ("a/b/c/fileabc", "abc-file1"),
        ("a/b/c/modify-perms", "modify-perms"),
        ("a/b/c/to-be-removed", "remove this"),
        ("to-be-removed", "remove this 2"),
    ];

    #[test]
    fn test_etc_diff() -> anyhow::Result<()> {
        let tempdir = cap_std_ext::cap_tempfile::tempdir(cap_std::ambient_authority())?;

        tempdir.create_dir("pristine_etc")?;
        tempdir.create_dir("current_etc")?;
        tempdir.create_dir("new_etc")?;

        let p = tempdir.open_dir("pristine_etc")?;
        let c = tempdir.open_dir("current_etc")?;
        let n = tempdir.open_dir("new_etc")?;

        p.create_dir_all("a/b/c")?;
        c.create_dir_all("a/b/c")?;

        for (file, content) in FILES {
            p.write(file, content.as_bytes())?;
            c.write(file, content.as_bytes())?;
        }

        let new_files = ["new_file", "a/new_file", "a/b/c/new_file"];

        // Add some new files
        for file in new_files {
            c.write(file, b"hello")?;
        }

        let overwritten_files = [FILES[1].0, FILES[4].0];
        let perm_changed_files = [FILES[5].0];

        // Modify some files
        c.write(overwritten_files[0], b"some new content")?;
        c.write(overwritten_files[1], b"some newer content")?;

        // Modify permissions
        let file = c.open(perm_changed_files[0])?;
        // This should be enough as the usual files have permission 644
        file.set_permissions(cap_std::fs::Permissions::from_mode(0o400))?;

        // Remove some files
        let deleted_files = [FILES[6].0, FILES[7].0];
        c.remove_file(deleted_files[0])?;
        c.remove_file(deleted_files[1])?;

        let (pristine_etc_files, current_etc_files, _) = traverse_etc(&p, &c, &n)?;
        let res = compute_diff(&pristine_etc_files, &current_etc_files)?;

        // Test added files
        assert_eq!(res.added.len(), new_files.len());
        assert!(res.added.iter().all(|file| {
            new_files
                .iter()
                .find(|x| PathBuf::from(*x) == *file)
                .is_some()
        }));

        // Test modified files
        let all_modified_files = overwritten_files
            .iter()
            .chain(&perm_changed_files)
            .collect::<Vec<_>>();

        assert_eq!(res.modified.len(), all_modified_files.len());
        assert!(res.modified.iter().all(|file| {
            all_modified_files
                .iter()
                .find(|x| PathBuf::from(*x) == *file)
                .is_some()
        }));

        // Test removed files
        assert_eq!(res.removed.len(), deleted_files.len());
        assert!(res.removed.iter().all(|file| {
            deleted_files
                .iter()
                .find(|x| PathBuf::from(*x) == *file)
                .is_some()
        }));

        Ok(())
    }

    fn compare_meta(meta1: Metadata, meta2: Metadata) -> bool {
        return meta1.is_file() == meta2.is_file()
            && meta1.is_dir() == meta2.is_dir()
            && meta1.is_symlink() == meta2.is_symlink()
            && meta1.mode() == meta2.mode()
            && meta1.uid() == meta2.uid()
            && meta1.gid() == meta2.gid();
    }

    fn files_eq(current_etc: &CapStdDir, new_etc: &CapStdDir, path: &str) -> anyhow::Result<bool> {
        return Ok(
            compare_meta(current_etc.metadata(path)?, new_etc.metadata(path)?)
                && current_etc.read(path)? == new_etc.read(path)?,
        );
    }

    #[test]
    fn test_merge() -> anyhow::Result<()> {
        let tempdir = cap_std_ext::cap_tempfile::tempdir(cap_std::ambient_authority())?;

        tempdir.create_dir("pristine_etc")?;
        tempdir.create_dir("current_etc")?;
        tempdir.create_dir("new_etc")?;

        let p = tempdir.open_dir("pristine_etc")?;
        let c = tempdir.open_dir("current_etc")?;
        let n = tempdir.open_dir("new_etc")?;

        p.create_dir_all("a/b")?;
        c.create_dir_all("a/b")?;
        n.create_dir_all("a/b")?;

        // File added in current_etc, with file NOT present in new_etc
        // arbitrary nesting
        c.write("new_file.txt", "text1")?;
        c.write("a/new_file.txt", "text2")?;
        c.write("a/b/new_file.txt", "text3")?;

        // File added in current_etc, with file present in new_etc
        c.write("present_file.txt", "new-present-text1")?;
        c.write("a/present_file.txt", "new-present-text2")?;
        c.write("a/b/present_file.txt", "new-present-text3")?;

        n.write("present_file.txt", "present-text1")?;
        n.write("a/present_file.txt", "present-text2")?;
        n.write("a/b/present_file.txt", "present-text3")?;

        // File (content) modified in current_etc, with file NOT PRESENT in new_etc
        p.write("content-modify.txt", "old-content1")?;
        p.write("a/content-modify.txt", "old-content2")?;
        p.write("a/b/content-modify.txt", "old-content3")?;

        c.write("content-modify.txt", "new-content1")?;
        c.write("a/content-modify.txt", "new-content2")?;
        c.write("a/b/content-modify.txt", "new-content3")?;

        // File (content) modified in current_etc, with file PRESENT in new_etc
        p.write("content-modify-present.txt", "old-present-content1")?;
        p.write("a/content-modify-present.txt", "old-present-content2")?;
        p.write("a/b/content-modify-present.txt", "old-present-content3")?;

        c.write("content-modify-present.txt", "current-present-content1")?;
        c.write("a/content-modify-present.txt", "current-present-content2")?;
        c.write("a/b/content-modify-present.txt", "current-present-content3")?;

        n.write("content-modify-present.txt", "new-present-content1")?;
        n.write("a/content-modify-present.txt", "new-present-content2")?;
        n.write("a/b/content-modify-present.txt", "new-present-content3")?;

        // File (permission) modified in current_etc, with file NOT PRESENT in new_etc
        p.write("permission-modify.txt", "old-content1")?;
        p.write("a/permission-modify.txt", "old-content2")?;
        p.write("a/b/permission-modify.txt", "old-content3")?;

        c.atomic_write_with_perms(
            "permission-modify.txt",
            "old-content1",
            Permissions::from_mode(0o755),
        )?;
        c.atomic_write_with_perms(
            "a/permission-modify.txt",
            "old-content2",
            Permissions::from_mode(0o766),
        )?;
        c.atomic_write_with_perms(
            "a/b/permission-modify.txt",
            "old-content3",
            Permissions::from_mode(0o744),
        )?;

        // File (permission) modified in current_etc, with file PRESENT in new_etc
        p.write("permission-modify-present.txt", "old-present-content1")?;
        p.write("a/permission-modify-present.txt", "old-present-content2")?;
        p.write("a/b/permission-modify-present.txt", "old-present-content3")?;

        c.atomic_write_with_perms(
            "permission-modify-present.txt",
            "old-present-content1",
            Permissions::from_mode(0o755),
        )?;
        c.atomic_write_with_perms(
            "a/permission-modify-present.txt",
            "old-present-content2",
            Permissions::from_mode(0o766),
        )?;
        c.atomic_write_with_perms(
            "a/b/permission-modify-present.txt",
            "old-present-content3",
            Permissions::from_mode(0o744),
        )?;

        n.write("permission-modify-present.txt", "new-present-content1")?;
        n.write("a/permission-modify-present.txt", "old-present-content2")?;
        n.write("a/b/permission-modify-present.txt", "new-present-content3")?;

        // Create a new dirtree
        c.create_dir_all("new/dir/tree/here")?;

        // Create a new dirtree in an already existing dirtree
        p.create_dir_all("existing/tree")?;
        c.create_dir_all("existing/tree/another/dir/tree")?;
        c.write(
            "existing/tree/another/dir/tree/file.txt",
            "dir-tree-contents",
        )?;

        // Directory permissions
        p.create_dir_all("dir/perms")?;
        p.create_dir_all("dir/perms/wo")?;
        p.create_dir_all("dir/perms/wo/ro")?;

        c.create_dir_all("dir/perms")?;
        c.set_permissions("dir/perms", Permissions::from_mode(0o777))?;

        c.create_dir_all("dir/perms/rwx")?;
        c.set_permissions("dir/perms/rwx", Permissions::from_mode(0o777))?;

        c.create_dir_all("dir/perms/wo")?;
        c.set_permissions("dir/perms/wo", Permissions::from_mode(0o733))?;

        c.create_dir_all("dir/perms/wo/ro")?;
        c.set_permissions("dir/perms/wo/ro", Permissions::from_mode(0o775))?;

        n.create_dir_all("dir/perms")?;
        n.write("dir/perms/some-file", "Some-file")?;

        let (pristine_etc_files, current_etc_files, new_etc_files) = traverse_etc(&p, &c, &n)?;
        let diff = compute_diff(&pristine_etc_files, &current_etc_files)?;
        merge(&c, &current_etc_files, &n, &new_etc_files, diff)?;

        assert!(files_eq(&c, &n, "new_file.txt")?);
        assert!(files_eq(&c, &n, "a/new_file.txt")?);
        assert!(files_eq(&c, &n, "a/b/new_file.txt")?);

        assert!(files_eq(&c, &n, "present_file.txt")?);
        assert!(files_eq(&c, &n, "a/present_file.txt")?);
        assert!(files_eq(&c, &n, "a/b/present_file.txt")?);

        assert!(files_eq(&c, &n, "content-modify.txt")?);
        assert!(files_eq(&c, &n, "a/content-modify.txt")?);
        assert!(files_eq(&c, &n, "a/b/content-modify.txt")?);

        assert!(files_eq(&c, &n, "content-modify-present.txt")?);
        assert!(files_eq(&c, &n, "a/content-modify-present.txt")?);
        assert!(files_eq(&c, &n, "a/b/content-modify-present.txt")?);

        assert!(files_eq(&c, &n, "permission-modify.txt")?);
        assert!(files_eq(&c, &n, "a/permission-modify.txt")?);
        assert!(files_eq(&c, &n, "a/b/permission-modify.txt")?);

        assert!(files_eq(&c, &n, "permission-modify-present.txt")?);
        assert!(files_eq(&c, &n, "a/permission-modify-present.txt")?);
        assert!(files_eq(&c, &n, "a/b/permission-modify-present.txt")?);

        assert!(n.exists("new/dir/tree/here"));
        assert!(n.exists("existing/tree/another/dir/tree"));
        assert!(files_eq(&c, &n, "existing/tree/another/dir/tree/file.txt")?);

        assert!(compare_meta(
            c.metadata("dir/perms")?,
            n.metadata("dir/perms")?
        ));

        // Make sure nothing is deleted from a directory
        assert!(n.exists("dir/perms/some-file"));

        const DIR_BITS: u32 = 0o040000;

        assert_eq!(
            n.metadata("dir/perms/rwx").unwrap().mode(),
            DIR_BITS | 0o777
        );
        assert_eq!(n.metadata("dir/perms/wo").unwrap().mode(), DIR_BITS | 0o733);
        assert_eq!(
            n.metadata("dir/perms/wo/ro").unwrap().mode(),
            DIR_BITS | 0o775
        );

        Ok(())
    }

    #[test]
    fn file_to_dir() -> anyhow::Result<()> {
        let tempdir = cap_std_ext::cap_tempfile::tempdir(cap_std::ambient_authority())?;

        tempdir.create_dir("pristine_etc")?;
        tempdir.create_dir("current_etc")?;
        tempdir.create_dir("new_etc")?;

        let p = tempdir.open_dir("pristine_etc")?;
        let c = tempdir.open_dir("current_etc")?;
        let n = tempdir.open_dir("new_etc")?;

        p.write("file-to-dir", "some text")?;
        c.write("file-to-dir", "some text 1")?;

        n.create_dir_all("file-to-dir")?;

        let (pristine_etc_files, current_etc_files, new_etc_files) = traverse_etc(&p, &c, &n)?;
        let diff = compute_diff(&pristine_etc_files, &current_etc_files)?;

        let merge_res = merge(&c, &current_etc_files, &n, &new_etc_files, diff);

        assert!(merge_res.is_err());
        assert_eq!(
            merge_res.unwrap_err().root_cause().to_string(),
            "Modified config file \"file-to-dir\" newly defaults to directory. Cannot merge"
        );

        Ok(())
    }
}
