//! Lib for /etc merge

#![allow(dead_code)]

use std::io::BufReader;
use std::path::PathBuf;
use std::rc::Rc;

use anyhow::Context;
use cap_std_ext::cap_std;
use cap_std_ext::cap_std::fs::{Dir as CapStdDir, MetadataExt};
use composefs::fsverity::{FsVerityHashValue, Sha256HashValue};
use composefs::generic_tree::{Directory, Inode, Leaf, LeafContent, Stat};
use composefs::tree::ImageError;
use rustix::fs::readlinkat;

#[derive(Debug)]
struct CustomMetadata {
    content_hash: String,
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

struct MyStat(Stat);

impl From<&cap_std::fs::Metadata> for MyStat {
    fn from(value: &cap_std::fs::Metadata) -> Self {
        Self(Stat {
            st_mode: value.mode(),
            st_uid: value.uid(),
            st_gid: value.gid(),
            st_mtim_sec: value.mtime(),
            xattrs: Default::default(),
        })
    }
}

fn stat_eq(this: &Stat, other: &Stat) -> bool {
    if this.st_uid != other.st_uid {
        return false;
    }

    if this.st_gid != other.st_gid {
        return false;
    }

    if this.st_mode != other.st_mode {
        return false;
    }

    if this.st_mtim_sec != other.st_mtim_sec {
        return false;
    }

    if this.xattrs != other.xattrs {
        return false;
    }

    return true;
}

#[derive(Debug)]
struct Diff {
    added: Vec<PathBuf>,
    modified: Vec<PathBuf>,
    removed: Vec<PathBuf>,
}

fn collect_all_files(root: &Directory<CustomMetadata>) -> Vec<PathBuf> {
    fn collect(
        root: &Directory<CustomMetadata>,
        mut current_path: PathBuf,
        files: &mut Vec<PathBuf>,
    ) {
        for (path, inode) in root.entries() {
            current_path.push(path);

            if let Inode::Directory(dir) = inode {
                collect(dir, current_path.clone(), files);
            } else {
                files.push(current_path.clone());
            }

            current_path.pop();
        }
    }

    let mut files = vec![];
    collect(root, PathBuf::new(), &mut files);

    return files;
}

fn get_deletions(
    pristine: &Directory<CustomMetadata>,
    current: &Directory<CustomMetadata>,
    mut current_path: PathBuf,
    diff: &mut Diff,
) -> anyhow::Result<()> {
    for (file_name, inode) in pristine.entries() {
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

                    Err(e) => Err(e)?,
                }
            }

            Inode::Leaf(..) => match current.ref_leaf(file_name) {
                Ok(..) => {
                    // Empty as all additions/modifications are tracked above
                }

                Err(ImageError::NotFound(..)) => {
                    // File was deleted
                    diff.removed.push(current_path.clone());
                }

                Err(e) => Err(e)?,
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
fn compute_diff_root(
    pristine: &mut Directory<CustomMetadata>,
    current: &Directory<CustomMetadata>,
    mut current_path: PathBuf,
    diff: &mut Diff,
) -> anyhow::Result<()> {
    for (path, inode) in current.entries() {
        current_path.push(path);

        match inode {
            Inode::Directory(curr_dir) => {
                match pristine.get_directory_mut(path) {
                    Ok(old_dir) => {
                        compute_diff_root(old_dir, &curr_dir, current_path.clone(), diff)?
                    }

                    Err(ImageError::NotFound(..)) => {
                        // Dir not found in original /etc, dir was added
                        diff.added.push(current_path.clone());

                        // Also add every file inside that dir
                        diff.added.extend(collect_all_files(&curr_dir));
                    }

                    Err(ImageError::NotADirectory(..)) => {
                        // A file was changed to a directory
                        diff.modified.push(current_path.clone());
                    }

                    Err(e) => Err(e)?,
                }
            }

            Inode::Leaf(leaf) => match pristine.ref_leaf(path) {
                Ok(old_leaf) => {
                    let LeafContent::Regular(current_meta) = &leaf.content else {
                        unreachable!("File types do not match");
                    };

                    let LeafContent::Regular(old_meta) = &old_leaf.content else {
                        unreachable!("File types do not match");
                    };

                    if old_meta.content_hash != current_meta.content_hash
                        || !stat_eq(&old_leaf.stat, &leaf.stat)
                    {
                        // File modified in some way
                        diff.modified.push(current_path.clone());
                    }

                    pristine.remove(path);
                }

                Err(ImageError::IsADirectory(..)) => {
                    // A directory was changed to a file
                    diff.modified.push(current_path.clone());
                }

                Err(ImageError::NotFound(..)) => {
                    // File not found in original /etc, file was added
                    diff.added.push(current_path.clone());
                }

                Err(e) => Err(e)?,
            },
        }

        current_path.pop();
    }

    Ok(())
}

fn compute_diff(
    pristine_etc: &CapStdDir,
    current_etc: &CapStdDir,
    new_etc: &CapStdDir,
) -> anyhow::Result<Diff> {
    let mut pristine_etc_files = Directory::default();
    recurse_dir(pristine_etc, &mut pristine_etc_files)
        .context(format!("Recursing {pristine_etc:?}"))?;

    let mut current_etc_files = Directory::default();
    recurse_dir(current_etc, &mut current_etc_files)
        .context(format!("Recursing {current_etc:?}"))?;

    let mut new_etc_files = Directory::default();
    recurse_dir(new_etc, &mut new_etc_files).context(format!("Recursing {new_etc:?}"))?;

    let mut diff = Diff {
        added: vec![],
        modified: vec![],
        removed: vec![],
    };

    compute_diff_root(
        &mut pristine_etc_files,
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

fn recurse_dir(dir: &CapStdDir, root: &mut Directory<CustomMetadata>) -> anyhow::Result<()> {
    for entry in dir.entries()? {
        let entry = entry.context(format!("Getting entry"))?;
        let entry_name = entry.file_name();

        let entry_type = entry.file_type()?;
        let entry_meta = entry
            .metadata()
            .context(format!("Getting metadata for {entry_name:?}"))?;

        if entry_type.is_dir() {
            let dir = dir
                .open_dir(&entry_name)
                .with_context(|| format!("Opening dir {entry_name:?} inside {dir:?}"))?;

            let mut directory = Directory::default();

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
        let measured_verity =
            composefs::fsverity::measure_verity_opt::<Sha256HashValue>(entry.open()?)?;

        if let Some(measured_verity) = measured_verity {
            root.insert(
                &entry_name,
                Inode::Leaf(Rc::new(Leaf {
                    stat: MyStat::from(&entry_meta).0,
                    content: LeafContent::Regular(CustomMetadata::new(
                        "".into(),
                        Some(measured_verity.to_hex()),
                    )),
                })),
            );

            // file has fs-verity enabled. We don't need to check the content/metadata
            continue;
        }

        let mut hasher = openssl::hash::Hasher::new(openssl::hash::MessageDigest::sha256())?;

        if entry_type.is_symlink() {
            let readlinkat_result = readlinkat(&dir, &entry_name, vec![])
                .context(format!("readlinkat {entry_name:?}"))?;

            hasher.update(readlinkat_result.as_bytes())?;
        } else if entry_type.is_file() {
            let file = entry
                .open()
                .context(format!("Opening entry {entry_name:?}"))?;

            let mut reader = BufReader::new(file);
            std::io::copy(&mut reader, &mut hasher)?;
        };

        let content_digest = hex::encode(hasher.finish()?);

        root.insert(
            &entry_name,
            Inode::Leaf(Rc::new(Leaf {
                stat: MyStat::from(&entry_meta).0,
                content: LeafContent::Regular(CustomMetadata::new(content_digest, None)),
            })),
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use cap_std::fs::PermissionsExt;

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

        let res = compute_diff(&p, &c, &n)?;

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
}
