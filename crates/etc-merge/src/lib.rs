//! Lib for /etc merge

#![allow(dead_code)]

use std::{collections::BTreeMap, io::Read, path::PathBuf};

use anyhow::Context;
use cap_std_ext::cap_std;
use cap_std_ext::cap_std::fs::{Dir as CapStdDir, MetadataExt, PermissionsExt};
use openssl::hash::DigestBytes;
use rustix::fs::readlinkat;

#[derive(Debug)]
struct Metadata {
    content_hash: String,
    metadata_hash: String,
}

impl Metadata {
    fn new(content_hash: String, metadata_hash: String) -> Self {
        Self {
            content_hash,
            metadata_hash,
        }
    }
}

type Map = BTreeMap<PathBuf, Metadata>;

#[derive(Debug)]
struct Diff {
    added: Vec<PathBuf>,
    modified: Vec<PathBuf>,
    removed: Vec<PathBuf>,
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

fn compute_diff(
    pristine_etc: &CapStdDir,
    current_etc: &CapStdDir,
    new_etc: &CapStdDir,
) -> anyhow::Result<Diff> {
    let mut pristine_etc_files = BTreeMap::new();
    recurse_dir(pristine_etc, PathBuf::new(), &mut pristine_etc_files)
        .context(format!("Recursing {pristine_etc:?}"))?;

    let mut current_etc_files = BTreeMap::new();
    recurse_dir(current_etc, PathBuf::new(), &mut current_etc_files)
        .context(format!("Recursing {current_etc:?}"))?;

    let mut new_etc_files = BTreeMap::new();
    recurse_dir(new_etc, PathBuf::new(), &mut new_etc_files)
        .context(format!("Recursing {new_etc:?}"))?;

    let mut added = vec![];
    let mut modified = vec![];

    for (current_file, current_meta) in current_etc_files {
        let Some(old_meta) = pristine_etc_files.get(&current_file) else {
            // File was created
            added.push(current_file);
            continue;
        };

        if old_meta.metadata_hash != current_meta.metadata_hash
            || old_meta.content_hash != current_meta.content_hash
        {
            modified.push(current_file.clone());
        }

        pristine_etc_files.remove(&current_file);
    }

    let removed = pristine_etc_files.into_keys().collect::<Vec<PathBuf>>();

    Ok(Diff {
        added,
        modified,
        removed,
    })
}

fn compute_metadata_hash(meta: &cap_std::fs::Metadata) -> anyhow::Result<DigestBytes> {
    let mut hasher = openssl::hash::Hasher::new(openssl::hash::MessageDigest::sha256())?;

    let mut ty = vec![];

    ty.push(meta.is_file() as u8);
    ty.push(meta.is_dir() as u8);
    ty.push(meta.is_symlink() as u8);

    hasher.update(&ty)?;

    if !meta.is_dir() {
        hasher.update(&meta.len().to_le_bytes())?;
    }

    hasher.update(&meta.permissions().mode().to_le_bytes())?;

    Ok(hasher.finish()?)
}

fn recurse_dir(dir: &CapStdDir, mut path: PathBuf, list: &mut Map) -> anyhow::Result<()> {
    for entry in dir.entries()? {
        let entry = entry.context(format!("Getting entry for {path:?}"))?;
        let entry_name = entry.file_name();

        path.push(&entry_name);

        let entry_type = entry.file_type()?;

        if entry_type.is_dir() {
            let dir = dir
                .open_dir(&entry_name)
                .with_context(|| format!("Opening dir {path:?} inside {dir:?}"))?;

            let metadata = dir
                .metadata(".")
                .context(format!("Getting dir meta for {path:?}"))?;

            list.insert(
                path.clone(),
                Metadata::new("".into(), hex::encode(compute_metadata_hash(&metadata)?)),
            );

            recurse_dir(&dir, path.clone(), list).context(format!("Recursing {path:?}"))?;

            path.pop();
            continue;
        }

        let buf = if entry_type.is_symlink() {
            let readlinkat_result = readlinkat(&dir, &entry_name, vec![])
                .context(format!("readlinkat {entry_name:?}"))?;

            readlinkat_result.into()
        } else if entry_type.is_file() {
            let mut buf = vec![0u8; entry.metadata()?.size() as usize];

            let mut file = entry.open().context(format!("Opening entry {path:?}"))?;
            file.read_exact(&mut buf)
                .context(format!("Reading {path:?}. Buf: {buf:?}"))?;

            buf
        } else {
            // We cannot read any other device like socket, pipe, fifo.
            // We shouldn't really find these in /etc in the first place
            unimplemented!("Found file of type {:?}", entry_type)
        };

        let mut hasher = openssl::hash::Hasher::new(openssl::hash::MessageDigest::sha256())?;
        hasher.update(&buf)?;
        let content_digest = hex::encode(hasher.finish()?);

        let meta = entry
            .metadata()
            .context(format!("Getting metadata for {path:?}"))?;

        list.insert(
            path.clone(),
            Metadata::new(content_digest, hex::encode(compute_metadata_hash(&meta)?)),
        );

        path.pop();
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

        let mut open_options = cap_std::fs::OpenOptions::new();
        open_options.create(true).write(true);

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
