// number: 51
// tmt:
//   summary: Enforce composefs image and object integrity independently of repository metadata
//   duration: 5m
//   adjust:
//     - when: running_env != image_mode
//       enabled: false
//       because: only the image_mode test image installs bootc-tests
// extra:
//   skip_if_ostree: true
//
//! Exercise the initramfs mount helper against disposable repositories. The
//! host's boot files and repository are never modified.

use std::{
    ffi::OsStr,
    fs::{self, File},
    io::Read,
    os::fd::{AsFd, OwnedFd},
    path::Path,
};

use anyhow::{Context, Result, ensure};
use bootc_initramfs_setup::mount_composefs_image;
use composefs_ctl::composefs::{
    erofs::{
        format::FormatVersion,
        writer::{ValidatedFileSystem, mkfs_erofs_versioned},
    },
    fsverity::{
        Algorithm, CompareVerityError, EnableVerityError, FsVerityHashValue, MeasureVerityError,
        Sha512HashValue, enable_verity_raw, measure_verity_opt,
    },
    mountcompat::prepare_mount,
    repository::{ImageNotFound, Repository, RepositoryConfig},
    tree::{FileSystem, Inode, LeafContent, RegularFile, Stat},
};
use rustix::{
    fs::{Mode, OFlags, openat},
    io::Errno,
    mount::{MountPropagationFlags, mount_change},
    thread::{UnshareFlags, unshare_unsafe},
};

/// How the repository is tampered with after the image has been written.
#[derive(Clone, Copy, Debug)]
enum Tamper {
    /// Nothing; the control case.
    None,
    /// The image is replaced by a byte-identical copy without fs-verity.
    Image,
    /// Like `Image`, but meta.json also loses fs-verity and a data object is
    /// replaced: the state an offline attacker would leave behind.
    ImageAndMetadata,
    /// A data object is replaced while the image stays intact.
    Data,
    /// `images/<digest>` is repointed at a different image that does carry
    /// fs-verity.
    ImageSwap,
    /// `images/<digest>` is removed and `images/refs/<digest>` points at a
    /// different image that does carry fs-verity.
    RefDigest,
    /// `images/<digest>` is removed and `images/refs/<digest>` is a copy of
    /// the image without fs-verity.
    RefVerity,
}

/// What `mount_composefs_image` must do with the tampered repository.
#[derive(Clone, Copy, Debug)]
enum Expect {
    /// The mount succeeds and `data` reads back its original contents.
    Original,
    /// The mount succeeds and `data` reads back the replaced contents.
    Replaced,
    /// The mount succeeds, but reading `data` fails with `EIO`.
    ReadEio,
    /// The mount is refused because the image has no fs-verity.
    VerityMissing,
    /// The mount is refused because the image found does not have the
    /// requested digest.
    DigestMismatch,
    /// The mount is refused because no image has the requested digest.
    NotFound,
}

#[derive(Clone, Copy, Debug)]
struct Case {
    /// Whether meta.json records fs-verity as enabled.
    metadata_verity: bool,
    tamper: Tamper,
    /// Whether the cmdline carries the `?` marker allowing missing fs-verity.
    relaxed: bool,
    expect: Expect,
}

/// A strict cmdline gets the same verdict whatever meta.json says: only the
/// image named by the digest, carrying fs-verity, is ever mounted.
const STRICT: &[(Tamper, Expect)] = &[
    (Tamper::None, Expect::Original),
    (Tamper::Image, Expect::VerityMissing),
    (Tamper::ImageAndMetadata, Expect::VerityMissing),
    (Tamper::Data, Expect::ReadEio),
    (Tamper::ImageSwap, Expect::DigestMismatch),
    (Tamper::RefDigest, Expect::NotFound),
    (Tamper::RefVerity, Expect::NotFound),
];

/// A relaxed cmdline tolerates missing fs-verity but still verifies whatever
/// can be measured, and never consults `images/refs/` either. The first
/// element is `metadata_verity`.
const RELAXED: &[(bool, Tamper, Expect)] = &[
    (true, Tamper::Data, Expect::ReadEio),
    (false, Tamper::ImageAndMetadata, Expect::Replaced),
    (false, Tamper::ImageSwap, Expect::DigestMismatch),
    (false, Tamper::RefDigest, Expect::NotFound),
    (false, Tamper::RefVerity, Expect::NotFound),
];

fn replace(path: &Path, data: &[u8]) -> Result<()> {
    let copy = path.with_extension("replacement");
    fs::write(&copy, data)?;
    fs::rename(copy, path)?;
    Ok(())
}

fn strip_verity(path: &Path) -> Result<()> {
    replace(path, &fs::read(path)?)?;
    ensure!(measure_verity_opt::<Sha512HashValue>(File::open(path)?)?.is_none());
    Ok(())
}

fn read_data(root: impl AsFd) -> std::io::Result<Vec<u8>> {
    let mut file = File::from(openat(
        root,
        "data",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(data)
}

fn is_expected_rejection(error: &anyhow::Error, expect: Expect) -> bool {
    match expect {
        Expect::VerityMissing => matches!(
            error.downcast_ref::<CompareVerityError>(),
            Some(CompareVerityError::Measure(
                MeasureVerityError::VerityMissing
            ))
        ),
        Expect::DigestMismatch => matches!(
            error.downcast_ref::<CompareVerityError>(),
            Some(CompareVerityError::DigestMismatch { .. })
        ),
        Expect::NotFound => error.downcast_ref::<ImageNotFound>().is_some(),
        Expect::Original | Expect::Replaced | Expect::ReadEio => false,
    }
}

fn check_case(parent: &Path, case: Case) -> Result<()> {
    let tmp = tempfile::tempdir_in(parent)?;
    let sysroot: OwnedFd = File::open(tmp.path())?.into();
    let config = RepositoryConfig::new(Algorithm::SHA512);
    let config = if case.metadata_verity {
        config
    } else {
        config.set_insecure()
    };
    let (repo, _) = Repository::<Sha512HashValue>::init_path(&sysroot, "composefs", config)?;
    let repo_path = tmp.path().join("composefs");
    ensure!(repo.is_insecure() != case.metadata_verity);

    let contents = b"original data\n".repeat(1024);
    let replaced = vec![b'x'; contents.len()];
    let object = repo.ensure_object(&contents)?;
    let object_path = repo_path.join("objects").join(object.to_object_pathname());
    let mut stat = Stat::uninitialized();
    stat.st_mode = 0o755;
    let mut tree = FileSystem::<Sha512HashValue>::new(stat.clone());
    stat.st_mode = 0o644;
    let leaf = tree.push_leaf(
        stat,
        LeafContent::Regular(RegularFile::External(object, contents.len() as u64)),
    );
    tree.root.insert(OsStr::new("data"), Inode::leaf(leaf));
    let image = mkfs_erofs_versioned(&ValidatedFileSystem::new(tree.clone())?, FormatVersion::V1);
    let digest = repo.write_image(None, &image)?.to_hex();
    let image_link = repo_path.join("images").join(&digest);
    let image_path = fs::canonicalize(&image_link)?;

    match case.tamper {
        Tamper::None => {}
        Tamper::Image => strip_verity(&image_path)?,
        Tamper::ImageAndMetadata => {
            strip_verity(&repo_path.join("meta.json"))?;
            strip_verity(&image_path)?;
            replace(&object_path, &replaced)?;
        }
        Tamper::Data => replace(&object_path, &replaced)?,
        Tamper::ImageSwap | Tamper::RefDigest => {
            tree.root.stat.st_mtim_sec += 1;
            let other_image =
                mkfs_erofs_versioned(&ValidatedFileSystem::new(tree)?, FormatVersion::V1);
            let swap = matches!(case.tamper, Tamper::ImageSwap);
            let reference = (!swap).then_some(digest.as_str());
            let other = repo.write_image(reference, &other_image)?.to_hex();
            ensure!(other != digest);
            fs::remove_file(&image_link)?;
            if swap {
                std::os::unix::fs::symlink(&other, &image_link)?;
            }
        }
        Tamper::RefVerity => {
            fs::create_dir_all(repo_path.join("images/refs"))?;
            fs::write(repo_path.join("images/refs").join(&digest), &image)?;
            fs::remove_file(&image_link)?;
        }
    }
    drop(repo);

    let mounted = mount_composefs_image(&sysroot, &digest, case.relaxed);
    let root = match case.expect {
        Expect::Original | Expect::Replaced | Expect::ReadEio => prepare_mount(mounted?)?,
        Expect::VerityMissing | Expect::DigestMismatch | Expect::NotFound => {
            let error = mounted.err().context("a tampered image was mounted")?;
            ensure!(
                is_expected_rejection(&error, case.expect),
                "Unexpected error: {error:#}"
            );
            return Ok(());
        }
    };
    let read = read_data(&root);
    match case.expect {
        Expect::Original => ensure!(read? == contents),
        Expect::Replaced => ensure!(read? == replaced),
        _ => {
            let error = read.err().context("a tampered object was readable")?;
            ensure!(
                error.raw_os_error() == Some(Errno::IO.raw_os_error()),
                "Unexpected read error: {error}"
            );
        }
    }
    Ok(())
}

pub(crate) fn run() -> Result<()> {
    super::tap_begin("composefs initramfs verity enforcement");
    // SAFETY: Only the mount namespace is unshared, not the file descriptor
    // table. No descriptors become inaccessible to other threads.
    #[allow(unsafe_code)]
    unsafe { unshare_unsafe(UnshareFlags::NEWNS) }.context("Creating test mount namespace")?;
    mount_change(
        "/",
        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
    )?;
    // /tmp is commonly tmpfs; /var/tmp is on the persistent data filesystem.
    let tmp = tempfile::tempdir_in("/var/tmp")?;
    let probe = tmp.path().join("verity-probe");
    fs::write(&probe, b"probe")?;
    match enable_verity_raw::<Sha512HashValue>(File::open(probe)?) {
        Ok(()) => {}
        Err(EnableVerityError::FilesystemNotSupported) => {
            println!("ok # SKIP /var/tmp filesystem does not support fs-verity");
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    }
    let strict = [true, false].into_iter().flat_map(|metadata_verity| {
        STRICT.iter().map(move |&(tamper, expect)| Case {
            metadata_verity,
            tamper,
            relaxed: false,
            expect,
        })
    });
    let relaxed = RELAXED
        .iter()
        .map(|&(metadata_verity, tamper, expect)| Case {
            metadata_verity,
            tamper,
            relaxed: true,
            expect,
        });
    for case in strict.chain(relaxed) {
        check_case(tmp.path(), case).with_context(|| format!("{case:?}"))?;
    }
    super::tap_ok();
    Ok(())
}
