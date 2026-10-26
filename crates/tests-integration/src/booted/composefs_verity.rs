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
        Algorithm, EnableVerityError, FsVerityHashValue, MeasureVerityError, Sha512HashValue,
        enable_verity_raw, measure_verity_opt,
    },
    mountcompat::prepare_mount,
    repository::{Repository, RepositoryConfig},
    tree::{FileSystem, Inode, LeafContent, RegularFile, Stat},
};
use rustix::{
    fs::{Mode, OFlags, openat},
    io::Errno,
    mount::{MountPropagationFlags, mount_change},
    thread::{UnshareFlags, unshare_unsafe},
};

#[derive(Clone, Copy, Debug)]
enum Tamper {
    None,
    Image,
    ImageAndMetadata,
    Data,
    RefDigest,
    RefVerity,
}

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

fn check_case(parent: &Path, metadata_verity: bool, tamper: Tamper, relaxed: bool) -> Result<()> {
    let tmp = tempfile::tempdir_in(parent)?;
    let sysroot: OwnedFd = File::open(tmp.path())?.into();
    let config = RepositoryConfig::new(Algorithm::SHA512);
    let config = if metadata_verity {
        config
    } else {
        config.set_insecure()
    };
    let (repo, _) = Repository::<Sha512HashValue>::init_path(&sysroot, "composefs", config)?;
    let repo_path = tmp.path().join("composefs");
    ensure!(repo.is_insecure() != metadata_verity);

    let contents = b"original data\n".repeat(1024);
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

    match tamper {
        Tamper::None => {}
        Tamper::Image => strip_verity(&image_path)?,
        Tamper::ImageAndMetadata => {
            strip_verity(&repo_path.join("meta.json"))?;
            strip_verity(&image_path)?;
            replace(&object_path, &vec![b'x'; contents.len()])?;
        }
        Tamper::Data => replace(&object_path, &vec![b'x'; contents.len()])?,
        Tamper::RefDigest => {
            tree.root.stat.st_mtim_sec += 1;
            let other_image =
                mkfs_erofs_versioned(&ValidatedFileSystem::new(tree)?, FormatVersion::V1);
            let other = repo.write_image(Some(&digest), &other_image)?.to_hex();
            ensure!(other != digest);
            fs::remove_file(&image_link)?;
        }
        Tamper::RefVerity => {
            fs::create_dir_all(repo_path.join("images/refs"))?;
            fs::write(repo_path.join("images/refs").join(&digest), &image)?;
            fs::remove_file(&image_link)?;
        }
    }
    drop(repo);

    let mounted = mount_composefs_image(&sysroot, &digest, relaxed);
    if !relaxed
        && matches!(
            tamper,
            Tamper::Image | Tamper::ImageAndMetadata | Tamper::RefVerity
        )
    {
        let error = mounted.err().context("unverified image was mounted")?;
        ensure!(
            matches!(
                error.downcast_ref::<MeasureVerityError>(),
                Some(MeasureVerityError::VerityMissing)
            ),
            "Unexpected error: {error:#}"
        );
    } else if matches!(tamper, Tamper::RefDigest) {
        let error = mounted
            .err()
            .context("a different image under the pinned ref was mounted")?;
        ensure!(
            format!("{error:#}").contains("composefs image fs-verity digest mismatch"),
            "Unexpected error: {error:#}"
        );
    } else {
        let root = prepare_mount(mounted?)?;
        let data = read_data(&root);
        if matches!(tamper, Tamper::Data) {
            let error = data.err().context("tampered object was readable")?;
            ensure!(
                error.raw_os_error() == Some(Errno::IO.raw_os_error()),
                "Unexpected read error: {error}"
            );
        } else if relaxed && matches!(tamper, Tamper::ImageAndMetadata) {
            ensure!(data? == vec![b'x'; contents.len()]);
        } else {
            ensure!(data? == contents);
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
    for metadata_verity in [true, false] {
        for tamper in [
            Tamper::None,
            Tamper::Image,
            Tamper::ImageAndMetadata,
            Tamper::Data,
            Tamper::RefDigest,
            Tamper::RefVerity,
        ] {
            check_case(tmp.path(), metadata_verity, tamper, false)
                .with_context(|| format!("metadata_verity={metadata_verity}, tamper={tamper:?}"))?;
        }
    }
    check_case(tmp.path(), false, Tamper::ImageAndMetadata, true)
        .context("explicitly relaxed command line")?;
    super::tap_ok();
    Ok(())
}
