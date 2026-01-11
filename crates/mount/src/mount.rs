//! Helpers for interacting with mountpoints

use std::{
    fs,
    mem::MaybeUninit,
    os::fd::{AsFd, OwnedFd},
    process::Command,
};

use anyhow::{Context, Result, anyhow};
use bootc_utils::CommandRunExt;
use camino::Utf8Path;
use cap_std_ext::{cap_std::fs::Dir, cmdext::CapStdExtCommandExt};
use fn_error_context::context;
use rustix::{
    mount::{MoveMountFlags, OpenTreeFlags},
    net::{
        AddressFamily, RecvFlags, SendAncillaryBuffer, SendAncillaryMessage, SendFlags,
        SocketFlags, SocketType,
    },
    process::WaitOptions,
    thread::Pid,
};
use serde::Deserialize;

pub mod tempmount;

/// Well known identifier for pid 1
pub const PID1: Pid = const {
    match Pid::from_raw(1) {
        Some(v) => v,
        None => panic!("Expected to parse pid1"),
    }
};

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
#[allow(dead_code)]
pub struct Filesystem {
    // Note if you add an entry to this list, you need to change the --output invocation below too
    pub source: String,
    pub target: String,
    #[serde(rename = "maj:min")]
    pub maj_min: String,
    pub fstype: String,
    pub options: String,
    pub uuid: Option<String>,
    pub children: Option<Vec<Filesystem>>,
}

#[derive(Deserialize, Debug, Default)]
pub struct Findmnt {
    pub filesystems: Vec<Filesystem>,
}

pub fn run_findmnt(args: &[&str], cwd: Option<&Dir>, path: Option<&str>) -> Result<Findmnt> {
    let mut cmd = Command::new("findmnt");
    if let Some(cwd) = cwd {
        cmd.cwd_dir(cwd.try_clone()?);
    }
    cmd.args([
        "-J",
        "-v",
        // If you change this you probably also want to change the Filesystem struct above
        "--output=SOURCE,TARGET,MAJ:MIN,FSTYPE,OPTIONS,UUID",
    ])
    .args(args)
    .args(path);
    let o: Findmnt = cmd.log_debug().run_and_parse_json()?;
    Ok(o)
}

// Retrieve a mounted filesystem from a device given a matching path
fn findmnt_filesystem(args: &[&str], cwd: Option<&Dir>, path: &str) -> Result<Filesystem> {
    let o = run_findmnt(args, cwd, Some(path))?;
    o.filesystems
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("findmnt returned no data for {path}"))
}

#[context("Inspecting filesystem {path}")]
/// Inspect a target which must be a mountpoint root - it is an error
/// if the target is not the mount root.
pub fn inspect_filesystem(path: &Utf8Path) -> Result<Filesystem> {
    findmnt_filesystem(&["--mountpoint"], None, path.as_str())
}

#[context("Inspecting filesystem")]
/// Inspect a target which must be a mountpoint root - it is an error
/// if the target is not the mount root.
pub fn inspect_filesystem_of_dir(d: &Dir) -> Result<Filesystem> {
    findmnt_filesystem(&["--mountpoint"], Some(d), ".")
}

#[context("Inspecting filesystem by UUID {uuid}")]
/// Inspect a filesystem by partition UUID
pub fn inspect_filesystem_by_uuid(uuid: &str) -> Result<Filesystem> {
    findmnt_filesystem(&["--source"], None, &(format!("UUID={uuid}")))
}

// Check if a specified device contains an already mounted filesystem
// in the root mount namespace
pub fn is_mounted_in_pid1_mountns(path: &str) -> Result<bool> {
    let o = run_findmnt(&["-N"], None, Some("1"))?;

    let mounted = o.filesystems.iter().any(|fs| is_source_mounted(path, fs));

    Ok(mounted)
}

// Recursively check a given filesystem to see if it contains an already mounted source
pub fn is_source_mounted(path: &str, mounted_fs: &Filesystem) -> bool {
    if mounted_fs.source.contains(path) {
        return true;
    }

    if let Some(ref children) = mounted_fs.children {
        for child in children {
            if is_source_mounted(path, child) {
                return true;
            }
        }
    }

    false
}

/// Mount a device to the target path.
pub fn mount(dev: &str, target: &Utf8Path) -> Result<()> {
    Command::new("mount")
        .args([dev, target.as_str()])
        .run_inherited_with_cmd_context()
}

/// If the fsid of the passed path matches the fsid of the same path rooted
/// at /proc/1/root, it is assumed that these are indeed the same mounted
/// filesystem between container and host.
/// Path should be absolute.
#[context("Comparing filesystems at {path} and /proc/1/root/{path}")]
pub fn is_same_as_host(path: &Utf8Path) -> Result<bool> {
    // Add a leading '/' in case a relative path is passed
    let path = Utf8Path::new("/").join(path);

    // Using statvfs instead of fs, since rustix will translate the fsid field
    // for us.
    let devstat = rustix::fs::statvfs(path.as_std_path())?;
    let hostpath = Utf8Path::new("/proc/1/root").join(path.strip_prefix("/")?);
    let hostdevstat = rustix::fs::statvfs(hostpath.as_std_path())?;
    tracing::trace!(
        "base mount id {:?}, host mount id {:?}",
        devstat.f_fsid,
        hostdevstat.f_fsid
    );
    Ok(devstat.f_fsid == hostdevstat.f_fsid)
}

/// Given a pid, enter its mount namespace and acquire a file descriptor
/// for a mount from that namespace.
#[allow(unsafe_code)]
#[context("Opening mount tree from pid")]
pub fn open_tree_from_pidns(
    pid: rustix::process::Pid,
    path: &Utf8Path,
    recursive: bool,
) -> Result<OwnedFd> {
    // Allocate a socket pair to use for sending file descriptors.
    let (sock_parent, sock_child) = rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .context("socketpair")?;
    const DUMMY_DATA: &[u8] = b"!";
    match unsafe { libc::fork() } {
        0 => {
            // We're in the child. At this point we know we don't have multiple threads, so we
            // can safely `setns`.

            drop(sock_parent);

            // Open up the namespace of the target process as a file descriptor, and enter it.
            let pidlink = fs::File::open(format!("/proc/{}/ns/mnt", pid.as_raw_nonzero()))?;
            rustix::thread::move_into_link_name_space(
                pidlink.as_fd(),
                Some(rustix::thread::LinkNameSpaceType::Mount),
            )
            .context("setns")?;

            // Open the target mount path as a file descriptor.
            let recursive = if recursive {
                OpenTreeFlags::AT_RECURSIVE
            } else {
                OpenTreeFlags::empty()
            };
            let fd = rustix::mount::open_tree(
                rustix::fs::CWD,
                path.as_std_path(),
                OpenTreeFlags::OPEN_TREE_CLOEXEC | OpenTreeFlags::OPEN_TREE_CLONE | recursive,
            )
            .context("open_tree")?;

            // And send that file descriptor via fd passing over the socketpair.
            let fd = fd.as_fd();
            let fds = [fd];
            let mut buffer = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
            let mut control = SendAncillaryBuffer::new(&mut buffer);
            let pushed = control.push(SendAncillaryMessage::ScmRights(&fds));
            assert!(pushed);
            let ios = std::io::IoSlice::new(DUMMY_DATA);
            rustix::net::sendmsg(sock_child, &[ios], &mut control, SendFlags::empty())?;
            // Then we're done.
            std::process::exit(0)
        }
        -1 => {
            // fork failed
            let e = std::io::Error::last_os_error();
            anyhow::bail!("failed to fork: {e}");
        }
        n => {
            // We're in the parent; create a pid (checking that n > 0).
            let pid = rustix::process::Pid::from_raw(n).unwrap();
            drop(sock_child);
            // Receive the mount file descriptor from the child
            let mut cmsg_space = vec![MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
            let mut cmsg_buffer = rustix::net::RecvAncillaryBuffer::new(&mut cmsg_space);
            let mut buf = [0u8; DUMMY_DATA.len()];
            let iov = std::io::IoSliceMut::new(buf.as_mut());
            let mut iov = [iov];
            let nread = rustix::net::recvmsg(
                sock_parent,
                &mut iov,
                &mut cmsg_buffer,
                RecvFlags::CMSG_CLOEXEC,
            )
            .context("recvmsg")?
            .bytes;
            anyhow::ensure!(nread == DUMMY_DATA.len());
            assert_eq!(buf, DUMMY_DATA);
            // And extract the file descriptor
            let r = cmsg_buffer
                .drain()
                .filter_map(|m| match m {
                    rustix::net::RecvAncillaryMessage::ScmRights(f) => Some(f),
                    _ => None,
                })
                .flatten()
                .next()
                .ok_or_else(|| anyhow::anyhow!("Did not receive a file descriptor"))?;
            // SAFETY: Since we're not setting WNOHANG, this will always return Some().
            let st = rustix::process::waitpid(Some(pid), WaitOptions::empty())?
                .expect("Wait status")
                .1;
            if let Some(0) = st.exit_status() {
                Ok(r)
            } else {
                anyhow::bail!("forked helper failed: {st:?}");
            }
        }
    }
}

/// Create a bind mount from the mount namespace of the target pid
/// into our mount namespace.
pub fn bind_mount_from_pidns(
    pid: Pid,
    src: &Utf8Path,
    target: &Utf8Path,
    recursive: bool,
) -> Result<()> {
    let src = open_tree_from_pidns(pid, src, recursive)?;
    rustix::mount::move_mount(
        src.as_fd(),
        "",
        rustix::fs::CWD,
        target.as_std_path(),
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )
    .context("Moving mount")?;
    Ok(())
}

// If the target path is not already mirrored from the host (e.g. via -v /dev:/dev)
// then recursively mount it.
pub fn ensure_mirrored_host_mount(path: impl AsRef<Utf8Path>) -> Result<()> {
    let path = path.as_ref();
    // If we didn't have this in our filesystem already (e.g. for /var/lib/containers)
    // then create it now.
    std::fs::create_dir_all(path)?;
    if is_same_as_host(path)? {
        tracing::debug!("Already mounted from host: {path}");
        return Ok(());
    }
    tracing::debug!("Propagating host mount: {path}");
    bind_mount_from_pidns(PID1, path, path, true)
}
