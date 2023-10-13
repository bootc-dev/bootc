use std::process::Command;

use anyhow::Result;
use camino::{Utf8Path, Utf8PathBuf};
use cap_std::fs::Dir;
use cap_std_ext::cap_std;
use fn_error_context::context;
use rustix::fd::AsFd;
use xshell::{cmd, Shell};

use super::cli::TestingOpts;
use super::spec::Host;

const IMGSIZE: u64 = 20 * 1024 * 1024 * 1024;

struct LoopbackDevice {
    #[allow(dead_code)]
    tmpf: tempfile::NamedTempFile,
    dev: Utf8PathBuf,
}

impl LoopbackDevice {
    fn new_temp(sh: &xshell::Shell) -> Result<Self> {
        let mut tmpd = tempfile::NamedTempFile::new_in("/var/tmp")?;
        rustix::fs::ftruncate(tmpd.as_file_mut().as_fd(), IMGSIZE)?;
        let diskpath = tmpd.path();
        let path = cmd!(sh, "losetup --find --show {diskpath}").read()?;
        Ok(Self {
            tmpf: tmpd,
            dev: path.into(),
        })
    }
}

impl Drop for LoopbackDevice {
    fn drop(&mut self) {
        let _ = Command::new("losetup")
            .args(["-d", self.dev.as_str()])
            .status();
    }
}

fn init_ostree(sh: &Shell, rootfs: &Utf8Path) -> Result<()> {
    cmd!(sh, "ostree admin init-fs --modern {rootfs}").run()?;
    Ok(())
}

#[context("bootc status")]
fn run_bootc_status() -> Result<()> {
    let sh = Shell::new()?;

    let loopdev = LoopbackDevice::new_temp(&sh)?;
    let devpath = &loopdev.dev;
    println!("Using {devpath:?}");

    let td = tempfile::tempdir()?;
    let td = td.path();
    let td: &Utf8Path = td.try_into()?;

    cmd!(sh, "mkfs.xfs {devpath}").run()?;
    cmd!(sh, "mount {devpath} {td}").run()?;

    init_ostree(&sh, td)?;

    // Basic sanity test of `bootc status` on an uninitialized root
    let _g = sh.push_env("OSTREE_SYSROOT", td);
    cmd!(sh, "bootc status").run()?;

    Ok(())
}

// This needs nontrivial work for loopback devices
// #[context("bootc install")]
// fn run_bootc_install() -> Result<()> {
//     let sh = Shell::new()?;
//     let loopdev = LoopbackDevice::new_temp(&sh)?;
//     let devpath = &loopdev.dev;
//     println!("Using {devpath:?}");

//     let selinux_enabled = crate::lsm::selinux_enabled()?;
//     let selinux_opt = if selinux_enabled {
//         ""
//     } else {
//         "--disable-selinux"
//     };

//     cmd!(sh, "bootc install {selinux_opt} {devpath}").run()?;

//     Ok(())
// }

/// Tests run an ostree-based host
#[context("Privileged container tests")]
pub(crate) fn impl_run_host() -> Result<()> {
    run_bootc_status()?;
    println!("ok bootc status");
    //run_bootc_install()?;
    //println!("ok bootc install");
    println!("ok host privileged testing");
    Ok(())
}

#[context("Container tests")]
pub(crate) fn impl_run_container() -> Result<()> {
    assert!(ostree_ext::container_utils::is_ostree_container()?);
    let sh = Shell::new()?;
    let host: Host = serde_yaml::from_str(&cmd!(sh, "bootc status").read()?)?;
    let status = host.status.unwrap();
    assert!(status.is_container);
    for c in ["upgrade", "update"] {
        let o = Command::new("bootc").arg(c).output()?;
        let st = o.status;
        assert!(!st.success());
        let stderr = String::from_utf8(o.stderr)?;
        assert!(stderr.contains("this command requires a booted host system"));
    }
    println!("ok container integration testing");
    Ok(())
}

#[context("Container tests")]
fn prep_test_install_filesystem(blockdev: &Utf8Path) -> Result<tempfile::TempDir> {
    let sh = Shell::new()?;
    // Arbitrarily larger partition offsets
    let efipn = "5";
    let bootpn = "6";
    let rootpn = "7";
    let mountpoint_dir = tempfile::tempdir()?;
    let mountpoint: &Utf8Path = mountpoint_dir.path().try_into().unwrap();
    // Create the partition setup; we add some random empty partitions for 2,3,4 just to exercise things
    cmd!(
        sh,
        "sgdisk -Z {blockdev} -n 1:0:+1M -c 1:BIOS-BOOT -t 1:21686148-6449-6E6F-744E-656564454649 -n 2:0:+3M -n 3:0:+2M -n 4:0:+5M -n {efipn}:0:+127M -c {efipn}:EFI-SYSTEM -t ${efipn}:C12A7328-F81F-11D2-BA4B-00A0C93EC93B -n {bootpn}:0:+510M -c {bootpn}:boot -n {rootpn}:0:0 -c {rootpn}:root -t {rootpn}:0FC63DAF-8483-4772-8E79-3D69D8477DE4"
    )
    .run()?;
    // Create filesystems and mount
    cmd!(sh, "mkfs.ext4 {blockdev}{bootpn}").run()?;
    cmd!(sh, "mkfs.ext4 {blockdev}{rootpn}").run()?;
    cmd!(sh, "mkfs.fat {blockdev}{efipn}").run()?;
    cmd!(sh, "mount {blockdev}{rootpn} {mountpoint}").run()?;
    cmd!(sh, "mkdir {mountpoint}/boot").run()?;
    cmd!(sh, "mount {blockdev}{bootpn} {mountpoint}/boot").run()?;
    let efidir = crate::bootloader::EFI_DIR;
    cmd!(sh, "mkdir {mountpoint}/boot/{efidir}").run()?;
    cmd!(sh, "mount {blockdev}{efipn} {mountpoint}/boot/{efidir}").run()?;

    Ok(mountpoint_dir)
}

#[context("Container tests")]
fn test_install_filesystem(image: &str, blockdev: &Utf8Path) -> Result<()> {
    let sh = Shell::new()?;

    let mountpoint_dir = prep_test_install_filesystem(blockdev)?;
    let mountpoint: &Utf8Path = mountpoint_dir.path().try_into().unwrap();

    // And run the install
    cmd!(sh, "podman run --rm --privileged --pid=host --net=none --env=RUST_LOG -v /usr/bin/bootc:/usr/bin/bootc -v /usr/lib/bootc:/usr/lib/bootc -v {mountpoint}:/target-root {image} bootc install-to-filesystem /target-root").run()?;

    cmd!(sh, "umount -R {mountpoint}").run()?;

    Ok(())
}

pub(crate) async fn run(opts: TestingOpts) -> Result<()> {
    match opts {
        TestingOpts::RunPrivilegedIntegration {} => {
            crate::cli::ensure_self_unshared_mount_namespace().await?;
            tokio::task::spawn_blocking(impl_run_host).await?
        }
        TestingOpts::RunContainerIntegration {} => {
            tokio::task::spawn_blocking(impl_run_container).await?
        }
        TestingOpts::CopySelfTo { target } => {
            let src_root = &Dir::open_ambient_dir("/", cap_std::ambient_authority())?;
            let target = &Dir::open_ambient_dir(target, cap_std::ambient_authority())?;
            let container_info = crate::containerenv::get_container_execution_info(src_root)?;
            let srcdata = crate::install::SourceInfo::from_container(&container_info)?;
            let (did_override, _guard) =
                crate::install::reexecute_self_for_selinux_if_needed(&srcdata, false)?;
            // Right now we don't expose an override flow
            assert!(!did_override);
            crate::systemtakeover::copy_self_to(&srcdata, target).await?;
            Ok(())
        }
        TestingOpts::PrepTestInstallFilesystem { blockdev } => {
            tokio::task::spawn_blocking(move || prep_test_install_filesystem(&blockdev).map(|_| ()))
                .await?
        }
        TestingOpts::TestInstallFilesystem { image, blockdev } => {
            crate::cli::ensure_self_unshared_mount_namespace().await?;
            tokio::task::spawn_blocking(move || test_install_filesystem(&image, &blockdev)).await?
        }
    }
}
