use std::os::fd::AsRawFd;
use std::path::Path;

use anyhow::Result;
use camino::Utf8Path;
use cap_std_ext::cap_std;
use cap_std_ext::cap_std::fs::Dir;
use fn_error_context::context;
use libtest_mimic::Trial;
use xshell::{Shell, cmd};

pub(crate) const BASE_ARGS: &[&str] = &["podman", "run", "--rm", "--privileged", "--pid=host"];

// Arbitrary
const NON_DEFAULT_STATEROOT: &str = "foo";

/// Clear out and delete any ostree roots, leverage bootc hidden wipe-ostree command to get rid of
/// otherwise hard to delete deployment files
pub(crate) fn reset_root(sh: &Shell, image: &str) -> Result<()> {
    delete_ostree_deployments(sh, image)?;
    delete_ostree(sh)?;
    Ok(())
}

pub(crate) fn delete_ostree(sh: &Shell) -> Result<(), anyhow::Error> {
    if !Path::new("/ostree/").exists() {
        return Ok(());
    }
    // TODO: This shouldn't be leaking out of installs
    cmd!(sh, "sudo umount -Rl /ostree/bootc/storage/overlay")
        .ignore_status()
        .run()?;
    cmd!(sh, "sudo /bin/sh -c 'rm -rf /ostree/'").run()?;
    Ok(())
}

fn delete_ostree_deployments(sh: &Shell, image: &str) -> Result<(), anyhow::Error> {
    if !Path::new("/ostree/deploy/").exists() {
        return Ok(());
    }
    let mounts = &["-v", "/ostree:/sysroot/ostree", "-v", "/boot:/boot"];
    cmd!(
        sh,
        "sudo {BASE_ARGS...} {mounts...} {image} bootc state wipe-ostree"
    )
    .run()?;
    cmd!(sh, "sudo /bin/sh -c 'rm -rf /ostree/deploy/*'").run()?;
    Ok(())
}

fn find_deployment_root() -> Result<Dir> {
    let _stateroot = "default";
    let d = Dir::open_ambient_dir(
        "/ostree/deploy/default/deploy",
        cap_std::ambient_authority(),
    )?;
    for child in d.entries()? {
        let child = child?;
        if !child.file_type()?.is_dir() {
            continue;
        }
        return Ok(child.open_dir()?);
    }
    anyhow::bail!("Failed to find deployment root")
}

// Hook relatively cheap post-install tests here
pub(crate) fn generic_post_install_verification() -> Result<()> {
    assert!(Utf8Path::new("/ostree/repo").try_exists()?);
    assert!(Utf8Path::new("/ostree/bootc/storage/overlay").try_exists()?);
    Ok(())
}

#[context("Install tests")]
pub(crate) fn run_alongside(image: &str, mut testargs: libtest_mimic::Arguments) -> Result<()> {
    // Force all of these tests to be serial because they mutate global state
    testargs.test_threads = Some(1);
    // Just leak the image name so we get a static reference as required by the test framework
    let image: &'static str = String::from(image).leak();
    // Handy defaults

    let target_args = &["-v", "/:/target"];

    let tests = [
        Trial::test("loopback install", move || {
            let sh = &xshell::Shell::new()?;
            reset_root(sh, image)?;
            let size = 10 * 1000 * 1000 * 1000;
            let mut tmpdisk = tempfile::NamedTempFile::new_in("/var/tmp")?;
            tmpdisk.as_file_mut().set_len(size)?;
            let tmpdisk = tmpdisk.into_temp_path();
            let tmpdisk = tmpdisk.to_str().unwrap();
            cmd!(sh, "sudo {BASE_ARGS...} -v {tmpdisk}:/disk {image} bootc install to-disk --via-loopback /disk").run()?;
            Ok(())
        }),
        Trial::test(
            "install to-filesystem with separate /var mount",
            move || {
                let sh = &xshell::Shell::new()?;
                reset_root(sh, image)?;

                // Create work directory for the test
                let tmpd = sh.create_temp_dir()?;
                let work_dir = tmpd.path();

                // Create a disk image with partitions for root and var
                let disk_img = work_dir.join("disk.img");
                let size = 12 * 1024 * 1024 * 1024;
                let disk_file = std::fs::File::create(&disk_img)?;
                disk_file.set_len(size)?;
                drop(disk_file);

                // Setup loop device
                let loop_dev = cmd!(sh, "sudo losetup -f --show {disk_img}")
                    .read()?
                    .trim()
                    .to_string();

                // Helper closure for cleanup
                let cleanup = |sh: &Shell, loop_dev: &str, target: &str| {
                    // Unmount filesystems
                    let _ = cmd!(sh, "sudo umount -R {target}").ignore_status().run();
                    // Deactivate LVM
                    let _ = cmd!(sh, "sudo vgchange -an BL").ignore_status().run();
                    let _ = cmd!(sh, "sudo vgremove -f BL").ignore_status().run();
                    // Detach loop device
                    let _ = cmd!(sh, "sudo losetup -d {loop_dev}").ignore_status().run();
                };

                // Create partition table
                if let Err(e) = (|| -> Result<()> {
                    cmd!(sh, "sudo parted -s {loop_dev} mklabel gpt").run()?;
                    // Create BIOS boot partition (for GRUB on GPT)
                    cmd!(sh, "sudo parted -s {loop_dev} mkpart primary 1MiB 2MiB").run()?;
                    cmd!(sh, "sudo parted -s {loop_dev} set 1 bios_grub on").run()?;
                    // Create EFI partition
                    cmd!(
                        sh,
                        "sudo parted -s {loop_dev} mkpart primary fat32 2MiB 202MiB"
                    )
                    .run()?;
                    cmd!(sh, "sudo parted -s {loop_dev} set 2 esp on").run()?;
                    // Create boot partition
                    cmd!(
                        sh,
                        "sudo parted -s {loop_dev} mkpart primary ext4 202MiB 1226MiB"
                    )
                    .run()?;
                    // Create LVM partition
                    cmd!(sh, "sudo parted -s {loop_dev} mkpart primary 1226MiB 100%").run()?;

                    // Reload partition table
                    cmd!(sh, "sudo partprobe {loop_dev}").run()?;
                    std::thread::sleep(std::time::Duration::from_secs(2));

                    let loop_part2 = format!("{}p2", loop_dev); // EFI
                    let loop_part3 = format!("{}p3", loop_dev); // Boot
                    let loop_part4 = format!("{}p4", loop_dev); // LVM

                    // Create filesystems on boot partitions
                    cmd!(sh, "sudo mkfs.vfat -F32 {loop_part2}").run()?;
                    cmd!(sh, "sudo mkfs.ext4 -F {loop_part3}").run()?;

                    // Setup LVM
                    cmd!(sh, "sudo pvcreate {loop_part4}").run()?;
                    cmd!(sh, "sudo vgcreate BL {loop_part4}").run()?;

                    // Create logical volumes
                    cmd!(sh, "sudo lvcreate -L 4G -n var02 BL").run()?;
                    cmd!(sh, "sudo lvcreate -L 5G -n root02 BL").run()?;

                    // Create filesystems on logical volumes
                    cmd!(sh, "sudo mkfs.ext4 -F /dev/BL/var02").run()?;
                    cmd!(sh, "sudo mkfs.ext4 -F /dev/BL/root02").run()?;

                    // Get UUIDs
                    let root_uuid = cmd!(sh, "sudo blkid -s UUID -o value /dev/BL/root02")
                        .read()?
                        .trim()
                        .to_string();
                    let boot_uuid = cmd!(sh, "sudo blkid -s UUID -o value {loop_part2}")
                        .read()?
                        .trim()
                        .to_string();

                    // Mount the partitions
                    let target_dir = work_dir.join("target");
                    std::fs::create_dir_all(&target_dir)?;
                    let target = target_dir.to_str().unwrap();

                    cmd!(sh, "sudo mount /dev/BL/root02 {target}").run()?;
                    cmd!(sh, "sudo mkdir -p {target}/boot").run()?;
                    cmd!(sh, "sudo mount {loop_part3} {target}/boot").run()?;
                    cmd!(sh, "sudo mkdir -p {target}/boot/efi").run()?;
                    cmd!(sh, "sudo mount {loop_part2} {target}/boot/efi").run()?;

                    // Critical: Mount /var as a separate partition
                    cmd!(sh, "sudo mkdir -p {target}/var").run()?;
                    cmd!(sh, "sudo mount /dev/BL/var02 {target}/var").run()?;

                    // Run bootc install to-filesystem
                    // This should succeed and handle the separate /var mount correctly
                    // Mount the target at /target inside the container for simplicity
                    cmd!(
                    sh,
                    "sudo {BASE_ARGS...} -v {target}:/target -v /dev:/dev {image} bootc install to-filesystem --karg=root=UUID={root_uuid} --root-mount-spec=UUID={root_uuid} --boot-mount-spec=UUID={boot_uuid} /target"
                )
                .run()?;

                    // Verify the installation succeeded
                    // Check that bootc created the necessary files
                    cmd!(sh, "sudo test -d {target}/ostree").run()?;
                    cmd!(sh, "sudo test -d {target}/ostree/repo").run()?;
                    // Verify bootloader was installed
                    cmd!(sh, "sudo test -d {target}/boot/grub2").run()?;

                    Ok(())
                })() {
                    let target = work_dir.join("target");
                    let target_str = target.to_str().unwrap();
                    cleanup(sh, &loop_dev, target_str);
                    return Err(e.into());
                }

                // Clean up on success
                let target = work_dir.join("target");
                let target_str = target.to_str().unwrap();
                cleanup(sh, &loop_dev, target_str);

                Ok(())
            },
        ),
        Trial::test(
            "replace=alongside with ssh keys and a karg, and SELinux disabled",
            move || {
                let sh = &xshell::Shell::new()?;
                reset_root(sh, image)?;
                let tmpd = &sh.create_temp_dir()?;
                let tmp_keys = tmpd.path().join("test_authorized_keys");
                let tmp_keys = tmp_keys.to_str().unwrap();
                std::fs::write(&tmp_keys, b"ssh-ed25519 ABC0123 testcase@example.com")?;
                cmd!(sh, "sudo {BASE_ARGS...} {target_args...} -v {tmp_keys}:/test_authorized_keys {image} bootc install to-filesystem --acknowledge-destructive --karg=foo=bar --replace=alongside --root-ssh-authorized-keys=/test_authorized_keys /target").run()?;

                // Also test install finalize here
                cmd!(
                    sh,
                    "sudo {BASE_ARGS...} {target_args...} {image} bootc install finalize /target"
                )
                .run()?;

                generic_post_install_verification()?;

                // Test kargs injected via CLI
                cmd!(
                    sh,
                    "sudo /bin/sh -c 'grep foo=bar /boot/loader/entries/*.conf'"
                )
                .run()?;
                // And kargs we added into our default container image
                cmd!(
                    sh,
                    "sudo /bin/sh -c 'grep localtestkarg=somevalue /boot/loader/entries/*.conf'"
                )
                .run()?;
                cmd!(
                    sh,
                    "sudo /bin/sh -c 'grep testing-kargsd=3 /boot/loader/entries/*.conf'"
                )
                .run()?;
                let deployment = &find_deployment_root()?;
                let cwd = sh.push_dir(format!("/proc/self/fd/{}", deployment.as_raw_fd()));
                cmd!(
                    sh,
                    "grep authorized_keys etc/tmpfiles.d/bootc-root-ssh.conf"
                )
                .run()?;
                drop(cwd);
                Ok(())
            },
        ),
        Trial::test("Install and verify selinux state", move || {
            let sh = &xshell::Shell::new()?;
            reset_root(sh, image)?;
            cmd!(sh, "sudo {BASE_ARGS...} {image} bootc install to-existing-root --acknowledge-destructive").run()?;
            generic_post_install_verification()?;
            let root = &Dir::open_ambient_dir("/ostree", cap_std::ambient_authority()).unwrap();
            crate::selinux::verify_selinux_recurse(root, false)?;
            Ok(())
        }),
        Trial::test("Install to non-default stateroot", move || {
            let sh = &xshell::Shell::new()?;
            reset_root(sh, image)?;
            cmd!(sh, "sudo {BASE_ARGS...} {image} bootc install to-existing-root --stateroot {NON_DEFAULT_STATEROOT} --acknowledge-destructive").run()?;
            generic_post_install_verification()?;
            assert!(
                Utf8Path::new(&format!("/ostree/deploy/{NON_DEFAULT_STATEROOT}")).try_exists()?
            );
            Ok(())
        }),
        Trial::test("without an install config", move || {
            let sh = &xshell::Shell::new()?;
            reset_root(sh, image)?;
            let empty = sh.create_temp_dir()?;
            let empty = empty.path().to_str().unwrap();
            cmd!(sh, "sudo {BASE_ARGS...} -v {empty}:/usr/lib/bootc/install {image} bootc install to-existing-root").run()?;
            generic_post_install_verification()?;
            Ok(())
        }),
    ];

    libtest_mimic::run(&testargs, tests.into()).exit()
}
