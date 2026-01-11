use anyhow::{Context, Result, anyhow};
use fn_error_context::context;
use libtest_mimic::Trial;
use rexpect::session::PtySession;
use rustix::fs::statfs;
use std::{
    fs::{self},
    path::Path,
    time::Duration,
};

use crate::install;

/// A generous timeout since some CI runs may be slower
const TIMEOUT: Duration = std::time::Duration::from_secs(5 * 60);

fn get_deployment_dir() -> Result<std::path::PathBuf> {
    let base_path = Path::new("/ostree/deploy/default/deploy");

    let entries: Vec<fs::DirEntry> = fs::read_dir(base_path)
        .with_context(|| format!("Failed to read directory: {}", base_path.display()))?
        .filter_map(|entry| match entry {
            Ok(e) if e.path().is_dir() => Some(e),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert_eq!(
        entries.len(),
        1,
        "Expected exactly one deployment directory"
    );

    let deploy_dir_entry = &entries[0];
    assert!(
        deploy_dir_entry.file_type()?.is_dir(),
        "deployment directory entry is not a directory: {}",
        base_path.display()
    );

    let hash = deploy_dir_entry.file_name();
    let hash_str = hash
        .to_str()
        .ok_or_else(|| anyhow!("Deployment directory name {:?} is not valid UTF-8", hash))?;

    println!("Using deployment directory: {hash_str}");

    Ok(base_path.join(hash_str))
}

#[context("System reinstall tests")]
pub(crate) fn run(image: &str, testargs: libtest_mimic::Arguments) -> Result<()> {
    // Just leak the image name so we get a static reference as required by the test framework
    let image: &'static str = String::from(image).leak();

    let tests = [
        Trial::test("default behavior", move || {
            let sh = &xshell::Shell::new()?;
            install::reset_root(sh, image)?;

            let mut p: PtySession = rexpect::spawn(
                format!("/usr/bin/system-reinstall-bootc {image}").as_str(),
                Some(TIMEOUT.as_millis().try_into().unwrap()),
            )?;

            // Basic flow stdout verification
            p.exp_string(
                format!("Image {image} is already present locally, skipping pull.").as_str(),
            )?;
            p.exp_regex("Found only one user ([^:]+) with ([\\d]+) SSH authorized keys.")?;
            p.exp_string("Would you like to import its SSH authorized keys")?;
            p.exp_string("into the root user on the new bootc system?")?;
            p.exp_string("Then you can login as root@ using those keys. [Y/n]")?;
            p.send_line("y")?;

            p.exp_string("Going to run command:")?;

            p.exp_regex(format!("podman run --privileged --pid=host --user=root:root -v /var/lib/containers:/var/lib/containers -v /dev:/dev --security-opt label=type:unconfined_t -v /:/target -v /tmp/([^:]+):/bootc_authorized_ssh_keys/root {image} bootc install to-existing-root --acknowledge-destructive --skip-fetch-check --cleanup --root-ssh-authorized-keys /bootc_authorized_ssh_keys/root").as_str())?;
            p.exp_string("NOTICE: This will replace the installed operating system and reboot. Are you sure you want to continue? [y/N]")?;

            p.send_line("y")?;

            p.exp_string(format!("Installing image: docker://{image}").as_str())?;
            p.exp_string("Initializing ostree layout")?;
            p.exp_string("Operation complete, rebooting in 10 seconds. Press Ctrl-C to cancel reboot, or press enter to continue immediately.")?;
            p.send_control('c')?;

            p.exp_eof()?;

            install::generic_post_install_verification()?;

            // Check for destructive cleanup and ssh key files
            let target_deployment_dir =
                get_deployment_dir().with_context(|| "Failed to get deployment directory")?;

            let files = [
                "usr/lib/bootc/fedora-bootc-destructive-cleanup",
                "usr/lib/systemd/system/bootc-destructive-cleanup.service",
                "etc/tmpfiles.d/bootc-root-ssh.conf",
            ];

            for f in files {
                let full_path = target_deployment_dir.join(f);
                assert!(
                    full_path.exists(),
                    "File not found: {}",
                    full_path.display()
                );
            }

            Ok(())
        }),
        Trial::test("disk space check", move || {
            let sh = &xshell::Shell::new()?;
            install::reset_root(sh, image)?;

            // Allocate a file with the size of the available space on the root partition
            let stat = statfs("/")?;
            let available_space_bytes: u64 = stat.f_bsize as u64 * stat.f_bavail as u64;
            let file_size = available_space_bytes - (250 * 1024 * 1024); //leave 250 MiB free

            let tempfile = tempfile::Builder::new().tempfile_in("/")?;
            let tempfile_path = tempfile.path();

            let file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(tempfile_path)?;

            rustix::fs::fallocate(&file, rustix::fs::FallocateFlags::empty(), 0, file_size)?;

            // Run system-reinstall-bootc
            let mut p: PtySession = rexpect::spawn(
                format!("/usr/bin/system-reinstall-bootc {image}").as_str(),
                Some(TIMEOUT.as_millis().try_into().unwrap()),
            )?;

            p.exp_regex("Found only one user ([^:]+) with ([\\d]+) SSH authorized keys.")?;
            p.exp_string("[Y/n]")?;
            p.send_line("y")?;
            p.exp_string("NOTICE: This will replace the installed operating system and reboot. Are you sure you want to continue? [y/N]")?;
            p.send_line("y")?;
            p.exp_string("Insufficient free space")?;
            p.exp_eof()?;
            Ok(())
        }),
        Trial::test("image pull check", move || {
            let sh = &xshell::Shell::new()?;
            install::reset_root(sh, image)?;

            // Run system-reinstall-bootc
            let mut p: PtySession = rexpect::spawn(
                "/usr/bin/system-reinstall-bootc quay.io/centos-bootc/centos-bootc:stream9",
                Some(600000), // Increase timeout for pulling the image
            )?;

            p.exp_string("Image quay.io/centos-bootc/centos-bootc:stream9 is not present locally, pulling it now.")?;
            p.exp_regex("Found only one user ([^:]+) with ([\\d]+) SSH authorized keys.")?;
            p.exp_string("[Y/n]")?;
            p.send_line("y")?;
            p.exp_string("NOTICE: This will replace the installed operating system and reboot. Are you sure you want to continue? [y/N]")?;
            p.send_line("y")?;
            p.exp_string("Operation complete, rebooting in 10 seconds. Press Ctrl-C to cancel reboot, or press enter to continue immediately.")?;
            p.send_control('c')?;
            p.exp_eof()?;
            Ok(())
        }),
    ];

    libtest_mimic::run(&testargs, tests.into()).exit()
}
