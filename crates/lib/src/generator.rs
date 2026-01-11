use std::io::BufRead;

use anyhow::{Context, Result};
use camino::Utf8PathBuf;
use cap_std::fs::Dir;
use cap_std_ext::{cap_std, dirext::CapStdExtDirExt};
use fn_error_context::context;
use ostree_ext::container_utils::{OSTREE_BOOTED, is_ostree_booted_in};
use rustix::{fd::AsFd, fs::StatVfsMountFlags};

use crate::install::DESTRUCTIVE_CLEANUP;

const STATUS_ONBOOT_UNIT: &str = "bootc-status-updated-onboot.target";
const STATUS_PATH_UNIT: &str = "bootc-status-updated.path";
const CLEANUP_UNIT: &str = "bootc-destructive-cleanup.service";
const MULTI_USER_TARGET: &str = "multi-user.target";
const EDIT_UNIT: &str = "bootc-fstab-edit.service";
const FSTAB_ANACONDA_STAMP: &str = "Created by anaconda";
pub(crate) const BOOTC_EDITED_STAMP: &str = "Updated by bootc-fstab-edit.service";

/// Called when the root is read-only composefs to reconcile /etc/fstab
#[context("bootc generator")]
pub(crate) fn fstab_generator_impl(root: &Dir, unit_dir: &Dir) -> Result<bool> {
    // Do nothing if not ostree-booted
    if !is_ostree_booted_in(root)? {
        return Ok(false);
    }

    if let Some(fd) = root
        .open_optional("etc/fstab")
        .context("Opening /etc/fstab")?
        .map(std::io::BufReader::new)
    {
        let mut from_anaconda = false;
        for line in fd.lines() {
            let line = line.context("Reading /etc/fstab")?;
            if line.contains(BOOTC_EDITED_STAMP) {
                // We're done
                return Ok(false);
            }
            if line.contains(FSTAB_ANACONDA_STAMP) {
                from_anaconda = true;
            }
        }
        if !from_anaconda {
            return Ok(false);
        }
        tracing::debug!("/etc/fstab from anaconda: {from_anaconda}");
        if from_anaconda {
            generate_fstab_editor(unit_dir)?;
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn enable_unit(unitdir: &Dir, name: &str, target: &str) -> Result<()> {
    let wants = Utf8PathBuf::from(format!("{target}.wants"));
    unitdir
        .create_dir_all(&wants)
        .with_context(|| format!("Creating {wants}"))?;
    let source = format!("/usr/lib/systemd/system/{name}");
    let target = wants.join(name);
    unitdir.remove_file_optional(&target)?;
    unitdir
        .symlink_contents(&source, &target)
        .with_context(|| format!("Writing {name}"))?;
    Ok(())
}

/// Enable our units
pub(crate) fn unit_enablement_impl(sysroot: &Dir, unit_dir: &Dir) -> Result<()> {
    for unit in [STATUS_ONBOOT_UNIT, STATUS_PATH_UNIT] {
        enable_unit(unit_dir, unit, MULTI_USER_TARGET)?;
    }

    if sysroot.try_exists(DESTRUCTIVE_CLEANUP)? {
        tracing::debug!("Found {DESTRUCTIVE_CLEANUP}");
        enable_unit(unit_dir, CLEANUP_UNIT, MULTI_USER_TARGET)?;
    } else {
        tracing::debug!("Didn't find {DESTRUCTIVE_CLEANUP}");
    }

    Ok(())
}

/// Main entrypoint for the generator
pub(crate) fn generator(root: &Dir, unit_dir: &Dir) -> Result<()> {
    // Only run on ostree systems
    if !root.try_exists(OSTREE_BOOTED)? {
        return Ok(());
    }

    let Some(ref sysroot) = root.open_dir_optional("sysroot")? else {
        return Ok(());
    };

    unit_enablement_impl(sysroot, unit_dir)?;

    // Also only run if the root is a read-only overlayfs (a composefs really)
    let st = rustix::fs::fstatfs(root.as_fd())?;
    if st.f_type != libc::OVERLAYFS_SUPER_MAGIC {
        tracing::trace!("Root is not overlayfs");
        return Ok(());
    }
    let st = rustix::fs::fstatvfs(root.as_fd())?;
    if !st.f_flag.contains(StatVfsMountFlags::RDONLY) {
        tracing::trace!("Root is writable");
        return Ok(());
    }
    let updated = fstab_generator_impl(root, unit_dir)?;
    tracing::trace!("Generated fstab: {updated}");

    Ok(())
}

/// Parse /etc/fstab and check if the root mount is out of sync with the composefs
/// state, and if so, fix it.
fn generate_fstab_editor(unit_dir: &Dir) -> Result<()> {
    unit_dir.atomic_write(
        EDIT_UNIT,
        "[Unit]\n\
DefaultDependencies=no\n\
After=systemd-fsck-root.service\n\
Before=local-fs-pre.target local-fs.target shutdown.target systemd-remount-fs.service\n\
\n\
[Service]\n\
Type=oneshot\n\
RemainAfterExit=yes\n\
ExecStart=bootc internals fixup-etc-fstab\n\
",
    )?;
    let target = "local-fs-pre.target.wants";
    unit_dir.create_dir_all(target)?;
    unit_dir.symlink(&format!("../{EDIT_UNIT}"), &format!("{target}/{EDIT_UNIT}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use camino::Utf8Path;

    use super::*;

    fn fixture() -> Result<cap_std_ext::cap_tempfile::TempDir> {
        let tempdir = cap_std_ext::cap_tempfile::tempdir(cap_std::ambient_authority())?;
        tempdir.create_dir("etc")?;
        tempdir.create_dir("run")?;
        tempdir.create_dir("sysroot")?;
        tempdir.create_dir_all("run/systemd/system")?;
        Ok(tempdir)
    }

    #[test]
    fn test_generator_no_fstab() -> Result<()> {
        let tempdir = fixture()?;
        let unit_dir = &tempdir.open_dir("run/systemd/system")?;
        fstab_generator_impl(&tempdir, &unit_dir).unwrap();

        assert_eq!(unit_dir.entries()?.count(), 0);
        Ok(())
    }

    #[test]
    fn test_units() -> Result<()> {
        let tempdir = &fixture()?;
        let sysroot = &tempdir.open_dir("sysroot").unwrap();
        let unit_dir = &tempdir.open_dir("run/systemd/system")?;

        let verify = |wantsdir: &Dir, n: u32| -> Result<()> {
            assert_eq!(unit_dir.entries()?.count(), 1);
            let r = wantsdir.read_link_contents(STATUS_ONBOOT_UNIT)?;
            let r: Utf8PathBuf = r.try_into().unwrap();
            assert_eq!(r, format!("/usr/lib/systemd/system/{STATUS_ONBOOT_UNIT}"));
            assert_eq!(wantsdir.entries()?.count(), n as usize);
            anyhow::Ok(())
        };

        // Explicitly run this twice to test idempotency

        unit_enablement_impl(sysroot, &unit_dir).unwrap();
        unit_enablement_impl(sysroot, &unit_dir).unwrap();
        let wantsdir = &unit_dir.open_dir("multi-user.target.wants")?;
        verify(wantsdir, 2)?;
        assert!(
            wantsdir
                .symlink_metadata_optional(CLEANUP_UNIT)
                .unwrap()
                .is_none()
        );

        // Now create sysroot and rerun the generator
        unit_enablement_impl(sysroot, &unit_dir).unwrap();
        verify(wantsdir, 2)?;

        // Create the destructive stamp
        sysroot
            .create_dir_all(Utf8Path::new(DESTRUCTIVE_CLEANUP).parent().unwrap())
            .unwrap();
        sysroot.atomic_write(DESTRUCTIVE_CLEANUP, b"").unwrap();
        unit_enablement_impl(sysroot, unit_dir).unwrap();
        verify(wantsdir, 3)?;

        // And now the unit should be enabled
        assert!(
            wantsdir
                .symlink_metadata(CLEANUP_UNIT)
                .unwrap()
                .is_symlink()
        );

        Ok(())
    }

    #[cfg(test)]
    mod test {
        use super::*;

        use ostree_ext::container_utils::OSTREE_BOOTED;

        #[test]
        fn test_generator_fstab() -> Result<()> {
            let tempdir = fixture()?;
            let unit_dir = &tempdir.open_dir("run/systemd/system")?;
            // Should still be a no-op
            tempdir.atomic_write("etc/fstab", "# Some dummy fstab")?;
            fstab_generator_impl(&tempdir, &unit_dir).unwrap();
            assert_eq!(unit_dir.entries()?.count(), 0);

            // Also a no-op, not booted via ostree
            tempdir.atomic_write("etc/fstab", &format!("# {FSTAB_ANACONDA_STAMP}"))?;
            fstab_generator_impl(&tempdir, &unit_dir).unwrap();
            assert_eq!(unit_dir.entries()?.count(), 0);

            // Now it should generate
            tempdir.atomic_write(OSTREE_BOOTED, "ostree booted")?;
            fstab_generator_impl(&tempdir, &unit_dir).unwrap();
            assert_eq!(unit_dir.entries()?.count(), 2);

            Ok(())
        }

        #[test]
        fn test_generator_fstab_idempotent() -> Result<()> {
            let anaconda_fstab = indoc::indoc! { "
#
# /etc/fstab
# Created by anaconda on Tue Mar 19 12:24:29 2024
#
# Accessible filesystems, by reference, are maintained under '/dev/disk/'.
# See man pages fstab(5), findfs(8), mount(8) and/or blkid(8) for more info.
#
# After editing this file, run 'systemctl daemon-reload' to update systemd
# units generated from this file.
#
# Updated by bootc-fstab-edit.service
UUID=715be2b7-c458-49f2-acec-b2fdb53d9089 /                       xfs     ro              0 0
UUID=341c4712-54e8-4839-8020-d94073b1dc8b /boot                   xfs     defaults        0 0
" };
            let tempdir = fixture()?;
            let unit_dir = &tempdir.open_dir("run/systemd/system")?;

            tempdir.atomic_write("etc/fstab", anaconda_fstab)?;
            tempdir.atomic_write(OSTREE_BOOTED, "ostree booted")?;
            let updated = fstab_generator_impl(&tempdir, &unit_dir).unwrap();
            assert!(!updated);
            assert_eq!(unit_dir.entries()?.count(), 0);

            Ok(())
        }
    }
}
