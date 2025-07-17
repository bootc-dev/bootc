use std::io::BufRead;

use anyhow::{Context, Result};
use cap_std::fs::Dir;
use cap_std_ext::{cap_std, dirext::CapStdExtDirExt};
use fn_error_context::context;
use ostree_ext::container_utils::is_ostree_booted_in;
use rustix::{fd::AsFd, fs::StatVfsMountFlags};

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

/// Main entrypoint for the generator
pub(crate) fn generator(root: &Dir, unit_dir: &Dir) -> Result<()> {
    // Right now we only do something if the root is a read-only overlayfs (a composefs really)
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
Conflicts=shutdown.target\n\
After=systemd-fsck-root.service\n\
Before=local-fs-pre.target local-fs.target shutdown.target systemd-remount-fs.service\n\
Wants=local-fs-pre.target\n\
\n\
[Service]\n\
Type=oneshot\n\
RemainAfterExit=yes\n\
ExecStart=bootc internals fixup-etc-fstab\n\
",
    )?;
    let target = "local-fs.target.wants";
    unit_dir.create_dir_all(target)?;
    unit_dir.symlink(&format!("../{EDIT_UNIT}"), &format!("{target}/{EDIT_UNIT}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Result<cap_std_ext::cap_tempfile::TempDir> {
        let tempdir = cap_std_ext::cap_tempfile::tempdir(cap_std::ambient_authority())?;
        tempdir.create_dir("etc")?;
        tempdir.create_dir("run")?;
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
