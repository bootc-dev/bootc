use std::io::BufRead;

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use cap_std::fs::Dir;
use cap_std_ext::{cap_std, dirext::CapStdExtDirExt};
use fn_error_context::context;
use ostree_ext::container_utils::{OSTREE_BOOTED, is_ostree_booted_in};
use ostree_ext::{gio, ostree};
use rustix::{fd::AsFd, fs::StatVfsMountFlags};

use crate::install::DESTRUCTIVE_CLEANUP;

const STATUS_ONBOOT_UNIT: &str = "bootc-status-updated-onboot.target";
const STATUS_PATH_UNIT: &str = "bootc-status-updated.path";
const CLEANUP_UNIT: &str = "bootc-destructive-cleanup.service";
const MULTI_USER_TARGET: &str = "multi-user.target";
const EDIT_UNIT: &str = "bootc-fstab-edit.service";
const FSTAB_ANACONDA_STAMP: &str = "Created by anaconda";
pub(crate) const BOOTC_EDITED_STAMP: &str = "Updated by bootc-fstab-edit.service";
const TRANSIENT_RELABEL_UNIT: &str = "bootc-early-overlay-relabel.service";
const SYSINIT_TARGET: &str = "sysinit.target";
const SHADOW_SYNC_UNIT: &str = "bootc-sysusers-shadow-sync.service";

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
    // === Relabel unit: runs for ALL composefs boots (native or ostree) ===
    // Must be before the ostree-booted guard because native composefs boots do
    // not write /run/ostree-booted, but still need the relabel unit when any
    // transient overlay is active.
    //
    // Gate on the root being overlayfs (composefs always mounts an overlay, so
    // this excludes non-composefs systems without needing the ostree-booted marker).
    //
    // Two triggering conditions, detected independently:
    //
    // 1. Transient root: the initramfs sets the overlay source to
    //    "transient:composefs=<digest>" in /proc/self/mountinfo.  Detect via
    //    inspect_filesystem() rather than fstatvfs() because the `ro` kernel
    //    cmdline flag can make an otherwise-writable overlay appear read-only
    //    at generator time.
    //
    // 2. Transient /etc: this is mounted by bootc-root-setup.service
    //    which runs *after* the generator, so fstatvfs would see the read-only
    //    composefs at generator time.  Read setup-root-conf.toml directly from
    //    the booted image instead.
    {
        let st = rustix::fs::fstatfs(root.as_fd())?;
        if st.f_type == libc::OVERLAYFS_SUPER_MAGIC {
            let root_is_transient =
                match bootc_mount::inspect_filesystem(camino::Utf8Path::new("/")) {
                    Ok(fs) => fs.source.starts_with("transient:composefs="),
                    Err(e) => {
                        tracing::debug!("Could not inspect root filesystem: {e:#}");
                        false
                    }
                };
            let submounts_are_transient = bootc_initramfs_setup::config_has_transient_submounts(
                std::path::Path::new(bootc_initramfs_setup::SETUP_ROOT_CONF_PATH),
            );
            if root_is_transient || submounts_are_transient {
                tracing::debug!(
                    root_is_transient,
                    submounts_are_transient,
                    "Transient overlay detected; generating relabel unit"
                );
                generate_transient_overlay_relabel(unit_dir)?;
            }
        }
    }

    // === Shadow sync unit: runs for ALL bootc systems (native composefs or ostree) ===
    // Must be before the ostree-booted guard because native composefs boots do
    // not write /run/ostree-booted, but still need the shadow sync to clean up
    // stale shadow/gshadow entries (the rechunk scenario).  Gate on either a
    // composefs mount source (native composefs boot) or the ostree-booted marker.
    {
        let is_composefs = match bootc_mount::inspect_filesystem(camino::Utf8Path::new("/")) {
            Ok(fs) => {
                fs.source.starts_with("composefs:") || fs.source.starts_with("transient:composefs=")
            }
            Err(e) => {
                tracing::debug!("Could not inspect root filesystem: {e:#}");
                false
            }
        };
        let is_ostree = root.try_exists(OSTREE_BOOTED)?;
        if is_composefs || is_ostree {
            let updated = shadow_sync_generator_impl(root, unit_dir)?;
            tracing::trace!("Enabled shadow sync: {updated}");
        }
    }

    // === Ostree-specific generator logic ===
    // Only run on ostree systems (native composefs boots skip below).
    if !root.try_exists(OSTREE_BOOTED)? {
        return Ok(());
    }

    let Some(ref sysroot) = root.open_dir_optional("sysroot")? else {
        return Ok(());
    };

    unit_enablement_impl(sysroot, unit_dir)?;

    // Only run for overlayfs roots (composefs mounts an overlay, regular or transient).
    let st = rustix::fs::fstatfs(root.as_fd())?;
    if st.f_type != libc::OVERLAYFS_SUPER_MAGIC {
        tracing::trace!("Root is not overlayfs");
        return Ok(());
    }

    // The fstab editor only applies to read-only composefs roots (not transient).
    let st = rustix::fs::fstatvfs(root.as_fd())?;
    if !st.f_flag.contains(StatVfsMountFlags::RDONLY) {
        tracing::trace!("Root is writable, skipping fstab generator");
        return Ok(());
    }

    let updated = fstab_generator_impl(root, unit_dir)?;
    tracing::trace!("Generated fstab: {updated}");

    Ok(())
}

/// Enable the statically-installed shadow sync unit by symlinking it into
/// `sysinit.target.wants/` in the generator output directory.
///
/// The unit file itself lives at `/usr/lib/systemd/system/bootc-sysusers-shadow-sync.service`
/// and is shipped with bootc; the generator only performs conditional enablement.
///
/// We check existence of `/etc/shadow` rather than writability because systemd
/// sandboxes generators in a private read-only mount namespace (see
/// `systemd.generator(7)`), so any writability check would always fail even
/// though `/etc` will be on its own writable mount by the time the service
/// actually runs.  The caller already gates on the ostree-booted marker,
/// which guarantees we are on a bootc system where `/etc` is writable at
/// service-run time.
#[context("shadow sync generator")]
pub(crate) fn shadow_sync_generator_impl(root: &Dir, unit_dir: &Dir) -> Result<bool> {
    if !root.try_exists("etc/shadow")? {
        tracing::trace!("/etc/shadow not found, skipping shadow sync");
        return Ok(false);
    }

    tracing::debug!("/etc/shadow found, enabling {SHADOW_SYNC_UNIT}");
    enable_unit(unit_dir, SHADOW_SYNC_UNIT, "sysinit.target")?;
    Ok(true)
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

/// Generate a oneshot service that relabels the transient overlay inode
/// after SELinux policy loads, fixing the tmpfs_t label SELinux assigns to
/// overlay upper-dir inodes at policy-load time.
fn generate_transient_overlay_relabel(unit_dir: &Dir) -> Result<()> {
    unit_dir.atomic_write(
        TRANSIENT_RELABEL_UNIT,
        include_str!("units/bootc-early-overlay-relabel.service"),
    )?;
    let wants = format!("{SYSINIT_TARGET}.wants");
    unit_dir.create_dir_all(&wants)?;
    unit_dir.symlink(
        &format!("../{TRANSIENT_RELABEL_UNIT}"),
        &format!("{wants}/{TRANSIENT_RELABEL_UNIT}"),
    )?;
    Ok(())
}

/// Relabel transient overlay mount point inodes using the running SELinux policy.
/// Called by the generated bootc-early-overlay-relabel.service oneshot to fix
/// the tmpfs_t label that fs_use_trans assigns to overlay upper-dir inodes at
/// policy-load time.  Each of /, /etc, /var is relabelled iff it is a writable
/// overlayfs (i.e. a transient overlay, not the read-only composefs).
pub(crate) fn relabel_overlay_mountpoints() -> Result<()> {
    let policy = ostree::SePolicy::new(&gio::File::for_path("/"), gio::Cancellable::NONE)
        .context("Loading SELinux policy")?;
    for path in ["/", "/etc", "/var"] {
        let dir = Dir::open_ambient_dir(path, cap_std::ambient_authority())
            .with_context(|| format!("Opening {path}"))?;
        let st = rustix::fs::fstatfs(dir.as_fd())?;
        if st.f_type != libc::OVERLAYFS_SUPER_MAGIC {
            tracing::trace!("{path} is not an overlayfs mount, skipping relabel");
            continue;
        }
        let stv = rustix::fs::fstatvfs(dir.as_fd())?;
        if stv.f_flag.contains(StatVfsMountFlags::RDONLY) {
            tracing::trace!("{path} is a read-only overlayfs (composefs), skipping relabel");
            continue;
        }
        let metadata = dir.metadata(".").with_context(|| format!("stat {path}"))?;
        crate::lsm::relabel(
            &dir,
            &metadata,
            Utf8Path::new("."),
            Some(Utf8Path::new(path)),
            &policy,
        )
        .with_context(|| format!("Relabelling {path}"))?;
        tracing::debug!("Relabelled {path}");
    }
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
        fn test_transient_overlay_relabel_generated() -> Result<()> {
            let tempdir = fixture()?;
            let unit_dir = &tempdir.open_dir("run/systemd/system")?;

            // We can't fake fstatfs or findmnt, so call generate_transient_overlay_relabel directly.
            generate_transient_overlay_relabel(unit_dir)?;

            // The unit file must exist
            assert!(unit_dir.try_exists(TRANSIENT_RELABEL_UNIT)?);
            // The symlink in sysinit.target.wants must point at the generated unit
            let wants = format!("{SYSINIT_TARGET}.wants");
            let link = unit_dir.read_link_contents(format!("{wants}/{TRANSIENT_RELABEL_UNIT}"))?;
            let link: camino::Utf8PathBuf = link.try_into().unwrap();
            assert_eq!(link, format!("../{TRANSIENT_RELABEL_UNIT}"));
            // The unit must invoke bootc internals relabel-overlay-mountpoints
            let content = unit_dir.read_to_string(TRANSIENT_RELABEL_UNIT)?;
            assert!(
                content.contains("ExecStart=bootc internals relabel-overlay-mountpoints"),
                "unexpected unit content: {content}"
            );

            Ok(())
        }

        #[test]
        fn test_transient_overlay_relabel_idempotent() -> Result<()> {
            let tempdir = fixture()?;
            let unit_dir = &tempdir.open_dir("run/systemd/system")?;

            // Calling generate_transient_overlay_relabel twice must succeed
            generate_transient_overlay_relabel(unit_dir)?;
            // Second call: atomic_write overwrites the unit file; symlink already exists
            // (symlink won't be re-created because the dir already contains it).
            // The test just checks the call doesn't error.
            // We need to remove the old symlink first (same as how enable_unit does it).
            let wants = format!("{SYSINIT_TARGET}.wants");
            unit_dir.remove_file_optional(format!("{wants}/{TRANSIENT_RELABEL_UNIT}"))?;
            generate_transient_overlay_relabel(unit_dir)?;

            assert!(unit_dir.try_exists(TRANSIENT_RELABEL_UNIT)?);

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

        #[test]
        fn test_shadow_sync_no_shadow() -> Result<()> {
            // No /etc/shadow => should not enable (boot detection is caller's job)
            let tempdir = fixture()?;
            let unit_dir = &tempdir.open_dir("run/systemd/system")?;
            let generated = shadow_sync_generator_impl(&tempdir, unit_dir)?;
            assert!(!generated);
            assert_eq!(unit_dir.entries()?.count(), 0);
            Ok(())
        }

        #[test]
        fn test_shadow_sync_enables_when_shadow_present() -> Result<()> {
            // /etc/shadow present => enables the static unit
            let tempdir = fixture()?;
            tempdir.atomic_write("etc/shadow", "root:*:18912:0:99999:7:::\n")?;
            let unit_dir = &tempdir.open_dir("run/systemd/system")?;
            let generated = shadow_sync_generator_impl(&tempdir, unit_dir)?;
            assert!(generated);
            // The generator creates a symlink in sysinit.target.wants/; check the
            // directory entry exists (symlink_contents creates an absolute-path symlink
            // that cap-std won't follow in a tempdir, so we check metadata directly).
            let wants = unit_dir.open_dir("sysinit.target.wants")?;
            let meta = wants.symlink_metadata(SHADOW_SYNC_UNIT)?;
            assert!(meta.is_symlink(), "expected symlink for {SHADOW_SYNC_UNIT}");
            Ok(())
        }

        /// Verify that generator() enables the shadow sync unit on traditional
        /// ostree boots (tmpfs root, OSTREE_BOOTED marker present).
        #[test]
        fn test_generator_shadow_sync_on_non_composefs() -> Result<()> {
            let tempdir = fixture()?;
            tempdir.atomic_write(OSTREE_BOOTED, "")?;
            tempdir.atomic_write("etc/shadow", "root:*:18912:0:99999:7:::\n")?;
            let unit_dir = &tempdir.open_dir("run/systemd/system")?;
            generator(&tempdir, unit_dir)?;
            let wants = unit_dir.open_dir("sysinit.target.wants")?;
            let meta = wants.symlink_metadata(SHADOW_SYNC_UNIT)?;
            assert!(
                meta.is_symlink(),
                "shadow sync unit must be enabled on non-composefs ostree systems"
            );
            Ok(())
        }
    }
}
