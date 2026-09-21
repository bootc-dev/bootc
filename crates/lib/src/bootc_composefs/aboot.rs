use anyhow::{Context, Result, ensure};
use cap_std_ext::{cap_std::fs::Dir, dirext::CapStdExtDirExt};
use composefs_ctl::composefs::fsverity::{FsVerityHashValue, Sha512HashValue};
use linux_kernel_cmdline::utf8::Cmdline;
use rustix::{
    fd::OwnedFd,
    fs::{FlockOperation, Mode, OFlags, flock, fsync, openat},
};

use crate::composefs_consts::ABOOT_STATE_DIR;

use super::{boot::BootType, state::read_boot_type};

const SLOT_SUFFIX: &str = "androidboot.slot_suffix";
const LOCK_FILE: &str = "bootc-aboot.lock";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Slot {
    A,
    B,
}

impl Slot {
    pub(crate) fn from_cmdline(cmdline: &Cmdline<'_>) -> Option<Self> {
        let mut suffixes = cmdline
            .iter()
            .filter(|param| param.key() == SLOT_SUFFIX.into());
        let suffix = suffixes.next()?;
        if suffixes.next().is_some() {
            return None;
        }
        match suffix.value()? {
            "_a" => Some(Self::A),
            "_b" => Some(Self::B),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::A => "a",
            Self::B => "b",
        }
    }
}

pub(crate) fn lock(run: &Dir) -> Result<OwnedFd> {
    let fd = openat(
        run,
        LOCK_FILE,
        OFlags::CREATE | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )
    .context("Opening aboot mutation lock")?;
    flock(&fd, FlockOperation::LockExclusive).context("Locking aboot state")?;
    Ok(fd)
}

pub(crate) fn read_slot(sysroot: &Dir, slot: Slot) -> Result<Option<Sha512HashValue>> {
    let path = format!("{ABOOT_STATE_DIR}/slots/{}", slot.name());
    let Some(contents) = sysroot.read_optional(&path)? else {
        return Ok(None);
    };
    let digest = match Sha512HashValue::from_hex(contents.trim_ascii()) {
        Ok(digest) => digest,
        Err(err) => {
            tracing::warn!(%path, %err, "Invalid aboot slot mapping");
            return Ok(None);
        }
    };
    if read_boot_type(sysroot, &digest.to_hex())? != Some(BootType::Aboot) {
        tracing::warn!(%path, "Aboot slot mapping has no corresponding aboot deployment");
        return Ok(None);
    }
    Ok(Some(digest))
}

pub(crate) fn record_booted(sysroot: &Dir, cmdline: &Cmdline<'_>, digest: &str) -> Result<()> {
    let digest = Sha512HashValue::from_hex(digest).context("Invalid booted deployment digest")?;
    ensure!(
        read_boot_type(sysroot, &digest.to_hex())? == Some(BootType::Aboot),
        "Booted deployment is not aboot"
    );
    let Some(slot) = Slot::from_cmdline(cmdline) else {
        tracing::warn!("No unambiguous aboot slot suffix; leaving slot mappings unchanged");
        return Ok(());
    };
    if read_slot(sysroot, slot)?.as_ref() == Some(&digest) {
        return Ok(());
    }

    let mut dir = sysroot.try_clone()?;
    for component in ABOOT_STATE_DIR.split('/').chain(["slots"]) {
        dir.create_dir_all(component)?;
        fsync(dir.reopen_as_ownedfd()?).context("Syncing aboot state directory")?;
        dir = dir.open_dir(component)?;
    }
    dir.atomic_write(slot.name(), format!("{}\n", digest.to_hex()))
        .context("Recording booted aboot slot")?;
    Ok(())
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "Used by aboot update finalization in a follow-up")
)]
pub(crate) fn invalidate_other(sysroot: &Dir, booted_slot: Slot) -> Result<()> {
    let other = match booted_slot {
        Slot::A => Slot::B,
        Slot::B => Slot::A,
    };
    let Some(slots) = sysroot.open_dir_optional(format!("{ABOOT_STATE_DIR}/slots"))? else {
        return Ok(());
    };
    slots.remove_file_optional(other.name())?;
    fsync(slots.reopen_as_ownedfd()?).context("Syncing invalidated aboot slot")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::composefs_consts::STATE_DIR_RELATIVE;
    use cap_std_ext::{cap_std::ambient_authority, cap_tempfile::tempdir};

    fn deployment(root: &Dir, digest: &str, boot_type: &str) -> Result<()> {
        let path = format!("{STATE_DIR_RELATIVE}/{digest}");
        root.create_dir_all(&path)?;
        root.atomic_write(
            format!("{path}/{digest}.origin"),
            format!("[boot]\nboot_type={boot_type}\n"),
        )?;
        Ok(())
    }

    #[test]
    fn slot_suffix() {
        for (cmdline, expected) in [
            ("androidboot.slot_suffix=_a", Some(Slot::A)),
            ("quiet androidboot.slot_suffix=_b rw", Some(Slot::B)),
            ("", None),
            ("androidboot.slot_suffix", None),
            ("androidboot.slot_suffix=", None),
            ("androidboot.slot_suffix=a", None),
            ("androidboot.slot_suffix=_c", None),
            (
                "androidboot.slot_suffix=_a androidboot.slot_suffix=_b",
                None,
            ),
            (
                "androidboot.slot_suffix=_a androidboot.slot_suffix=_a",
                None,
            ),
        ] {
            assert_eq!(
                Slot::from_cmdline(&Cmdline::from(cmdline)),
                expected,
                "{cmdline}"
            );
        }
    }

    #[test]
    fn slot_lifecycle() -> Result<()> {
        let root = tempdir(ambient_authority())?;
        let a = "aa".repeat(64);
        let b = "bb".repeat(64);
        deployment(&root, &a, "aboot")?;
        deployment(&root, &b, "aboot")?;
        let cmdline_a = Cmdline::from("androidboot.slot_suffix=_a");
        let cmdline_b = Cmdline::from("androidboot.slot_suffix=_b");

        assert_eq!(read_slot(&root, Slot::A)?, None);
        invalidate_other(&root, Slot::A)?;
        record_booted(&root, &cmdline_a, &a)?;
        record_booted(&root, &cmdline_a, &a)?;
        assert_eq!(read_slot(&root, Slot::B)?, None);
        record_booted(&root, &cmdline_b, &b)?;
        assert_eq!(
            read_slot(&root, Slot::A)?,
            Some(Sha512HashValue::from_hex(&a)?)
        );
        assert_eq!(
            read_slot(&root, Slot::B)?,
            Some(Sha512HashValue::from_hex(&b)?)
        );

        for slot in [Slot::A, Slot::B] {
            record_booted(&root, &cmdline_a, &a)?;
            record_booted(&root, &cmdline_b, &b)?;
            invalidate_other(&root, slot)?;
            invalidate_other(&root, slot)?;
            assert!(read_slot(&root, slot)?.is_some());
            let other = if slot == Slot::A { Slot::B } else { Slot::A };
            assert_eq!(read_slot(&root, other)?, None);
            assert!(!root.try_exists(format!("{ABOOT_STATE_DIR}/slots/{}", other.name()))?);
        }

        record_booted(&root, &cmdline_a, &a)?;
        record_booted(&root, &Cmdline::from(""), &b)?;
        assert_eq!(
            read_slot(&root, Slot::A)?,
            Some(Sha512HashValue::from_hex(&a)?)
        );
        record_booted(&root, &cmdline_a, &b)?;
        assert_eq!(
            read_slot(&root, Slot::A)?,
            Some(Sha512HashValue::from_hex(&b)?)
        );
        Ok(())
    }

    #[test]
    fn invalid_mappings() -> Result<()> {
        let root = tempdir(ambient_authority())?;
        let slots = format!("{ABOOT_STATE_DIR}/slots");
        root.create_dir_all(&slots)?;
        for contents in [String::new(), "invalid".into(), "aa".repeat(64)] {
            root.atomic_write(format!("{slots}/a"), contents)?;
            assert_eq!(read_slot(&root, Slot::A)?, None);
        }
        root.atomic_write(format!("{slots}/a"), [0xff; 128])?;
        assert_eq!(read_slot(&root, Slot::A)?, None);
        let digest = "aa".repeat(64);
        root.atomic_write(format!("{slots}/a"), &digest)?;
        deployment(&root, &digest, "uki")?;
        assert_eq!(read_slot(&root, Slot::A)?, None);
        assert!(
            record_booted(&root, &Cmdline::from("androidboot.slot_suffix=_a"), &digest).is_err()
        );
        assert!(record_booted(&root, &Cmdline::from(""), "../invalid").is_err());
        Ok(())
    }

    #[test]
    fn mutation_lock() -> Result<()> {
        let run = tempdir(ambient_authority())?;
        let guard = lock(&run)?;
        let other = run.open(LOCK_FILE)?;
        assert_eq!(
            flock(&other, FlockOperation::NonBlockingLockExclusive),
            Err(rustix::io::Errno::WOULDBLOCK)
        );
        drop(guard);
        flock(&other, FlockOperation::NonBlockingLockExclusive)?;
        Ok(())
    }
}
