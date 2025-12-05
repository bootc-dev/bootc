//! Helpers for interacting with sysroots.

use std::{ops::Deref, os::fd::BorrowedFd, time::SystemTime};

use anyhow::Result;
use chrono::Datelike as _;
use ocidir::cap_std::fs_utf8::Dir;
use ostree::gio;

/// We may automatically allocate stateroots, this string is the prefix.
const AUTO_STATEROOT_PREFIX: &str = "state-";

use crate::utils::async_task_with_spinner;

/// A locked system root.
#[derive(Debug)]
pub struct SysrootLock {
    /// The underlying sysroot value.
    pub sysroot: ostree::Sysroot,
    /// True if we didn't actually lock
    unowned: bool,
}

impl Drop for SysrootLock {
    fn drop(&mut self) {
        if self.unowned {
            return;
        }
        self.sysroot.unlock();
    }
}

impl Deref for SysrootLock {
    type Target = ostree::Sysroot;

    fn deref(&self) -> &Self::Target {
        &self.sysroot
    }
}

/// Access the file descriptor for a sysroot
#[allow(unsafe_code)]
pub fn sysroot_fd(sysroot: &ostree::Sysroot) -> BorrowedFd<'_> {
    unsafe { BorrowedFd::borrow_raw(sysroot.fd()) }
}

/// A stateroot can match our auto "state-" prefix, or be manual.
#[derive(Debug, PartialEq, Eq)]
pub enum StaterootKind {
    /// This stateroot has an automatic name
    Auto((u64, u64)),
    /// This stateroot is manually named
    Manual,
}

/// Metadata about a stateroot.
#[derive(Debug, PartialEq, Eq)]
pub struct Stateroot {
    /// The name
    pub name: String,
    /// Kind
    pub kind: StaterootKind,
    /// Creation timestamp (from the filesystem)
    pub creation: SystemTime,
}

impl StaterootKind {
    fn new(name: &str) -> Self {
        if let Some(v) = parse_auto_stateroot_name(name) {
            return Self::Auto(v);
        }
        Self::Manual
    }
}

/// Load metadata for a stateroot
fn read_stateroot(sysroot_dir: &Dir, name: &str) -> Result<Stateroot> {
    let path = format!("ostree/deploy/{name}");
    let kind = StaterootKind::new(&name);
    let creation = sysroot_dir.symlink_metadata(&path)?.created()?.into_std();
    let r = Stateroot {
        name: name.to_owned(),
        kind,
        creation,
    };
    Ok(r)
}

/// Enumerate stateroots, which are basically the default place for `/var`.
pub fn list_stateroots(sysroot: &ostree::Sysroot) -> Result<Vec<Stateroot>> {
    let sysroot_dir = &Dir::reopen_dir(&sysroot_fd(sysroot))?;
    let r = sysroot_dir
        .read_dir("ostree/deploy")?
        .try_fold(Vec::new(), |mut acc, v| {
            let v = v?;
            let name = v.file_name()?;
            if sysroot_dir.try_exists(format!("ostree/deploy/{name}/deploy"))? {
                acc.push(read_stateroot(sysroot_dir, &name)?);
            }
            anyhow::Ok(acc)
        })?;
    Ok(r)
}

/// Given a string, if it matches the form of an automatic state root, parse it into its <year>.<serial> pair.
fn parse_auto_stateroot_name(name: &str) -> Option<(u64, u64)> {
    let Some(statename) = name.strip_prefix(AUTO_STATEROOT_PREFIX) else {
        return None;
    };
    let Some((year, serial)) = statename.split_once("-") else {
        return None;
    };
    let Ok(year) = year.parse::<u64>() else {
        return None;
    };
    let Ok(serial) = serial.parse::<u64>() else {
        return None;
    };
    Some((year, serial))
}

/// Given a set of stateroots, allocate a new one
pub fn allocate_new_stateroot(
    sysroot: &ostree::Sysroot,
    stateroots: &[Stateroot],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Stateroot> {
    let sysroot_dir = &Dir::reopen_dir(&sysroot_fd(sysroot))?;

    let current_year = now.year().try_into().unwrap_or_default();
    let (year, serial) = stateroots
        .iter()
        .filter_map(|v| {
            if let StaterootKind::Auto(v) = v.kind {
                Some(v)
            } else {
                None
            }
        })
        .max()
        .map(|(year, serial)| (year, serial + 1))
        .unwrap_or((current_year, 0));

    let name = format!("state-{year}-{serial}");

    sysroot.init_osname(&name, gio::Cancellable::NONE)?;

    read_stateroot(sysroot_dir, &name)
}

impl SysrootLock {
    /// Asynchronously acquire a sysroot lock.  If the lock cannot be acquired
    /// immediately, a status message will be printed to standard output.
    /// The lock will be unlocked when this object is dropped.
    pub async fn new_from_sysroot(sysroot: &ostree::Sysroot) -> Result<Self> {
        let sysroot_clone = sysroot.clone();
        let locker = tokio::task::spawn_blocking(move || sysroot_clone.lock());
        async_task_with_spinner("Waiting for sysroot lock...", locker).await??;
        Ok(Self {
            sysroot: sysroot.clone(),
            unowned: false,
        })
    }

    /// This function should only be used when you have locked the sysroot
    /// externally (e.g. in C/C++ code).  This also does not unlock on drop.
    pub fn from_assumed_locked(sysroot: &ostree::Sysroot) -> Self {
        Self {
            sysroot: sysroot.clone(),
            unowned: true,
        }
    }

    /// Toggle the finalization lock state of a staged deployment.
    /// If the deployment is currently locked, it will be unlocked, and vice versa.
    /// The deployment must be a staged deployment.
    #[allow(unsafe_code)]
    pub fn change_finalization(&self, deployment: &ostree::Deployment) -> Result<()> {
        use ostree::glib::translate::*;
        use std::ptr;
        unsafe {
            let mut error = ptr::null_mut();
            let result = ostree::ffi::ostree_sysroot_change_finalization(
                self.sysroot.to_glib_none().0,
                deployment.to_glib_none().0,
                &mut error,
            );
            if result == 0 {
                return Err(from_glib_full::<_, ostree::glib::Error>(error).into());
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_auto_stateroot_name_valid() {
        let test_cases = [
            // Basic valid cases
            ("state-2024-0", Some((2024, 0))),
            ("state-2024-1", Some((2024, 1))),
            ("state-2023-123", Some((2023, 123))),
            // Large numbers
            (
                "state-18446744073709551615-18446744073709551615",
                Some((18446744073709551615, 18446744073709551615)),
            ),
            // Zero values
            ("state-0-0", Some((0, 0))),
            ("state-0-123", Some((0, 123))),
            // Leading zeros (should work - u64::parse handles them)
            ("state-0002024-001", Some((2024, 1))),
            ("state-000-000", Some((0, 0))),
        ];

        for (input, expected) in test_cases {
            assert_eq!(
                parse_auto_stateroot_name(input),
                expected,
                "Failed for input: {}",
                input
            );
        }
    }

    #[test]
    fn test_parse_auto_stateroot_name_invalid() {
        let test_cases = [
            // Missing prefix
            "2024-1",
            // Wrong prefix
            "stat-2024-1",
            "states-2024-1",
            "prefix-2024-1",
            // Empty string
            "",
            // Only prefix
            "state-",
            // Missing separator
            "state-20241",
            // Wrong separator
            "state-2024.1",
            "state-2024_1",
            "state-2024:1",
            // Multiple separators
            "state-2024-1-2",
            // Missing year or serial
            "state--1",
            "state-2024-",
            // Non-numeric year
            "state-abc-1",
            "state-2024a-1",
            // Non-numeric serial
            "state-2024-abc",
            "state-2024-1a",
            // Both non-numeric
            "state-abc-def",
            // Negative numbers (handled by parse::<u64>() failure)
            "state--2024-1",
            "state-2024--1",
            // Floating point numbers
            "state-2024.5-1",
            "state-2024-1.5",
            // Numbers with whitespace
            "state- 2024-1",
            "state-2024- 1",
            "state-2024 -1",
            "state-2024- 1 ",
            // Case sensitivity (should fail - prefix is lowercase)
            "State-2024-1",
            "STATE-2024-1",
            // Unicode characters
            "state-2024-1🦀",
            "state-2024🦀-1",
            // Hex-like strings (should fail - not decimal)
            "state-0x2024-1",
            "state-2024-0x1",
        ];

        for input in test_cases {
            assert_eq!(
                parse_auto_stateroot_name(input),
                None,
                "Expected None for input: {}",
                input
            );
        }
    }

    #[test]
    fn test_stateroot_kind_new() {
        let test_cases = [
            ("state-2024-1", StaterootKind::Auto((2024, 1))),
            ("manual-name", StaterootKind::Manual),
            ("state-invalid", StaterootKind::Manual),
            ("", StaterootKind::Manual),
        ];

        for (input, expected) in test_cases {
            assert_eq!(
                StaterootKind::new(input),
                expected,
                "Failed for input: {}",
                input
            );
        }
    }
}
