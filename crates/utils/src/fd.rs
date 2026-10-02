//! File descriptors passed to bootc by number on the command line.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Result};
use rustix::io::FdFlags;

/// An open file descriptor that the calling process passed by number.
///
/// Parsing one checks that the fd is open and not close-on-exec.  Everything
/// bootc opens itself is close-on-exec, while an fd inherited across exec
/// can't be, so this rejects a number the caller didn't actually pass which
/// happens to be in use internally (e.g. by the async runtime).  stdin,
/// stdout and stderr are rejected too, as bootc uses them itself.
///
/// Rust can't give I/O safety for an fd known only by its number (see
/// <https://github.com/rust-lang/rust/issues/116059>): nothing proves that
/// the fd isn't owned by something else in the process.  The checks above
/// are what we have instead.  Ownership is taken once, when parsing; clones
/// (which clap needs) share it.
#[derive(Debug, Clone)]
pub struct InheritedFd(Arc<OwnedFd>);

impl InheritedFd {
    /// Check that `fd` was inherited from the calling process, and take
    /// ownership of it.
    pub fn new(fd: RawFd) -> Result<Self> {
        if fd < 0 {
            anyhow::bail!("Invalid fd {fd}");
        }
        if fd <= 2 {
            anyhow::bail!("Cannot use fd {fd}: stdin, stdout and stderr are used by bootc itself");
        }
        // SAFETY: For a number from the command line there is no way to
        // uphold borrow_raw()'s contract that the fd is open (see the type's
        // documentation); this borrow only lives for the one fcntl() call
        // that rejects a number that isn't.
        #[allow(unsafe_code)]
        let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
        // Not with_context(), as clap shows only the outermost error
        let flags =
            rustix::io::fcntl_getfd(borrowed).map_err(|e| anyhow::anyhow!("fd {fd}: {e}"))?;
        if flags.contains(FdFlags::CLOEXEC) {
            anyhow::bail!("fd {fd} was not inherited from the calling process");
        }
        // SAFETY: It is open, and see the type's documentation for why we
        // treat it as ours.
        #[allow(unsafe_code)]
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self(Arc::new(fd)))
    }

    /// Take sole ownership of the file descriptor, so that it is closed when
    /// dropped.  This fails if it is still shared with a clone.
    pub fn into_owned(self) -> Result<OwnedFd> {
        let fd = self.0.as_raw_fd();
        Arc::try_unwrap(self.0).map_err(|_| anyhow::anyhow!("fd {fd} is still in use"))
    }
}

impl AsFd for InheritedFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl PartialEq for InheritedFd {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_raw_fd() == other.0.as_raw_fd()
    }
}

impl Eq for InheritedFd {}

impl FromStr for InheritedFd {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let fd = s
            .parse()
            .with_context(|| format!("Invalid fd number {s:?}"))?;
        Self::new(fd)
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::IntoRawFd as _;

    use super::*;

    #[test]
    fn test_parse() -> Result<()> {
        for (input, msg) in [
            ("", "Invalid fd number"),
            ("x", "Invalid fd number"),
            ("-1", "Invalid fd -1"),
            ("0", "stdin, stdout and stderr"),
            ("2", "stdin, stdout and stderr"),
            ("2147483647", "fd 2147483647"),
        ] {
            let e = input.parse::<InheritedFd>().unwrap_err();
            assert!(format!("{e:#}").contains(msg), "{input:?}: {e:#}");
        }

        // Everything std opens is close-on-exec, so it wasn't inherited
        let f = tempfile::tempfile()?;
        let e = f
            .as_raw_fd()
            .to_string()
            .parse::<InheritedFd>()
            .unwrap_err();
        assert!(format!("{e:#}").contains("not inherited"), "{e:#}");

        rustix::io::fcntl_setfd(f.as_fd(), FdFlags::empty())?;
        let fdnum = f.into_raw_fd();
        let fd = fdnum.to_string().parse::<InheritedFd>()?;
        assert_eq!(fd.as_fd().as_raw_fd(), fdnum);
        let clone = fd.clone();
        assert!(fd.clone().into_owned().is_err());
        drop(clone);
        // Closed when dropped
        drop(fd.into_owned()?);
        assert!(InheritedFd::new(fdnum).is_err());
        Ok(())
    }
}
