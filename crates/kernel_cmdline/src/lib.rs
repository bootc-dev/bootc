//! Kernel command line parsing utilities.
//!
//! This module provides functionality for parsing and working with kernel command line
//! arguments, supporting both key-only switches and key-value pairs with proper quote handling.
//!
//! The kernel command line is not required to be UTF-8.  The `bytes`
//! module works on arbitrary byte data and attempts to parse the
//! command line in the same manner as the kernel itself.
//!
//! The `utf8` module performs the same functionality, but requires
//! all data to be valid UTF-8.

pub mod bytes;
pub mod utf8;

/// This is used by dracut.
pub const INITRD_ARG_PREFIX: &str = "rd.";
/// The kernel argument for configuring the rootfs flags.
pub const ROOTFLAGS: &str = "rootflags";
