//! The composefs boot backend.
//!
//! This module and its submodules implement bootc's composefs-native boot
//! backend, where the OS image is stored and booted directly from a composefs
//! EROFS overlay rather than through an ostree deployment.
//!
//! ## Submodule layout
//!
//! | Submodule | Responsibility |
//! |-----------|----------------|
//! | `repo` / `update` | Pull images into the composefs object store; handle upgrades and switches |
//! | `status` | Read deployment state from bootloader entries and composefs origin files |
//! | `export` | Export composefs-repo images to OCI layout for reconcile / registry push |
//! | `gc` | Garbage-collect unreferenced composefs tags and splitstreams |
//! | `boot` / `finalize` | Prepare the boot environment (BLS entries, UKI, TPM sealing) |
//! | `selinux` | SELinux policy compatibility checks for in-place updates |
//! | `soft_reboot` | systemd-soft-reboot support for zero-downtime image switches |

pub(crate) mod backwards_compat;
pub(crate) mod boot;
pub(crate) mod delete;
pub(crate) mod digest;
pub(crate) mod export;
pub(crate) mod finalize;
pub(crate) mod gc;
pub(crate) mod repo;
pub(crate) mod rollback;
pub(crate) mod selinux;
pub(crate) mod service;
pub(crate) mod soft_reboot;
pub(crate) mod state;
pub(crate) mod status;
pub(crate) mod switch;
pub(crate) mod update;
pub(crate) mod utils;
