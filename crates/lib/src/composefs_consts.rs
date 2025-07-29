/// composefs= paramter in kernel cmdline
pub const COMPOSEFS_CMDLINE: &str = "composefs=";
/// composefs=? paramter in kernel cmdline. The `?` signifies that the fs-verity validation is
/// optional in case the filesystem doesn't support it.
pub const COMPOSEFS_INSECURE_CMDLINE: &str = "composefs=?";

/// Directory to store transient state, such as staged deployemnts etc
pub(crate) const COMPOSEFS_TRANSIENT_STATE_DIR: &str = "/run/composefs";
/// File created in /run/composefs to record a staged-deployment
pub(crate) const COMPOSEFS_STAGED_DEPLOYMENT_FNAME: &str = "staged-deployment";

/// Absolute path to composefs-native state directory
pub(crate) const STATE_DIR_ABS: &str = "/sysroot/state/deploy";
/// Relative path to composefs-native state directory. Relative to /sysroot
pub(crate) const STATE_DIR_RELATIVE: &str = "state/deploy";

/// Section in .origin file to store boot related metadata
pub(crate) const ORIGIN_KEY_BOOT: &str = "boot";
/// Whether the deployment was booted with BLS or UKI
pub(crate) const ORIGIN_KEY_BOOT_TYPE: &str = "boot_type";
/// Key to store the SHA256 sum of vmlinuz + initrd for a deployment
pub(crate) const ORIGIN_KEY_BOOT_DIGEST: &str = "digest";

/// Filename for `loader/entries`
pub(crate) const BOOT_LOADER_ENTRIES: &str = "entries";
/// Filename for staged boot loader entries
pub(crate) const STAGED_BOOT_LOADER_ENTRIES: &str = "entries.staged";
/// Filename for rollback boot loader entries
pub(crate) const ROLLBACK_BOOT_LOADER_ENTRIES: &str = STAGED_BOOT_LOADER_ENTRIES;

/// Filename for grub user config
pub(crate) const USER_CFG: &str = "user.cfg";
/// Filename for staged grub user config
pub(crate) const USER_CFG_STAGED: &str = "user.cfg.staged";
/// Filename for rollback grub user config
pub(crate) const USER_CFG_ROLLBACK: &str = USER_CFG_STAGED;
