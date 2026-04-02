/// composefs= parameter in kernel cmdline
pub const COMPOSEFS_CMDLINE: &str = "composefs";

/// Directory to store transient state, such as staged deployemnts etc
pub(crate) const COMPOSEFS_TRANSIENT_STATE_DIR: &str = "/run/composefs";
/// File created in /run/composefs to record a staged-deployment
pub(crate) const COMPOSEFS_STAGED_DEPLOYMENT_FNAME: &str = "staged-deployment";

/// Absolute path to composefs-backend state directory
pub(crate) const STATE_DIR_ABS: &str = "/sysroot/state/deploy";
/// Relative path to composefs-backend state directory. Relative to /sysroot
pub(crate) const STATE_DIR_RELATIVE: &str = "state/deploy";
/// Relative path to the shared 'var' directory. Relative to /sysroot
pub(crate) const SHARED_VAR_PATH: &str = "state/os/default/var";

/// Section in .origin file to store boot related metadata
pub(crate) const ORIGIN_KEY_BOOT: &str = "boot";
/// Whether the deployment was booted with BLS or UKI
pub(crate) const ORIGIN_KEY_BOOT_TYPE: &str = "boot_type";
/// Key to store the SHA256 sum of vmlinuz + initrd for a deployment
pub(crate) const ORIGIN_KEY_BOOT_DIGEST: &str = "digest";

/// Section in .origin file to store OCI image metadata
pub(crate) const ORIGIN_KEY_IMAGE: &str = "image";
/// Key to store the OCI manifest digest (e.g. "sha256:abc...")
pub(crate) const ORIGIN_KEY_MANIFEST_DIGEST: &str = "manifest_digest";

/// Filename for `loader/entries`
pub(crate) const BOOT_LOADER_ENTRIES: &str = "entries";
/// Filename for staged boot loader entries
pub(crate) const STAGED_BOOT_LOADER_ENTRIES: &str = "entries.staged";

/// Filename for grub user config
pub(crate) const USER_CFG: &str = "user.cfg";
/// Filename for staged grub user config
pub(crate) const USER_CFG_STAGED: &str = "user.cfg.staged";

/// Path to the config files directory for Type1 boot entries
/// This is relative to the boot/efi directory
pub(crate) const TYPE1_ENT_PATH: &str = "loader/entries";
pub(crate) const TYPE1_ENT_PATH_STAGED: &str = "loader/entries.staged";

pub(crate) const BOOTC_FINALIZE_STAGED_SERVICE: &str = "bootc-finalize-staged.service";

/// The prefix for the directories containing kernel + initrd
pub(crate) const TYPE1_BOOT_DIR_PREFIX: &str = "bootc_composefs-";

/// The prefix for names of UKI and UKI Addons
pub(crate) const UKI_NAME_PREFIX: &str = TYPE1_BOOT_DIR_PREFIX;

/// Prefix for OCI tags owned by bootc in the composefs repository.
///
/// Tags are created as `localhost/bootc-<manifest_digest>` to act as GC roots
/// that keep the manifest, config, and layer splitstreams alive. This is
/// analogous to how ostree uses `ostree/` refs.
pub(crate) const BOOTC_TAG_PREFIX: &str = "localhost/bootc-";
