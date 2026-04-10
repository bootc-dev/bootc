//! Test infrastructure for simulating a composefs BLS Type1 sysroot.
//!
//! Provides [`TestRoot`] which creates a realistic sysroot filesystem layout
//! suitable for unit-testing the GC, status, and boot entry logic without
//! requiring a real booted system.

use std::sync::Arc;

use anyhow::{Context, Result};
use cap_std_ext::cap_std::{self, fs::Dir};
use cap_std_ext::cap_tempfile;
use cap_std_ext::dirext::CapStdExtDirExt;

use crate::bootc_composefs::boot::{
    FILENAME_PRIORITY_PRIMARY, FILENAME_PRIORITY_SECONDARY, get_type1_dir_name, primary_sort_key,
    secondary_sort_key, type1_entry_conf_file_name,
};
use crate::composefs_consts::{
    ORIGIN_KEY_BOOT, ORIGIN_KEY_BOOT_DIGEST, ORIGIN_KEY_BOOT_TYPE, STATE_DIR_RELATIVE,
    TYPE1_BOOT_DIR_PREFIX, TYPE1_ENT_PATH,
};
use crate::parsers::bls_config::{BLSConfig, parse_bls_config};
use crate::store::ComposefsRepository;

use ostree_ext::container::deploy::ORIGIN_CONTAINER;

/// Return a deterministic SHA-256 hex digest for a test build version.
///
/// Computes `sha256("build-{n}")`, producing a realistic 64-char hex digest
/// that is stable across runs.
pub(crate) fn fake_digest_version(n: u32) -> String {
    let hash = openssl::hash::hash(
        openssl::hash::MessageDigest::sha256(),
        format!("build-{n}").as_bytes(),
    )
    .expect("sha256");
    hex::encode(hash)
}

/// What changed in an upgrade.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub(crate) enum ChangeType {
    /// Only userspace changed; kernel+initrd are identical, so the new
    /// deployment shares the previous deployment's boot binary directory.
    Userspace,
    /// The kernel (and/or initrd) changed, so the new deployment gets
    /// its own boot binary directory.
    Kernel,
    /// Both userspace and kernel changed. New boot binary directory and
    /// new composefs image.
    Both,
}

/// Controls whether TestRoot writes boot entries in the current (prefixed)
/// or legacy (unprefixed) format.
///
/// Older versions of bootc didn't prefix boot binary directories or UKI
/// filenames with `bootc_composefs-`. PR #2128 adds a migration path that
/// renames these on first run. This enum lets tests simulate both layouts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum LayoutMode {
    /// Current layout: directories named `bootc_composefs-<digest>`,
    /// BLS linux paths reference the prefixed directory name.
    Current,
    /// Legacy layout: directories named with just the raw `<digest>`,
    /// BLS linux paths reference the unprefixed directory name.
    /// This simulates a system installed with an older bootc.
    Legacy,
}

/// Metadata for a single simulated deployment.
#[derive(Clone, Debug)]
pub(crate) struct DeploymentMeta {
    /// The deployment's composefs verity digest (what goes in `composefs=`).
    pub verity: String,
    /// SHA256 digest of the vmlinuz+initrd pair.
    pub boot_digest: String,
    /// The name of the boot binary directory (verity portion only, no prefix).
    /// This equals `verity` for the deployment that created the directory,
    /// but may point to a different deployment's directory for shared entries.
    pub boot_dir_verity: String,
    /// The container image reference stored in the origin file.
    pub imgref: String,
    /// OS identifier for BLS entry naming.
    pub os_id: String,
    /// Version string for BLS entry.
    pub version: String,
}

/// A simulated composefs BLS Type1 sysroot for testing.
///
/// Creates the filesystem layout that the GC, status, and boot entry code
/// expects:
///
/// ```text
/// <tmpdir>/
/// ├── composefs/           # composefs repo (objects/, images/, streams/)
/// │   └── images/
/// │       └── <verity>     # one file per deployed image
/// ├── state/deploy/
/// │   └── <verity>/
/// │       ├── <verity>.origin
/// │       └── etc/
/// └── boot/
///     ├── bootc_composefs-<verity>/
///     │   ├── vmlinuz
///     │   └── initrd
///     └── loader/entries/
///         └── *.conf
/// ```
pub(crate) struct TestRoot {
    /// The root Dir — equivalent to `Storage.physical_root`.
    /// Also owns the tempdir lifetime.
    root: cap_tempfile::TempDir,
    /// Deployments added so far, in order.
    deployments: Vec<DeploymentMeta>,
    /// Composefs repository handle.
    repo: Arc<ComposefsRepository>,
    /// Whether to write entries in the current (prefixed) or legacy format.
    layout: LayoutMode,
}

impl TestRoot {
    /// Create a new test sysroot with one initial deployment (the "install").
    ///
    /// The deployment gets:
    /// - An EROFS image entry in `composefs/images/`
    /// - A state directory with a `.origin` file
    /// - A boot binary directory with vmlinuz + initrd
    /// - A primary BLS Type1 entry in `loader/entries/`
    pub fn new() -> Result<Self> {
        Self::with_layout(LayoutMode::Current)
    }

    /// Create a new test sysroot using the legacy (unprefixed) layout.
    ///
    /// This simulates a system installed with an older version of bootc
    /// that didn't prefix boot binary directories with `bootc_composefs-`.
    /// Useful for testing the backwards compatibility migration from PR #2128.
    #[allow(dead_code)]
    pub fn new_legacy() -> Result<Self> {
        Self::with_layout(LayoutMode::Legacy)
    }

    /// Create a test sysroot with the specified layout mode.
    fn with_layout(layout: LayoutMode) -> Result<Self> {
        let root = cap_tempfile::tempdir(cap_std::ambient_authority())?;

        // Create the composefs repo directory structure
        root.create_dir_all("composefs")
            .context("Creating composefs/")?;
        root.create_dir_all("composefs/images")
            .context("Creating composefs/images/")?;

        // Create the state directory
        root.create_dir_all(STATE_DIR_RELATIVE)
            .context("Creating state/deploy/")?;

        // Create the boot directory with loader/entries
        root.create_dir_all(&format!("boot/{TYPE1_ENT_PATH}"))
            .context("Creating boot/loader/entries/")?;

        // Initialize the composefs repo (creates meta.json)
        let repo_dir = root.open_dir("composefs")?;
        let (mut repo, _created) = ComposefsRepository::init_path(
            &repo_dir,
            ".",
            cfsctl::composefs::fsverity::Algorithm::SHA512,
            false,
        )
        .context("Initializing composefs repo")?;
        repo.set_insecure();

        let mut test_root = Self {
            root,
            deployments: Vec::new(),
            repo: Arc::new(repo),
            layout,
        };

        // Add an initial deployment (version 0)
        let meta = DeploymentMeta {
            verity: fake_digest_version(0),
            boot_digest: fake_digest_version(0),
            boot_dir_verity: fake_digest_version(0),
            imgref: "oci:quay.io/test/image:latest".into(),
            os_id: "fedora".into(),
            version: "42.20250101.0".into(),
        };
        test_root.add_deployment(&meta, true)?;

        Ok(test_root)
    }

    /// Access the root directory (equivalent to `Storage.physical_root`).
    #[allow(dead_code)]
    pub fn root(&self) -> &Dir {
        &self.root
    }

    /// Access the boot directory (equivalent to `Storage.boot_dir`).
    pub fn boot_dir(&self) -> Result<Dir> {
        self.root.open_dir("boot").context("Opening boot/")
    }

    /// Access the composefs repository.
    #[allow(dead_code)]
    pub fn repo(&self) -> &Arc<ComposefsRepository> {
        &self.repo
    }

    /// The most recently added deployment.
    pub fn current(&self) -> &DeploymentMeta {
        self.deployments.last().expect("at least one deployment")
    }

    /// All deployments, oldest first.
    #[allow(dead_code)]
    pub fn deployments(&self) -> &[DeploymentMeta] {
        &self.deployments
    }

    /// Simulate an upgrade: adds a new deployment as the primary boot entry.
    ///
    /// The previous primary becomes the secondary. `change` controls whether
    /// the kernel changed:
    ///
    /// - [`ChangeType::Userspace`]: only userspace changed, so the new
    ///   deployment shares the previous deployment's boot binary directory.
    ///   This is the scenario that triggers the GC bug from issue #2102.
    /// - [`ChangeType::Kernel`]: the kernel+initrd changed, so a new boot
    ///   binary directory is created.
    pub fn upgrade(&mut self, version: u32, change: ChangeType) -> Result<&DeploymentMeta> {
        let prev = self.current().clone();

        let new_verity = fake_digest_version(version);
        let (boot_dir_verity, boot_digest) = match change {
            ChangeType::Userspace => (prev.boot_dir_verity.clone(), prev.boot_digest.clone()),
            ChangeType::Kernel | ChangeType::Both => {
                let new_boot_digest = fake_digest_version(version);
                (new_verity.clone(), new_boot_digest)
            }
        };

        let meta = DeploymentMeta {
            verity: new_verity,
            boot_digest,
            boot_dir_verity,
            imgref: prev.imgref.clone(),
            os_id: prev.os_id.clone(),
            version: format!("4{}.20250201.0", self.deployments.len() + 1),
        };

        self.add_deployment(&meta, false)?;

        // Rewrite loader/entries/ to have the new primary + old secondary
        self.rewrite_bls_entries()?;

        Ok(self.deployments.last().unwrap())
    }

    /// Simulate GC of the oldest deployment: removes its EROFS image, state
    /// dir, and BLS entry, but leaves boot binaries alone (the real GC
    /// decides whether to remove them based on `boot_artifact_name`).
    pub fn gc_deployment(&mut self, verity: &str) -> Result<()> {
        // Remove EROFS image
        let images_dir = self.root.open_dir("composefs/images")?;
        images_dir
            .remove_file(verity)
            .with_context(|| format!("Removing image {verity}"))?;

        // Remove state directory
        self.root
            .remove_dir_all(format!("{STATE_DIR_RELATIVE}/{verity}"))
            .with_context(|| format!("Removing state dir for {verity}"))?;

        // Remove from our tracking list
        self.deployments.retain(|d| d.verity != verity);

        // Rewrite BLS entries for remaining deployments
        self.rewrite_bls_entries()?;

        Ok(())
    }

    /// Add a deployment: creates image, state dir, boot binaries, and BLS entry.
    fn add_deployment(&mut self, meta: &DeploymentMeta, is_initial: bool) -> Result<()> {
        self.write_erofs_image(&meta.verity)?;
        self.write_state_dir(meta)?;
        self.write_boot_binaries(&meta.boot_dir_verity)?;

        self.deployments.push(meta.clone());

        if is_initial {
            self.rewrite_bls_entries()?;
        }

        Ok(())
    }

    /// Create a placeholder file in composefs/images/ for this deployment.
    fn write_erofs_image(&self, verity: &str) -> Result<()> {
        let images_dir = self.root.open_dir("composefs/images")?;
        images_dir.atomic_write(verity, b"erofs-placeholder")?;
        Ok(())
    }

    /// Create the state directory with a .origin file.
    fn write_state_dir(&self, meta: &DeploymentMeta) -> Result<()> {
        let state_path = format!("{STATE_DIR_RELATIVE}/{}", meta.verity);
        self.root.create_dir_all(format!("{state_path}/etc"))?;

        // tini merges items under the same section name, so the repeated
        // .section(ORIGIN_KEY_BOOT) calls produce a single [boot] section
        // with both keys. This matches how state.rs writes the origin file.
        let origin = tini::Ini::new()
            .section("origin")
            .item(
                ORIGIN_CONTAINER,
                format!("ostree-unverified-image:{}", meta.imgref),
            )
            .section(ORIGIN_KEY_BOOT)
            .item(ORIGIN_KEY_BOOT_TYPE, "bls")
            .section(ORIGIN_KEY_BOOT)
            .item(ORIGIN_KEY_BOOT_DIGEST, &meta.boot_digest);

        let state_dir = self.root.open_dir(&state_path)?;
        state_dir.atomic_write(
            format!("{}.origin", meta.verity),
            origin.to_string().as_bytes(),
        )?;

        Ok(())
    }

    /// Return the boot binary directory name for a given verity digest,
    /// respecting the current layout mode.
    fn boot_binary_dir_name(&self, boot_dir_verity: &str) -> String {
        match self.layout {
            LayoutMode::Current => get_type1_dir_name(boot_dir_verity),
            LayoutMode::Legacy => boot_dir_verity.to_string(),
        }
    }

    /// Create the boot binary directory with vmlinuz + initrd.
    /// Skips if the directory already exists (shared entry case).
    fn write_boot_binaries(&self, boot_dir_verity: &str) -> Result<()> {
        let dir_name = self.boot_binary_dir_name(boot_dir_verity);
        let path = format!("boot/{dir_name}");

        if self.root.exists(&path) {
            return Ok(());
        }

        self.root.create_dir_all(&path)?;
        let boot_bin_dir = self.root.open_dir(&path)?;
        boot_bin_dir.atomic_write("vmlinuz", b"fake-kernel")?;
        boot_bin_dir.atomic_write("initrd", b"fake-initrd")?;
        Ok(())
    }

    /// Rewrite the BLS entries in loader/entries/ to match current deployments.
    ///
    /// The last deployment is primary, the second-to-last (if any) is secondary.
    fn rewrite_bls_entries(&self) -> Result<()> {
        let entries_dir = self.root.open_dir(&format!("boot/{TYPE1_ENT_PATH}"))?;

        // Remove all existing .conf files
        for entry in entries_dir.entries()? {
            let entry = entry?;
            let name = entry.file_name();
            if name.to_string_lossy().ends_with(".conf") {
                entries_dir.remove_file(name)?;
            }
        }

        let n = self.deployments.len();
        if n == 0 {
            return Ok(());
        }

        // Primary = most recent deployment
        let primary = &self.deployments[n - 1];
        let primary_conf = self.build_bls_config(primary, true);
        let primary_fname =
            type1_entry_conf_file_name(&primary.os_id, &primary.version, FILENAME_PRIORITY_PRIMARY);
        entries_dir.atomic_write(&primary_fname, primary_conf.as_bytes())?;

        // Secondary = previous deployment (if exists)
        if n >= 2 {
            let secondary = &self.deployments[n - 2];
            let secondary_conf = self.build_bls_config(secondary, false);
            let secondary_fname = type1_entry_conf_file_name(
                &secondary.os_id,
                &secondary.version,
                FILENAME_PRIORITY_SECONDARY,
            );
            entries_dir.atomic_write(&secondary_fname, secondary_conf.as_bytes())?;
        }

        Ok(())
    }

    /// Build a BLS .conf file body for a deployment.
    fn build_bls_config(&self, meta: &DeploymentMeta, is_primary: bool) -> String {
        let dir_name = self.boot_binary_dir_name(&meta.boot_dir_verity);
        let sort_key = if is_primary {
            primary_sort_key(&meta.os_id)
        } else {
            secondary_sort_key(&meta.os_id)
        };

        format!(
            "title {os_id} {version}\n\
             version {version}\n\
             sort-key {sort_key}\n\
             linux /boot/{dir_name}/vmlinuz\n\
             initrd /boot/{dir_name}/initrd\n\
             options root=UUID=test-uuid rw composefs={verity}\n",
            os_id = meta.os_id,
            version = meta.version,
            sort_key = sort_key,
            dir_name = dir_name,
            verity = meta.verity,
        )
    }

    /// Parse the current BLS entries from disk and return them.
    #[allow(dead_code)]
    pub fn read_bls_entries(&self) -> Result<Vec<BLSConfig>> {
        let boot_dir = self.boot_dir()?;
        let entries_dir = boot_dir.open_dir(TYPE1_ENT_PATH)?;

        let mut configs = Vec::new();
        for entry in entries_dir.entries()? {
            let entry = entry?;
            let name = entry.file_name();
            if !name.to_string_lossy().ends_with(".conf") {
                continue;
            }
            let contents = entries_dir.read_to_string(&name)?;
            configs.push(parse_bls_config(&contents)?);
        }

        configs.sort();
        Ok(configs)
    }

    /// List EROFS image names present in composefs/images/.
    #[allow(dead_code)]
    pub fn list_images(&self) -> Result<Vec<String>> {
        let images_dir = self.root.open_dir("composefs/images")?;
        let mut names = Vec::new();
        for entry in images_dir.entries()? {
            let entry = entry?;
            let name = entry.file_name();
            names.push(name.to_string_lossy().into_owned());
        }
        names.sort();
        Ok(names)
    }

    /// List state directory names present in state/deploy/.
    #[allow(dead_code)]
    pub fn list_state_dirs(&self) -> Result<Vec<String>> {
        let state = self.root.open_dir(STATE_DIR_RELATIVE)?;
        let mut names = Vec::new();
        for entry in state.entries()? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                names.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
        names.sort();
        Ok(names)
    }

    /// List boot binary directories (stripped of any prefix).
    ///
    /// In `Current` mode, strips `TYPE1_BOOT_DIR_PREFIX`; in `Legacy` mode,
    /// returns directory names that look like hex digests directly.
    #[allow(dead_code)]
    pub fn list_boot_binaries(&self) -> Result<Vec<String>> {
        let boot_dir = self.boot_dir()?;
        let mut names = Vec::new();
        for entry in boot_dir.entries()? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            // Skip non-boot directories like "loader"
            if name == "loader" {
                continue;
            }
            match self.layout {
                LayoutMode::Current => {
                    if let Some(verity) = name.strip_prefix(TYPE1_BOOT_DIR_PREFIX) {
                        names.push(verity.to_string());
                    }
                }
                LayoutMode::Legacy => {
                    // Legacy dirs are just the raw hex digest (64 chars).
                    // Only include entries that look like hex digests to
                    // avoid accidentally counting "loader" or other dirs.
                    if name.len() == 64 && name.chars().all(|c| c.is_ascii_hexdigit()) {
                        names.push(name);
                    }
                }
            }
        }
        names.sort();
        Ok(names)
    }

    /// Simulate the backwards compatibility migration: rename all legacy
    /// (unprefixed) boot binary directories to use the `bootc_composefs-`
    /// prefix, and rewrite BLS entries to reference the new paths.
    ///
    /// This mirrors what `prepend_custom_prefix()` from PR #2128 does.
    #[allow(dead_code)]
    pub fn migrate_to_prefixed(&mut self) -> Result<()> {
        anyhow::ensure!(
            self.layout == LayoutMode::Legacy,
            "migrate_to_prefixed only makes sense for legacy layouts"
        );

        let boot_dir = self.boot_dir()?;

        // Rename all unprefixed boot binary directories
        let mut to_rename = Vec::new();
        for entry in boot_dir.entries()? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == "loader" {
                continue;
            }
            // Rename directories that look like bare hex digests
            // (the legacy format). This is intentionally simplified
            // compared to the real migration in PR #2128 which also
            // handles UKI PE files and GRUB configs.
            if !name.starts_with(TYPE1_BOOT_DIR_PREFIX)
                && name.len() == 64
                && name.chars().all(|c| c.is_ascii_hexdigit())
            {
                to_rename.push(name);
            }
        }

        for old_name in &to_rename {
            let new_name = format!("{TYPE1_BOOT_DIR_PREFIX}{old_name}");
            rustix::fs::renameat(&boot_dir, old_name.as_str(), &boot_dir, new_name.as_str())
                .with_context(|| format!("Renaming {old_name} -> {new_name}"))?;
        }

        // Switch to current mode and rewrite BLS entries
        self.layout = LayoutMode::Current;
        self.rewrite_bls_entries()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: verify TestRoot creates a valid sysroot layout.
    #[test]
    fn test_initial_install() -> Result<()> {
        let root = TestRoot::new()?;

        let depl = root.current();
        assert_eq!(depl.verity, fake_digest_version(0));

        // All three storage areas should have exactly one entry
        assert_eq!(root.list_images()?.len(), 1);
        assert_eq!(root.list_state_dirs()?.len(), 1);
        assert_eq!(root.list_boot_binaries()?.len(), 1);

        // BLS entry should round-trip through the parser correctly
        let entries = root.read_bls_entries()?;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].get_verity()?, depl.verity);
        assert_eq!(entries[0].boot_artifact_name()?, depl.verity);

        Ok(())
    }

    /// Verify that the legacy layout creates unprefixed boot directories
    /// and BLS entries that reference unprefixed paths.
    #[test]
    fn test_legacy_layout_creates_unprefixed_dirs() -> Result<()> {
        let root = TestRoot::new_legacy()?;
        let depl = root.current();

        // Boot binary directory should be the raw digest, no prefix
        let boot_dir = root.boot_dir()?;
        let expected_dir = &depl.verity;
        assert!(
            boot_dir.exists(expected_dir),
            "Legacy layout should create unprefixed dir {expected_dir}"
        );

        // The prefixed version should NOT exist
        let prefixed_dir = format!("{TYPE1_BOOT_DIR_PREFIX}{}", depl.verity);
        assert!(
            !boot_dir.exists(&prefixed_dir),
            "Legacy layout should NOT create prefixed dir {prefixed_dir}"
        );

        // BLS entry should parse and return the correct verity digest.
        // boot_artifact_name() handles legacy entries by returning the raw
        // dir name when the prefix is absent.
        let entries = root.read_bls_entries()?;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].get_verity()?, depl.verity);
        assert_eq!(entries[0].boot_artifact_name()?, depl.verity);

        Ok(())
    }

    /// Verify that legacy layout with multiple deployments (shared kernel
    /// scenario) works correctly.
    #[test]
    fn test_legacy_layout_shared_kernel() -> Result<()> {
        let mut root = TestRoot::new_legacy()?;
        let digest_a = root.current().verity.clone();

        // B shares A's kernel
        root.upgrade(1, ChangeType::Userspace)?;
        let digest_b = root.current().verity.clone();

        // Should still have only one boot binary dir (shared)
        let boot_bins = root.list_boot_binaries()?;
        assert_eq!(boot_bins.len(), 1);
        assert_eq!(boot_bins[0], digest_a);

        // Both BLS entries should reference A's boot dir via boot_artifact_name
        let entries = root.read_bls_entries()?;
        assert_eq!(entries.len(), 2);
        for entry in &entries {
            assert_eq!(
                entry.boot_artifact_name()?,
                digest_a,
                "Both entries should point to A's boot dir"
            );
        }

        // But they should have different composefs= verity digests
        let verity_set: std::collections::HashSet<String> =
            entries.iter().map(|e| e.get_verity().unwrap()).collect();
        assert!(verity_set.contains(&digest_a));
        assert!(verity_set.contains(&digest_b));

        Ok(())
    }

    /// Verify that migrate_to_prefixed renames directories and rewrites
    /// BLS entries correctly.
    #[test]
    fn test_migrate_to_prefixed() -> Result<()> {
        let mut root = TestRoot::new_legacy()?;
        let digest_a = root.current().verity.clone();

        // Add a second deployment with a new kernel
        root.upgrade(1, ChangeType::Kernel)?;
        let digest_b = root.current().verity.clone();

        // Before migration: unprefixed dirs
        let boot_dir = root.boot_dir()?;
        assert!(boot_dir.exists(&digest_a));
        assert!(boot_dir.exists(&digest_b));

        // Perform migration
        root.migrate_to_prefixed()?;

        // After migration: prefixed dirs
        let boot_dir = root.boot_dir()?;
        let prefixed_a = format!("{TYPE1_BOOT_DIR_PREFIX}{digest_a}");
        let prefixed_b = format!("{TYPE1_BOOT_DIR_PREFIX}{digest_b}");
        assert!(
            boot_dir.exists(&prefixed_a),
            "After migration, {prefixed_a} should exist"
        );
        assert!(
            boot_dir.exists(&prefixed_b),
            "After migration, {prefixed_b} should exist"
        );
        assert!(
            !boot_dir.exists(&digest_a),
            "After migration, unprefixed {digest_a} should be gone"
        );
        assert!(
            !boot_dir.exists(&digest_b),
            "After migration, unprefixed {digest_b} should be gone"
        );

        // BLS entries should now reference the prefixed paths
        let entries = root.read_bls_entries()?;
        assert_eq!(entries.len(), 2);
        for entry in &entries {
            let artifact = entry.boot_artifact_name()?;
            assert!(
                artifact == digest_a || artifact == digest_b,
                "boot_artifact_name should strip the prefix and return the digest"
            );
        }

        Ok(())
    }

    /// Verify that boot_artifact_info() returns has_prefix=false for legacy
    /// entries, which is the signal the migration code uses to decide what
    /// needs renaming. After migration, has_prefix should be true.
    #[test]
    fn test_boot_artifact_info_prefix_detection() -> Result<()> {
        let mut root = TestRoot::new_legacy()?;
        let digest_a = root.current().verity.clone();
        root.upgrade(1, ChangeType::Kernel)?;

        // Legacy entries: boot_artifact_info should report has_prefix=false
        let entries = root.read_bls_entries()?;
        for entry in &entries {
            let (digest, has_prefix) = entry.boot_artifact_info()?;
            assert!(
                !has_prefix,
                "Legacy entry for {digest} should have has_prefix=false"
            );
        }

        // Migrate to prefixed
        root.migrate_to_prefixed()?;

        // Current entries: boot_artifact_info should report has_prefix=true
        let entries = root.read_bls_entries()?;
        for entry in &entries {
            let (digest, has_prefix) = entry.boot_artifact_info()?;
            assert!(
                has_prefix,
                "Migrated entry for {digest} should have has_prefix=true"
            );
        }

        // boot_artifact_name() should return the same digest in both cases
        let migrated_digests: std::collections::HashSet<&str> = entries
            .iter()
            .map(|e| e.boot_artifact_name().unwrap())
            .collect();
        assert!(migrated_digests.contains(digest_a.as_str()));

        Ok(())
    }

    /// Verify that boot_artifact_info() works correctly in a shared-kernel
    /// scenario with legacy layout. Both entries should report has_prefix=false
    /// and the same boot_artifact_name (the shared directory).
    #[test]
    fn test_boot_artifact_info_shared_kernel_legacy() -> Result<()> {
        let mut root = TestRoot::new_legacy()?;
        let digest_a = root.current().verity.clone();

        root.upgrade(1, ChangeType::Userspace)?;

        let entries = root.read_bls_entries()?;
        assert_eq!(entries.len(), 2);

        for entry in &entries {
            let (digest, has_prefix) = entry.boot_artifact_info()?;
            assert!(!has_prefix, "Legacy shared entry should have no prefix");
            assert_eq!(digest, digest_a, "Both should share A's boot dir");
        }

        Ok(())
    }
}
