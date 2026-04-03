//! # Boot Loader Specification entry management
//!
//! This module implements support for merging disparate kernel argument sources
//! into the single BLS entry `options` field. Each source (e.g., TuneD, admin,
//! bootc kargs.d) can independently manage its own set of kernel arguments,
//! which are tracked via `x-options-source-<name>` extension keys in BLS config
//! files.
//!
//! See <https://github.com/ostreedev/ostree/pull/3570>
//! See <https://github.com/bootc-dev/bootc/issues/899>

use anyhow::{Context, Result, ensure};
use bootc_kernel_cmdline::utf8::{Cmdline, CmdlineOwned};
use cap_std_ext::cap_std;
use fn_error_context::context;
use ostree::gio;
use ostree_ext::ostree;
use std::collections::BTreeMap;

/// The BLS extension key prefix for source-tracked options.
const OPTIONS_SOURCE_KEY_PREFIX: &str = "x-options-source-";

/// A validated source name (alphanumeric + hyphens + underscores, non-empty).
///
/// This is a newtype wrapper around `String` that enforces validation at
/// construction time. See <https://lexi-lambda.github.io/blog/2019/11/05/parse-don-t-validate/>.
struct SourceName(String);

impl SourceName {
    /// Parse and validate a source name.
    fn parse(source: &str) -> Result<Self> {
        ensure!(!source.is_empty(), "Source name must not be empty");
        ensure!(
            source
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "Source name must contain only alphanumeric characters, hyphens, or underscores"
        );
        Ok(Self(source.to_owned()))
    }

    /// The BLS key for this source (e.g., `x-options-source-tuned`).
    fn bls_key(&self) -> String {
        format!("{OPTIONS_SOURCE_KEY_PREFIX}{}", self.0)
    }
}

impl std::ops::Deref for SourceName {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SourceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Extract source options from BLS entry content. Parses `x-options-source-*` keys
/// from the raw BLS text since the ostree BootconfigParser doesn't expose key iteration.
fn extract_source_options_from_bls(content: &str) -> BTreeMap<String, CmdlineOwned> {
    let mut sources = BTreeMap::new();
    for line in content.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix(OPTIONS_SOURCE_KEY_PREFIX) else {
            continue;
        };
        let Some((source_name, value)) = rest.split_once(|c: char| c.is_ascii_whitespace()) else {
            continue;
        };
        if source_name.is_empty() {
            continue;
        }
        sources.insert(
            source_name.to_string(),
            CmdlineOwned::from(value.trim().to_string()),
        );
    }
    sources
}

/// Compute the merged `options` line from all sources.
///
/// The algorithm:
/// 1. Start with the current options line
/// 2. Remove all options that belong to the old value of the specified source
/// 3. Add the new options for the specified source
///
/// Options not tracked by any source are preserved as-is.
fn compute_merged_options(
    current_options: &str,
    source_options: &BTreeMap<String, CmdlineOwned>,
    target_source: &SourceName,
    new_options: Option<&str>,
) -> CmdlineOwned {
    let mut merged = CmdlineOwned::from(current_options.to_owned());

    // Remove old options from the target source (if it was previously tracked)
    if let Some(old_source_opts) = source_options.get(&**target_source) {
        for param in old_source_opts.iter() {
            merged.remove_exact(&param);
        }
    }

    // Add new options for the target source
    if let Some(new_opts) = new_options {
        if !new_opts.is_empty() {
            let new_cmdline = Cmdline::from(new_opts);
            for param in new_cmdline.iter() {
                merged.add(&param);
            }
        }
    }

    merged
}

/// Read the BLS entry file content for a deployment from /boot/loader/entries/.
///
/// Returns `Ok(Some(content))` if the entry is found, `Ok(None)` if no matching
/// entry exists, or `Err` if there's an I/O error.
///
/// We match by checking the `options` line for the deployment's ostree path
/// (which includes the stateroot, bootcsum, and bootserial).
fn read_bls_entry_for_deployment(deployment: &ostree::Deployment) -> Result<Option<String>> {
    let sysroot_dir = cap_std::fs::Dir::open_ambient_dir("/", cap_std::ambient_authority())?;
    let entries_dir = sysroot_dir
        .open_dir("boot/loader/entries")
        .context("Opening boot/loader/entries")?;

    // Build the expected ostree= value from the deployment to match against.
    // The ostree= karg format is: /ostree/boot.N/$stateroot/$bootcsum/$bootserial
    // where bootcsum is the boot checksum and bootserial is the serial among
    // deployments sharing the same bootcsum (NOT the deployserial).
    let stateroot = deployment.stateroot();
    let bootserial = deployment.bootserial();
    let bootcsum = deployment.bootcsum();
    let ostree_match = format!("/{stateroot}/{bootcsum}/{bootserial}");

    for entry in entries_dir.entries_utf8()? {
        let entry = entry?;
        let file_name = entry.file_name()?;

        if !file_name.starts_with("ostree-") || !file_name.ends_with(".conf") {
            continue;
        }
        let content = entries_dir
            .read_to_string(&file_name)
            .with_context(|| format!("Reading BLS entry {file_name}"))?;
        // Match by parsing the ostree= karg from the options line and checking
        // that its path ends with our deployment's stateroot/bootcsum/bootserial.
        // A simple `contains` would be fragile (e.g., serial 0 vs 01).
        if content.lines().any(|line| {
            line.starts_with("options ")
                && line.split_ascii_whitespace().any(|arg| {
                    arg.strip_prefix("ostree=")
                        .is_some_and(|path| path.ends_with(&ostree_match))
                })
        }) {
            return Ok(Some(content));
        }
    }

    Ok(None)
}

/// Set the kernel arguments for a specific source via ostree staged deployment.
///
/// If no staged deployment exists, this stages a new deployment based on
/// the booted deployment's commit with the updated kargs. If a staged
/// deployment already exists (e.g. from `bootc upgrade`), it is replaced
/// with a new one using the staged commit and origin, preserving any
/// pending upgrade while layering the source kargs change on top.
///
/// The `x-options-source-*` keys survive the staging roundtrip via the
/// ostree `bootconfig-extra` serialization: source keys are set on the
/// merge deployment's in-memory bootconfig before staging, ostree inherits
/// them during `stage_tree_with_options()`, serializes them into the staged
/// GVariant, and restores them at shutdown during finalization.
#[context("Setting options for source '{source}' (staged)")]
pub(crate) fn set_options_for_source_staged(
    sysroot: &ostree_ext::sysroot::SysrootLock,
    source: &str,
    new_options: Option<&str>,
) -> Result<()> {
    let source = SourceName::parse(source)?;

    // The bootconfig-extra serialization (preserving x-prefixed BLS keys through
    // staged deployment roundtrips) was added in ostree 2026.1. Without it,
    // source keys are silently dropped during finalization at shutdown.
    if !ostree::check_version(2026, 1) {
        anyhow::bail!("This feature requires ostree >= 2026.1 for bootconfig-extra support");
    }

    let booted = sysroot
        .booted_deployment()
        .ok_or_else(|| anyhow::anyhow!("Not booted into an ostree deployment"))?;

    // Determine the "base" deployment whose kargs and source keys we start from.
    // If there's already a staged deployment (e.g. from `bootc upgrade`), we use
    // its commit, origin, and kargs so we don't discard a pending upgrade. If no
    // staged deployment exists, we use the booted deployment.
    let staged = sysroot.staged_deployment();
    let base_deployment = staged.as_ref().unwrap_or(&booted);

    let bootconfig = ostree::Deployment::bootconfig(base_deployment)
        .ok_or_else(|| anyhow::anyhow!("Base deployment has no bootconfig"))?;

    // Read current options from the base deployment's bootconfig.
    let current_options = bootconfig
        .get("options")
        .map(|s| s.to_string())
        .unwrap_or_default();

    // Read existing x-options-source-* keys.
    //
    // Known limitation: when multiple *different* sources call set-options-for-source
    // before rebooting (e.g., source A then source B), the second call can only
    // discover source A if it was already in the booted BLS entry or is the target
    // source. If source A was brand-new (added in a previous staged deployment that
    // was never booted), its keys may not be discovered here and could be lost when
    // the staged deployment is replaced. In practice, this is unlikely — sources
    // like TuneD run at boot after finalization, so there's no staged deployment.
    // A future improvement could store a manifest of active sources in a dedicated
    // BLS key (e.g., x-bootc-active-sources) to enable full discovery.
    let source_options = if staged.is_some() {
        // For staged deployments, extract source keys from the in-memory bootconfig.
        // We can't read a BLS file because it hasn't been written yet (finalization
        // happens at shutdown). Discover source names from the booted BLS entry,
        // then probe the staged bootconfig for their values.
        let mut sources = BTreeMap::new();
        if let Some(bls_content) =
            read_bls_entry_for_deployment(&booted).context("Reading booted BLS entry")?
        {
            let booted_sources = extract_source_options_from_bls(&bls_content);
            for (name, _) in &booted_sources {
                let key = format!("{OPTIONS_SOURCE_KEY_PREFIX}{name}");
                if let Some(val) = bootconfig.get(&key) {
                    sources.insert(name.clone(), CmdlineOwned::from(val.to_string()));
                }
            }
        }
        // Also check the target source directly in the staged bootconfig.
        // This handles the case where set-options-for-source was called
        // multiple times before rebooting: the target source exists in the
        // staged bootconfig but not in the booted BLS entry.
        if !sources.contains_key(&*source) {
            let target_key = source.bls_key();
            if let Some(val) = bootconfig.get(&target_key) {
                if !val.is_empty() {
                    sources.insert(source.0.clone(), CmdlineOwned::from(val.to_string()));
                }
            }
        }
        sources
    } else {
        // For booted deployments, parse the BLS file directly
        let bls_content = read_bls_entry_for_deployment(&booted)
            .context("Reading booted BLS entry")?
            .ok_or_else(|| anyhow::anyhow!("No BLS entry found for booted deployment"))?;
        extract_source_options_from_bls(&bls_content)
    };

    // Compute merged options
    let source_key = source.bls_key();
    let merged = compute_merged_options(&current_options, &source_options, &source, new_options);

    // Check for idempotency: if nothing changed, skip staging.
    // Compare the merged cmdline against the current one, and the source value.
    let merged_str = merged.to_string();
    let is_options_unchanged = merged_str == current_options;
    let is_source_unchanged = match (source_options.get(&*source), new_options) {
        (Some(old), Some(new)) => &**old == new,
        (None, None) => true,
        _ => false,
    };

    if is_options_unchanged && is_source_unchanged {
        tracing::info!("No changes needed for source '{source}'");
        return Ok(());
    }

    // Use the base deployment's commit and origin so we don't discard a
    // pending upgrade. The merge deployment is always the booted one (for
    // /etc merge), but the commit/origin come from whichever deployment
    // we're building on top of.
    let stateroot = booted.stateroot();
    let merge_deployment = sysroot
        .merge_deployment(Some(stateroot.as_str()))
        .unwrap_or_else(|| booted.clone());

    let origin = ostree::Deployment::origin(base_deployment)
        .ok_or_else(|| anyhow::anyhow!("Base deployment has no origin"))?;

    let ostree_commit = base_deployment.csum();

    // Update the source keys on the merge deployment's bootconfig BEFORE staging.
    // The ostree patch (bootconfig-extra) inherits x-prefixed keys from the merge
    // deployment's bootconfig during stage_tree_with_options(). By updating the
    // merge deployment's in-memory bootconfig here, the updated source keys will
    // be serialized into the staged GVariant and survive finalization at shutdown.
    let merge_bootconfig = ostree::Deployment::bootconfig(&merge_deployment)
        .ok_or_else(|| anyhow::anyhow!("Merge deployment has no bootconfig"))?;

    // Set all desired source keys on the merge bootconfig.
    // First, clear any existing source keys that we know about by setting
    // them to empty string. BootconfigParser has no remove() API, so ""
    // acts as a tombstone. An empty x-options-source-* key is harmless:
    // extract_source_options_from_bls will parse it as an empty value,
    // and the idempotency check skips empty values (!val.is_empty()).
    for (name, _) in &source_options {
        let key = format!("{OPTIONS_SOURCE_KEY_PREFIX}{name}");
        merge_bootconfig.set(&key, "");
    }
    // Re-set the keys we want to keep (all except the one being removed)
    for (name, value) in &source_options {
        if name != &*source {
            let key = format!("{OPTIONS_SOURCE_KEY_PREFIX}{name}");
            merge_bootconfig.set(&key, &value.to_string());
        }
    }
    // Set the new/updated source key (if not removing)
    if let Some(opts_str) = new_options {
        merge_bootconfig.set(&source_key, opts_str);
    }

    // Build kargs as string slices for the ostree API
    let kargs_strs: Vec<String> = merged.iter_str().map(|s| s.to_string()).collect();
    let kargs_refs: Vec<&str> = kargs_strs.iter().map(|s| s.as_str()).collect();

    let mut opts = ostree::SysrootDeployTreeOpts::default();
    opts.override_kernel_argv = Some(&kargs_refs);

    sysroot.stage_tree_with_options(
        Some(stateroot.as_str()),
        &ostree_commit,
        Some(&origin),
        Some(&merge_deployment),
        &opts,
        gio::Cancellable::NONE,
    )?;

    tracing::info!("Staged deployment with updated kargs for source '{source}'");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source_name_validation() {
        assert!(SourceName::parse("tuned").is_ok());
        assert!(SourceName::parse("bootc-kargs-d").is_ok());
        assert!(SourceName::parse("my_source_123").is_ok());
        assert!(SourceName::parse("").is_err());
        assert!(SourceName::parse("bad name").is_err());
        assert!(SourceName::parse("bad/name").is_err());
        assert!(SourceName::parse("bad.name").is_err());
    }

    #[test]
    fn test_source_name_bls_key() {
        let name = SourceName::parse("tuned").unwrap();
        assert_eq!(name.bls_key(), "x-options-source-tuned");
    }

    #[test]
    fn test_extract_source_options_from_bls() {
        let bls = "\
title Fedora Linux 43
version 6.8.0-300.fc40.x86_64
linux /vmlinuz-6.8.0
initrd /initramfs-6.8.0.img
options root=UUID=abc rw nohz=full isolcpus=1-3 rd.driver.pre=vfio-pci
x-options-source-tuned nohz=full isolcpus=1-3
x-options-source-dracut rd.driver.pre=vfio-pci
";

        let sources = extract_source_options_from_bls(bls);
        assert_eq!(sources.len(), 2);
        assert_eq!(&*sources["tuned"], "nohz=full isolcpus=1-3");
        assert_eq!(&*sources["dracut"], "rd.driver.pre=vfio-pci");
    }

    #[test]
    fn test_extract_source_options_ignores_non_source_keys() {
        let bls = "\
title Test
version 1
linux /vmlinuz
options root=UUID=abc
x-unrelated-key some-value
custom-key data
";

        let sources = extract_source_options_from_bls(bls);
        assert!(sources.is_empty());
    }

    #[test]
    fn test_compute_merged_options_add_new_source() {
        let current = "root=UUID=abc123 rw composefs=digest123";
        let sources = BTreeMap::new();
        let source = SourceName::parse("tuned").unwrap();

        let result = compute_merged_options(
            current,
            &sources,
            &source,
            Some("isolcpus=1-3 nohz_full=1-3"),
        );

        assert_eq!(
            &*result,
            "root=UUID=abc123 rw composefs=digest123 isolcpus=1-3 nohz_full=1-3"
        );
    }

    #[test]
    fn test_compute_merged_options_update_existing_source() {
        let current = "root=UUID=abc123 rw isolcpus=1-3 nohz_full=1-3";
        let mut sources = BTreeMap::new();
        sources.insert(
            "tuned".to_string(),
            CmdlineOwned::from("isolcpus=1-3 nohz_full=1-3".to_string()),
        );
        let source = SourceName::parse("tuned").unwrap();

        let result = compute_merged_options(current, &sources, &source, Some("isolcpus=0-7"));

        assert_eq!(&*result, "root=UUID=abc123 rw isolcpus=0-7");
    }

    #[test]
    fn test_compute_merged_options_remove_source() {
        let current = "root=UUID=abc123 rw isolcpus=1-3 nohz_full=1-3";
        let mut sources = BTreeMap::new();
        sources.insert(
            "tuned".to_string(),
            CmdlineOwned::from("isolcpus=1-3 nohz_full=1-3".to_string()),
        );
        let source = SourceName::parse("tuned").unwrap();

        let result = compute_merged_options(current, &sources, &source, None);

        assert_eq!(&*result, "root=UUID=abc123 rw");
    }

    #[test]
    fn test_compute_merged_options_empty_initial() {
        let current = "";
        let sources = BTreeMap::new();
        let source = SourceName::parse("tuned").unwrap();

        let result = compute_merged_options(current, &sources, &source, Some("isolcpus=1-3"));

        assert_eq!(&*result, "isolcpus=1-3");
    }

    #[test]
    fn test_compute_merged_options_clear_source_with_empty() {
        let current = "root=UUID=abc123 rw isolcpus=1-3";
        let mut sources = BTreeMap::new();
        sources.insert(
            "tuned".to_string(),
            CmdlineOwned::from("isolcpus=1-3".to_string()),
        );
        let source = SourceName::parse("tuned").unwrap();

        let result = compute_merged_options(current, &sources, &source, Some(""));

        assert_eq!(&*result, "root=UUID=abc123 rw");
    }

    #[test]
    fn test_compute_merged_options_preserves_untracked() {
        let current = "root=UUID=abc123 rw quiet isolcpus=1-3";
        let mut sources = BTreeMap::new();
        sources.insert(
            "tuned".to_string(),
            CmdlineOwned::from("isolcpus=1-3".to_string()),
        );
        let source = SourceName::parse("tuned").unwrap();

        let result = compute_merged_options(current, &sources, &source, Some("nohz=full"));

        assert_eq!(&*result, "root=UUID=abc123 rw quiet nohz=full");
    }

    #[test]
    fn test_compute_merged_options_multiple_sources() {
        let current = "root=UUID=abc rw isolcpus=1-3 rd.driver.pre=vfio-pci";
        let mut sources = BTreeMap::new();
        sources.insert(
            "tuned".to_string(),
            CmdlineOwned::from("isolcpus=1-3".to_string()),
        );
        sources.insert(
            "dracut".to_string(),
            CmdlineOwned::from("rd.driver.pre=vfio-pci".to_string()),
        );
        let source = SourceName::parse("tuned").unwrap();

        // Update tuned, dracut should be preserved
        let result = compute_merged_options(current, &sources, &source, Some("nohz=full"));

        assert_eq!(
            &*result,
            "root=UUID=abc rw rd.driver.pre=vfio-pci nohz=full"
        );
    }
}
