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
use fn_error_context::context;
use ostree::{gio, glib};
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
        let value = value.trim();
        if source_name.is_empty() || value.is_empty() {
            continue;
        }
        sources.insert(
            source_name.to_string(),
            CmdlineOwned::from(value.to_string()),
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
    if let Some(new_opts) = new_options.filter(|v| !v.is_empty()) {
        let new_cmdline = Cmdline::from(new_opts);
        for param in new_cmdline.iter() {
            merged.add(&param);
        }
    }

    merged
}

/// Read x-options-source-* keys from the staged deployment data file.
///
/// When a deployment is staged, ostree serializes any extension BLS keys into
/// the "bootconfig-extra" field of the staged deployment GVariant at
/// /run/ostree/staged-deployment. This function reads that file, extracts the
/// bootconfig-extra dict, and returns all x-options-source-* entries.
///
/// This is needed to discover sources set by previous calls to
/// set-options-for-source in the same boot cycle, since the staged BLS entry
/// doesn't exist on disk yet (finalization writes it at shutdown).
fn read_staged_bootconfig_extra_sources(
    sysroot: &ostree::Sysroot,
) -> Result<BTreeMap<String, CmdlineOwned>> {
    let mut sources = BTreeMap::new();
    let sysroot_dir = crate::utils::sysroot_dir(sysroot)?;

    // The staged deployment data file is written by ostree during
    // stage_tree_with_options() and lives under /run/ostree/.
    let data = match sysroot_dir.open("run/ostree/staged-deployment") {
        Ok(mut f) => {
            let mut buf = Vec::new();
            std::io::Read::read_to_end(&mut f, &mut buf)
                .context("Reading staged deployment data")?;
            buf
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(sources),
        Err(e) => return Err(anyhow::Error::new(e).context("Opening staged deployment data")),
    };

    // The staged deployment file is a GVariant of type a{sv}.
    let variant = glib::Variant::from_data_with_type(&data, glib::VariantTy::VARDICT);
    let dict = glib::VariantDict::new(Some(&variant));

    // Look up "bootconfig-extra" which is stored as a{ss} inside the a{sv} dict.
    if let Some(extra) = dict.lookup_value("bootconfig-extra", None) {
        // Handle both direct a{ss} and variant-wrapped a{ss}
        let inner = if extra.type_().as_str() == "v" {
            extra.child_value(0)
        } else {
            extra
        };
        if inner.type_().as_str() == "a{ss}" {
            for i in 0..inner.n_children() {
                let entry = inner.child_value(i);
                let key: String = entry.child_value(0).get().ok_or_else(|| {
                    anyhow::anyhow!("Unexpected type for key in bootconfig-extra entry")
                })?;
                let value: String = entry.child_value(1).get().ok_or_else(|| {
                    anyhow::anyhow!("Unexpected type for value in bootconfig-extra entry")
                })?;
                if let Some(name) = key.strip_prefix(OPTIONS_SOURCE_KEY_PREFIX) {
                    if !value.is_empty() {
                        sources.insert(name.to_string(), CmdlineOwned::from(value));
                    }
                }
            }
        }
    }

    Ok(sources)
}

/// Read the BLS entry file content for a deployment from /boot/loader/entries/.
///
/// Returns `Ok(Some(content))` if the entry is found, `Ok(None)` if no matching
/// entry exists, or `Err` if there's an I/O error.
///
/// We match by checking the `options` line for the deployment's ostree path
/// (which includes the stateroot, bootcsum, and bootserial).
fn read_bls_entry_for_deployment(
    sysroot: &ostree::Sysroot,
    deployment: &ostree::Deployment,
) -> Result<Option<String>> {
    let sysroot_dir = crate::utils::sysroot_dir(sysroot)?;
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
    let source_options = if staged.is_some() {
        // For staged deployments, extract source keys from the in-memory bootconfig.
        // We can't read a BLS file because it hasn't been written yet (finalization
        // happens at shutdown).
        //
        // We discover sources from two places:
        // 1. The booted BLS entry (sources that have been finalized in previous boots)
        // 2. The staged bootconfig (sources set since last boot via prior calls to
        //    set-options-for-source that haven't been finalized yet)
        //
        // For (2), the staged bootconfig's extra keys are restored from the
        // "bootconfig-extra" GVariant by ostree's _ostree_sysroot_reload_staged()
        // during sysroot.load(). We probe the bootconfig for all source keys we
        // can discover.
        let mut sources = BTreeMap::new();

        // First: discover from the booted BLS entry (already-finalized sources)
        if let Some(bls_content) =
            read_bls_entry_for_deployment(sysroot, &booted).context("Reading booted BLS entry")?
        {
            let booted_sources = extract_source_options_from_bls(&bls_content);
            for name in booted_sources.keys() {
                let key = format!("{OPTIONS_SOURCE_KEY_PREFIX}{name}");
                if let Some(val) = bootconfig.get(&key) {
                    sources.insert(name.clone(), CmdlineOwned::from(val.to_string()));
                }
            }
        }

        // Second: discover from the staged bootconfig's extra keys.
        // These are sources set by prior calls to set-options-for-source
        // in this boot cycle (before any reboot). We read them from the
        // staged deployment data file which contains the serialized
        // bootconfig-extra GVariant.
        let staged_sources = read_staged_bootconfig_extra_sources(sysroot)?;
        for (name, value) in staged_sources {
            sources.entry(name).or_insert(value);
        }

        sources
    } else {
        // For booted deployments, parse the BLS file directly
        let bls_content = read_bls_entry_for_deployment(sysroot, &booted)
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
        (None, None) | (None, Some("")) => true,
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
    for name in source_options.keys() {
        let key = format!("{OPTIONS_SOURCE_KEY_PREFIX}{name}");
        merge_bootconfig.set(&key, "");
    }
    // Re-set the keys we want to keep (all except the one being removed)
    for (name, value) in &source_options {
        if name != &*source {
            let key = format!("{OPTIONS_SOURCE_KEY_PREFIX}{name}");
            merge_bootconfig.set(&key, value);
        }
    }
    // Set the new/updated source key (if not removing)
    if let Some(opts_str) = new_options {
        merge_bootconfig.set(&source_key, opts_str);
    }

    // Build kargs as string slices for the ostree API
    let kargs_strs: Vec<String> = merged.iter_str().map(|s| s.to_string()).collect();
    let kargs_refs: Vec<&str> = kargs_strs.iter().map(|s| s.as_str()).collect();

    let opts = ostree::SysrootDeployTreeOpts {
        override_kernel_argv: Some(&kargs_refs),
        ..Default::default()
    };

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
        // (input, should_succeed)
        let cases = [
            ("tuned", true),
            ("bootc-kargs-d", true),
            ("my_source_123", true),
            ("", false),
            ("bad name", false),
            ("bad/name", false),
            ("bad.name", false),
            ("foo@bar", false),
        ];
        for (input, expect_ok) in cases {
            let result = SourceName::parse(input);
            assert_eq!(
                result.is_ok(),
                expect_ok,
                "SourceName::parse({input:?}) should {}",
                if expect_ok { "succeed" } else { "fail" }
            );
        }
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
    fn test_extract_source_options_ignores_empty_values() {
        // Empty value (tombstone) should be filtered out
        let bls = "\
options root=UUID=abc
x-options-source-tuned
x-options-source-dracut   
x-options-source-admin nohz=full
";

        let sources = extract_source_options_from_bls(bls);
        assert_eq!(sources.len(), 1);
        assert_eq!(&*sources["admin"], "nohz=full");
    }

    #[test]
    fn test_compute_merged_options() {
        // Each case: (description, current_options, source_map, target_source, new_options, expected)
        let cases: &[(&str, &str, &[(&str, &str)], &str, Option<&str>, &str)] = &[
            (
                "add new source",
                "root=UUID=abc123 rw composefs=digest123",
                &[],
                "tuned",
                Some("isolcpus=1-3 nohz_full=1-3"),
                "root=UUID=abc123 rw composefs=digest123 isolcpus=1-3 nohz_full=1-3",
            ),
            (
                "update existing source",
                "root=UUID=abc123 rw isolcpus=1-3 nohz_full=1-3",
                &[("tuned", "isolcpus=1-3 nohz_full=1-3")],
                "tuned",
                Some("isolcpus=0-7"),
                "root=UUID=abc123 rw isolcpus=0-7",
            ),
            (
                "remove source (None)",
                "root=UUID=abc123 rw isolcpus=1-3 nohz_full=1-3",
                &[("tuned", "isolcpus=1-3 nohz_full=1-3")],
                "tuned",
                None,
                "root=UUID=abc123 rw",
            ),
            (
                "empty initial options",
                "",
                &[],
                "tuned",
                Some("isolcpus=1-3"),
                "isolcpus=1-3",
            ),
            (
                "clear source with empty string",
                "root=UUID=abc123 rw isolcpus=1-3",
                &[("tuned", "isolcpus=1-3")],
                "tuned",
                Some(""),
                "root=UUID=abc123 rw",
            ),
            (
                "preserves untracked options",
                "root=UUID=abc123 rw quiet isolcpus=1-3",
                &[("tuned", "isolcpus=1-3")],
                "tuned",
                Some("nohz=full"),
                "root=UUID=abc123 rw quiet nohz=full",
            ),
            (
                "multiple sources, update one preserves others",
                "root=UUID=abc rw isolcpus=1-3 rd.driver.pre=vfio-pci",
                &[
                    ("tuned", "isolcpus=1-3"),
                    ("dracut", "rd.driver.pre=vfio-pci"),
                ],
                "tuned",
                Some("nohz=full"),
                "root=UUID=abc rw rd.driver.pre=vfio-pci nohz=full",
            ),
        ];

        for (desc, current, source_entries, target, new_opts, expected) in cases {
            let mut sources = BTreeMap::new();
            for (name, value) in *source_entries {
                sources.insert(name.to_string(), CmdlineOwned::from(value.to_string()));
            }
            let source = SourceName::parse(target).unwrap();
            let result = compute_merged_options(current, &sources, &source, *new_opts);
            assert_eq!(&*result, *expected, "case: {desc}");
        }
    }
}
