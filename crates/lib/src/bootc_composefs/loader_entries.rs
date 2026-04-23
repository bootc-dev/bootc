//! # Composefs backend for source-tracked kernel arguments
//!
//! This module implements `set-options-for-source` for composefs-booted systems.
//! Unlike the ostree path (which stages a new deployment via ostree APIs), the
//! composefs path directly modifies BLS entry files on /boot. This is both
//! simpler and more efficient:
//!
//! - `BLSConfig.extra` already preserves `x-options-source-*` keys through
//!   parse/write roundtrips
//! - No GVariant serialization, no ostree version gating, no finalization needed
//! - Kargs take effect on next boot without requiring a finalization service
//!
//! When a staged deployment exists (e.g. from `bootc upgrade`), the staged BLS
//! entries are also updated so finalization doesn't overwrite the kargs changes.
//!
//! See <https://github.com/bootc-dev/bootc/issues/899>

use anyhow::{Context, Result};
use bootc_kernel_cmdline::utf8::CmdlineOwned;
use cap_std_ext::cap_std::fs::Dir;
use cap_std_ext::dirext::CapStdExtDirExt;
use fn_error_context::context;
use std::collections::BTreeMap;

use super::state::get_booted_bls;
use super::status::get_sorted_staged_type1_boot_entries;
use crate::composefs_consts::TYPE1_ENT_PATH_STAGED;
use crate::loader_entries::{OPTIONS_SOURCE_KEY_PREFIX, SourceName, compute_merged_options};
use crate::parsers::bls_config::{BLSConfig, BLSConfigType, parse_bls_config};
use crate::store::{BootedComposefs, Storage};

/// Extract source options from a parsed `BLSConfig`'s `extra` HashMap.
fn extract_source_options_from_extra(bls: &BLSConfig) -> BTreeMap<String, CmdlineOwned> {
    let mut sources = BTreeMap::new();
    for (key, value) in &bls.extra {
        if let Some(name) = key.strip_prefix(OPTIONS_SOURCE_KEY_PREFIX) {
            if !name.is_empty() && !value.is_empty() {
                sources.insert(name.to_string(), CmdlineOwned::from(value.clone()));
            }
        }
    }
    sources
}

/// Get the current options string from a BLS config.
fn get_options_str(bls: &BLSConfig) -> Result<String> {
    match &bls.cfg_type {
        BLSConfigType::NonEFI { options, .. } => {
            Ok(options.as_ref().map(|o| o.to_string()).unwrap_or_default())
        }
        _ => anyhow::bail!(
            "BLS entry is not a NonEFI (BLS) type; \
             source-tracked kargs are only supported with BLS boot entries"
        ),
    }
}

/// Update a BLS config's options line and source keys in place.
fn update_bls_config(
    bls: &mut BLSConfig,
    merged_options: &CmdlineOwned,
    source: &SourceName,
    new_options: Option<&str>,
    source_options: &BTreeMap<String, CmdlineOwned>,
) -> Result<()> {
    // Update the options line
    match &mut bls.cfg_type {
        BLSConfigType::NonEFI { options, .. } => {
            *options = Some(merged_options.clone());
        }
        _ => anyhow::bail!("BLS entry is not a NonEFI (BLS) type"),
    }

    // Clear all known source keys, then re-set the ones we want to keep.
    for name in source_options.keys() {
        let key = format!("{OPTIONS_SOURCE_KEY_PREFIX}{name}");
        bls.extra.remove(&key);
    }
    // Re-set the keys we want to keep (all except the one being modified)
    for (name, value) in source_options {
        if name != &**source {
            let key = format!("{OPTIONS_SOURCE_KEY_PREFIX}{name}");
            bls.extra.insert(key, value.to_string());
        }
    }
    // Set the new/updated source key
    let source_key = source.bls_key();
    match new_options {
        Some(opts) => {
            bls.extra.insert(source_key, opts.to_string());
        }
        None => {
            // Removal: ensure the key is not present
            bls.extra.remove(&source_key);
        }
    }

    Ok(())
}

/// Read, update, and write back a BLS entry file in a directory.
///
/// Finds the entry matching the given version, parses it, applies the
/// source kargs change, and writes it back atomically.
fn update_bls_entry_in_dir(
    entries_dir: &Dir,
    target_version: &str,
    source: &SourceName,
    new_options: Option<&str>,
) -> Result<bool> {
    for entry in entries_dir.entries_utf8()? {
        let entry = entry?;
        let file_name = entry.file_name()?;
        if !file_name.ends_with(".conf") {
            continue;
        }
        let content = entries_dir
            .read_to_string(&file_name)
            .with_context(|| format!("Reading BLS entry {file_name}"))?;
        let mut bls =
            parse_bls_config(&content).with_context(|| format!("Parsing BLS entry {file_name}"))?;

        if bls.version().to_string() != target_version {
            continue;
        }

        // Skip EFI/UKI entries — can't modify their options
        if !matches!(bls.cfg_type, BLSConfigType::NonEFI { .. }) {
            continue;
        }

        let current_options = get_options_str(&bls)?;
        let source_options = extract_source_options_from_extra(&bls);
        let merged = compute_merged_options(&current_options, &source_options, source, new_options);

        update_bls_config(&mut bls, &merged, source, new_options, &source_options)?;

        entries_dir
            .atomic_write(&file_name, bls.to_string().as_bytes())
            .with_context(|| format!("Writing updated BLS entry {file_name}"))?;

        tracing::info!("Updated BLS entry '{file_name}' with kargs for source '{source}'");
        return Ok(true);
    }
    Ok(false)
}

/// Set the kernel arguments for a specific source on a composefs-booted system.
///
/// This directly modifies the BLS entry files on /boot rather than staging a
/// new deployment. The `x-options-source-*` keys are stored in the BLS
/// `extra` HashMap, which round-trips through parse/Display automatically.
///
/// If a staged deployment exists (e.g. from `bootc upgrade`), the staged BLS
/// entries are also updated so finalization doesn't overwrite the changes.
#[context("Setting options for source '{source}' (composefs)")]
pub(crate) fn set_options_for_source(
    storage: &Storage,
    booted_cfs: &BootedComposefs,
    source: &str,
    new_options: Option<&str>,
) -> Result<()> {
    let source = SourceName::parse(source)?;
    let boot_dir = storage.require_boot_dir()?;

    // Get the booted BLS entry to determine boot type and read source keys
    let booted_bls = get_booted_bls(boot_dir, booted_cfs)?;

    // Bail on UKI/EFI boot type — kargs are embedded in the PE binary
    if matches!(booted_bls.cfg_type, BLSConfigType::EFI { .. }) {
        anyhow::bail!(
            "Source-tracked kargs are not supported with UKI boot entries; \
             kernel arguments are embedded in the UKI PE binary"
        );
    }

    // Check for existing staged entries — if present, we work from those
    // so we don't lose changes from a pending upgrade.
    let staged_entries = get_sorted_staged_type1_boot_entries(boot_dir, true)?;
    let has_staged = !staged_entries.is_empty();

    // Determine the "current" BLS config to compute idempotency from.
    // If staged entries exist, use the primary staged entry (highest priority).
    // Otherwise, use the booted entry.
    let current_bls = if has_staged {
        staged_entries.last().expect("staged_entries is non-empty")
    } else {
        &booted_bls
    };

    // Read current options and source keys for idempotency check
    let current_options = get_options_str(current_bls)?;
    let source_options = extract_source_options_from_extra(current_bls);

    // Compute merged options
    let merged = compute_merged_options(&current_options, &source_options, &source, new_options);

    // Check for idempotency
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

    let booted_version = booted_bls.version().to_string();

    // Update the booted BLS entry in loader/entries/
    let entries_dir = boot_dir
        .open_dir("loader/entries")
        .context("Opening loader/entries")?;

    if !update_bls_entry_in_dir(&entries_dir, &booted_version, &source, new_options)? {
        anyhow::bail!(
            "Could not find BLS entry for booted deployment (version '{booted_version}')"
        );
    }

    // If staged entries exist, also update them so finalization doesn't
    // overwrite our changes.
    if has_staged {
        let staged_dir = boot_dir
            .open_dir(TYPE1_ENT_PATH_STAGED)
            .context("Opening staged entries directory")?;

        for staged_bls in &staged_entries {
            let staged_version = staged_bls.version().to_string();
            // Update each staged entry (best effort — some may be rollback
            // entries that share our version)
            let _ = update_bls_entry_in_dir(&staged_dir, &staged_version, &source, new_options);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader_entries::extract_source_options_from_bls;

    /// Helper to create a BLS config string with source keys
    fn make_bls(options: &str, source_keys: &[(&str, &str)]) -> String {
        let mut s = format!(
            "title Test OS\n\
             version 42.0\n\
             linux /vmlinuz\n\
             initrd /initramfs.img\n\
             options {options}\n"
        );
        for (key, value) in source_keys {
            s.push_str(&format!("x-options-source-{key} {value}\n"));
        }
        s
    }

    #[test]
    fn test_extract_source_options_from_extra() {
        let bls_text = make_bls(
            "root=UUID=abc rw nohz=full isolcpus=1-3",
            &[("tuned", "nohz=full isolcpus=1-3"), ("admin", "quiet")],
        );
        let bls = parse_bls_config(&bls_text).unwrap();
        let sources = extract_source_options_from_extra(&bls);
        assert_eq!(sources.len(), 2);
        assert_eq!(&*sources["tuned"], "nohz=full isolcpus=1-3");
        assert_eq!(&*sources["admin"], "quiet");
    }

    #[test]
    fn test_extract_source_options_from_extra_empty_value() {
        let bls_text = "title Test\nversion 1\nlinux /vmlinuz\noptions root=UUID=abc\n\
                         x-options-source-tuned \n";
        let bls = parse_bls_config(bls_text).unwrap();
        let sources = extract_source_options_from_extra(&bls);
        assert!(sources.is_empty(), "empty value should be filtered out");
    }

    #[test]
    fn test_extract_source_options_from_extra_no_sources() {
        let bls_text = make_bls("root=UUID=abc rw", &[]);
        let bls = parse_bls_config(&bls_text).unwrap();
        let sources = extract_source_options_from_extra(&bls);
        assert!(sources.is_empty());
    }

    #[test]
    fn test_update_bls_config_add_source() {
        let bls_text = make_bls("root=UUID=abc rw composefs=digest123", &[]);
        let mut bls = parse_bls_config(&bls_text).unwrap();
        let source = SourceName::parse("tuned").unwrap();
        let source_options = BTreeMap::new();
        let merged = compute_merged_options(
            "root=UUID=abc rw composefs=digest123",
            &source_options,
            &source,
            Some("nohz=full isolcpus=1-3"),
        );

        update_bls_config(
            &mut bls,
            &merged,
            &source,
            Some("nohz=full isolcpus=1-3"),
            &source_options,
        )
        .unwrap();

        // Verify options updated
        let opts = get_options_str(&bls).unwrap();
        assert!(opts.contains("nohz=full"), "should contain nohz=full");
        assert!(opts.contains("isolcpus=1-3"), "should contain isolcpus=1-3");
        assert!(
            opts.contains("root=UUID=abc"),
            "should preserve system kargs"
        );

        // Verify source key set
        assert_eq!(
            bls.extra.get("x-options-source-tuned").unwrap(),
            "nohz=full isolcpus=1-3"
        );
    }

    #[test]
    fn test_update_bls_config_replace_source() {
        let bls_text = make_bls(
            "root=UUID=abc rw nohz=full isolcpus=1-3",
            &[("tuned", "nohz=full isolcpus=1-3")],
        );
        let mut bls = parse_bls_config(&bls_text).unwrap();
        let source = SourceName::parse("tuned").unwrap();
        let mut source_options = BTreeMap::new();
        source_options.insert(
            "tuned".to_string(),
            CmdlineOwned::from("nohz=full isolcpus=1-3".to_string()),
        );
        let merged = compute_merged_options(
            "root=UUID=abc rw nohz=full isolcpus=1-3",
            &source_options,
            &source,
            Some("nohz=on rcu_nocbs=2-7"),
        );

        update_bls_config(
            &mut bls,
            &merged,
            &source,
            Some("nohz=on rcu_nocbs=2-7"),
            &source_options,
        )
        .unwrap();

        let opts = get_options_str(&bls).unwrap();
        assert!(!opts.contains("nohz=full"), "old nohz=full should be gone");
        assert!(
            !opts.contains("isolcpus=1-3"),
            "old isolcpus=1-3 should be gone"
        );
        assert!(opts.contains("nohz=on"), "new nohz=on should be present");
        assert!(
            opts.contains("rcu_nocbs=2-7"),
            "new rcu_nocbs=2-7 should be present"
        );
        assert_eq!(
            bls.extra.get("x-options-source-tuned").unwrap(),
            "nohz=on rcu_nocbs=2-7"
        );
    }

    #[test]
    fn test_update_bls_config_remove_source() {
        let bls_text = make_bls("root=UUID=abc rw nohz=full", &[("tuned", "nohz=full")]);
        let mut bls = parse_bls_config(&bls_text).unwrap();
        let source = SourceName::parse("tuned").unwrap();
        let mut source_options = BTreeMap::new();
        source_options.insert(
            "tuned".to_string(),
            CmdlineOwned::from("nohz=full".to_string()),
        );
        let merged =
            compute_merged_options("root=UUID=abc rw nohz=full", &source_options, &source, None);

        update_bls_config(&mut bls, &merged, &source, None, &source_options).unwrap();

        let opts = get_options_str(&bls).unwrap();
        assert!(!opts.contains("nohz=full"), "source karg should be removed");
        assert!(
            opts.contains("root=UUID=abc"),
            "system kargs should be preserved"
        );
        assert!(
            !bls.extra.contains_key("x-options-source-tuned"),
            "source key should be removed"
        );
    }

    #[test]
    fn test_update_bls_config_multiple_sources() {
        let bls_text = make_bls(
            "root=UUID=abc rw nohz=full rd.driver.pre=vfio-pci",
            &[("tuned", "nohz=full"), ("dracut", "rd.driver.pre=vfio-pci")],
        );
        let mut bls = parse_bls_config(&bls_text).unwrap();
        let source = SourceName::parse("tuned").unwrap();
        let mut source_options = BTreeMap::new();
        source_options.insert(
            "tuned".to_string(),
            CmdlineOwned::from("nohz=full".to_string()),
        );
        source_options.insert(
            "dracut".to_string(),
            CmdlineOwned::from("rd.driver.pre=vfio-pci".to_string()),
        );
        let merged = compute_merged_options(
            "root=UUID=abc rw nohz=full rd.driver.pre=vfio-pci",
            &source_options,
            &source,
            Some("isolcpus=1-3"),
        );

        update_bls_config(
            &mut bls,
            &merged,
            &source,
            Some("isolcpus=1-3"),
            &source_options,
        )
        .unwrap();

        let opts = get_options_str(&bls).unwrap();
        assert!(
            !opts.contains("nohz=full"),
            "old tuned karg should be removed"
        );
        assert!(
            opts.contains("isolcpus=1-3"),
            "new tuned karg should be present"
        );
        assert!(
            opts.contains("rd.driver.pre=vfio-pci"),
            "dracut karg should be preserved"
        );
        assert_eq!(
            bls.extra.get("x-options-source-tuned").unwrap(),
            "isolcpus=1-3"
        );
        assert_eq!(
            bls.extra.get("x-options-source-dracut").unwrap(),
            "rd.driver.pre=vfio-pci"
        );
    }

    #[test]
    fn test_bls_roundtrip_preserves_source_keys() {
        let bls_text = make_bls("root=UUID=abc rw nohz=full", &[("tuned", "nohz=full")]);
        let bls = parse_bls_config(&bls_text).unwrap();

        // Roundtrip: serialize and re-parse
        let serialized = bls.to_string();
        let reparsed = parse_bls_config(&serialized).unwrap();

        assert_eq!(
            reparsed.extra.get("x-options-source-tuned").unwrap(),
            "nohz=full"
        );
        let sources = extract_source_options_from_extra(&reparsed);
        assert_eq!(sources.len(), 1);
        assert_eq!(&*sources["tuned"], "nohz=full");
    }

    #[test]
    fn test_extract_matches_bls_text_parser() {
        // Verify that extracting from BLSConfig.extra gives the same
        // result as extracting from raw BLS text
        let bls_text = make_bls(
            "root=UUID=abc rw nohz=full isolcpus=1-3",
            &[("tuned", "nohz=full isolcpus=1-3"), ("admin", "quiet")],
        );
        let bls = parse_bls_config(&bls_text).unwrap();

        let from_extra = extract_source_options_from_extra(&bls);
        let from_text = extract_source_options_from_bls(&bls_text);

        assert_eq!(from_extra.len(), from_text.len());
        for (name, value) in &from_extra {
            assert_eq!(&**value, &*from_text[name], "mismatch for source '{name}'");
        }
    }
}
