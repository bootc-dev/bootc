//! # Boot Loader Specification entry management
//!
//! This module implements support for merging disparate kernel argument sources
//! into the single BLS entry `options` field. Each source (e.g., TuneD, admin,
//! bootc kargs.d) can independently manage its own set of kernel arguments,
//! which are tracked via `# x-ostree-options-source-<name>` magic comments
//! in BLS config files.
//!
//! See <https://github.com/ostreedev/ostree/pull/3570>
//! See <https://github.com/bootc-dev/bootc/issues/899>

use anyhow::{Context, Result, ensure};
use bootc_kernel_cmdline::utf8::{Cmdline, CmdlineOwned};
use camino::{Utf8Path, Utf8PathBuf};
use fn_error_context::context;
use std::collections::BTreeMap;

use crate::parsers::bls_config::{BLSConfigType, parse_bls_config};

/// The standard path to BLS entry files, relative to the filesystem root.
const LOADER_ENTRIES_PATH: &str = "boot/loader/entries";

/// Set the kernel arguments for a specific source in all BLS entries,
/// then recompute the merged `options` line.
///
/// This is the core implementation of `bootc loader-entries set-options-for-source`.
///
/// When `new_options` is `None`, the source is removed entirely.
/// When `new_options` is `Some("")` (empty), the source is recorded but contributes no options.
#[context("Setting options for source '{source}'")]
pub(crate) fn set_options_for_source(
    root: &str,
    source: &str,
    new_options: Option<&str>,
) -> Result<()> {
    ensure!(!source.is_empty(), "Source name must not be empty");
    ensure!(
        source
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "Source name must contain only alphanumeric characters, hyphens, or underscores"
    );

    let entries_dir = Utf8Path::new(root).join(LOADER_ENTRIES_PATH);
    ensure!(
        entries_dir.is_dir(),
        "Boot loader entries directory not found: {entries_dir}"
    );

    let mut found_any = false;
    for entry in entries_dir
        .read_dir_utf8()
        .with_context(|| format!("Reading {entries_dir}"))?
    {
        let entry = entry?;
        let path = Utf8PathBuf::from(entry.path().as_str());
        if path.extension() != Some("conf") {
            continue;
        }

        found_any = true;
        set_options_for_source_in_entry(&path, source, new_options)
            .with_context(|| format!("Processing entry {path}"))?;
    }

    ensure!(found_any, "No .conf BLS entries found in {entries_dir}");

    Ok(())
}

/// Process a single BLS entry file: update the source options and recompute the merged options.
fn set_options_for_source_in_entry(
    path: &Utf8Path,
    source: &str,
    new_options: Option<&str>,
) -> Result<()> {
    let contents = std::fs::read_to_string(path).with_context(|| format!("Reading {path}"))?;
    let mut config = parse_bls_config(&contents).with_context(|| format!("Parsing {path}"))?;

    // Get the current options (only for NonEFI configs)
    let BLSConfigType::NonEFI { ref options, .. } = config.cfg_type else {
        tracing::debug!("Skipping EFI/unknown entry {path} (no options field)");
        return Ok(());
    };

    let current_options = options.as_deref().unwrap_or_default().to_string();

    // Compute the new merged options
    let merged = compute_merged_options(
        &current_options,
        &config.source_options,
        source,
        new_options,
    )?;

    // Update the source tracking
    match new_options {
        Some(opts) => {
            config
                .source_options
                .insert(source.to_string(), CmdlineOwned::from(opts.to_string()));
        }
        None => {
            config.source_options.remove(source);
        }
    }

    // Update the options field
    if let BLSConfigType::NonEFI {
        ref mut options, ..
    } = config.cfg_type
    {
        *options = Some(merged);
    }

    // Write back
    let output = format!("{config}");
    std::fs::write(path, output).with_context(|| format!("Writing {path}"))?;

    tracing::info!("Updated entry {path}");
    Ok(())
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
    target_source: &str,
    new_options: Option<&str>,
) -> Result<CmdlineOwned> {
    let mut result = Cmdline::from(current_options);

    // Remove old options from the target source (if it was previously tracked)
    if let Some(old_source_opts) = source_options.get(target_source) {
        for param in old_source_opts.iter() {
            result.remove_exact(&param);
        }
    }

    // Add new options for the target source
    if let Some(new_opts) = new_options {
        if !new_opts.is_empty() {
            let new_cmdline = Cmdline::from(new_opts);
            for param in new_cmdline.iter() {
                result.add(&param);
            }
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_merged_options_add_new_source() {
        let current = "root=UUID=abc123 rw composefs=digest123";
        let sources = BTreeMap::new();

        let result = compute_merged_options(
            current,
            &sources,
            "tuned",
            Some("isolcpus=1-3 nohz_full=1-3"),
        )
        .unwrap();

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

        let result =
            compute_merged_options(current, &sources, "tuned", Some("isolcpus=0-7")).unwrap();

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

        let result = compute_merged_options(current, &sources, "tuned", None).unwrap();

        assert_eq!(&*result, "root=UUID=abc123 rw");
    }

    #[test]
    fn test_compute_merged_options_empty_initial() {
        let current = "";
        let sources = BTreeMap::new();

        let result =
            compute_merged_options(current, &sources, "tuned", Some("isolcpus=1-3")).unwrap();

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

        let result = compute_merged_options(current, &sources, "tuned", Some("")).unwrap();

        assert_eq!(&*result, "root=UUID=abc123 rw");
    }

    #[test]
    fn test_roundtrip_with_source_comments() {
        let input = r#"
            title Fedora 42 (CoreOS)
            version 2
            linux /boot/vmlinuz
            initrd /boot/initramfs.img
            # x-ostree-options-source-base root=UUID=abc123 rw
            # x-ostree-options-source-tuned isolcpus=1-3
            options root=UUID=abc123 rw isolcpus=1-3
        "#;

        let config = parse_bls_config(input).unwrap();

        // Verify source options were parsed
        assert_eq!(config.source_options.len(), 2);
        assert_eq!(&*config.source_options["base"], "root=UUID=abc123 rw");
        assert_eq!(&*config.source_options["tuned"], "isolcpus=1-3");

        // Verify roundtrip preserves source comments
        let output = format!("{config}");
        assert!(output.contains("# x-ostree-options-source-base root=UUID=abc123 rw"));
        assert!(output.contains("# x-ostree-options-source-tuned isolcpus=1-3"));
        assert!(output.contains("options root=UUID=abc123 rw isolcpus=1-3"));
    }

    #[test]
    fn test_set_options_for_source_in_entry() {
        let td = tempfile::tempdir().unwrap();
        let entry_path = Utf8Path::from_path(td.path())
            .expect("temp path should be valid UTF-8")
            .join("test.conf");

        let initial_content = "\
title Test OS
version 1
linux /boot/vmlinuz
initrd /boot/initramfs.img
options root=UUID=abc123 rw
";
        std::fs::write(&entry_path, initial_content).unwrap();

        // Add a new source
        set_options_for_source_in_entry(&entry_path, "tuned", Some("isolcpus=1-3 nohz_full=1-3"))
            .unwrap();

        let result = std::fs::read_to_string(&entry_path).unwrap();
        let config = parse_bls_config(&result).unwrap();

        assert_eq!(config.source_options.len(), 1);
        assert_eq!(
            &*config.source_options["tuned"],
            "isolcpus=1-3 nohz_full=1-3"
        );

        let BLSConfigType::NonEFI { options, .. } = &config.cfg_type else {
            panic!("Expected NonEFI");
        };
        let options_str = options.as_deref().unwrap().to_string();
        assert!(options_str.contains("root=UUID=abc123"));
        assert!(options_str.contains("rw"));
        assert!(options_str.contains("isolcpus=1-3"));
        assert!(options_str.contains("nohz_full=1-3"));

        // Now update the source
        set_options_for_source_in_entry(&entry_path, "tuned", Some("isolcpus=0-7")).unwrap();

        let result = std::fs::read_to_string(&entry_path).unwrap();
        let config = parse_bls_config(&result).unwrap();

        assert_eq!(&*config.source_options["tuned"], "isolcpus=0-7");

        let BLSConfigType::NonEFI { options, .. } = &config.cfg_type else {
            panic!("Expected NonEFI");
        };
        let options_str = options.as_deref().unwrap().to_string();
        assert!(options_str.contains("root=UUID=abc123"));
        assert!(options_str.contains("isolcpus=0-7"));
        assert!(!options_str.contains("nohz_full=1-3"));

        // Now remove the source
        set_options_for_source_in_entry(&entry_path, "tuned", None).unwrap();

        let result = std::fs::read_to_string(&entry_path).unwrap();
        let config = parse_bls_config(&result).unwrap();

        assert!(config.source_options.is_empty());

        let BLSConfigType::NonEFI { options, .. } = &config.cfg_type else {
            panic!("Expected NonEFI");
        };
        let options_str = options.as_deref().unwrap().to_string();
        assert!(options_str.contains("root=UUID=abc123"));
        assert!(!options_str.contains("isolcpus"));
    }

    #[test]
    fn test_source_name_validation() {
        assert!(set_options_for_source("/nonexistent", "", Some("foo")).is_err());
        assert!(set_options_for_source("/nonexistent", "bad name", Some("foo")).is_err());
        assert!(set_options_for_source("/nonexistent", "bad/name", Some("foo")).is_err());
    }
}
