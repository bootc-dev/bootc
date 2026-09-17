//! # Composefs backend for source-tracked kernel arguments
//!
//! bootc owns the BLS entries on composefs systems, so there is no ostree
//! staging to go through.  `set-options-for-source` still behaves like the
//! ostree backend: it stages the booted deployment again with an entry
//! carrying the merged `options` line, and the current entry becomes the
//! rollback.  Finalization installs the pending entries at shutdown as for
//! any staged deployment; there is no new state directory since the
//! deployment is the same.  `bootc rollback` then undoes the change.
//!
//! When an upgrade is already staged, its pending entry under
//! `loader/entries.staged/` is rewritten instead, so the change rides along
//! with it and is dropped with it.
//!
//! Removing a source deletes its `x-options-source-*` key; the ostree backend
//! leaves an empty tombstone because its parser cannot remove keys.
//!
//! See <https://github.com/bootc-dev/bootc/issues/899>

use anyhow::{Context, Result};
use cap_std_ext::cap_std::ambient_authority;
use cap_std_ext::cap_std::fs::Dir;
use cap_std_ext::dirext::CapStdExtDirExt;
use fn_error_context::context;
use linux_kernel_cmdline::utf8::CmdlineOwned;
use std::collections::BTreeMap;

use super::boot::{os_id_from_sort_key, primary_sort_key, secondary_sort_key, write_type1_entries};
use super::service::start_finalize_stated_svc;
use super::state::{get_booted_bls, write_staged_deployment};
use super::status::{StagedDeployment, get_composefs_status, get_sorted_type1_entries};
use crate::composefs_consts::{
    COMPOSEFS_STAGED_DEPLOYMENT_FNAME, COMPOSEFS_TRANSIENT_STATE_DIR, TYPE1_ENT_PATH_STAGED,
};
use crate::loader_entries::{OPTIONS_SOURCE_KEY_PREFIX, SourceName, compute_merged_options};
use crate::parsers::bls_config::{BLSConfig, BLSConfigType};
use crate::spec::Host;
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

/// Update a BLS config's options line and source keys in place.
fn update_bls_config(
    bls: &mut BLSConfig,
    merged_options: &CmdlineOwned,
    source: &SourceName,
    new_options: Option<&str>,
) -> Result<()> {
    match &mut bls.cfg_type {
        BLSConfigType::NonEFI { options, .. } => {
            *options = Some(merged_options.clone());
        }
        _ => anyhow::bail!("BLS entry is not a NonEFI (BLS) type"),
    }

    let source_key = source.bls_key();
    match new_options {
        Some(opts) => {
            bls.extra.insert(source_key, opts.to_string());
        }
        None => {
            bls.extra.remove(&source_key);
        }
    }

    Ok(())
}

/// Whether setting `new_options` for `source` would change anything: the
/// options line and the source's own record are both already as requested.
fn is_unchanged(
    current_options: &str,
    merged: &CmdlineOwned,
    source_options: &BTreeMap<String, CmdlineOwned>,
    source: &SourceName,
    new_options: Option<&str>,
) -> bool {
    let source_unchanged = match (source_options.get(&**source), new_options) {
        (Some(old), Some(new)) => &**old == new,
        (None, None) | (None, Some("")) => true,
        _ => false,
    };
    source_unchanged && &**merged == current_options
}

/// Whether the staged deployment is the booted one with other kernel arguments
fn is_kargs_only_staged(host: &Host, booted_cfs: &BootedComposefs) -> bool {
    host.status
        .staged
        .as_ref()
        .and_then(|s| s.composefs.as_ref())
        .is_some_and(|s| *s.verity == *booted_cfs.cmdline.digest)
}

/// Drop the staged deployment record and its pending entries
#[context("Removing staged deployment")]
fn remove_staged_deployment(boot_dir: &Dir) -> Result<()> {
    boot_dir
        .remove_all_optional(TYPE1_ENT_PATH_STAGED)
        .context("Removing staged entries")?;
    if let Ok(transient_dir) =
        Dir::open_ambient_dir(COMPOSEFS_TRANSIENT_STATE_DIR, ambient_authority())
    {
        transient_dir
            .remove_file_optional(COMPOSEFS_STAGED_DEPLOYMENT_FNAME)
            .context("Removing staged deployment file")?;
    }
    Ok(())
}

/// Set the kernel arguments for a specific source on a composefs-booted system.
#[context("Setting options for source '{source}' (composefs)")]
pub(crate) async fn set_options_for_source(
    storage: &Storage,
    booted_cfs: &BootedComposefs,
    source: &str,
    new_options: Option<&str>,
) -> Result<()> {
    let source = SourceName::parse(source)?;
    let boot_dir = storage.require_boot_dir()?;

    let booted_bls = get_booted_bls(boot_dir, booted_cfs)?;

    // Bail on UKI/EFI boot type — kargs are embedded in the PE binary
    if matches!(booted_bls.cfg_type, BLSConfigType::EFI { .. }) {
        anyhow::bail!(
            "Source-tracked kargs are not supported with UKI boot entries; \
             kernel arguments are embedded in the UKI PE binary"
        );
    }

    // Build on the pending entry when a deployment is staged, so a pending
    // upgrade keeps its kernel arguments and this change is not undone at
    // finalization.
    let host = get_composefs_status(storage, booted_cfs).await?;
    let staged_primary = match host.status.staged {
        Some(_) => get_sorted_type1_entries(boot_dir, true, true)?
            .into_iter()
            .next(),
        None => None,
    };
    let base = staged_primary
        .as_ref()
        .map(|entry| &entry.config)
        .unwrap_or(&booted_bls);

    let current_options = base.get_cmdline()?.to_string();
    let source_options = extract_source_options_from_extra(base);
    let merged = compute_merged_options(&current_options, &source_options, &source, new_options);

    if is_unchanged(
        &current_options,
        &merged,
        &source_options,
        &source,
        new_options,
    ) {
        tracing::info!("No changes needed for source '{source}'");
        return Ok(());
    }

    let mut updated = base.clone();
    update_bls_config(&mut updated, &merged, &source, new_options)?;

    match staged_primary {
        // A pending kernel-argument change brought back to what is booted:
        // nothing is left to finalize
        Some(_)
            if is_kargs_only_staged(&host, booted_cfs)
                && updated.get_cmdline().ok() == booted_bls.get_cmdline().ok()
                && updated.extra == booted_bls.extra =>
        {
            remove_staged_deployment(boot_dir)?;
            tracing::info!("Pending kargs change for source '{source}' reverted; nothing staged");
        }
        Some(staged) => {
            let staged_dir = boot_dir
                .open_dir(TYPE1_ENT_PATH_STAGED)
                .context("Opening staged entries directory")?;
            staged_dir
                .atomic_write(&staged.filename, updated.to_string().as_bytes())
                .with_context(|| format!("Writing staged BLS entry {}", staged.filename))?;
            let owned = staged_dir
                .reopen_as_ownedfd()
                .context("Reopening as owned fd")?;
            rustix::fs::fsync(owned).context("fsync")?;
            tracing::info!(
                "Updated staged BLS entry '{}' with kargs for source '{source}'",
                staged.filename
            );
        }
        None => {
            // Stage the booted deployment again: the new entry becomes the
            // default and the current one its rollback, exactly as an upgrade
            // keeps the booted entry.
            let os_id = os_id_from_sort_key(&booted_bls).to_string();
            updated.sort_key = Some(primary_sort_key(&os_id));
            let mut rollback = booted_bls.clone();
            rollback.sort_key = Some(secondary_sort_key(&os_id));

            boot_dir
                .remove_all_optional(TYPE1_ENT_PATH_STAGED)
                .context("Removing stale staged entries")?;
            boot_dir
                .create_dir_all(TYPE1_ENT_PATH_STAGED)
                .context("Creating staged entries directory")?;
            let staged_dir = boot_dir
                .open_dir(TYPE1_ENT_PATH_STAGED)
                .context("Opening staged entries directory")?;
            write_type1_entries(&staged_dir, &os_id, &updated, Some(&rollback))?;

            start_finalize_stated_svc()?;
            write_staged_deployment(&StagedDeployment {
                depl_id: booted_cfs.cmdline.digest.to_string(),
                finalization_locked: false,
            })?;
            tracing::info!("Staged kargs for source '{source}'; the current entry is the rollback");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader_entries::extract_source_options_from_bls;
    use crate::parsers::bls_config::parse_bls_config;

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

    fn options_of(bls: &BLSConfig) -> String {
        bls.get_cmdline().unwrap().to_string()
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

        // Same result as the text parser used by the ostree backend
        let from_text = extract_source_options_from_bls(&bls_text);
        assert_eq!(sources.len(), from_text.len());
        for (name, value) in &sources {
            assert_eq!(&**value, &*from_text[name]);
        }
    }

    #[test]
    fn test_extract_source_options_from_extra_skips_empty() {
        let bls_text = "title Test\nversion 1\nlinux /vmlinuz\noptions root=UUID=abc\n\
                         x-options-source-tuned \n";
        let bls = parse_bls_config(bls_text).unwrap();
        assert!(extract_source_options_from_extra(&bls).is_empty());
        let bls = parse_bls_config(&make_bls("root=UUID=abc rw", &[])).unwrap();
        assert!(extract_source_options_from_extra(&bls).is_empty());
    }

    /// (options, existing source keys, new options for `tuned`) -> (expected
    /// options, expected tuned key, keys that must survive untouched)
    #[test]
    fn test_update_bls_config() {
        let cases: &[(&str, &[(&str, &str)], Option<&str>, &str, Option<&str>)] = &[
            (
                "root=UUID=abc rw composefs=digest123",
                &[],
                Some("nohz=full isolcpus=1-3"),
                "root=UUID=abc rw composefs=digest123 nohz=full isolcpus=1-3",
                Some("nohz=full isolcpus=1-3"),
            ),
            (
                "root=UUID=abc rw nohz=full isolcpus=1-3",
                &[("tuned", "nohz=full isolcpus=1-3")],
                Some("nohz=on rcu_nocbs=2-7"),
                "root=UUID=abc rw nohz=on rcu_nocbs=2-7",
                Some("nohz=on rcu_nocbs=2-7"),
            ),
            (
                "root=UUID=abc rw nohz=full",
                &[("tuned", "nohz=full")],
                None,
                "root=UUID=abc rw",
                None,
            ),
            (
                "root=UUID=abc rw nohz=full rd.driver.pre=vfio-pci",
                &[("tuned", "nohz=full"), ("dracut", "rd.driver.pre=vfio-pci")],
                Some("isolcpus=1-3"),
                "root=UUID=abc rw isolcpus=1-3 rd.driver.pre=vfio-pci",
                Some("isolcpus=1-3"),
            ),
        ];
        let source = SourceName::parse("tuned").unwrap();
        for (options, keys, new_options, expected_options, expected_key) in cases {
            let mut bls = parse_bls_config(&make_bls(options, keys)).unwrap();
            let source_options = extract_source_options_from_extra(&bls);
            let merged = compute_merged_options(options, &source_options, &source, *new_options);
            update_bls_config(&mut bls, &merged, &source, *new_options).unwrap();

            assert_eq!(
                options_of(&bls),
                *expected_options,
                "options for {options:?}"
            );
            assert_eq!(
                bls.extra.get("x-options-source-tuned").map(String::as_str),
                *expected_key,
                "tuned key for {options:?}"
            );
            for (name, value) in keys.iter().filter(|(name, _)| *name != "tuned") {
                assert_eq!(
                    bls.extra.get(&format!("x-options-source-{name}")).unwrap(),
                    value,
                    "{name} must be untouched"
                );
            }
            // Survives serialization
            let reparsed = parse_bls_config(&bls.to_string()).unwrap();
            assert_eq!(reparsed.extra, bls.extra);
        }
    }

    #[test]
    fn test_is_unchanged() {
        let source = SourceName::parse("tuned").unwrap();
        let cases: &[(&str, &[(&str, &str)], Option<&str>, bool)] = &[
            // Same value re-applied, even with other arguments after it
            (
                "root=/dev/a nohz=full quiet",
                &[("tuned", "nohz=full")],
                Some("nohz=full"),
                true,
            ),
            ("root=/dev/a", &[], None, true),
            ("root=/dev/a", &[], Some(""), true),
            (
                "root=/dev/a nohz=full",
                &[("tuned", "nohz=full")],
                Some("nohz=on"),
                false,
            ),
            (
                "root=/dev/a nohz=full",
                &[("tuned", "nohz=full")],
                None,
                false,
            ),
            ("root=/dev/a", &[], Some("nohz=full"), false),
        ];
        for (options, keys, new_options, expected) in cases {
            let bls = parse_bls_config(&make_bls(options, keys)).unwrap();
            let source_options = extract_source_options_from_extra(&bls);
            let merged = compute_merged_options(options, &source_options, &source, *new_options);
            assert_eq!(
                is_unchanged(options, &merged, &source_options, &source, *new_options),
                *expected,
                "{options:?} -> {new_options:?}"
            );
        }
    }
}
