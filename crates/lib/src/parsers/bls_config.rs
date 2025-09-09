//! See <https://uapi-group.org/specifications/specs/boot_loader_specification/>
//!
//! This module parses the config files for the spec.

#![allow(dead_code)]

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::fmt::Display;
use uapi_version::Version;

/// Represents a single Boot Loader Specification config file.
///
/// The boot loader should present the available boot menu entries to the user in a sorted list.
/// The list should be sorted by the `sort-key` field, if it exists, otherwise by the `machine-id` field.
/// If multiple entries have the same `sort-key` (or `machine-id`), they should be sorted by the `version` field in descending order.
#[derive(Debug, Eq, PartialEq, Default)]
#[non_exhaustive]
pub(crate) struct BLSConfig {
    /// The title of the boot entry, to be displayed in the boot menu.
    pub(crate) title: Option<String>,
    /// The version of the boot entry.
    /// See <https://uapi-group.org/specifications/specs/version_format_specification/>
    ///
    /// This is hidden and must be accessed via [`Self::version()`];
    version: String,
    /// The path to the linux kernel to boot.
    pub(crate) linux: String,
    /// The paths to the initrd images.
    pub(crate) initrd: Vec<String>,
    /// Kernel command line options.
    pub(crate) options: Option<String>,
    /// The machine ID of the OS.
    pub(crate) machine_id: Option<String>,
    /// The sort key for the boot menu.
    pub(crate) sort_key: Option<String>,

    /// Any extra fields not defined in the spec.
    pub(crate) extra: HashMap<String, String>,
}

impl PartialOrd for BLSConfig {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BLSConfig {
    /// This implements the sorting logic from the Boot Loader Specification.
    ///
    /// The list should be sorted by the `sort-key` field, if it exists, otherwise by the `machine-id` field.
    /// If multiple entries have the same `sort-key` (or `machine-id`), they should be sorted by the `version` field in descending order.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // If both configs have a sort key, compare them.
        if let (Some(key1), Some(key2)) = (&self.sort_key, &other.sort_key) {
            let ord = key1.cmp(key2);
            if ord != std::cmp::Ordering::Equal {
                return ord;
            }
        }

        // If both configs have a machine ID, compare them.
        if let (Some(id1), Some(id2)) = (&self.machine_id, &other.machine_id) {
            let ord = id1.cmp(id2);
            if ord != std::cmp::Ordering::Equal {
                return ord;
            }
        }

        // Finally, sort by version in descending order.
        self.version().cmp(&other.version()).reverse()
    }
}

impl Display for BLSConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(title) = &self.title {
            writeln!(f, "title {}", title)?;
        }

        writeln!(f, "version {}", self.version)?;
        writeln!(f, "linux {}", self.linux)?;
        for initrd in self.initrd.iter() {
            writeln!(f, "initrd {}", initrd)?;
        }
        if let Some(options) = self.options.as_deref() {
            writeln!(f, "options {}", options)?;
        }
        if let Some(machine_id) = self.machine_id.as_deref() {
            writeln!(f, "machine-id {}", machine_id)?;
        }
        if let Some(sort_key) = self.sort_key.as_deref() {
            writeln!(f, "sort-key {}", sort_key)?;
        }

        for (key, value) in &self.extra {
            writeln!(f, "{} {}", key, value)?;
        }

        Ok(())
    }
}

impl BLSConfig {
    pub(crate) fn version(&self) -> Version {
        Version::from(&self.version)
    }

    pub(crate) fn with_title(&mut self, new_val: String) -> &mut Self {
        self.title = Some(new_val);
        self
    }
    pub(crate) fn with_version(&mut self, new_val: String) -> &mut Self {
        self.version = new_val;
        self
    }
    pub(crate) fn with_linux(&mut self, new_val: String) -> &mut Self {
        self.linux = new_val;
        self
    }
    pub(crate) fn with_initrd(&mut self, new_val: Vec<String>) -> &mut Self {
        self.initrd = new_val;
        self
    }
    pub(crate) fn with_options(&mut self, new_val: String) -> &mut Self {
        self.options = Some(new_val);
        self
    }
    #[allow(dead_code)]
    pub(crate) fn with_machine_id(&mut self, new_val: String) -> &mut Self {
        self.machine_id = Some(new_val);
        self
    }
    pub(crate) fn with_sort_key(&mut self, new_val: String) -> &mut Self {
        self.sort_key = Some(new_val);
        self
    }
    #[allow(dead_code)]
    pub(crate) fn with_extra(&mut self, new_val: HashMap<String, String>) -> &mut Self {
        self.extra = new_val;
        self
    }
}

pub(crate) fn parse_bls_config(input: &str) -> Result<BLSConfig> {
    let mut title = None;
    let mut version = None;
    let mut linux = None;
    let mut initrd = Vec::new();
    let mut options = None;
    let mut machine_id = None;
    let mut sort_key = None;
    let mut extra = HashMap::new();

    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((key, value)) = line.split_once(' ') {
            let value = value.trim().to_string();
            match key {
                "title" => title = Some(value),
                "version" => version = Some(value),
                "linux" => linux = Some(value),
                "initrd" => initrd.push(value),
                "options" => options = Some(value),
                "machine-id" => machine_id = Some(value),
                "sort-key" => sort_key = Some(value),
                _ => {
                    extra.insert(key.to_string(), value);
                }
            }
        }
    }

    let linux = linux.ok_or_else(|| anyhow!("Missing 'linux' value"))?;
    let version = version.ok_or_else(|| anyhow!("Missing 'version' value"))?;

    Ok(BLSConfig {
        title,
        version,
        linux,
        initrd,
        options,
        machine_id,
        sort_key,
        extra,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_bls_config() -> Result<()> {
        let input = r#"
            title Fedora 42.20250623.3.1 (CoreOS)
            version 2
            linux /boot/7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6/vmlinuz-5.14.10
            initrd /boot/7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6/initramfs-5.14.10.img
            options root=UUID=abc123 rw composefs=7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6
            custom1 value1
            custom2 value2
        "#;

        let config = parse_bls_config(input)?;

        assert_eq!(
            config.title,
            Some("Fedora 42.20250623.3.1 (CoreOS)".to_string())
        );
        assert_eq!(config.version, "2");
        assert_eq!(config.linux, "/boot/7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6/vmlinuz-5.14.10");
        assert_eq!(config.initrd, vec!["/boot/7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6/initramfs-5.14.10.img"]);
        assert_eq!(config.options, Some("root=UUID=abc123 rw composefs=7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6".to_string()));
        assert_eq!(config.extra.get("custom1"), Some(&"value1".to_string()));
        assert_eq!(config.extra.get("custom2"), Some(&"value2".to_string()));

        Ok(())
    }

    #[test]
    fn test_parse_multiple_initrd() -> Result<()> {
        let input = r#"
            title Fedora 42.20250623.3.1 (CoreOS)
            version 2
            linux /boot/vmlinuz
            initrd /boot/initramfs-1.img
            initrd /boot/initramfs-2.img
            options root=UUID=abc123 rw
        "#;

        let config = parse_bls_config(input)?;

        assert_eq!(
            config.initrd,
            vec!["/boot/initramfs-1.img", "/boot/initramfs-2.img"]
        );

        Ok(())
    }

    #[test]
    fn test_parse_missing_version() {
        let input = r#"
            title Fedora
            linux /vmlinuz
            initrd /initramfs.img
            options root=UUID=xyz ro quiet
        "#;

        let parsed = parse_bls_config(input);
        assert!(parsed.is_err());
    }

    #[test]
    fn test_parse_missing_linux() {
        let input = r#"
            title Fedora
            version 1
            initrd /initramfs.img
            options root=UUID=xyz ro quiet
        "#;

        let parsed = parse_bls_config(input);
        assert!(parsed.is_err());
    }

    #[test]
    fn test_display_output() -> Result<()> {
        let input = r#"
            title Test OS
            version 10
            linux /boot/vmlinuz
            initrd /boot/initrd.img
            initrd /boot/initrd-extra.img
            options root=UUID=abc composefs=some-uuid
            foo bar
        "#;

        let config = parse_bls_config(input)?;
        let output = format!("{}", config);
        let mut output_lines = output.lines();

        assert_eq!(output_lines.next().unwrap(), "title Test OS");
        assert_eq!(output_lines.next().unwrap(), "version 10");
        assert_eq!(output_lines.next().unwrap(), "linux /boot/vmlinuz");
        assert_eq!(output_lines.next().unwrap(), "initrd /boot/initrd.img");
        assert_eq!(
            output_lines.next().unwrap(),
            "initrd /boot/initrd-extra.img"
        );
        assert_eq!(
            output_lines.next().unwrap(),
            "options root=UUID=abc composefs=some-uuid"
        );
        assert_eq!(output_lines.next().unwrap(), "foo bar");

        Ok(())
    }

    #[test]
    fn test_ordering_by_version() -> Result<()> {
        let config1 = parse_bls_config(
            r#"
            title Entry 1
            version 3
            linux /vmlinuz-3
            initrd /initrd-3
            options opt1
        "#,
        )?;

        let config2 = parse_bls_config(
            r#"
            title Entry 2
            version 5
            linux /vmlinuz-5
            initrd /initrd-5
            options opt2
        "#,
        )?;

        assert!(config1 > config2);
        Ok(())
    }

    #[test]
    fn test_ordering_by_sort_key() -> Result<()> {
        let config1 = parse_bls_config(
            r#"
            title Entry 1
            version 3
            sort-key a
            linux /vmlinuz-3
            initrd /initrd-3
            options opt1
        "#,
        )?;

        let config2 = parse_bls_config(
            r#"
            title Entry 2
            version 5
            sort-key b
            linux /vmlinuz-5
            initrd /initrd-5
            options opt2
        "#,
        )?;

        assert!(config1 < config2);
        Ok(())
    }

    #[test]
    fn test_ordering_by_sort_key_and_version() -> Result<()> {
        let config1 = parse_bls_config(
            r#"
            title Entry 1
            version 3
            sort-key a
            linux /vmlinuz-3
            initrd /initrd-3
            options opt1
        "#,
        )?;

        let config2 = parse_bls_config(
            r#"
            title Entry 2
            version 5
            sort-key a
            linux /vmlinuz-5
            initrd /initrd-5
            options opt2
        "#,
        )?;

        assert!(config1 > config2);
        Ok(())
    }

    #[test]
    fn test_ordering_by_machine_id() -> Result<()> {
        let config1 = parse_bls_config(
            r#"
            title Entry 1
            version 3
            machine-id a
            linux /vmlinuz-3
            initrd /initrd-3
            options opt1
        "#,
        )?;

        let config2 = parse_bls_config(
            r#"
            title Entry 2
            version 5
            machine-id b
            linux /vmlinuz-5
            initrd /initrd-5
            options opt2
        "#,
        )?;

        assert!(config1 < config2);
        Ok(())
    }

    #[test]
    fn test_ordering_by_machine_id_and_version() -> Result<()> {
        let config1 = parse_bls_config(
            r#"
            title Entry 1
            version 3
            machine-id a
            linux /vmlinuz-3
            initrd /initrd-3
            options opt1
        "#,
        )?;

        let config2 = parse_bls_config(
            r#"
            title Entry 2
            version 5
            machine-id a
            linux /vmlinuz-5
            initrd /initrd-5
            options opt2
        "#,
        )?;

        assert!(config1 > config2);
        Ok(())
    }

    #[test]
    fn test_ordering_by_nontrivial_version() -> Result<()> {
        let config_final = parse_bls_config(
            r#"
            title Entry 1
            version 1.0
            linux /vmlinuz-1
            initrd /initrd-1
        "#,
        )?;

        let config_rc1 = parse_bls_config(
            r#"
            title Entry 2
            version 1.0~rc1
            linux /vmlinuz-2
            initrd /initrd-2
        "#,
        )?;

        // In a sorted list, we want 1.0 to appear before 1.0~rc1 because
        // versions are sorted descending. This means that in Rust's sort order,
        // config_final should be "less than" config_rc1.
        assert!(config_final < config_rc1);
        Ok(())
    }
}
