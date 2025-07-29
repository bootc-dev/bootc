use anyhow::Result;
use serde::de::Error;
use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::fmt::Display;

#[derive(Debug, Deserialize, Eq)]
pub(crate) struct BLSConfig {
    pub(crate) title: Option<String>,
    #[serde(deserialize_with = "deserialize_version")]
    pub(crate) version: u32,
    pub(crate) linux: String,
    pub(crate) initrd: String,
    pub(crate) options: String,

    #[serde(flatten)]
    pub(crate) extra: HashMap<String, String>,
}

impl PartialEq for BLSConfig {
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
    }
}

impl PartialOrd for BLSConfig {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.version.partial_cmp(&other.version)
    }
}

impl Ord for BLSConfig {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.version.cmp(&other.version)
    }
}

impl Display for BLSConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(title) = &self.title {
            writeln!(f, "title {}", title)?;
        }

        writeln!(f, "version {}", self.version)?;
        writeln!(f, "linux {}", self.linux)?;
        writeln!(f, "initrd {}", self.initrd)?;
        writeln!(f, "options {}", self.options)?;

        for (key, value) in &self.extra {
            writeln!(f, "{} {}", key, value)?;
        }

        Ok(())
    }
}

fn deserialize_version<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;

    match s {
        Some(s) => Ok(s.parse::<u32>().map_err(D::Error::custom)?),
        None => Err(D::Error::custom("Version not found")),
    }
}

pub(crate) fn parse_bls_config(input: &str) -> Result<BLSConfig> {
    let mut map = HashMap::new();

    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((key, value)) = line.split_once(' ') {
            map.insert(key.to_string(), value.trim().to_string());
        }
    }

    let value = serde_json::to_value(map)?;
    let parsed: BLSConfig = serde_json::from_value(value)?;

    Ok(parsed)
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
        assert_eq!(config.version, 2);
        assert_eq!(config.linux, "/boot/7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6/vmlinuz-5.14.10");
        assert_eq!(config.initrd, "/boot/7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6/initramfs-5.14.10.img");
        assert_eq!(config.options, "root=UUID=abc123 rw composefs=7e11ac46e3e022053e7226a20104ac656bf72d1a84e3a398b7cce70e9df188b6");
        assert_eq!(config.extra.get("custom1"), Some(&"value1".to_string()));
        assert_eq!(config.extra.get("custom2"), Some(&"value2".to_string()));

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
    fn test_parse_invalid_version_format() {
        let input = r#"
            title Fedora
            version not_an_int
            linux /vmlinuz
            initrd /initramfs.img
            options root=UUID=abc composefs=some-uuid
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
            "options root=UUID=abc composefs=some-uuid"
        );
        assert_eq!(output_lines.next().unwrap(), "foo bar");

        Ok(())
    }

    #[test]
    fn test_ordering() -> Result<()> {
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

        assert!(config1 < config2);
        Ok(())
    }
}
