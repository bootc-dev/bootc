//! Lockfile generation for rpm-ostree

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Package lockfile structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Lockfile {
    pub packages: HashMap<String, PackageLock>,
}

/// Individual package lock entry
#[derive(Debug, Serialize, Deserialize)]
pub struct PackageLock {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evra: Option<String>,
}

impl Lockfile {
    /// Create a new empty lockfile
    pub fn new() -> Self {
        Self {
            packages: HashMap::new(),
        }
    }

    /// Add a package from NEVRA or NEVR string
    ///
    /// The format can be either:
    /// - NEVRA: name-epoch:version-release.arch
    /// - NEVR: name-epoch:version-release
    pub fn add_package(&mut self, nevra: &str) -> Result<()> {
        // Split from the right to get name, epoch:version, and release[.arch]
        let parts: Vec<&str> = nevra.rsplitn(3, '-').collect();
        if parts.len() != 3 {
            anyhow::bail!("Invalid NEVRA/NEVR format: {}", nevra);
        }

        let r_or_ra = parts[0];
        let ev = parts[1];
        let name = parts[2];

        let evr_or_evra = format!("{}-{}", ev, r_or_ra);

        // Detect architecture based on common arch suffixes
        let arch = std::env::consts::ARCH;
        let is_evra = r_or_ra.ends_with(".noarch") || r_or_ra.ends_with(&format!(".{}", arch));

        let lock = if is_evra {
            PackageLock {
                evr: None,
                evra: Some(evr_or_evra),
            }
        } else {
            PackageLock {
                evr: Some(evr_or_evra),
                evra: None,
            }
        };

        tracing::debug!("Adding package lock: {} -> {:?}", name, lock);
        self.packages.insert(name.to_string(), lock);

        Ok(())
    }

    /// Write this lockfile to a temporary JSON file
    pub fn write_to_tempfile(&self) -> Result<tempfile::NamedTempFile> {
        let mut tmpfile = tempfile::Builder::new()
            .suffix(".json")
            .tempfile()
            .context("Failed to create temporary lockfile")?;

        serde_json::to_writer_pretty(&mut tmpfile, self)
            .context("Failed to write lockfile to temporary file")?;

        Ok(tmpfile)
    }
}

impl Default for Lockfile {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_package_nevra() {
        let mut lockfile = Lockfile::new();

        // Test NEVRA format (with architecture)
        lockfile.add_package("bash-0:5.1.8-6.el9.x86_64").unwrap();

        let bash_lock = lockfile.packages.get("bash").unwrap();
        assert_eq!(bash_lock.evra, Some("0:5.1.8-6.el9.x86_64".to_string()));
        assert_eq!(bash_lock.evr, None);
    }

    #[test]
    fn test_add_package_nevr() {
        let mut lockfile = Lockfile::new();

        // Test NEVR format (without architecture)
        lockfile.add_package("bash-0:5.1.8-6.el9").unwrap();

        let bash_lock = lockfile.packages.get("bash").unwrap();
        assert_eq!(bash_lock.evr, Some("0:5.1.8-6.el9".to_string()));
        assert_eq!(bash_lock.evra, None);
    }

    #[test]
    fn test_add_package_noarch() {
        let mut lockfile = Lockfile::new();

        // Test noarch package
        lockfile
            .add_package("python3-pip-21.2.3-6.el9.noarch")
            .unwrap();

        let pip_lock = lockfile.packages.get("python3-pip").unwrap();
        assert_eq!(pip_lock.evra, Some("21.2.3-6.el9.noarch".to_string()));
        assert_eq!(pip_lock.evr, None);
    }

    #[test]
    fn test_invalid_format() {
        let mut lockfile = Lockfile::new();

        // Test invalid format
        let result = lockfile.add_package("invalid");
        assert!(result.is_err());
    }
}
