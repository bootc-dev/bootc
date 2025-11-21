//! Manifest handling utilities

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::constants::MANIFESTDIR;

/// Find a manifest file by name, checking both .yaml and .hidden.yaml variants
pub fn find_manifest(name: &str) -> Result<Utf8PathBuf> {
    let manifest_dir = Utf8Path::new("/").join(MANIFESTDIR);

    for suffix in ["yaml", "hidden.yaml"] {
        let filename = format!("{}.{}", name, suffix);
        let path = manifest_dir.join(&filename);
        if path.exists() {
            tracing::debug!("Found manifest at: {}", path);
            return Ok(path);
        }
    }

    anyhow::bail!("Manifest not found: {}", name)
}

/// Manifest override structure that gets serialized to JSON
#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestOverride {
    /// Path to the base manifest to include
    pub include: String,

    /// Additional packages to install
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packages: Option<Vec<String>>,

    /// OSTree overlay layers
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "ostree-override-layers"
    )]
    pub ostree_override_layers: Option<Vec<String>>,

    /// Documentation setting
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documentation: Option<bool>,

    /// Sysusers setting
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sysusers: Option<String>,

    /// Variables (e.g., passwd_mode)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variables: Option<HashMap<String, String>>,

    /// Repository overrides
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repos: Option<Vec<String>>,
}

impl ManifestOverride {
    /// Create a new manifest override with the given base manifest path
    pub fn new(base_manifest: String) -> Self {
        Self {
            include: base_manifest,
            packages: None,
            ostree_override_layers: None,
            documentation: None,
            sysusers: None,
            variables: None,
            repos: None,
        }
    }

    /// Write this override to a temporary JSON file
    pub fn write_to_tempfile(&self) -> Result<tempfile::NamedTempFile> {
        let mut tmpfile = tempfile::Builder::new()
            .suffix(".json")
            .tempfile()
            .context("Failed to create temporary manifest file")?;

        serde_json::to_writer_pretty(&mut tmpfile, self)
            .context("Failed to write manifest override to temporary file")?;

        Ok(tmpfile)
    }
}
