//! List available build manifests

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use serde_json::Value;
use std::process::Command;

use crate::constants::MANIFESTDIR;

/// List all available manifests with their descriptions
pub fn list_manifests() -> Result<()> {
    let manifest_dir = Utf8Path::new("/").join(MANIFESTDIR);

    if !manifest_dir.exists() {
        anyhow::bail!(
            "Manifest directory not found: {}. This command must be run in a bootc base image.",
            manifest_dir
        );
    }

    let entries = std::fs::read_dir(&manifest_dir)
        .with_context(|| format!("Failed to read manifest directory: {}", manifest_dir))?;

    let mut manifests = Vec::new();

    for entry in entries {
        let entry = entry.context("Failed to read directory entry")?;

        // Skip symlinks
        if entry
            .file_type()
            .context("Failed to get file type")?
            .is_symlink()
        {
            continue;
        }

        let path = Utf8PathBuf::try_from(entry.path()).context("Invalid UTF-8 in path")?;
        let file_name = match path.file_name() {
            Some(name) => name,
            None => continue,
        };

        // Skip files that aren't .yaml or are .hidden.yaml
        if !file_name.ends_with(".yaml") || file_name.ends_with(".hidden.yaml") {
            continue;
        }

        let name = file_name
            .strip_suffix(".yaml")
            .expect("Already checked .yaml suffix");

        manifests.push((name.to_string(), path));
    }

    // Sort manifests by name
    manifests.sort_by(|a, b| a.0.cmp(&b.0));

    // Print each manifest with its description
    for (name, path) in manifests {
        match get_manifest_description(&path) {
            Ok(description) => {
                println!("{}: {}", name, description);
                println!("---");
            }
            Err(e) => {
                tracing::warn!("Failed to get description for {}: {}", name, e);
                println!("{}: <description unavailable>", name);
                println!("---");
            }
        }
    }

    Ok(())
}

/// Get the description from a manifest file using rpm-ostree
fn get_manifest_description(path: &Utf8Path) -> Result<String> {
    let output = Command::new("rpm-ostree")
        .args(["compose", "tree", "--print-only", path.as_str()])
        .output()
        .context("Failed to execute rpm-ostree")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("rpm-ostree failed: {}", stderr);
    }

    let manifest: Value = serde_json::from_slice(&output.stdout)
        .context("Failed to parse rpm-ostree output as JSON")?;

    let description = manifest
        .get("metadata")
        .and_then(|m| m.get("summary"))
        .and_then(|s| s.as_str())
        .unwrap_or("<no description>");

    Ok(description.to_string())
}
