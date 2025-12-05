//! Rechunk container images into content-addressed layers

use anyhow::{Context, Result};
use std::process::Command;

use crate::cli::RechunkOpts;

/// Rechunk a container image into split, reproducible layers
///
/// This uses `rpm-ostree experimental compose build-chunked-oci` to create
/// a new container image with content-addressed, reproducible layers.
pub fn rechunk(opts: &RechunkOpts) -> Result<()> {
    // Validate inputs
    anyhow::ensure!(!opts.from_image.is_empty(), "Source image cannot be empty");
    anyhow::ensure!(
        !opts.to_image.is_empty(),
        "Destination image cannot be empty"
    );
    anyhow::ensure!(
        opts.from_image != opts.to_image,
        "Source and destination images must be different"
    );

    let mut argv = vec![
        "rpm-ostree".to_string(),
        "experimental".to_string(),
        "compose".to_string(),
        "build-chunked-oci".to_string(),
    ];

    // Add max-layers if specified
    if let Some(max_layers) = opts.max_layers {
        argv.push(format!("--max-layers={}", max_layers));
    }

    // Add required flags
    argv.push("--bootc".to_string());
    argv.push("--format-version=1".to_string());
    argv.push(format!("--from={}", opts.from_image));
    argv.push(format!("--output=containers-storage:{}", opts.to_image));

    tracing::info!("Rechunking {} -> {}", opts.from_image, opts.to_image);
    if let Some(max_layers) = opts.max_layers {
        tracing::debug!("Using max-layers: {}", max_layers);
    }
    tracing::debug!("Executing: {}", argv.join(" "));

    // Execute rpm-ostree command
    // We use inherit for stdio to show rpm-ostree's progress output directly
    let status = Command::new(&argv[0])
        .args(&argv[1..])
        .status()
        .context("Failed to execute rpm-ostree")?;

    if !status.success() {
        anyhow::bail!(
            "rpm-ostree command failed with exit code: {}",
            status.code().unwrap_or(-1)
        );
    }

    tracing::info!("Successfully rechunked image to {}", opts.to_image);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_same_images() {
        let opts = RechunkOpts {
            max_layers: None,
            from_image: "test".to_string(),
            to_image: "test".to_string(),
        };

        let result = rechunk(&opts);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Source and destination images must be different"));
    }

    #[test]
    fn test_validation_empty_source() {
        let opts = RechunkOpts {
            max_layers: None,
            from_image: "".to_string(),
            to_image: "dest".to_string(),
        };

        let result = rechunk(&opts);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Source image cannot be empty"));
    }

    #[test]
    fn test_validation_empty_dest() {
        let opts = RechunkOpts {
            max_layers: None,
            from_image: "source".to_string(),
            to_image: "".to_string(),
        };

        let result = rechunk(&opts);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Destination image cannot be empty"));
    }
}
