//! Build system validation checks.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use fn_error_context::context;
use xshell::{Shell, cmd};

const DOCKERFILE_NETWORK_CUTOFF: &str = "external dependency cutoff point";

/// Check build system properties
///
/// - Reproducible builds for the RPM
/// - Dockerfile network isolation after cutoff point
#[context("Checking build system")]
pub fn check_buildsys(sh: &Shell, dockerfile_path: &Utf8Path) -> Result<()> {
    check_package_reproducibility(sh)?;
    check_dockerfile_network_isolation(dockerfile_path)?;
    Ok(())
}

/// Verify that consecutive `just package` invocations produce identical RPM checksums.
#[context("Checking package reproducibility")]
fn check_package_reproducibility(sh: &Shell) -> Result<()> {
    println!("Checking reproducible builds...");
    // Helper to compute SHA256 of bootc RPMs in target/packages/
    fn get_rpm_checksums(sh: &Shell) -> Result<BTreeMap<String, String>> {
        // Find bootc*.rpm files in target/packages/
        let packages_dir = Utf8Path::new("target/packages");
        let mut rpm_files: Vec<Utf8PathBuf> = Vec::new();
        for entry in std::fs::read_dir(packages_dir).context("Reading target/packages")? {
            let entry = entry?;
            let path = Utf8PathBuf::try_from(entry.path())?;
            if path.extension() == Some("rpm") {
                rpm_files.push(path);
            }
        }

        assert!(!rpm_files.is_empty());

        let mut checksums = BTreeMap::new();
        for rpm_path in &rpm_files {
            let output = cmd!(sh, "sha256sum {rpm_path}").read()?;
            let (hash, filename) = output
                .split_once("  ")
                .with_context(|| format!("failed to parse sha256sum output: '{}'", output))?;
            checksums.insert(filename.to_owned(), hash.to_owned());
        }
        Ok(checksums)
    }

    cmd!(sh, "just package").run()?;
    let first_checksums = get_rpm_checksums(sh)?;
    cmd!(sh, "just package").run()?;
    let second_checksums = get_rpm_checksums(sh)?;

    itertools::assert_equal(first_checksums, second_checksums);
    println!("ok package reproducibility");

    Ok(())
}

/// Verify that all RUN instructions in the Dockerfile after the network cutoff
/// point include `--network=none`.
#[context("Checking Dockerfile network isolation")]
fn check_dockerfile_network_isolation(dockerfile_path: &Utf8Path) -> Result<()> {
    println!("Checking Dockerfile network isolation...");
    let dockerfile = std::fs::read_to_string(dockerfile_path).context("Reading Dockerfile")?;
    verify_dockerfile_network_isolation(&dockerfile)?;
    println!("ok Dockerfile network isolation");
    Ok(())
}

const RUN_NETWORK_NONE: &str = "RUN --network=none";

/// Verify that all RUN instructions after the network cutoff marker start with
/// `RUN --network=none`.
///
/// Returns Ok(()) if all RUN instructions comply, or an error listing violations.
pub fn verify_dockerfile_network_isolation(dockerfile: &str) -> Result<()> {
    // Find the cutoff point
    let cutoff_line = dockerfile
        .lines()
        .position(|line| line.contains(DOCKERFILE_NETWORK_CUTOFF))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Dockerfile missing '{}' marker comment",
                DOCKERFILE_NETWORK_CUTOFF
            )
        })?;

    // Check all RUN instructions after the cutoff point
    let mut errors = Vec::new();

    for (idx, line) in dockerfile.lines().enumerate().skip(cutoff_line + 1) {
        let line_num = idx + 1; // 1-based line numbers
        let trimmed = line.trim();

        // Check if this is a RUN instruction
        if trimmed.starts_with("RUN ") {
            // Must start with exactly "RUN --network=none"
            if !trimmed.starts_with(RUN_NETWORK_NONE) {
                errors.push(format!(
                    "  line {}: RUN instruction must start with `{}`",
                    line_num, RUN_NETWORK_NONE
                ));
            }
        }
    }

    if !errors.is_empty() {
        anyhow::bail!(
            "Dockerfile has RUN instructions after '{}' that don't start with `{}`:\n{}",
            DOCKERFILE_NETWORK_CUTOFF,
            RUN_NETWORK_NONE,
            errors.join("\n")
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_isolation_valid() {
        let dockerfile = r#"
FROM base
RUN echo "before cutoff, no network restriction needed"
# external dependency cutoff point
RUN --network=none echo "good"
RUN --network=none --mount=type=bind,from=foo,target=/bar some-command
"#;
        verify_dockerfile_network_isolation(dockerfile).unwrap();
    }

    #[test]
    fn test_network_isolation_missing_flag() {
        let dockerfile = r#"
FROM base
# external dependency cutoff point
RUN --network=none echo "good"
RUN echo "bad - missing network flag"
"#;
        let err = verify_dockerfile_network_isolation(dockerfile).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("line 5"), "error should mention line 5: {msg}");
    }

    #[test]
    fn test_network_isolation_wrong_position() {
        // --network=none must come immediately after RUN
        let dockerfile = r#"
FROM base
# external dependency cutoff point
RUN --mount=type=bind,from=foo,target=/bar --network=none echo "bad"
"#;
        let err = verify_dockerfile_network_isolation(dockerfile).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("line 4"), "error should mention line 4: {msg}");
    }
}
