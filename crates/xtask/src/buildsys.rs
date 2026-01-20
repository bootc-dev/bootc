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
/// - Dockerfile tmpfs on /run and /tmp for all RUN instructions
#[context("Checking build system")]
pub fn check_buildsys(sh: &Shell, dockerfile_path: &Utf8Path) -> Result<()> {
    check_package_reproducibility(sh)?;
    check_dockerfile_rules(dockerfile_path)?;
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

/// Verify Dockerfile rules:
/// - All RUN instructions must include `--mount=type=tmpfs,target=/run`
/// - After cutoff, all RUN instructions must start with `--network=none`
#[context("Checking Dockerfile rules")]
fn check_dockerfile_rules(dockerfile_path: &Utf8Path) -> Result<()> {
    println!("Checking Dockerfile rules...");
    let dockerfile = std::fs::read_to_string(dockerfile_path).context("Reading Dockerfile")?;
    verify_dockerfile_rules(&dockerfile)?;
    println!("ok Dockerfile rules");
    Ok(())
}

const RUN_NETWORK_NONE: &str = "RUN --network=none";
const RUN_TMPFS_RUN: &str = "--mount=type=tmpfs,target=/run";
const RUN_TMPFS_TMP: &str = "--mount=type=tmpfs,target=/tmp";
const ALLOW_NON_TMPFS: &str = "# lint: allow non-tmpfs";

/// Verify Dockerfile rules:
/// - All RUN instructions must include `--mount=type=tmpfs,target=/run` and
///   `--mount=type=tmpfs,target=/tmp` to prevent podman's DNS resolver files
///   and temporary files from leaking into the image
/// - A comment `# lint: allow non-tmpfs` on the preceding line exempts a RUN
///   instruction from the tmpfs requirement
/// - After the network cutoff, all RUN instructions must start with `--network=none`
///
/// Returns Ok(()) if all RUN instructions comply, or an error listing violations.
pub fn verify_dockerfile_rules(dockerfile: &str) -> Result<()> {
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

    let mut errors = Vec::new();
    let mut skip_tmpfs_check = false;

    for (idx, line) in dockerfile.lines().enumerate() {
        let line_num = idx + 1; // 1-based line numbers
        let trimmed = line.trim();

        // Check for the allow comment directive
        if trimmed.starts_with(ALLOW_NON_TMPFS) {
            skip_tmpfs_check = true;
            continue;
        }

        // Check if this is a RUN instruction
        if trimmed.starts_with("RUN ") {
            if !skip_tmpfs_check {
                // All RUN instructions must include tmpfs mount on /run
                if !trimmed.contains(RUN_TMPFS_RUN) {
                    errors.push(format!(
                        "  line {}: RUN instruction must include `{}`",
                        line_num, RUN_TMPFS_RUN
                    ));
                }

                // All RUN instructions must include tmpfs mount on /tmp
                if !trimmed.contains(RUN_TMPFS_TMP) {
                    errors.push(format!(
                        "  line {}: RUN instruction must include `{}`",
                        line_num, RUN_TMPFS_TMP
                    ));
                }
            }
            skip_tmpfs_check = false;

            // After cutoff, must start with exactly "RUN --network=none"
            if idx > cutoff_line && !trimmed.starts_with(RUN_NETWORK_NONE) {
                errors.push(format!(
                    "  line {}: RUN instruction after cutoff must start with `{}`",
                    line_num, RUN_NETWORK_NONE
                ));
            }
        }
    }

    if !errors.is_empty() {
        anyhow::bail!(
            "Dockerfile has invalid RUN instructions:\n{}",
            errors.join("\n")
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dockerfile_rules_valid() {
        let dockerfile = r#"
FROM base
RUN --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp echo "before cutoff, network allowed"
# external dependency cutoff point
RUN --network=none --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp echo "good"
RUN --network=none --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp --mount=type=bind,from=foo,target=/bar some-command
# lint: allow non-tmpfs
RUN --network=none bootc container lint --fatal-warnings
"#;
        verify_dockerfile_rules(dockerfile).unwrap();
    }

    #[test]
    fn test_dockerfile_rules_missing_tmpfs_run_before_cutoff() {
        let dockerfile = r#"
FROM base
RUN --mount=type=tmpfs,target=/tmp echo "bad - missing /run tmpfs"
# external dependency cutoff point
RUN --network=none --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp echo "good"
"#;
        let err = verify_dockerfile_rules(dockerfile).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("line 3"), "error should mention line 3: {msg}");
        assert!(
            msg.contains("target=/run"),
            "error should mention target=/run: {msg}"
        );
    }

    #[test]
    fn test_dockerfile_rules_missing_tmpfs_tmp_before_cutoff() {
        let dockerfile = r#"
FROM base
RUN --mount=type=tmpfs,target=/run echo "bad - missing /tmp tmpfs"
# external dependency cutoff point
RUN --network=none --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp echo "good"
"#;
        let err = verify_dockerfile_rules(dockerfile).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("line 3"), "error should mention line 3: {msg}");
        assert!(
            msg.contains("target=/tmp"),
            "error should mention target=/tmp: {msg}"
        );
    }

    #[test]
    fn test_dockerfile_rules_missing_network_flag_after_cutoff() {
        let dockerfile = r#"
FROM base
RUN --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp echo "before cutoff"
# external dependency cutoff point
RUN --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp echo "bad - missing network flag"
"#;
        let err = verify_dockerfile_rules(dockerfile).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("line 5"), "error should mention line 5: {msg}");
        assert!(
            msg.contains("--network=none"),
            "error should mention --network=none: {msg}"
        );
    }

    #[test]
    fn test_dockerfile_rules_missing_tmpfs_after_cutoff() {
        let dockerfile = r#"
FROM base
RUN --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp echo "before cutoff"
# external dependency cutoff point
RUN --network=none echo "bad - missing both tmpfs"
"#;
        let err = verify_dockerfile_rules(dockerfile).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("line 5"), "error should mention line 5: {msg}");
        assert!(msg.contains("tmpfs"), "error should mention tmpfs: {msg}");
    }

    #[test]
    fn test_dockerfile_rules_network_wrong_position() {
        // --network=none must come immediately after RUN
        let dockerfile = r#"
FROM base
RUN --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp echo "before cutoff"
# external dependency cutoff point
RUN --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp --network=none echo "bad - network flag not first"
"#;
        let err = verify_dockerfile_rules(dockerfile).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("line 5"), "error should mention line 5: {msg}");
    }
}
