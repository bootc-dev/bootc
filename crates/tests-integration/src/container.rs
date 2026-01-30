use indoc::indoc;
use scopeguard::defer;
use serde::Deserialize;
use std::fs;
use std::process::Command;

use anyhow::{Context, Result};
use camino::Utf8Path;
use fn_error_context::context;
use libtest_mimic::Trial;
use xshell::{Shell, cmd};

fn new_test(description: &'static str, f: fn() -> anyhow::Result<()>) -> libtest_mimic::Trial {
    Trial::test(description, move || f().map_err(Into::into))
}

pub(crate) fn test_bootc_status() -> Result<()> {
    let sh = Shell::new()?;
    let host: serde_json::Value = serde_json::from_str(&cmd!(sh, "bootc status --json").read()?)?;
    assert!(host.get("status").unwrap().get("ty").is_none());
    Ok(())
}

pub(crate) fn test_bootc_container_inspect() -> Result<()> {
    let sh = Shell::new()?;
    let inspect: serde_json::Value =
        serde_json::from_str(&cmd!(sh, "bootc container inspect --json").read()?)?;

    // check kargs processing
    let kargs = inspect.get("kargs").unwrap().as_array().unwrap();
    assert!(kargs.iter().any(|arg| arg == "kargsd-test=1"));
    assert!(kargs.iter().any(|arg| arg == "kargsd-othertest=2"));
    assert!(kargs.iter().any(|arg| arg == "testing-kargsd=3"));

    // check kernel field
    let kernel = inspect
        .get("kernel")
        .expect("kernel field should be present")
        .as_object()
        .expect("kernel should be an object");
    let version = kernel
        .get("version")
        .expect("kernel.version should be present")
        .as_str()
        .expect("kernel.version should be a string");
    // Verify version is non-empty (for traditional kernels it's uname-style, for UKI it's the filename)
    assert!(!version.is_empty(), "kernel.version should not be empty");
    let unified = kernel
        .get("unified")
        .expect("kernel.unified should be present")
        .as_bool()
        .expect("kernel.unified should be a boolean");
    if let Some(variant) = std::env::var("BOOTC_variant").ok() {
        match variant.as_str() {
            "ostree" => {
                assert!(!unified, "Expected unified=false for ostree variant");
                // For traditional kernels, version should look like a uname (contains digits)
                assert!(
                    version.chars().any(|c| c.is_ascii_digit()),
                    "version should contain version numbers for traditional kernel: {version}"
                );
            }
            "composefs-sealeduki-sdboot" => {
                assert!(unified, "Expected unified=true for UKI variant");
                // For UKI, version is the filename without .efi extension (should not end with .efi)
                assert!(
                    !version.ends_with(".efi"),
                    "version should not include .efi extension: {version}"
                );
                // Version should be non-empty after stripping extension
                assert!(!version.is_empty(), "version should not be empty for UKI");
            }
            o => eprintln!("notice: Unhandled variant for kernel check: {o}"),
        }
    }

    Ok(())
}

pub(crate) fn test_bootc_upgrade() -> Result<()> {
    for c in ["upgrade", "update"] {
        let o = Command::new("bootc").arg(c).output()?;
        let st = o.status;
        assert!(!st.success());
        let stderr = String::from_utf8(o.stderr)?;
        assert!(
            stderr.contains("this command requires a booted host system"),
            "stderr: {stderr}",
        );
    }
    Ok(())
}

pub(crate) fn test_bootc_install_config() -> Result<()> {
    let sh = &xshell::Shell::new()?;
    let config = cmd!(sh, "bootc install print-configuration").read()?;
    let config: serde_json::Value =
        serde_json::from_str(&config).context("Parsing install config")?;
    // check that it parses okay, but also ensure kargs is not available here (only via --all)
    assert!(config.get("kargs").is_none());
    Ok(())
}

pub(crate) fn test_bootc_install_config_all() -> Result<()> {
    #[derive(Deserialize)]
    #[serde(rename_all = "kebab-case")]
    struct TestOstreeConfig {
        bls_append_except_default: Option<String>,
    }

    #[derive(Deserialize)]
    struct TestInstallConfig {
        kargs: Vec<String>,
        ostree: Option<TestOstreeConfig>,
    }

    let config_d = std::path::Path::new("/run/bootc/install/");
    let test_toml_path = config_d.join("10-test.toml");
    std::fs::create_dir_all(&config_d)?;
    let content = indoc! {r#"
        [install]
        kargs = ["karg1=1", "karg2=2"]
        [install.ostree]
        bls-append-except-default = "grub_users=\"\""
    "#};
    std::fs::write(&test_toml_path, content)?;
    defer! {
    fs::remove_file(test_toml_path).expect("cannot remove tempfile");
    }

    let sh = &xshell::Shell::new()?;
    let config = cmd!(sh, "bootc install print-configuration --all").read()?;
    let config: TestInstallConfig =
        serde_json::from_str(&config).context("Parsing install config")?;
    assert_eq! {config.kargs, vec!["karg1=1".to_string(), "karg2=2".to_string(), "localtestkarg=somevalue".to_string(), "otherlocalkarg=42".to_string()]};
    assert_eq!(
        config
            .ostree
            .as_ref()
            .and_then(|o| o.bls_append_except_default.as_deref()),
        Some("grub_users=\"\"")
    );
    Ok(())
}

/// Previously system-reinstall-bootc bombed out when run as non-root even if passing --help
fn test_system_reinstall_help() -> Result<()> {
    let o = Command::new("runuser")
        .args(["-u", "bin", "system-reinstall-bootc", "--help"])
        .output()?;
    assert!(o.status.success());
    Ok(())
}

/// Verify that the values of `variant` and `base` from Justfile actually applied
/// to this container image.
fn test_variant_base_crosscheck() -> Result<()> {
    if let Some(variant) = std::env::var("BOOTC_variant").ok() {
        // TODO add this to `bootc status` or so?
        let boot_efi = Utf8Path::new("/boot/EFI");
        match variant.as_str() {
            "ostree" => {
                assert!(!boot_efi.try_exists()?);
            }
            "composefs-sealeduki-sdboot" => {
                assert!(boot_efi.try_exists()?);
            }
            o => panic!("Unhandled variant: {o}"),
        }
    }
    if let Some(base) = std::env::var("BOOTC_base").ok() {
        // Hackily reverse back from container pull spec to ID-VERSION_ID
        // TODO: move the OsReleaseInfo into an internal crate we use
        let osrelease = std::fs::read_to_string("/usr/lib/os-release")?;
        if base.contains("centos-bootc") {
            assert!(osrelease.contains(r#"ID="centos""#))
        } else if base.contains("fedora-bootc") {
            assert!(osrelease.contains(r#"ID=fedora"#));
        } else {
            eprintln!("notice: Unhandled base {base}")
        }
    }
    Ok(())
}

/// Test that container export --format=tar creates a valid tar archive
pub(crate) fn test_container_export_tar() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    // Create temp directory with test filesystem structure
    let td = tempfile::tempdir()?;
    let root = td.path();

    // Create directories and files that should appear in the tar
    fs::create_dir_all(root.join("usr/bin"))?;
    fs::create_dir_all(root.join("etc"))?;
    fs::create_dir_all(root.join("var/log"))?;
    fs::create_dir_all(root.join("boot"))?;

    // Create a mock kernel structure (required for export)
    // Using traditional kernel layout: /usr/lib/modules/<version>/vmlinuz
    let kernel_version = "6.0.0-test";
    let modules_dir = root.join(format!("usr/lib/modules/{}", kernel_version));
    fs::create_dir_all(&modules_dir)?;
    fs::write(modules_dir.join("vmlinuz"), "mock kernel content")?;

    // Create test files
    let test_file = root.join("usr/bin/test-binary");
    fs::write(&test_file, "#!/bin/bash\necho 'test'\n")?;
    fs::set_permissions(&test_file, fs::Permissions::from_mode(0o755))?;

    let config_file = root.join("etc/test.conf");
    fs::write(&config_file, "test=value\n")?;
    fs::set_permissions(&config_file, fs::Permissions::from_mode(0o644))?;

    // Create a symlink
    std::os::unix::fs::symlink("test-binary", root.join("usr/bin/test-link"))?;

    // Create output file for tar
    let tar_output = td.path().join("export.tar");

    // Run bootc container export
    let sh = Shell::new()?;
    let root_str = root.to_str().unwrap();
    let tar_str = tar_output.to_str().unwrap();

    // Test the export command
    let export_result = cmd!(
        sh,
        "bootc container export --format=tar -o {tar_str} {root_str}"
    )
    .run();
    export_result.context("Running bootc container export")?;

    // Verify the tar file was created
    assert!(tar_output.exists(), "Export tar file should be created");

    // Verify the tar file is not empty
    let tar_size = tar_output.metadata()?.len();
    assert!(
        tar_size > 0,
        "Export tar file should not be empty, got size {}",
        tar_size
    );

    // Use tar to list contents first (safer than extraction)
    let list_output = cmd!(sh, "tar -tf {tar_str}").read()?;
    assert!(
        list_output.contains("usr/bin/test-binary"),
        "tar should contain test-binary"
    );
    assert!(
        list_output.contains("etc/test.conf"),
        "tar should contain test.conf"
    );
    assert!(
        list_output.contains("usr/bin/test-link"),
        "tar should contain symlink"
    );

    // Extract and verify contents using tar command
    let extract_dir = td.path().join("extracted");
    fs::create_dir_all(&extract_dir)?;
    let extract_str = extract_dir.to_str().unwrap();
    cmd!(sh, "tar -xf {tar_str} -C {extract_str}")
        .run()
        .context("Extracting tar file")?;

    // Verify expected files exist in extracted tar
    let extracted_binary = extract_dir.join("usr/bin/test-binary");
    assert!(
        extracted_binary.exists(),
        "test-binary should be in tar after extraction"
    );

    let extracted_config = extract_dir.join("etc/test.conf");
    assert!(
        extracted_config.exists(),
        "test.conf should be in tar after extraction"
    );

    let extracted_symlink = extract_dir.join("usr/bin/test-link");
    assert!(
        extracted_symlink.exists(),
        "symlink should be in tar after extraction"
    );

    // Verify symlink is actually a symlink
    let link_metadata = extracted_symlink.symlink_metadata()?;
    assert!(
        link_metadata.file_type().is_symlink(),
        "test-link should be a symlink"
    );

    // Verify file permissions are preserved (at least executable bit for binary)
    let binary_perms = extracted_binary.metadata()?.permissions().mode() & 0o777;
    assert_ne!(
        binary_perms & 0o100,
        0,
        "Binary should have execute bit set"
    );

    // Verify file contents are preserved
    let binary_content = fs::read_to_string(&extracted_binary)?;
    assert!(
        binary_content.contains("echo 'test'"),
        "Binary content should be preserved"
    );

    let config_content = fs::read_to_string(&extracted_config)?;
    assert_eq!(
        config_content.trim(),
        "test=value",
        "Config content should be preserved"
    );

    Ok(())
}

/// Test that compute-composefs-digest works on a directory
pub(crate) fn test_compute_composefs_digest() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    // Create temp directory with test filesystem structure
    let td = tempfile::tempdir()?;
    let root = td.path();

    // Create directories required by transform_for_boot
    fs::create_dir_all(root.join("boot"))?;
    fs::create_dir_all(root.join("sysroot"))?;

    // Create usr/bin/hello (executable)
    let usr_bin = root.join("usr/bin");
    fs::create_dir_all(&usr_bin)?;
    let hello_path = usr_bin.join("hello");
    fs::write(&hello_path, "test\n")?;
    fs::set_permissions(&hello_path, fs::Permissions::from_mode(0o755))?;

    // Create etc/config (regular file)
    let etc = root.join("etc");
    fs::create_dir_all(&etc)?;
    let config_path = etc.join("config");
    fs::write(&config_path, "test\n")?;
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o644))?;

    // Run bootc container compute-composefs-digest
    let sh = Shell::new()?;
    let path_str = root.to_str().unwrap();
    let digest = cmd!(sh, "bootc container compute-composefs-digest {path_str}").read()?;
    let digest = digest.trim();

    // Verify it's a valid hex string of expected length (SHA-512 = 128 hex chars)
    assert_eq!(
        digest.as_bytes().len(),
        128,
        "Expected 512-bit hex digest, got length {}",
        digest.as_bytes().len()
    );
    assert!(
        digest.chars().all(|c| c.is_ascii_hexdigit()),
        "Digest contains non-hex characters: {digest}"
    );

    // Verify consistency - running the command twice produces the same result
    let digest2 = cmd!(sh, "bootc container compute-composefs-digest {path_str}").read()?;
    assert_eq!(
        digest,
        digest2.trim(),
        "Digest should be consistent across multiple invocations"
    );

    Ok(())
}

/// Tests that should be run in a default container image.
#[context("Container tests")]
pub(crate) fn run(testargs: libtest_mimic::Arguments) -> Result<()> {
    let tests = [
        new_test("variant-base-crosscheck", test_variant_base_crosscheck),
        new_test("bootc upgrade", test_bootc_upgrade),
        new_test("install config", test_bootc_install_config),
        new_test("printconfig --all", test_bootc_install_config_all),
        new_test("status", test_bootc_status),
        new_test("container inspect", test_bootc_container_inspect),
        new_test("system-reinstall --help", test_system_reinstall_help),
        new_test("container export tar", test_container_export_tar),
        new_test("compute-composefs-digest", test_compute_composefs_digest),
    ];

    libtest_mimic::run(&testargs, tests.into()).exit()
}
