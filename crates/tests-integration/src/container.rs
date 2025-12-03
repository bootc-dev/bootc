use indoc::indoc;
use scopeguard::defer;
use serde::Deserialize;
use std::fs;
use std::process::Command;

use anyhow::{Context, Result};
use camino::Utf8Path;
use fn_error_context::context;
use libtest_mimic::Trial;
use xshell::{cmd, Shell};

fn new_test(description: &'static str, f: fn() -> anyhow::Result<()>) -> libtest_mimic::Trial {
    Trial::test(description, move || f().map_err(Into::into))
}

pub(crate) fn test_bootc_status() -> Result<()> {
    let sh = Shell::new()?;
    let host: serde_json::Value = serde_json::from_str(&cmd!(sh, "bootc status --json").read()?)?;
    assert!(host.get("status").unwrap().get("ty").is_none());
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
    struct TestInstallConfig {
        kargs: Vec<String>,
    }

    let config_d = std::path::Path::new("/run/bootc/install/");
    let test_toml_path = config_d.join("10-test.toml");
    std::fs::create_dir_all(&config_d)?;
    let content = indoc! {r#"
        [install]
        kargs = ["karg1=1", "karg2=2"]
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

/// Tests that should be run in a default container image.
#[context("Container tests")]
pub(crate) fn run(testargs: libtest_mimic::Arguments) -> Result<()> {
    let tests = [
        new_test("variant-base-crosscheck", test_variant_base_crosscheck),
        new_test("bootc upgrade", test_bootc_upgrade),
        new_test("install config", test_bootc_install_config),
        new_test("printconfig --all", test_bootc_install_config_all),
        new_test("status", test_bootc_status),
        new_test("system-reinstall --help", test_system_reinstall_help),
    ];

    libtest_mimic::run(&testargs, tests.into()).exit()
}
