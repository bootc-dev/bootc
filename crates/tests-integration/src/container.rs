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
    // Just verify we parsed the config, if any
    drop(config);
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
        new_test("status", test_bootc_status),
        new_test("system-reinstall --help", test_system_reinstall_help),
    ];

    libtest_mimic::run(&testargs, tests.into()).exit()
}
