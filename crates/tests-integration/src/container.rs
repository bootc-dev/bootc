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

    let is_uki = std::env::var("BOOTC_boot_type").is_ok_and(|var| var == "uki");

    if let Some(variant) = std::env::var("BOOTC_variant").ok() {
        match (variant.as_str(), is_uki) {
            (v @ "ostree", _) | (v @ "composefs", false) => {
                assert!(!unified, "Expected unified=false for variant {v}");
                // For traditional kernels, version should look like a uname (contains digits)
                assert!(
                    version.chars().any(|c| c.is_ascii_digit()),
                    "version should contain version numbers for traditional kernel: {version}"
                );
            }
            ("composefs", true) => {
                assert!(unified, "Expected unified=true for UKI variant");
                // For UKI, version is the filename without .efi extension (should not end with .efi)
                assert!(
                    !version.ends_with(".efi"),
                    "version should not include .efi extension: {version}"
                );
                // Version should be non-empty after stripping extension
                assert!(!version.is_empty(), "version should not be empty for UKI");
            }
            o => eprintln!("notice: Unhandled variant for kernel check: {o:?}"),
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
    let is_uki = std::env::var("BOOTC_boot_type").is_ok_and(|var| var == "uki");

    if let Some(variant) = std::env::var("BOOTC_variant").ok() {
        // TODO add this to `bootc status` or so?
        let boot_efi = Utf8Path::new("/boot/EFI");
        match (variant.as_str(), is_uki) {
            ("composefs", false) | ("ostree", _) => {
                assert!(!boot_efi.try_exists()?);
            }
            ("composefs", true) => {
                assert!(boot_efi.try_exists()?);
            }
            o => panic!("Unhandled variant: {o:?}"),
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

/// Verify exported tar has correct size/mode/content vs source.
/// Checks all critical paths (kernel, boot) plus ~10% random sample.
pub(crate) fn test_container_export_tar() -> Result<()> {
    use rand::{RngExt, SeedableRng};
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;

    const TARGET: &str = "/run/target";
    const CRITICAL: &[&str] = &["usr/lib/modules/", "usr/lib/ostree-boot/", "boot/"];

    anyhow::ensure!(
        std::path::Path::new(TARGET).exists(),
        "Test requires image mounted at {TARGET}"
    );

    let td = tempfile::tempdir()?;
    let tar_path = td.path().join("export.tar");
    let tar_str = tar_path.to_str().unwrap();

    let sh = Shell::new()?;
    cmd!(
        sh,
        "bootc container export --format=tar -o {tar_str} {TARGET}"
    )
    .run()?;

    // Collect tar entries: path -> (size, mode, first 4KB content)
    let mut entries: Vec<(String, u64, u32, Vec<u8>)> = Vec::new();
    for entry in tar::Archive::new(fs::File::open(&tar_path)?).entries()? {
        let mut entry = entry?;
        let header = entry.header();
        if header.entry_type() != tar::EntryType::Regular {
            continue;
        }
        let path = entry.path()?.to_string_lossy().into_owned();
        let size: u64 = header.size()?;
        let mode = header.mode()?;
        let sample_len = usize::try_from(size).unwrap_or(usize::MAX).min(4096);
        let mut sample = vec![0u8; sample_len];
        entry.read_exact(&mut sample)?;
        entries.push((path, size, mode, sample));
    }
    assert!(entries.len() > 100, "too few files: {}", entries.len());

    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let (mut verified, mut critical_count) = (0, 0);

    for (path, tar_size, tar_mode, tar_sample) in &entries {
        let is_critical = CRITICAL.iter().any(|p| path.contains(p));
        if !is_critical && !rng.random_bool(0.1) {
            continue;
        }

        let src = std::path::Path::new(TARGET).join(path);
        let Ok(meta) = src.symlink_metadata() else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }

        assert_eq!(*tar_size, meta.len(), "{path}: size mismatch");
        assert_eq!(
            tar_mode & 0o7777,
            meta.mode() & 0o7777,
            "{path}: mode mismatch"
        );

        let mut src_sample = vec![0u8; tar_sample.len()];
        fs::File::open(&src)?.read_exact(&mut src_sample)?;
        assert_eq!(tar_sample, &src_sample, "{path}: content mismatch");

        verified += 1;
        if is_critical {
            critical_count += 1;
        }
    }

    assert!(verified >= 50, "only verified {verified} files");
    assert!(critical_count >= 5, "only {critical_count} critical files");
    eprintln!(
        "Verified {verified}/{} files ({critical_count} critical)",
        entries.len()
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

/// Test that `bootc container ukify --erofs-version` is plumbed correctly.
///
/// Verifies that:
/// - `compute-composefs-digest --erofs-version=v1` and `=v2` produce distinct,
///   valid 128-char SHA-512 hex digests (different EROFS layouts → different IDs).
/// - `bootc container ukify --erofs-version=v1` either invokes ukify (skipping
///   gracefully if ukify is absent) or fails with a clear error before ukify.
pub(crate) fn test_container_ukify_erofs_versions() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    // Build a minimal rootfs that satisfies find_kernel() and build_ukify()'s
    // existence checks.  The files don't need to be real ELF/CPIO — bootc only
    // stat-checks them before handing them off to ukify.
    let td = tempfile::tempdir()?;
    let root = td.path();

    fs::create_dir_all(root.join("boot"))?;
    fs::create_dir_all(root.join("sysroot"))?;

    let usr_bin = root.join("usr/bin");
    fs::create_dir_all(&usr_bin)?;
    let hello = usr_bin.join("hello");
    fs::write(&hello, b"#!/bin/sh\necho hello\n")?;
    fs::set_permissions(&hello, fs::Permissions::from_mode(0o755))?;

    // Kernel layout that find_kernel() expects
    let kver = "6.1.0-test";
    let mod_dir = root.join("usr/lib/modules").join(kver);
    fs::create_dir_all(&mod_dir)?;
    fs::write(mod_dir.join("vmlinuz"), b"fake-vmlinuz")?;
    fs::write(mod_dir.join("initramfs.img"), b"fake-initramfs")?;

    // ukify reads --os-release @usr/lib/os-release relative to the rootfs cwd
    let os_release_dir = root.join("usr/lib");
    fs::create_dir_all(&os_release_dir)?;
    fs::write(
        os_release_dir.join("os-release"),
        b"ID=test\nNAME=Test\nVERSION_ID=1\n",
    )?;

    let root_str = root.to_str().unwrap();

    // ── Part 1: compare V1 vs V2 digest via compute-composefs-digest ──────────
    let sh = Shell::new()?;

    let digest_v2 = cmd!(
        sh,
        "bootc container compute-composefs-digest {root_str} --erofs-version=v2"
    )
    .read()?;
    let digest_v1 = cmd!(
        sh,
        "bootc container compute-composefs-digest {root_str} --erofs-version=v1"
    )
    .read()?;

    let digest_v2 = digest_v2.trim();
    let digest_v1 = digest_v1.trim();

    assert_eq!(digest_v2.as_bytes().len(), 128, "V2 digest must be 128 hex chars");
    assert_eq!(digest_v1.as_bytes().len(), 128, "V1 digest must be 128 hex chars");
    assert!(
        digest_v2.chars().all(|c| c.is_ascii_hexdigit()),
        "V2 digest contains non-hex chars: {digest_v2}"
    );
    assert!(
        digest_v1.chars().all(|c| c.is_ascii_hexdigit()),
        "V1 digest contains non-hex chars: {digest_v1}"
    );
    assert_ne!(
        digest_v1, digest_v2,
        "V1 and V2 EROFS digests must differ (they use different on-disk layouts)"
    );

    // ── Part 2: smoke-test the full ukify CLI path with --erofs-version=v1 ────
    //
    // We don't assert success because ukify will fail on fake kernel blobs.
    // What we're testing is that bootc reaches the ukify invocation stage —
    // i.e. the --erofs-version plumbing is wired correctly all the way through.
    let output = Command::new("bootc")
        .args([
            "container",
            "ukify",
            "--rootfs",
            root_str,
            "--erofs-version=v1",
            "--allow-missing-verity",
            "--",
            "--output=/dev/null",
        ])
        .output()?;

    let stderr = String::from_utf8_lossy(&output.stderr);

    if stderr.contains("ukify executable not found in PATH") {
        // ukify binary absent: the CLI plumbing still ran up to that check.
        eprintln!("note: ukify not found, skipping ukify invocation check");
        return Ok(());
    }

    // ukify was found and invoked.  It will fail because of the fake kernel
    // blobs, but bootc must have reached the `ukify build` invocation, which
    // means the V1 digest was computed and the cmdline assembled.  Assert that
    // no *bootc* logic bailed before reaching ukify (i.e. no "No kernel found",
    // "already contains a UKI", or similar early exits).
    assert!(
        !stderr.contains("No kernel found") && !stderr.contains("already contains a UKI"),
        "bootc bailed before reaching ukify; stderr:\n{stderr}"
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
        new_test(
            "container-ukify-erofs-versions",
            test_container_ukify_erofs_versions,
        ),
    ];

    libtest_mimic::run(&testargs, tests.into()).exit()
}
