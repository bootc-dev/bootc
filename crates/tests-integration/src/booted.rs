//! Tests that tmt runs on a booted host, ported from the nushell tests in
//! tmt/tests/booted; see <https://github.com/bootc-dev/bootc/issues/2547>.
//!
//! Each module in booted/ is one subcommand.
//!
//! Checks fail with an error rather than a panic, because tmt reports an exit
//! code of 1 as a failure and any other (101 from a panic) as an error.

use anyhow::{Context, Result};
use clap::Subcommand;
use xshell::{Shell, cmd};

mod switch_zstd_chunked;

#[derive(Debug, Subcommand)]
#[clap(rename_all = "kebab-case")]
pub(crate) enum Opt {
    /// Switch to an image with zstd:chunked compressed layers
    SwitchZstdChunked,
}

pub(crate) fn run(opt: Opt) -> Result<()> {
    let sh = &Shell::new()?;
    match opt {
        Opt::SwitchZstdChunked => switch_zstd_chunked::run(sh),
    }
}

/// Start a "Test anything protocol" stream:
/// <https://testanything.org/tap-version-14-specification.html>
fn tap_begin(description: &str) {
    println!("TAP version 14");
    println!("{description}");
}

fn tap_ok() {
    println!("ok");
}

/// How many times tmt has rebooted the host during this test; see
/// <https://tmt.readthedocs.io/en/stable/stories/features.html#reboot-during-test>
fn reboot_count() -> Result<u32> {
    match std::env::var("TMT_REBOOT_COUNT") {
        Ok(v) => v
            .parse()
            .with_context(|| format!("Invalid TMT_REBOOT_COUNT {v}")),
        Err(std::env::VarError::NotPresent) => Ok(0),
        Err(e) => Err(e).context("Reading TMT_REBOOT_COUNT"),
    }
}

fn host_status(sh: &Shell) -> Result<serde_json::Value> {
    let st = cmd!(sh, "bootc status --json").read()?;
    serde_json::from_str(&st).context("Parsing bootc status")
}

/// The EROFS format selected by the tmt configuration, so that derived UKI
/// test images use the same default as the source image.
fn selected_erofs_version() -> Result<String> {
    let version = match std::env::var("BOOTC_erofs_version") {
        Ok(v) => v,
        Err(std::env::VarError::NotPresent) => "v1".to_owned(),
        Err(e) => return Err(e).context("Reading BOOTC_erofs_version"),
    };
    anyhow::ensure!(
        matches!(version.as_str(), "v1" | "v2"),
        "Unsupported EROFS version: {version}"
    );
    Ok(version)
}

/// If the host boots a composefs UKI, append the stages that rebuild the UKI
/// for the image `containerfile` builds (as its `base` stage).
fn make_uki_containerfile(sh: &Shell, containerfile: &str) -> Result<String> {
    let erofs_version = selected_erofs_version()?;
    let st = host_status(sh)?;
    uki_containerfile(containerfile, &st, &erofs_version)
}

fn uki_containerfile(
    containerfile: &str,
    st: &serde_json::Value,
    erofs_version: &str,
) -> Result<String> {
    let Some(composefs) = st
        .pointer("/status/booted/composefs")
        .filter(|v| !v.is_null())
    else {
        return Ok(containerfile.to_owned());
    };
    let boot_type = composefs
        .get("bootType")
        .and_then(|v| v.as_str())
        .context("Missing composefs bootType")?;
    if !boot_type.eq_ignore_ascii_case("uki") {
        return Ok(containerfile.to_owned());
    }
    let missing_verity_allowed = composefs
        .get("missingVerityAllowed")
        .and_then(|v| v.as_bool())
        .context("Missing composefs missingVerityAllowed")?;
    let allow_missing_verity = if missing_verity_allowed {
        "--allow-missing-verity"
    } else {
        ""
    };

    // TODO: Handle sealed UKI
    let seal_state = "unsealed";

    let uki_stages = format!(
        r#"
        FROM base as kernel
        RUN <<-EOF
            kver=$(bootc container inspect --rootfs / --json | jq -r '.kernel.version')
            bootc internals uki extract /boot/EFI/Linux/$kver.efi /boot
        EOF

        FROM base as base-final
        RUN rm -rf /boot/EFI/Linux/*.efi

        FROM base as sealed-uki
        RUN --network=none --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp \
            --mount=type=bind,from=base-final,src=/,target=/run/target \
            --mount=type=bind,from=kernel,src=/,target=/run/kernel <<-EOF

              kver=$(bootc container inspect --rootfs /run/kernel --json | jq -r '.kernel.version')

              /usr/bin/seal-uki \
                  --target /run/target \
                  --output /out \
                  --secrets /run/secrets {allow_missing_verity} \
                  --kernel-dir /run/kernel/boot/${{kver}} \
                  --write-dumpfile-to /out/${{kver}}.dump \
                  --seal-state {seal_state} \
                  --erofs-version {erofs_version}
        EOF

        FROM base-final

        # Copy the sealed UKI and finalize the image remove raw kernel, create symlinks
        RUN --network=none --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp \
            --mount=type=bind,from=sealed-uki,src=/,target=/run/sealed-uki \
            --mount=type=bind,from=kernel,src=/,target=/run/kernel \
            /usr/bin/finalize-uki /run/sealed-uki/out $(bootc container inspect --rootfs /run/kernel --json | jq -r '.kernel.version')
    "#
    );
    let uki_stages = uki_stages.lines().map(str::trim).collect::<Vec<_>>();
    Ok(format!("{containerfile}\n{}", uki_stages.join("\n")))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn status(composefs: serde_json::Value) -> serde_json::Value {
        json!({"status": {"booted": {"composefs": composefs}}})
    }

    #[test]
    fn test_uki_containerfile() {
        let base = "FROM localhost/bootc as base\n";
        let unchanged = [
            json!({"status": {"booted": {"ostree": {}}}}),
            status(json!(null)),
            status(json!({"bootType": "Bls", "missingVerityAllowed": false})),
        ];
        for st in unchanged {
            assert_eq!(uki_containerfile(base, &st, "v1").unwrap(), base, "{st}");
        }

        let uki =
            |allowed: bool| status(json!({"bootType": "Uki", "missingVerityAllowed": allowed}));
        let r = uki_containerfile(base, &uki(false), "v2").unwrap();
        assert!(r.starts_with(base));
        assert!(r.contains("\nFROM base as kernel\n"));
        assert!(r.contains("\n--secrets /run/secrets  \\\n"));
        assert!(r.contains("\n--kernel-dir /run/kernel/boot/${kver} \\\n"));
        assert!(r.contains("\n--erofs-version v2\nEOF\n"));
        let r = uki_containerfile(base, &uki(true), "v1").unwrap();
        assert!(r.contains("\n--secrets /run/secrets --allow-missing-verity \\\n"));

        assert!(uki_containerfile(base, &status(json!({})), "v1").is_err());
    }
}
