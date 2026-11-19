//! Integration with Red Hat Subscription Manager

use anyhow::{Context, Result};
use cap_std::fs::Dir;
use cap_std_ext::{cap_std, dirext::CapStdExtDirExt};
use fn_error_context::context;
use rustix::fs::StatVfsMountFlags;
use serde::Serialize;

/// Where subscription-manager reads facts from, relative to the root
const FACTS_DIR: &str = "etc/rhsm/facts";
/// The file the facts are written to, in [`FACTS_DIR`]
const FACTS_FILE: &str = "bootc.facts";

#[derive(Serialize, PartialEq, Eq, Debug, Default)]
struct RhsmFacts {
    #[serde(rename = "bootc.booted.image")]
    booted_image: String,
    #[serde(rename = "bootc.booted.version")]
    booted_version: String,
    #[serde(rename = "bootc.booted.digest")]
    booted_digest: String,
    #[serde(rename = "bootc.staged.image")]
    staged_image: String,
    #[serde(rename = "bootc.staged.version")]
    staged_version: String,
    #[serde(rename = "bootc.staged.digest")]
    staged_digest: String,
    #[serde(rename = "bootc.rollback.image")]
    rollback_image: String,
    #[serde(rename = "bootc.rollback.version")]
    rollback_version: String,
    #[serde(rename = "bootc.rollback.digest")]
    rollback_digest: String,
    #[serde(rename = "bootc.available.image")]
    available_image: String,
    #[serde(rename = "bootc.available.version")]
    available_version: String,
    #[serde(rename = "bootc.available.digest")]
    available_digest: String,
}

/// Return the image reference, version and digest as owned strings.
/// A missing version is serialized as the empty string.
fn status_to_strings(imagestatus: &crate::spec::ImageStatus) -> (String, String, String) {
    let image = imagestatus.image.image.clone();
    let version = imagestatus.version.as_ref().cloned().unwrap_or_default();
    let digest = imagestatus.image_digest.clone();
    (image, version, digest)
}

impl From<crate::spec::HostStatus> for RhsmFacts {
    fn from(hoststatus: crate::spec::HostStatus) -> Self {
        let (booted_image, booted_version, booted_digest) = hoststatus
            .booted
            .as_ref()
            .and_then(|boot_entry| boot_entry.image.as_ref().map(status_to_strings))
            .unwrap_or_default();

        let (staged_image, staged_version, staged_digest) = hoststatus
            .staged
            .as_ref()
            .and_then(|boot_entry| boot_entry.image.as_ref().map(status_to_strings))
            .unwrap_or_default();

        let (rollback_image, rollback_version, rollback_digest) = hoststatus
            .rollback
            .as_ref()
            .and_then(|boot_entry| boot_entry.image.as_ref().map(status_to_strings))
            .unwrap_or_default();

        let (available_image, available_version, available_digest) = hoststatus
            .booted
            .as_ref()
            .and_then(|boot_entry| boot_entry.cached_update.as_ref().map(status_to_strings))
            .unwrap_or_default();

        Self {
            booted_image,
            booted_version,
            booted_digest,
            staged_image,
            staged_version,
            staged_digest,
            rollback_image,
            rollback_version,
            rollback_digest,
            available_image,
            available_version,
            available_digest,
        }
    }
}

/// Whether `dir` is on a read-only mount.
fn is_read_only_mount(dir: &Dir) -> Result<bool> {
    let st = rustix::fs::fstatvfs(dir).context("Querying mount flags")?;
    Ok(st.f_flag.contains(StatVfsMountFlags::RDONLY))
}

/// Write `facts` to [`FACTS_FILE`] in `facts_dir`.
fn write_facts(facts_dir: &Dir, facts: &RhsmFacts) -> Result<()> {
    facts_dir
        .atomic_replace_with(FACTS_FILE, |w| {
            serde_json::to_writer_pretty(w, facts)?;
            anyhow::Ok(())
        })
        .with_context(|| format!("Writing /{FACTS_DIR}/{FACTS_FILE}"))
}

/// Publish facts for subscription-manager consumption
#[context("Publishing facts")]
pub(crate) async fn publish_facts(root: &Dir) -> Result<()> {
    let facts_dir = root
        .open_dir(FACTS_DIR)
        .with_context(|| format!("Opening /{FACTS_DIR}"))?;
    // /etc can be read-only for a whole boot, for instance while a
    // systemd-confext is merged over it. There is nowhere to publish the
    // facts then, which is not an error: the previously published facts stay
    // until the next run with a writable /etc, such as on the next boot.
    if is_read_only_mount(&facts_dir)? {
        tracing::info!("/{FACTS_DIR} is on a read-only mount; not publishing facts");
        return Ok(());
    }

    let sysroot = super::cli::get_storage().await?;
    let ostree = sysroot.get_ostree()?;
    let (_, _, host) = crate::status::get_status_require_booted(ostree)?;

    write_facts(&facts_dir, &RhsmFacts::from(host.status))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::spec::Host;

    #[test]
    fn test_rhsm_facts_from_host() {
        let host: Host = serde_yaml::from_str(include_str!("fixtures/spec-staged-booted.yaml"))
            .expect("No spec found");
        let facts = RhsmFacts::from(host.status);

        assert_eq!(
            facts,
            RhsmFacts {
                booted_image: "quay.io/example/someimage:latest".into(),
                booted_version: "nightly".into(),
                booted_digest:
                    "sha256:736b359467c9437c1ac915acaae952aad854e07eb4a16a94999a48af08c83c34".into(),
                staged_image: "quay.io/example/someimage:latest".into(),
                staged_version: "nightly".into(),
                staged_digest:
                    "sha256:16dc2b6256b4ff0d2ec18d2dbfb06d117904010c8cf9732cdb022818cf7a7566".into(),
                ..Default::default()
            }
        );
    }

    #[test]
    fn test_write_facts() -> Result<()> {
        let td = cap_std_ext::cap_tempfile::tempdir(cap_std_ext::cap_std::ambient_authority())?;
        assert!(!is_read_only_mount(&td)?);

        let facts = RhsmFacts {
            booted_image: "quay.io/example/someimage:latest".into(),
            booted_version: "nightly".into(),
            ..Default::default()
        };
        write_facts(&td, &facts)?;
        let written: serde_json::Value = serde_json::from_str(&td.read_to_string(FACTS_FILE)?)?;
        assert_eq!(
            written["bootc.booted.image"],
            "quay.io/example/someimage:latest"
        );
        assert_eq!(written["bootc.booted.version"], "nightly");
        assert_eq!(written["bootc.staged.image"], "");
        Ok(())
    }
}
