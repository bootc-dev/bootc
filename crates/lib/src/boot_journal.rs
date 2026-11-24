//! Record the booted deployment's image in the journal.
//!
//! `bootc-log-boot.service` runs `bootc internals log-boot` on every boot so
//! that the journal holds a structured record of which image the system
//! booted. See <https://github.com/bootc-dev/bootc/issues/452>.
//!
//! This deliberately avoids the full `bootc status` path: on composefs that
//! path remounts `/sysroot` read-write, mounts the ESP and may migrate boot
//! entries, which a logging unit running unattended at every boot should not
//! do. Instead it reads only the deployment's origin file and the image in the
//! composefs repository, through [`Storage::open_booted_composefs_readonly`].
//!
//! The entry is written with [`libsystemd::logging::journal_send`] rather
//! than `tracing`, because the tracing journald layer prefixes every custom
//! field with `F_`. Writing directly gives a standard `MESSAGE_ID` field that
//! `journalctl MESSAGE_ID=...` matches.

use anyhow::{Context, Result};
use fn_error_context::context;

use crate::bootc_composefs::state::read_origin;
use crate::bootc_composefs::status::{composefs_booted, image_status_from_origin};
use crate::spec::ImageStatus;
use crate::store::Storage;

/// Journal `MESSAGE_ID` for the record of the booted image.
pub(crate) const BOOT_JOURNAL_ID: &str = "66797517e29842bfa048064146ec92c2";

/// Build the human-readable message and the structured journal fields that
/// describe a booted deployment.
fn boot_record(
    backend: &str,
    deployment: &str,
    image: Option<&ImageStatus>,
) -> (String, Vec<(&'static str, String)>) {
    let mut fields = vec![
        ("MESSAGE_ID", BOOT_JOURNAL_ID.to_owned()),
        ("SYSLOG_IDENTIFIER", "bootc".to_owned()),
        ("BOOTC_BACKEND", backend.to_owned()),
        ("BOOTC_DEPLOYMENT", deployment.to_owned()),
    ];

    let Some(image) = image else {
        let msg = format!("Booted {backend} deployment {deployment} (not from a container image)");
        return (msg, fields);
    };

    fields.extend([
        ("BOOTC_IMAGE", image.image.image.clone()),
        ("BOOTC_TRANSPORT", image.image.transport.clone()),
        ("BOOTC_MANIFEST_DIGEST", image.image_digest.clone()),
        ("BOOTC_ARCHITECTURE", image.architecture.clone()),
    ]);
    if let Some(version) = image.version.as_ref() {
        fields.push(("BOOTC_VERSION", version.clone()));
    }
    if let Some(timestamp) = image.timestamp.as_ref() {
        fields.push(("BOOTC_TIMESTAMP", timestamp.to_rfc3339()));
    }

    let version = image
        .version
        .as_deref()
        .map(|v| format!(" version {v}"))
        .unwrap_or_default();
    let msg = format!(
        "Booted {:#}{version} ({}) from {backend} deployment {deployment}",
        image.image, image.image_digest
    );
    (msg, fields)
}

/// Implementation of `bootc internals log-boot`.
#[context("Logging booted image")]
pub(crate) fn log_boot() -> Result<()> {
    let cmdline = composefs_booted()?
        .context("Not booted via composefs; only the composefs backend is supported")?;
    let digest = &*cmdline.digest;

    let storage = Storage::open_booted_composefs_readonly(cmdline)?;
    let origin = read_origin(&storage.physical_root, digest)?
        .with_context(|| format!("No origin file for deployment {digest}"))?;
    let image = image_status_from_origin(&storage, &origin, digest)?;

    let (msg, fields) = boot_record("composefs", digest, image.as_ref());
    libsystemd::logging::journal_send(
        libsystemd::logging::Priority::Info,
        &msg,
        fields.iter().map(|(k, v)| (*k, v.as_str())),
    )
    .context("Writing to the journal")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::ImageReference;

    fn image(transport: &str, name: &str, version: Option<&str>, created: bool) -> ImageStatus {
        ImageStatus {
            image: ImageReference {
                image: name.into(),
                transport: transport.into(),
                signature: None,
            },
            version: version.map(Into::into),
            timestamp: created.then(|| {
                chrono::DateTime::parse_from_rfc3339("2026-11-01T12:00:00Z")
                    .unwrap()
                    .into()
            }),
            image_digest: "sha256:0123".into(),
            architecture: "amd64".into(),
        }
    }

    #[test]
    fn test_boot_record() {
        let registry = "quay.io/example/os:latest";
        let common = [
            ("MESSAGE_ID", BOOT_JOURNAL_ID),
            ("SYSLOG_IDENTIFIER", "bootc"),
            ("BOOTC_BACKEND", "composefs"),
            ("BOOTC_DEPLOYMENT", "abcd"),
        ];
        let image_fields = |transport, name| {
            [
                ("BOOTC_IMAGE", name),
                ("BOOTC_TRANSPORT", transport),
                ("BOOTC_MANIFEST_DIGEST", "sha256:0123"),
                ("BOOTC_ARCHITECTURE", "amd64"),
            ]
        };
        // (image, expected message, expected fields after the common ones)
        let cases: Vec<(Option<ImageStatus>, &str, Vec<(&str, &str)>)> = vec![
            (
                None,
                "Booted composefs deployment abcd (not from a container image)",
                vec![],
            ),
            (
                Some(image("registry", registry, Some("42.1"), true)),
                "Booted quay.io/example/os:latest version 42.1 (sha256:0123) from composefs deployment abcd",
                image_fields("registry", registry)
                    .into_iter()
                    .chain([
                        ("BOOTC_VERSION", "42.1"),
                        ("BOOTC_TIMESTAMP", "2026-11-01T12:00:00+00:00"),
                    ])
                    .collect(),
            ),
            (
                Some(image("registry", registry, None, false)),
                "Booted quay.io/example/os:latest (sha256:0123) from composefs deployment abcd",
                image_fields("registry", registry).to_vec(),
            ),
            (
                Some(image("containers-storage", "localhost/os", None, false)),
                "Booted ostree-unverified-image:containers-storage:localhost/os (sha256:0123) from composefs deployment abcd",
                image_fields("containers-storage", "localhost/os").to_vec(),
            ),
        ];
        for (image, expected_msg, extra) in cases {
            let (msg, fields) = boot_record("composefs", "abcd", image.as_ref());
            assert_eq!(msg, expected_msg);
            let fields: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
            let expected: Vec<(&str, &str)> = common.into_iter().chain(extra).collect();
            assert_eq!(fields, expected, "{expected_msg}");
        }
    }
}
