//! A pending origin change for the booted image, without a second OS deployment.
//!
//! The OCI manifest must match exactly. Finalization changes only the origin;
//! the existing /etc, boot artifacts, and OS rollback deployment are retained.

use anyhow::{Context, Result, ensure};
use canon_json::CanonJsonSerialize;
use cap_std_ext::{cap_std::fs::Dir, dirext::CapStdExtDirExt};
use composefs_ctl::composefs::fsverity::{FsVerityHashValue, Sha512HashValue};
use ostree_ext::oci_spec::image::Digest;
use rustix::fs::fsync;
use serde::{Deserialize, Serialize};

use super::state::{read_origin, with_image_references, write_origin};
use crate::spec::{Host, ImageReference};

pub(crate) const PENDING_ORIGIN: &str = "state/bootc-origin-change.json";

pub(crate) fn should_reboot(
    soft_reboot: Option<crate::cli::SoftRebootMode>,
    apply: bool,
    locked: bool,
) -> Result<bool> {
    ensure!(
        !apply || !locked,
        "Staged deployment is download-only; use --from-downloaded --apply"
    );
    if let Some(mode) = soft_reboot {
        ensure!(
            ostree_ext::systemd_has_soft_reboot(),
            "System does not support soft reboots"
        );
        super::soft_reboot::check_capability(false, mode)?;
    }
    Ok(apply && soft_reboot.is_none())
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct OriginChange {
    pub(crate) deployment: String,
    manifest_digest: Digest,
    previous_origin: String,
    pub(crate) source: ImageReference,
    target: ImageReference,
    pub(crate) finalization_locked: bool,
}

impl OriginChange {
    pub(crate) fn new(
        sysroot: &Dir,
        host: &Host,
        manifest_digest: &Digest,
        source: &ImageReference,
        target: &ImageReference,
        finalization_locked: bool,
    ) -> Result<Self> {
        let booted = host
            .status
            .booted
            .as_ref()
            .context("No booted deployment")?;
        let deployment = booted.require_composefs()?.verity.clone();
        let previous_origin = read_origin(sysroot, &deployment)?
            .context("No booted origin")?
            .to_string();
        let pending = Self {
            deployment,
            manifest_digest: manifest_digest.clone(),
            previous_origin,
            source: source.clone(),
            target: target.clone(),
            finalization_locked,
        };
        pending.validate(sysroot, host)?;
        Ok(pending)
    }

    pub(crate) fn read(sysroot: &Dir) -> Result<Option<Self>> {
        let Some(contents) = sysroot.read_optional(PENDING_ORIGIN)? else {
            return Ok(None);
        };
        let pending: Self =
            serde_json::from_slice(&contents).context("Reading pending origin change")?;
        Sha512HashValue::from_hex(&pending.deployment)
            .context("Invalid origin-change deployment")?;
        Ok(Some(pending))
    }

    pub(crate) fn write(&self, sysroot: &Dir) -> Result<()> {
        sysroot
            .atomic_write(PENDING_ORIGIN, self.to_canon_json_vec()?)
            .context("Writing pending origin change")
    }

    /// Stale metadata must not hide real deployments or prevent their activation.
    /// Keep it on disk for explicit cancellation with delete-deployment.
    pub(crate) fn read_active(sysroot: &Dir, host: &Host) -> Result<Option<Self>> {
        let Some(pending) = Self::read(sysroot)? else {
            return Ok(None);
        };
        if !pending.is_applicable(sysroot, host)? {
            tracing::warn!(
                "Ignoring stale origin change; cancel it with bootc delete-deployment {}",
                pending.deployment
            );
            return Ok(None);
        }
        Ok(Some(pending))
    }

    fn desired_origin(&self) -> Result<tini::Ini> {
        let previous =
            tini::Ini::from_string(&self.previous_origin).context("Parsing previous origin")?;
        with_image_references(previous, Some(&self.source), &self.target)
    }

    fn is_applicable(&self, sysroot: &Dir, host: &Host) -> Result<bool> {
        let booted = host
            .status
            .booted
            .as_ref()
            .context("No booted deployment")?;
        if booted.require_composefs()?.verity != self.deployment
            || !booted
                .image
                .as_ref()
                .is_some_and(|image| image.image_digest == self.manifest_digest.as_ref())
            || host.status.rollback_queued
            || !host.status.staged.as_ref().is_none_or(|entry| {
                entry
                    .composefs
                    .as_ref()
                    .is_some_and(|c| c.verity == self.deployment)
            })
        {
            return Ok(false);
        }
        let Some(current) = read_origin(sysroot, &self.deployment)? else {
            return Ok(false);
        };
        let current = current.to_string();
        // The desired value is valid after interruption between the origin write
        // and removing the transaction. Retrying finalization is then idempotent.
        Ok(current == self.previous_origin || current == self.desired_origin()?.to_string())
    }

    pub(crate) fn validate(&self, sysroot: &Dir, host: &Host) -> Result<()> {
        ensure!(
            self.is_applicable(sysroot, host)?,
            "Pending origin change no longer matches the deployment; cancel it with delete-deployment"
        );
        Ok(())
    }

    pub(crate) fn project(&self, sysroot: &Dir, host: &mut Host) -> Result<()> {
        self.validate(sysroot, host)?;
        let mut staged = host.status.booted.clone().context("No booted deployment")?;
        staged.image.as_mut().context("No booted image")?.image = self.target.clone();
        staged.cached_update = None;
        staged.download_only = self.finalization_locked;
        staged.soft_reboot_capable = false;
        host.status.staged = Some(staged);
        host.spec.image = Some(self.target.clone());
        Ok(())
    }

    pub(crate) fn finalize(&self, sysroot: &Dir, host: &Host) -> Result<()> {
        self.validate(sysroot, host)?;
        ensure!(
            !self.finalization_locked,
            "Pending origin change is download-only"
        );
        write_origin(sysroot, &self.deployment, &self.desired_origin()?)?;
        cancel(sysroot)
    }
}

pub(crate) fn cancel(sysroot: &Dir) -> Result<()> {
    if sysroot.remove_file_optional(PENDING_ORIGIN)? {
        fsync(sysroot.open_dir("state")?.reopen_as_ownedfd()?)
            .context("Syncing origin cancellation")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootc_composefs::boot::BootType;
    use crate::composefs_consts::STATE_DIR_RELATIVE;
    use crate::deploy::{ORIGIN_BOOTC, ORIGIN_SOURCE_IMAGE};
    use crate::spec::{BootEntry, BootEntryComposefs, Bootloader, HostSpec, ImageStatus};
    use ostree_ext::container::deploy::ORIGIN_CONTAINER;

    fn fixture() -> Result<(cap_std_ext::cap_tempfile::TempDir, Host, ImageReference)> {
        let root = cap_std_ext::cap_tempfile::tempdir(cap_std_ext::cap_std::ambient_authority())?;
        let deployment = "ab".repeat(64);
        let source = ImageReference {
            image: "localhost/os:v1".into(),
            transport: "containers-storage".into(),
            signature: None,
        };
        let mut host = Host::new(HostSpec {
            image: Some(source.clone()),
            ..Default::default()
        });
        host.status.booted = Some(BootEntry {
            image: Some(ImageStatus {
                image: source.clone(),
                version: None,
                timestamp: None,
                image_digest: format!("sha256:{}", "cd".repeat(32)),
                architecture: "amd64".into(),
            }),
            cached_update: None,
            incompatible: false,
            pinned: false,
            soft_reboot_capable: false,
            download_only: false,
            store: None,
            ostree: None,
            composefs: Some(BootEntryComposefs {
                verity: deployment.clone(),
                boot_type: BootType::Uki,
                bootloader: Bootloader::None,
                boot_digest: Some("boot-digest".into()),
                missing_verity_allowed: false,
            }),
        });
        let mut rollback = host.status.booted.clone().unwrap();
        rollback.composefs.as_mut().unwrap().verity = "ef".repeat(64);
        host.status.rollback = Some(rollback);
        root.create_dir_all(format!("{STATE_DIR_RELATIVE}/{deployment}"))?;
        let origin = tini::Ini::new()
            .section("origin")
            .item(ORIGIN_CONTAINER, source.to_string())
            .section("boot")
            .item("digest", "boot-digest")
            .section("custom")
            .item("keep", "yes");
        write_origin(&root, &deployment, &origin)?;
        let target = ImageReference {
            image: "quay.io/example/os:v1".into(),
            transport: "registry".into(),
            signature: None,
        };
        Ok((root, host, target))
    }

    #[test]
    fn origin_change_lifecycle() -> Result<()> {
        let (root, host, target) = fixture()?;
        let image = host.status.booted.as_ref().unwrap().image.as_ref().unwrap();
        let pending =
            OriginChange::new(&root, &host, &image.digest()?, &image.image, &target, true)?;
        let before = read_origin(&root, &pending.deployment)?
            .unwrap()
            .to_string();
        pending.write(&root)?;

        // Re-read from durable state, as after a reboot with /run cleared.
        let mut pending = OriginChange::read(&root)?.unwrap();
        let mut projected = host.clone();
        pending.project(&root, &mut projected)?;
        assert_eq!(projected.status.booted, host.status.booted);
        assert_eq!(projected.status.rollback, host.status.rollback);
        assert_eq!(projected.spec.image.as_ref(), Some(&target));
        assert!(projected.status.staged.as_ref().unwrap().download_only);
        assert!(pending.finalize(&root, &projected).is_err());
        assert_eq!(
            read_origin(&root, &pending.deployment)?
                .unwrap()
                .to_string(),
            before
        );

        pending.finalization_locked = false;
        pending.write(&root)?;
        // Simulate interruption after replacing the origin but before consuming
        // the transaction; the next finalization must finish safely.
        write_origin(&root, &pending.deployment, &pending.desired_origin()?)?;
        let pending = OriginChange::read(&root)?.unwrap();
        pending.finalize(&root, &projected)?;
        assert!(OriginChange::read(&root)?.is_none());
        let origin = read_origin(&root, &pending.deployment)?.unwrap();
        assert_eq!(
            origin.get::<String>("custom", "keep").as_deref(),
            Some("yes")
        );
        assert_eq!(
            origin.get::<String>("boot", "digest").as_deref(),
            Some("boot-digest")
        );
        assert_eq!(
            origin.get::<String>(ORIGIN_BOOTC, ORIGIN_SOURCE_IMAGE),
            Some(image.image.to_string())
        );
        let recorded: ostree_ext::container::OstreeImageReference = origin
            .get::<String>("origin", ORIGIN_CONTAINER)
            .unwrap()
            .as_str()
            .try_into()?;
        assert_eq!(ImageReference::from(recorded), target);
        Ok(())
    }

    #[test]
    fn origin_change_metadata_compatibility() -> Result<()> {
        let (root, host, target) = fixture()?;
        let image = host.status.booted.as_ref().unwrap().image.as_ref().unwrap();
        // The persisted format uses strings, including when written before the
        // manifest digest became typed. Keep accepting that representation.
        let metadata = serde_json::json!({
            "deployment": host.require_composefs_booted()?.verity,
            "manifest_digest": image.image_digest,
            "previous_origin": "[origin]\ncontainer-image-reference=old\n",
            "source": image.image,
            "target": target,
            "finalization_locked": true,
        });
        root.write(PENDING_ORIGIN, serde_json::to_vec(&metadata)?)?;
        let pending = OriginChange::read(&root)?.unwrap();
        assert_eq!(serde_json::to_value(&pending)?, metadata);
        for (key, invalid) in [
            ("manifest_digest", "not-a-digest"),
            ("manifest_digest", "sha256:1234"),
            ("deployment", "../another-deployment"),
        ] {
            let mut invalid_metadata = metadata.clone();
            invalid_metadata[key] = invalid.into();
            root.write(PENDING_ORIGIN, serde_json::to_vec(&invalid_metadata)?)?;
            assert!(OriginChange::read(&root).is_err(), "{key}: {invalid}");
        }
        Ok(())
    }

    #[test]
    fn origin_references_preserve_metadata() -> Result<()> {
        let (root, host, target) = fixture()?;
        let source = host.spec.image.as_ref().unwrap();
        let previous = read_origin(&root, &host.require_composefs_booted()?.verity)?
            .unwrap()
            .to_string();
        for source in [None, Some(source), Some(&target)] {
            let old = tini::Ini::from_string(&previous)?
                .section(ORIGIN_BOOTC)
                .item(ORIGIN_SOURCE_IMAGE, "stale");
            let updated = with_image_references(old, source, &target)?;
            assert_eq!(
                updated.get::<String>("custom", "keep").as_deref(),
                Some("yes")
            );
            assert_eq!(
                updated.get::<String>("boot", "digest").as_deref(),
                Some("boot-digest")
            );
            assert_eq!(
                updated.get::<String>(ORIGIN_BOOTC, ORIGIN_SOURCE_IMAGE),
                source.map(ToString::to_string)
            );
            let recorded: ostree_ext::container::OstreeImageReference = updated
                .get::<String>("origin", ORIGIN_CONTAINER)
                .unwrap()
                .as_str()
                .try_into()?;
            assert_eq!(ImageReference::from(recorded), target);
        }
        Ok(())
    }

    #[test]
    fn origin_change_rejects_stale_state_and_cancels() -> Result<()> {
        for case in [
            "manifest",
            "deployment",
            "staged",
            "rollback",
            "origin",
            "missing-origin",
        ] {
            let (root, mut host, target) = fixture()?;
            let image = host.status.booted.as_ref().unwrap().image.as_ref().unwrap();
            let pending =
                OriginChange::new(&root, &host, &image.digest()?, &image.image, &target, false)?;
            pending.write(&root)?;
            match case {
                "manifest" => {
                    host.status
                        .booted
                        .as_mut()
                        .unwrap()
                        .image
                        .as_mut()
                        .unwrap()
                        .image_digest = "sha256:different".into()
                }
                "deployment" => {
                    host.status
                        .booted
                        .as_mut()
                        .unwrap()
                        .composefs
                        .as_mut()
                        .unwrap()
                        .verity = "12".repeat(64)
                }
                "staged" => host.status.staged = host.status.rollback.clone(),
                "rollback" => host.status.rollback_queued = true,
                "origin" => write_origin(
                    &root,
                    &pending.deployment,
                    &tini::Ini::new().section("custom").item("changed", "yes"),
                )?,
                "missing-origin" => root.remove_file(format!(
                    "{STATE_DIR_RELATIVE}/{0}/{0}.origin",
                    pending.deployment
                ))?,
                _ => unreachable!(),
            }
            let before_host = host.clone();
            if let Some(active) = OriginChange::read_active(&root, &host)? {
                active.project(&root, &mut host)?;
                panic!("Stale state must not be projected: {case}");
            }
            assert_eq!(host, before_host);
            assert!(pending.finalize(&root, &host).is_err(), "{case}");
            assert!(OriginChange::read(&root)?.is_some());
            let before = read_origin(&root, &pending.deployment)?.map(|origin| origin.to_string());
            cancel(&root)?;
            cancel(&root)?;
            assert!(OriginChange::read(&root)?.is_none());
            assert_eq!(
                read_origin(&root, &pending.deployment)?.map(|origin| origin.to_string()),
                before
            );
        }
        Ok(())
    }
}
