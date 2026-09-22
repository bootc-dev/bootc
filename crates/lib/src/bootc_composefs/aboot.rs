//! Persistent Aboot state relative to the physical root:
//!
//! ```text
//! state/boot/aboot/
//!   slots/a                 observed deployment ID for slot A
//!   slots/b                 observed deployment ID for slot B
//!   pending                 staged deployment, payload hashes, and finalization lock
//!   attempted               deployment attempt and the boot ID which initiated it
//!   rollback                queued rollback deployment and originating boot ID
//!
//! state/deploy/<deployment ID>/aboot/
//!   aboot.img               staged boot partition payload
//!   vbmeta.img              optional staged vbmeta payload
//! ```
//!
//! A missing slot file means that slot has no known valid mapping. Pending and
//! attempted state retain an update until a later boot observes its result.
//! `/run/composefs/staged-deployment` is a transient version of pending state
//! used by the common status and finalization code.
//!
//! Update staging first creates the deployment state, then writes and hashes the boot
//! (and optional vbmeta payloads) below that deployment. Only after those writes are
//! durable does it publish `pending` and the transient staged view. No boot partitions
//! are written during staging.
//!
//! At shutdown the finalizer verifies the staged payload hashes, writes `attempted`,
//! invalidates the non-booted slot mapping, and invokes aboot-deploy. On the next boot,
//! observing the candidate consumes `pending`, its staged payload directory, and
//! `attempted`. Observing another deployment retains them without automatically retrying
//! the write. An unattempted pending update is projected back into `/run` and rearmed
//! unless it was staged download-only.

use anyhow::{Context, Result, ensure};
use camino::{Utf8Path, Utf8PathBuf};
use canon_json::CanonJsonSerialize;
use cap_std_ext::{cap_std::fs::Dir, dirext::CapStdExtDirExt};
use composefs_ctl::composefs::fsverity::{FsVerityHashValue, Sha512HashValue};
use linux_kernel_cmdline::utf8::Cmdline;
use rustix::{
    fd::OwnedFd,
    fs::{FlockOperation, Mode, OFlags, flock, fsync, openat},
};
use serde::{Deserialize, Serialize};

use crate::composefs_consts::{
    ABOOT_ARTIFACT_DIR, ABOOT_ATTEMPTED_FNAME, ABOOT_IMAGE_FNAME, ABOOT_PENDING_FNAME,
    ABOOT_ROLLBACK_FNAME, ABOOT_STATE_DIR, ABOOT_VBMETA_FNAME, STATE_DIR_RELATIVE,
};

use super::{
    boot::BootType,
    state::{read_boot_type, remove_staged_deployment, write_staged_deployment},
    status::StagedDeployment,
};

const SLOT_SUFFIX: &str = "androidboot.slot_suffix";
const LOCK_FILE: &str = "bootc-aboot.lock";

/// Logical A/B slot observed from the running kernel command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Slot {
    A,
    B,
}

/// Durable staged-deployment state and hashes of the payloads to flash to the boot partitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PendingDeployment {
    pub(crate) depl_id: String,
    pub(crate) finalization_locked: bool,
    boot_image_sha256: String,
    vbmeta_image_sha256: Option<String>,
}

impl PendingDeployment {
    pub(crate) fn staged(&self) -> StagedDeployment {
        StagedDeployment {
            depl_id: self.depl_id.clone(),
            finalization_locked: self.finalization_locked,
        }
    }
}

/// Records an attempted deployment and the system boot id which initiated it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AttemptedDeployment {
    pub(crate) depl_id: String,
    boot_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct QueuedRollback {
    depl_id: String,
    boot_id: String,
}

/// Absolute paths to staged payloads after their hashes have been verified.
pub(crate) struct ArtifactPaths {
    pub(crate) boot: Utf8PathBuf,
    pub(crate) vbmeta: Option<Utf8PathBuf>,
}

fn boot_id() -> Result<String> {
    Ok(std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_string())
}

enum ReconcileAction {
    None,
    RemoveTransient,
    Publish(PendingDeployment),
}

/// An open fd to the persistent Aboot state
pub(crate) struct AbootState<'a> {
    sysroot: &'a Dir,
    state: Option<Dir>,
    slots: Option<Dir>,
}

impl<'a> AbootState<'a> {
    pub(crate) fn open(sysroot: &'a Dir) -> Result<Self> {
        let state = sysroot.open_dir_optional(ABOOT_STATE_DIR)?;
        let slots = match state.as_ref() {
            Some(state) => state.open_dir_optional("slots")?,
            None => None,
        };
        Ok(Self {
            sysroot,
            state,
            slots,
        })
    }

    fn ensure_state(&mut self) -> Result<&Dir> {
        if self.state.is_none() {
            let mut dir = self.sysroot.try_clone()?;
            for component in ABOOT_STATE_DIR.split('/') {
                dir.create_dir_all(component)?;
                fsync(dir.reopen_as_ownedfd()?).context("Syncing aboot state directory")?;
                dir = dir.open_dir(component)?;
            }
            self.state = Some(dir);
        }
        Ok(self.state.as_ref().unwrap())
    }

    fn ensure_slots(&mut self) -> Result<&Dir> {
        if self.slots.is_none() {
            {
                let state = self.ensure_state()?;
                state.create_dir_all("slots")?;
                fsync(state.reopen_as_ownedfd()?).context("Syncing aboot state directory")?;
            }
            self.slots = Some(self.state.as_ref().unwrap().open_dir("slots")?);
        }
        Ok(self.slots.as_ref().unwrap())
    }

    fn read_json<T: for<'de> Deserialize<'de>>(&self, name: &str) -> Result<Option<T>> {
        let Some(state) = self.state.as_ref() else {
            return Ok(None);
        };
        let Some(contents) = state.read_optional(name)? else {
            return Ok(None);
        };
        serde_json::from_slice(&contents)
            .with_context(|| format!("Parsing aboot {name}"))
            .map(Some)
    }

    fn write_json(&mut self, name: &str, value: &impl CanonJsonSerialize) -> Result<()> {
        let state = self.ensure_state()?;
        state.atomic_write(name, value.to_canon_json_vec()?)?;
        fsync(state.reopen_as_ownedfd()?).context("Syncing aboot state")?;
        Ok(())
    }

    fn remove_state_file(&self, name: &str) -> Result<()> {
        let Some(state) = self.state.as_ref() else {
            return Ok(());
        };
        state.remove_file_optional(name)?;
        fsync(state.reopen_as_ownedfd()?).context("Syncing aboot state")?;
        Ok(())
    }

    pub(crate) fn read_pending(&self) -> Result<Option<PendingDeployment>> {
        self.read_json(ABOOT_PENDING_FNAME)
    }

    /// Publish or replace a pending deployment unless one was already attempted.
    pub(crate) fn write_pending(&mut self, pending: &PendingDeployment) -> Result<()> {
        ensure!(
            self.read_attempted()?.is_none(),
            "Cannot replace an attempted aboot deployment"
        );
        self.write_json(ABOOT_PENDING_FNAME, pending)
    }

    pub(crate) fn read_attempted(&self) -> Result<Option<AttemptedDeployment>> {
        self.read_json(ABOOT_ATTEMPTED_FNAME)
    }

    fn read_rollback(&self) -> Result<Option<QueuedRollback>> {
        self.read_json(ABOOT_ROLLBACK_FNAME)
    }

    pub(crate) fn queued_rollback(&self) -> Result<Option<String>> {
        let Some(rollback) = self.read_rollback()? else {
            return Ok(None);
        };
        if rollback.boot_id != boot_id()? {
            return Ok(None);
        }
        Ok(Some(rollback.depl_id))
    }

    pub(crate) fn queue_rollback(&mut self, deployment: &str) -> Result<()> {
        let digest = Sha512HashValue::from_hex(deployment).context("Invalid rollback digest")?;
        ensure!(
            self.slot_deployments()?.contains(&digest),
            "Rollback deployment is not mapped to an aboot slot"
        );
        self.write_json(
            ABOOT_ROLLBACK_FNAME,
            &QueuedRollback {
                depl_id: deployment.to_string(),
                boot_id: boot_id()?,
            },
        )
    }

    pub(crate) fn clear_rollback(&self) -> Result<()> {
        self.remove_state_file(ABOOT_ROLLBACK_FNAME)
    }

    /// Make a download-only pending deployment eligible for finalization.
    pub(crate) fn unlock_pending(&mut self, deployment: &str) -> Result<PendingDeployment> {
        let mut pending = self
            .read_pending()?
            .ok_or_else(|| anyhow::anyhow!("No pending aboot deployment"))?;
        ensure!(
            pending.depl_id == deployment,
            "Pending aboot deployment changed"
        );
        pending.finalization_locked = false;
        self.write_pending(&pending)?;
        Ok(pending)
    }

    /// Store the exact partition payloads before publishing the pending deployment.
    pub(crate) fn stage_artifacts(
        &self,
        deployment: &str,
        finalization_locked: bool,
        boot: &[u8],
        vbmeta: Option<&[u8]>,
    ) -> Result<PendingDeployment> {
        Sha512HashValue::from_hex(deployment).context("Invalid staged deployment digest")?;
        ensure!(
            read_boot_type(self.sysroot, deployment)? == Some(BootType::Aboot),
            "Staged deployment is not aboot"
        );
        let deployment_dir = self
            .sysroot
            .open_dir(format!("{STATE_DIR_RELATIVE}/{deployment}"))
            .context("Opening staged deployment")?;
        deployment_dir.create_dir_all(ABOOT_ARTIFACT_DIR)?;
        fsync(deployment_dir.reopen_as_ownedfd()?).context("Syncing staged deployment")?;
        let artifacts = deployment_dir.open_dir(ABOOT_ARTIFACT_DIR)?;
        artifacts.atomic_write(ABOOT_IMAGE_FNAME, boot)?;
        match vbmeta {
            Some(vbmeta) => artifacts.atomic_write(ABOOT_VBMETA_FNAME, vbmeta)?,
            None => {
                artifacts.remove_file_optional(ABOOT_VBMETA_FNAME)?;
            }
        }
        fsync(artifacts.reopen_as_ownedfd()?).context("Syncing staged aboot artifacts")?;
        Ok(PendingDeployment {
            depl_id: deployment.to_string(),
            finalization_locked,
            boot_image_sha256: hex::encode(openssl::sha::sha256(boot)),
            vbmeta_image_sha256: vbmeta.map(|data| hex::encode(openssl::sha::sha256(data))),
        })
    }

    /// Verify staged payloads and return paths suitable for passing to aboot-deploy.
    pub(crate) fn verify_artifacts(
        &self,
        root_path: &Utf8Path,
        pending: &PendingDeployment,
    ) -> Result<ArtifactPaths> {
        let relative = Utf8PathBuf::from(STATE_DIR_RELATIVE)
            .join(&pending.depl_id)
            .join(ABOOT_ARTIFACT_DIR);
        let artifacts = self.sysroot.open_dir(&relative)?;
        let boot = artifacts.read(ABOOT_IMAGE_FNAME)?;
        ensure!(
            hex::encode(openssl::sha::sha256(&boot)) == pending.boot_image_sha256,
            "Staged aboot image was modified"
        );
        let vbmeta = match pending.vbmeta_image_sha256.as_ref() {
            Some(expected) => {
                let data = artifacts.read(ABOOT_VBMETA_FNAME)?;
                ensure!(
                    hex::encode(openssl::sha::sha256(&data)) == *expected,
                    "Staged vbmeta image was modified"
                );
                Some(root_path.join(&relative).join(ABOOT_VBMETA_FNAME))
            }
            None => None,
        };
        Ok(ArtifactPaths {
            boot: root_path.join(relative).join(ABOOT_IMAGE_FNAME),
            vbmeta,
        })
    }

    fn remove_artifacts(&self, deployment: &str) -> Result<()> {
        let deployment_dir = self
            .sysroot
            .open_dir(format!("{STATE_DIR_RELATIVE}/{deployment}"))
            .context("Opening deployed state")?;
        if deployment_dir
            .open_dir_optional(ABOOT_ARTIFACT_DIR)?
            .is_some()
        {
            deployment_dir
                .remove_dir_all(ABOOT_ARTIFACT_DIR)
                .context("Removing staged aboot artifacts")?;
        }
        fsync(deployment_dir.reopen_as_ownedfd()?).context("Syncing deployed state")?;
        Ok(())
    }

    pub(crate) fn discard_pending(&self) -> Result<()> {
        ensure!(
            self.read_attempted()?.is_none(),
            "An attempted aboot update has not been reconciled"
        );
        if let Some(pending) = self.read_pending()? {
            self.remove_state_file(ABOOT_PENDING_FNAME)?;
            self.remove_artifacts(&pending.depl_id)?;
        }
        remove_staged_deployment()?;
        Ok(())
    }

    /// Mark an update attempted before invalidating a slot or writing partitions.
    pub(crate) fn record_attempt(&mut self, deployment: &str) -> Result<()> {
        ensure!(
            self.read_attempted()?.is_none(),
            "Aboot deployment was already attempted"
        );
        let pending = self
            .read_pending()?
            .ok_or_else(|| anyhow::anyhow!("No pending aboot deployment"))?;
        ensure!(
            pending.depl_id == deployment,
            "Pending aboot deployment changed"
        );
        self.write_json(
            ABOOT_ATTEMPTED_FNAME,
            &AttemptedDeployment {
                depl_id: deployment.to_string(),
                boot_id: boot_id()?,
            },
        )
    }

    fn reconcile_state(&mut self, booted: &str, current_boot_id: &str) -> Result<ReconcileAction> {
        if self
            .read_rollback()?
            .is_some_and(|rollback| rollback.boot_id != current_boot_id)
        {
            self.remove_state_file(ABOOT_ROLLBACK_FNAME)?;
        }
        if let Some(attempted) = self.read_attempted()? {
            if attempted.boot_id == current_boot_id {
                // The still-running system cannot tell us whether the new payload will boot.
                return Ok(ReconcileAction::None);
            }
            if attempted.depl_id == booted {
                // Remove pending first so interruption cannot make a successful write retryable.
                self.remove_state_file(ABOOT_PENDING_FNAME)?;
                self.remove_artifacts(&attempted.depl_id)?;
                self.remove_state_file(ABOOT_ATTEMPTED_FNAME)?;
                return Ok(ReconcileAction::RemoveTransient);
            }
            // Firmware booted another deployment; retain the candidate without retrying it.
            return Ok(ReconcileAction::None);
        }

        let Some(pending) = self.read_pending()? else {
            return Ok(ReconcileAction::RemoveTransient);
        };
        Ok(ReconcileAction::Publish(pending))
    }

    /// Restore the transient staged view and return whether finalization should be armed.
    pub(crate) fn reconcile(&mut self, booted: &str) -> Result<bool> {
        match self.reconcile_state(booted, &boot_id()?)? {
            ReconcileAction::None => Ok(false),
            ReconcileAction::RemoveTransient => {
                remove_staged_deployment()?;
                Ok(false)
            }
            ReconcileAction::Publish(pending) => {
                write_staged_deployment(&pending.staged())?;
                Ok(!pending.finalization_locked)
            }
        }
    }
}

impl Slot {
    pub(crate) fn from_cmdline(cmdline: &Cmdline<'_>) -> Option<Self> {
        let mut suffixes = cmdline
            .iter()
            .filter(|param| param.key() == SLOT_SUFFIX.into());
        let suffix = suffixes.next()?;
        if suffixes.next().is_some() {
            return None;
        }
        match suffix.value()? {
            "_a" => Some(Self::A),
            "_b" => Some(Self::B),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::A => "a",
            Self::B => "b",
        }
    }
}

/// Serialize aboot state mutations and partition deployment for the guard's lifetime.
pub(crate) fn lock(run: &Dir) -> Result<OwnedFd> {
    let fd = openat(
        run,
        LOCK_FILE,
        OFlags::CREATE | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )
    .context("Opening aboot mutation lock")?;
    flock(&fd, FlockOperation::LockExclusive).context("Locking aboot state")?;
    Ok(fd)
}

impl AbootState<'_> {
    pub(crate) fn slot_deployments(&self) -> Result<Vec<Sha512HashValue>> {
        let mut deployments = Vec::new();
        for slot in [Slot::A, Slot::B] {
            let Some(deployment) = self.read_slot(slot)? else {
                continue;
            };
            if !deployments.contains(&deployment) {
                deployments.push(deployment);
            }
        }
        Ok(deployments)
    }

    fn read_slot(&self, slot: Slot) -> Result<Option<Sha512HashValue>> {
        let path = format!("{ABOOT_STATE_DIR}/slots/{}", slot.name());
        let Some(slots) = self.slots.as_ref() else {
            return Ok(None);
        };
        let Some(contents) = slots.read_optional(slot.name())? else {
            return Ok(None);
        };
        let digest = match Sha512HashValue::from_hex(contents.trim_ascii()) {
            Ok(digest) => digest,
            Err(err) => {
                tracing::warn!(%path, %err, "Invalid aboot slot mapping");
                return Ok(None);
            }
        };
        if read_boot_type(self.sysroot, &digest.to_hex())? != Some(BootType::Aboot) {
            tracing::warn!(%path, "Aboot slot mapping has no corresponding aboot deployment");
            return Ok(None);
        }
        Ok(Some(digest))
    }

    /// Record a slot mapping only after that deployment has been observed running.
    pub(crate) fn record_booted(&mut self, cmdline: &Cmdline<'_>, digest: &str) -> Result<()> {
        let digest =
            Sha512HashValue::from_hex(digest).context("Invalid booted deployment digest")?;
        ensure!(
            read_boot_type(self.sysroot, &digest.to_hex())? == Some(BootType::Aboot),
            "Booted deployment is not aboot"
        );
        let Some(slot) = Slot::from_cmdline(cmdline) else {
            tracing::warn!("No unambiguous aboot slot suffix; leaving slot mappings unchanged");
            return Ok(());
        };
        if self.read_slot(slot)?.as_ref() == Some(&digest) {
            return Ok(());
        }

        self.ensure_slots()?
            .atomic_write(slot.name(), format!("{}\n", digest.to_hex()))
            .context("Recording booted aboot slot")?;
        Ok(())
    }

    /// Invalidate only the non-booted slot mapping before deployment.
    pub(crate) fn invalidate_other(&self, booted_slot: Slot) -> Result<()> {
        let other = match booted_slot {
            Slot::A => Slot::B,
            Slot::B => Slot::A,
        };
        let Some(slots) = self.slots.as_ref() else {
            return Ok(());
        };
        slots.remove_file_optional(other.name())?;
        fsync(slots.reopen_as_ownedfd()?).context("Syncing invalidated aboot slot")?;
        Ok(())
    }

    pub(crate) fn delete_deployment(&self, deployment: &str) -> Result<()> {
        let digest = Sha512HashValue::from_hex(deployment).context("Invalid deployment digest")?;
        let current_boot_id = boot_id()?;

        if let Some(rollback) = self.read_rollback()? {
            if rollback.boot_id == current_boot_id {
                ensure!(
                    rollback.depl_id != deployment,
                    "Cannot delete a queued aboot rollback deployment"
                );
            } else {
                self.clear_rollback()?;
            }
        }

        if let Some(attempted) = self
            .read_attempted()?
            .filter(|attempted| attempted.depl_id == deployment)
        {
            ensure!(
                attempted.boot_id != current_boot_id,
                "Cannot delete an aboot deployment attempted during this boot"
            );
            if self
                .read_pending()?
                .is_some_and(|pending| pending.depl_id == deployment)
            {
                self.remove_state_file(ABOOT_PENDING_FNAME)?;
                remove_staged_deployment()?;
                self.remove_artifacts(deployment)?;
            }
            self.remove_state_file(ABOOT_ATTEMPTED_FNAME)?;
        } else if self
            .read_pending()?
            .is_some_and(|pending| pending.depl_id == deployment)
        {
            self.remove_state_file(ABOOT_PENDING_FNAME)?;
            remove_staged_deployment()?;
            self.remove_artifacts(deployment)?;
        }

        let mut removed = false;
        for slot in [Slot::A, Slot::B] {
            if self.read_slot(slot)?.as_ref() == Some(&digest) {
                self.slots.as_ref().unwrap().remove_file(slot.name())?;
                removed = true;
            }
        }
        if removed {
            fsync(self.slots.as_ref().unwrap().reopen_as_ownedfd()?)
                .context("Syncing aboot slot mappings")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::composefs_consts::STATE_DIR_RELATIVE;
    use cap_std_ext::{cap_std::ambient_authority, cap_tempfile::tempdir};

    fn deployment(root: &Dir, digest: &str, boot_type: &str) -> Result<()> {
        let path = format!("{STATE_DIR_RELATIVE}/{digest}");
        root.create_dir_all(&path)?;
        root.atomic_write(
            format!("{path}/{digest}.origin"),
            format!("[boot]\nboot_type={boot_type}\n"),
        )?;
        Ok(())
    }

    #[test]
    fn slot_suffix() {
        for (cmdline, expected) in [
            ("androidboot.slot_suffix=_a", Some(Slot::A)),
            ("quiet androidboot.slot_suffix=_b rw", Some(Slot::B)),
            ("", None),
            ("androidboot.slot_suffix", None),
            ("androidboot.slot_suffix=", None),
            ("androidboot.slot_suffix=a", None),
            ("androidboot.slot_suffix=_c", None),
            (
                "androidboot.slot_suffix=_a androidboot.slot_suffix=_b",
                None,
            ),
            (
                "androidboot.slot_suffix=_a androidboot.slot_suffix=_a",
                None,
            ),
        ] {
            assert_eq!(
                Slot::from_cmdline(&Cmdline::from(cmdline)),
                expected,
                "{cmdline}"
            );
        }
    }

    #[test]
    fn slot_lifecycle() -> Result<()> {
        let root = tempdir(ambient_authority())?;
        let a = "aa".repeat(64);
        let b = "bb".repeat(64);
        deployment(&root, &a, "aboot")?;
        deployment(&root, &b, "aboot")?;
        let cmdline_a = Cmdline::from("androidboot.slot_suffix=_a");
        let cmdline_b = Cmdline::from("androidboot.slot_suffix=_b");
        let mut state = AbootState::open(&root)?;

        assert_eq!(state.read_slot(Slot::A)?, None);
        state.invalidate_other(Slot::A)?;
        state.record_booted(&cmdline_a, &a)?;
        state.record_booted(&cmdline_a, &a)?;
        assert_eq!(state.read_slot(Slot::B)?, None);
        state.record_booted(&cmdline_b, &b)?;
        assert_eq!(
            state.read_slot(Slot::A)?,
            Some(Sha512HashValue::from_hex(&a)?)
        );
        assert_eq!(
            state.read_slot(Slot::B)?,
            Some(Sha512HashValue::from_hex(&b)?)
        );

        for slot in [Slot::A, Slot::B] {
            state.record_booted(&cmdline_a, &a)?;
            state.record_booted(&cmdline_b, &b)?;
            state.invalidate_other(slot)?;
            state.invalidate_other(slot)?;
            assert!(state.read_slot(slot)?.is_some());
            let other = if slot == Slot::A { Slot::B } else { Slot::A };
            assert_eq!(state.read_slot(other)?, None);
            assert!(!root.try_exists(format!("{ABOOT_STATE_DIR}/slots/{}", other.name()))?);
        }

        state.record_booted(&cmdline_a, &a)?;
        state.record_booted(&Cmdline::from(""), &b)?;
        assert_eq!(
            state.read_slot(Slot::A)?,
            Some(Sha512HashValue::from_hex(&a)?)
        );
        state.record_booted(&cmdline_a, &b)?;
        assert_eq!(
            state.read_slot(Slot::A)?,
            Some(Sha512HashValue::from_hex(&b)?)
        );
        Ok(())
    }

    #[test]
    fn invalid_mappings() -> Result<()> {
        let root = tempdir(ambient_authority())?;
        let slots = format!("{ABOOT_STATE_DIR}/slots");
        root.create_dir_all(&slots)?;
        let mut state = AbootState::open(&root)?;
        for contents in [String::new(), "invalid".into(), "aa".repeat(64)] {
            root.atomic_write(format!("{slots}/a"), contents)?;
            assert_eq!(state.read_slot(Slot::A)?, None);
        }
        root.atomic_write(format!("{slots}/a"), [0xff; 128])?;
        assert_eq!(state.read_slot(Slot::A)?, None);
        let digest = "aa".repeat(64);
        root.atomic_write(format!("{slots}/a"), &digest)?;
        deployment(&root, &digest, "uki")?;
        assert_eq!(state.read_slot(Slot::A)?, None);
        assert!(
            state
                .record_booted(&Cmdline::from("androidboot.slot_suffix=_a"), &digest)
                .is_err()
        );
        assert!(
            state
                .record_booted(&Cmdline::from(""), "../invalid")
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn deployments_deduplicates_slots() -> Result<()> {
        let root = tempdir(ambient_authority())?;
        let digest = "aa".repeat(64);
        deployment(&root, &digest, "aboot")?;
        let mut state = AbootState::open(&root)?;
        state.record_booted(&Cmdline::from("androidboot.slot_suffix=_a"), &digest)?;
        state.record_booted(&Cmdline::from("androidboot.slot_suffix=_b"), &digest)?;
        assert_eq!(
            state.slot_deployments()?,
            vec![Sha512HashValue::from_hex(digest)?]
        );
        Ok(())
    }

    #[test]
    fn pending_artifacts_and_attempt() -> Result<()> {
        let root = tempdir(ambient_authority())?;
        let digest = "aa".repeat(64);
        deployment(&root, &digest, "aboot")?;
        let mut state = AbootState::open(&root)?;
        let pending = state.stage_artifacts(&digest, true, b"boot", Some(b"vbmeta"))?;
        state.write_pending(&pending)?;
        assert_eq!(state.read_pending()?, Some(pending.clone()));

        let paths = state.verify_artifacts(Utf8Path::new("/sysroot"), &pending)?;
        assert_eq!(
            paths.boot,
            Utf8PathBuf::from(format!(
                "/sysroot/{STATE_DIR_RELATIVE}/{digest}/{ABOOT_ARTIFACT_DIR}/{ABOOT_IMAGE_FNAME}"
            ))
        );
        assert!(paths.vbmeta.is_some());

        let pending = state.unlock_pending(&digest)?;
        assert!(!pending.finalization_locked);
        state.record_attempt(&digest)?;
        assert_eq!(state.read_attempted()?.unwrap().depl_id, digest);
        assert!(state.write_pending(&pending).is_err());

        let artifacts = root.open_dir(format!(
            "{STATE_DIR_RELATIVE}/{digest}/{ABOOT_ARTIFACT_DIR}"
        ))?;
        artifacts.atomic_write(ABOOT_IMAGE_FNAME, b"modified")?;
        assert!(
            state
                .verify_artifacts(Utf8Path::new("/sysroot"), &pending)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn reconcile_attempt() -> Result<()> {
        let root = tempdir(ambient_authority())?;
        let digest = "aa".repeat(64);
        let artifact_dir = format!("{STATE_DIR_RELATIVE}/{digest}/{ABOOT_ARTIFACT_DIR}");
        deployment(&root, &digest, "aboot")?;
        let mut state = AbootState::open(&root)?;
        let pending = state.stage_artifacts(&digest, false, b"boot", None)?;
        state.write_pending(&pending)?;
        assert!(root.try_exists(&artifact_dir)?);
        assert!(matches!(
            state.reconcile_state("booted", "new-boot")?,
            ReconcileAction::Publish(_)
        ));

        state.write_json(
            ABOOT_ATTEMPTED_FNAME,
            &AttemptedDeployment {
                depl_id: digest.clone(),
                boot_id: "old-boot".into(),
            },
        )?;
        assert!(matches!(
            state.reconcile_state("booted", "old-boot")?,
            ReconcileAction::None
        ));
        assert!(matches!(
            state.reconcile_state("booted", "new-boot")?,
            ReconcileAction::None
        ));
        assert!(state.read_pending()?.is_some());
        assert!(root.try_exists(&artifact_dir)?);
        assert!(matches!(
            state.reconcile_state(&digest, "new-boot")?,
            ReconcileAction::RemoveTransient
        ));
        assert!(state.read_pending()?.is_none());
        assert!(state.read_attempted()?.is_none());
        assert!(!root.try_exists(&artifact_dir)?);
        Ok(())
    }

    #[test]
    fn rollback_and_deletion() -> Result<()> {
        let root = tempdir(ambient_authority())?;
        let a = "aa".repeat(64);
        let b = "bb".repeat(64);
        let staged = "cc".repeat(64);
        for digest in [&a, &b, &staged] {
            deployment(&root, digest, "aboot")?;
        }
        let mut state = AbootState::open(&root)?;
        state.record_booted(&Cmdline::from("androidboot.slot_suffix=_a"), &a)?;
        state.record_booted(&Cmdline::from("androidboot.slot_suffix=_b"), &b)?;

        state.queue_rollback(&b)?;
        assert_eq!(state.queued_rollback()?.as_deref(), Some(b.as_str()));
        assert!(state.delete_deployment(&b).is_err());
        state.clear_rollback()?;

        let pending = state.stage_artifacts(&staged, false, b"boot", None)?;
        state.write_pending(&pending)?;
        state.delete_deployment(&staged)?;
        assert!(state.read_pending()?.is_none());
        assert!(!root.try_exists(format!(
            "{STATE_DIR_RELATIVE}/{staged}/{ABOOT_ARTIFACT_DIR}"
        ))?);

        state.delete_deployment(&b)?;
        assert_eq!(state.read_slot(Slot::B)?, None);
        assert_eq!(
            state.read_slot(Slot::A)?,
            Some(Sha512HashValue::from_hex(&a)?)
        );

        let pending = state.stage_artifacts(&staged, false, b"boot", None)?;
        state.write_pending(&pending)?;
        state.write_json(
            ABOOT_ATTEMPTED_FNAME,
            &AttemptedDeployment {
                depl_id: staged.clone(),
                boot_id: boot_id()?,
            },
        )?;
        assert!(state.delete_deployment(&staged).is_err());
        state.write_json(
            ABOOT_ATTEMPTED_FNAME,
            &AttemptedDeployment {
                depl_id: staged.clone(),
                boot_id: "previous-boot".into(),
            },
        )?;
        state.delete_deployment(&staged)?;
        assert!(state.read_pending()?.is_none());
        assert!(state.read_attempted()?.is_none());
        Ok(())
    }

    #[test]
    fn rollback_marker_expires_after_boot() -> Result<()> {
        let root = tempdir(ambient_authority())?;
        let a = "aa".repeat(64);
        let b = "bb".repeat(64);
        deployment(&root, &a, "aboot")?;
        deployment(&root, &b, "aboot")?;
        let mut state = AbootState::open(&root)?;
        state.record_booted(&Cmdline::from("androidboot.slot_suffix=_a"), &a)?;
        state.record_booted(&Cmdline::from("androidboot.slot_suffix=_b"), &b)?;
        state.queue_rollback(&b)?;

        let current_boot_id = boot_id()?;
        assert!(matches!(
            state.reconcile_state(&a, &current_boot_id)?,
            ReconcileAction::RemoveTransient
        ));
        assert_eq!(state.queued_rollback()?.as_deref(), Some(b.as_str()));
        assert!(matches!(
            state.reconcile_state(&b, "next-boot")?,
            ReconcileAction::RemoveTransient
        ));
        assert!(state.read_rollback()?.is_none());
        Ok(())
    }

    #[test]
    fn mutation_lock() -> Result<()> {
        let run = tempdir(ambient_authority())?;
        let guard = lock(&run)?;
        let other = run.open(LOCK_FILE)?;
        assert_eq!(
            flock(&other, FlockOperation::NonBlockingLockExclusive),
            Err(rustix::io::Errno::WOULDBLOCK)
        );
        drop(guard);
        flock(&other, FlockOperation::NonBlockingLockExclusive)?;
        Ok(())
    }
}
