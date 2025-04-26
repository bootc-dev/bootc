//! The definition for host system state.

use std::fmt::Display;

use ostree_ext::oci_spec::image::Digest;
use ostree_ext::{container::OstreeImageReference, ostree::DeploymentUnlockedState};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{k8sapitypes, status::Slot};

const API_VERSION: &str = "org.containers.bootc/v1";
const KIND: &str = "BootcHost";
/// The default object name we use; there's only one.
pub(crate) const OBJECT_NAME: &str = "host";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
/// The core host definition
pub struct Host {
    /// Metadata
    #[serde(flatten)]
    pub resource: k8sapitypes::Resource,
    /// The spec
    #[serde(default)]
    pub spec: HostSpec,
    /// The status
    #[serde(default)]
    pub status: HostStatus,
}

/// Configuration for system boot ordering.

#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum BootOrder {
    /// The staged or booted deployment will be booted next
    #[default]
    Default,
    /// The rollback deployment will be booted next
    Rollback,
}

#[derive(
    clap::ValueEnum, Serialize, Deserialize, Copy, Clone, Debug, PartialEq, Eq, JsonSchema, Default,
)]
#[serde(rename_all = "camelCase")]
/// The container storage backend
pub enum Store {
    /// Use the ostree-container storage backend.
    #[default]
    #[value(alias = "ostreecontainer")] // default is kebab-case
    OstreeContainer,
}

#[derive(
    clap::ValueEnum, Serialize, Deserialize, Copy, Clone, Debug, PartialEq, Eq, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
/// The filesystem overlay type
pub enum FilesystemOverlay {
    /// Readonly overlay mode
    Readonly,
    /// Read-write overlay mode
    ReadWrite,
}

impl FilesystemOverlay {
    /// Convert from the ostree deployment state
    pub fn from_ostree_deployment_state(state: &DeploymentUnlockedState) -> Option<Self> {
        match state {
            DeploymentUnlockedState::None => Some(Self::Readonly),
            DeploymentUnlockedState::Development
            | DeploymentUnlockedState::Transient
            | DeploymentUnlockedState::Hotfix => Some(Self::ReadWrite),
            // Default to readonly when unknown since it is the default
            // for bootc deployments.
            _ => Some(Self::Readonly),
        }
    }

    /// Convert the FilesystemOverlay value to a human-readable string
    pub fn to_human_string(&self) -> String {
        match self {
            Self::Readonly => "read-only".to_string(),
            Self::ReadWrite => "read-write".to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
/// The host specification
pub struct HostSpec {
    /// The host image
    pub image: Option<ImageReference>,
    /// If set, and there is a rollback deployment, it will be set for the next boot.
    #[serde(default)]
    pub boot_order: BootOrder,
    /// Matches the `ostree admin unlock` state
    #[serde(default)]
    pub usr_overlay: Option<FilesystemOverlay>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
/// An image signature
#[serde(rename_all = "camelCase")]
pub enum ImageSignature {
    /// Fetches will use the named ostree remote for signature verification of the ostree commit.
    OstreeRemote(String),
    /// Fetches will defer to the `containers-policy.json`, but we make a best effort to reject `default: insecureAcceptAnything` policy.
    ContainerPolicy,
    /// No signature verification will be performed
    Insecure,
}

/// A container image reference with attached transport and signature verification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ImageReference {
    /// The container image reference
    pub image: String,
    /// The container image transport
    pub transport: String,
    /// Signature verification type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<ImageSignature>,
}

/// The status of the booted image
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ImageStatus {
    /// The currently booted image
    pub image: ImageReference,
    /// The version string, if any
    pub version: Option<String>,
    /// The build timestamp, if any
    pub timestamp: Option<chrono::DateTime<chrono::Utc>>,
    /// The digest of the fetched image (e.g. sha256:a0...);
    pub image_digest: String,
    /// The hardware architecture of this image
    pub architecture: String,
}

/// A bootable entry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BootEntryOstree {
    /// The ostree commit checksum
    pub checksum: String,
    /// The deployment serial
    pub deploy_serial: u32,
}

/// A bootable entry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BootEntry {
    /// The image reference
    pub image: Option<ImageStatus>,
    /// The last fetched cached update metadata
    pub cached_update: Option<ImageStatus>,
    /// Whether this boot entry is not compatible (has origin changes bootc does not understand)
    pub incompatible: bool,
    /// Whether this entry will be subject to garbage collection
    pub pinned: bool,
    /// The container storage backend
    #[serde(default)]
    pub store: Option<Store>,
    /// If this boot entry is ostree based, the corresponding state
    pub ostree: Option<BootEntryOstree>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
/// The detected type of running system.  Note that this is not exhaustive
/// and new variants may be added in the future.
pub enum HostType {
    /// The current system is deployed in a bootc compatible way.
    BootcHost,
}

/// The status of the host system
#[derive(Debug, Clone, Serialize, Default, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HostStatus {
    /// The staged image for the next boot
    pub staged: Option<BootEntry>,
    /// The booted image; this will be unset if the host is not bootc compatible.
    pub booted: Option<BootEntry>,
    /// The previously booted image
    pub rollback: Option<BootEntry>,
    /// Set to true if the rollback entry is queued for the next boot.
    #[serde(default)]
    pub rollback_queued: bool,
    /// Matches the `ostree admin unlock` state
    #[serde(default)]
    pub usr_overlay: Option<FilesystemOverlay>,

    /// The detected type of system
    #[serde(rename = "type")]
    pub ty: Option<HostType>,
}

impl Host {
    /// Create a new host
    pub fn new(spec: HostSpec) -> Self {
        let metadata = k8sapitypes::ObjectMeta {
            name: Some(OBJECT_NAME.to_owned()),
            ..Default::default()
        };
        Self {
            resource: k8sapitypes::Resource {
                api_version: API_VERSION.to_owned(),
                kind: KIND.to_owned(),
                metadata,
            },
            spec,
            status: Default::default(),
        }
    }

    /// Filter out the requested slot
    pub fn filter_to_slot(&mut self, slot: Slot) {
        match slot {
            Slot::Staged => {
                self.status.booted = None;
                self.status.rollback = None;
            }
            Slot::Booted => {
                self.status.staged = None;
                self.status.rollback = None;
            }
            Slot::Rollback => {
                self.status.staged = None;
                self.status.booted = None;
            }
        }
    }
}

impl Default for Host {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

impl HostSpec {
    /// Validate a spec state transition; some changes cannot be made simultaneously,
    /// such as fetching a new image and doing a rollback.
    pub(crate) fn verify_transition(&self, new: &Self) -> anyhow::Result<()> {
        let rollback = self.boot_order != new.boot_order;
        let image_change = self.image != new.image;
        if rollback && image_change {
            anyhow::bail!("Invalid state transition: rollback and image change");
        }
        Ok(())
    }
}

impl BootOrder {
    pub(crate) fn swap(&self) -> Self {
        match self {
            BootOrder::Default => BootOrder::Rollback,
            BootOrder::Rollback => BootOrder::Default,
        }
    }
}

impl Display for ImageReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // For the default of fetching from a remote registry, just output the image name
        if f.alternate() && self.signature.is_none() && self.transport == "registry" {
            self.image.fmt(f)
        } else {
            let ostree_imgref = OstreeImageReference::from(self.clone());
            ostree_imgref.fmt(f)
        }
    }
}

impl ImageStatus {
    pub(crate) fn digest(&self) -> anyhow::Result<Digest> {
        use std::str::FromStr;
        Ok(Digest::from_str(&self.image_digest)?)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_parse_spec_v1_null() {
        const SPEC_FIXTURE: &str = include_str!("fixtures/spec-v1-null.json");
        let host: Host = serde_json::from_str(SPEC_FIXTURE).unwrap();
        assert_eq!(host.resource.api_version, "org.containers.bootc/v1");
    }

    #[test]
    fn test_parse_spec_v1a1_orig() {
        const SPEC_FIXTURE: &str = include_str!("fixtures/spec-v1a1-orig.yaml");
        let host: Host = serde_yaml::from_str(SPEC_FIXTURE).unwrap();
        assert_eq!(
            host.spec.image.as_ref().unwrap().image.as_str(),
            "quay.io/example/someimage:latest"
        );
    }

    #[test]
    fn test_parse_spec_v1a1() {
        const SPEC_FIXTURE: &str = include_str!("fixtures/spec-v1a1.yaml");
        let host: Host = serde_yaml::from_str(SPEC_FIXTURE).unwrap();
        assert_eq!(
            host.spec.image.as_ref().unwrap().image.as_str(),
            "quay.io/otherexample/otherimage:latest"
        );
        assert_eq!(host.spec.image.as_ref().unwrap().signature, None);
    }

    #[test]
    fn test_parse_ostreeremote() {
        const SPEC_FIXTURE: &str = include_str!("fixtures/spec-ostree-remote.yaml");
        let host: Host = serde_yaml::from_str(SPEC_FIXTURE).unwrap();
        assert_eq!(
            host.spec.image.as_ref().unwrap().signature,
            Some(ImageSignature::OstreeRemote("fedora".into()))
        );
    }

    #[test]
    fn test_display_imgref() {
        let src = "ostree-unverified-registry:quay.io/example/foo:sometag";
        let s = OstreeImageReference::from_str(src).unwrap();
        let s = ImageReference::from(s);
        let displayed = format!("{s}");
        assert_eq!(displayed.as_str(), src);
        // Alternative display should be short form
        assert_eq!(format!("{s:#}"), "quay.io/example/foo:sometag");

        let src = "ostree-remote-image:fedora:docker://quay.io/example/foo:sometag";
        let s = OstreeImageReference::from_str(src).unwrap();
        let s = ImageReference::from(s);
        let displayed = format!("{s}");
        assert_eq!(displayed.as_str(), src);
        assert_eq!(format!("{s:#}"), src);
    }

    #[test]
    fn test_store_from_str() {
        use clap::ValueEnum;

        // should be case-insensitive, kebab-case optional
        assert!(Store::from_str("Ostree-Container", true).is_ok());
        assert!(Store::from_str("OstrEeContAiner", true).is_ok());
        assert!(Store::from_str("invalid", true).is_err());
    }

    #[test]
    fn test_host_filter_to_slot() {
        fn create_host() -> Host {
            let mut host = Host::default();
            host.status.staged = Some(default_boot_entry());
            host.status.booted = Some(default_boot_entry());
            host.status.rollback = Some(default_boot_entry());
            host
        }

        fn default_boot_entry() -> BootEntry {
            BootEntry {
                image: None,
                cached_update: None,
                incompatible: false,
                pinned: false,
                store: None,
                ostree: None,
            }
        }

        fn assert_host_state(
            host: &Host,
            staged: Option<BootEntry>,
            booted: Option<BootEntry>,
            rollback: Option<BootEntry>,
        ) {
            assert_eq!(host.status.staged, staged);
            assert_eq!(host.status.booted, booted);
            assert_eq!(host.status.rollback, rollback);
        }

        let mut host = create_host();
        host.filter_to_slot(Slot::Staged);
        assert_host_state(&host, Some(default_boot_entry()), None, None);

        let mut host = create_host();
        host.filter_to_slot(Slot::Booted);
        assert_host_state(&host, None, Some(default_boot_entry()), None);

        let mut host = create_host();
        host.filter_to_slot(Slot::Rollback);
        assert_host_state(&host, None, None, Some(default_boot_entry()));
    }
}
