//! The definition for host system state.

use std::fmt::Display;

use std::str::FromStr;

use anyhow::Result;
use ostree_ext::container::Transport;
use ostree_ext::oci_spec::distribution::Reference;
use ostree_ext::oci_spec::image::Digest;
use ostree_ext::{container::OstreeImageReference, oci_spec};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::bootc_composefs::boot::BootType;
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

#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
/// The host specification
pub struct HostSpec {
    /// The host image
    pub image: Option<ImageReference>,
    /// If set, and there is a rollback deployment, it will be set for the next boot.
    #[serde(default)]
    pub boot_order: BootOrder,
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

/// If the reference is in :tag@digest form, strip the tag.
fn canonicalize_reference(reference: Reference) -> Option<Reference> {
    // No tag? Just pass through.
    reference.tag()?;

    // No digest? Also pass through.
    let digest = reference.digest()?;
    // Otherwise, replace with the digest
    Some(reference.clone_with_digest(digest.to_owned()))
}

impl ImageReference {
    /// Returns a canonicalized version of this image reference, preferring the digest over the tag if both are present.
    pub fn canonicalize(self) -> Result<Self> {
        // TODO maintain a proper transport enum in the spec here
        let transport = Transport::try_from(self.transport.as_str())?;
        match transport {
            Transport::Registry => {
                let reference: oci_spec::distribution::Reference = self.image.parse()?;

                // Check if the image reference needs canonicicalization
                let Some(reference) = canonicalize_reference(reference) else {
                    return Ok(self);
                };

                let r = ImageReference {
                    image: reference.to_string(),
                    transport: self.transport.clone(),
                    signature: self.signature.clone(),
                };
                Ok(r)
            }
            _ => {
                // For other transports, we don't do any canonicalization
                Ok(self)
            }
        }
    }

    /// Parse the transport string into a Transport enum.
    pub fn transport(&self) -> Result<Transport> {
        Transport::try_from(self.transport.as_str())
            .map_err(|e| anyhow::anyhow!("Invalid transport '{}': {}", self.transport, e))
    }

    /// Convert to a container reference string suitable for use with container storage APIs.
    /// For registry transport, returns just the image name. For other transports, prepends the transport.
    pub fn to_transport_image(&self) -> Result<String> {
        if self.transport()? == Transport::Registry {
            // For registry transport, the image name is already in the right format
            Ok(self.image.clone())
        } else {
            // For other transports (containers-storage, oci, etc.), prepend the transport
            Ok(format!("{}:{}", self.transport, self.image))
        }
    }
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
    /// The name of the storage for /etc and /var content
    pub stateroot: String,
    /// The ostree commit checksum
    pub checksum: String,
    /// The deployment serial
    pub deploy_serial: u32,
}

/// Bootloader type to determine whether system was booted via Grub or Systemd
#[derive(
    clap::ValueEnum, Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema,
)]
pub enum Bootloader {
    /// Use Grub as the bootloader
    #[default]
    Grub,
    /// Use SystemdBoot as the bootloader
    Systemd,
    /// Don't use a bootloader managed by bootc
    None,
}

impl Display for Bootloader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let string = match self {
            Bootloader::Grub => "grub",
            Bootloader::Systemd => "systemd",
            Bootloader::None => "none",
        };

        write!(f, "{}", string)
    }
}

impl FromStr for Bootloader {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "grub" => Ok(Self::Grub),
            "systemd" => Ok(Self::Systemd),
            "none" => Ok(Self::None),
            unrecognized => Err(anyhow::anyhow!("Unrecognized bootloader: '{unrecognized}'")),
        }
    }
}

/// A bootable entry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BootEntryComposefs {
    /// The erofs verity
    pub verity: String,
    /// Whether this deployment is to be booted via Type1 (vmlinuz + initrd) or Type2 (UKI) entry
    pub boot_type: BootType,
    /// Whether we boot using systemd or grub
    pub bootloader: Bootloader,
    /// The sha256sum of vmlinuz + initrd
    /// Only `Some` for Type1 boot entries
    pub boot_digest: Option<String>,
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
    /// This is true if (relative to the booted system) this is a possible target for a soft reboot
    #[serde(default)]
    pub soft_reboot_capable: bool,
    /// Whether this deployment is in download-only mode (prevented from automatic finalization on shutdown).
    /// This is set via --download-only on the CLI.
    #[serde(default)]
    pub download_only: bool,
    /// The container storage backend
    #[serde(default)]
    pub store: Option<Store>,
    /// If this boot entry is ostree based, the corresponding state
    pub ostree: Option<BootEntryOstree>,
    /// If this boot entry is composefs based, the corresponding state
    pub composefs: Option<BootEntryComposefs>,
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
    /// Other deployments (i.e. pinned)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub other_deployments: Vec<BootEntry>,
    /// Set to true if the rollback entry is queued for the next boot.
    #[serde(default)]
    pub rollback_queued: bool,

    /// The detected type of system
    #[serde(rename = "type")]
    pub ty: Option<HostType>,
}

pub(crate) struct DeploymentEntry<'a> {
    pub(crate) ty: Option<Slot>,
    pub(crate) deployment: &'a BootEntryComposefs,
    pub(crate) pinned: bool,
    pub(crate) soft_reboot_capable: bool,
}

/// The result of a `bootc container inspect` command.
#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct ContainerInspect {
    /// Kernel arguments embedded in the container image.
    pub(crate) kargs: Vec<String>,
    /// Information about the kernel in the container image.
    pub(crate) kernel: Option<crate::kernel::Kernel>,
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

    pub(crate) fn require_composefs_booted(&self) -> anyhow::Result<&BootEntryComposefs> {
        let cfs = self
            .status
            .booted
            .as_ref()
            .ok_or(anyhow::anyhow!("Could not find booted deployment"))?
            .require_composefs()?;

        Ok(cfs)
    }

    /// Returns all composefs deployments in a list
    #[fn_error_context::context("Getting all composefs deployments")]
    pub(crate) fn all_composefs_deployments<'a>(&'a self) -> Result<Vec<DeploymentEntry<'a>>> {
        let mut all_deps = vec![];

        let booted = self.require_composefs_booted()?;
        all_deps.push(DeploymentEntry {
            ty: Some(Slot::Booted),
            deployment: booted,
            pinned: false,
            soft_reboot_capable: false,
        });

        if let Some(staged) = &self.status.staged {
            all_deps.push(DeploymentEntry {
                ty: Some(Slot::Staged),
                deployment: staged.require_composefs()?,
                pinned: false,
                soft_reboot_capable: staged.soft_reboot_capable,
            });
        }

        if let Some(rollback) = &self.status.rollback {
            all_deps.push(DeploymentEntry {
                ty: Some(Slot::Rollback),
                deployment: rollback.require_composefs()?,
                pinned: false,
                soft_reboot_capable: rollback.soft_reboot_capable,
            });
        }

        for pinned in &self.status.other_deployments {
            all_deps.push(DeploymentEntry {
                ty: None,
                deployment: pinned.require_composefs()?,
                pinned: true,
                soft_reboot_capable: pinned.soft_reboot_capable,
            });
        }

        Ok(all_deps)
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
    fn test_canonicalize_reference() {
        // expand this
        let passthrough = [
            ("quay.io/example/someimage:latest"),
            ("quay.io/example/someimage"),
            ("quay.io/example/someimage@sha256:5db6d8b5f34d3cbdaa1e82ed0152a5ac980076d19317d4269db149cbde057bb2"),
        ];
        let mapped = [
            (
                "quay.io/example/someimage:latest@sha256:5db6d8b5f34d3cbdaa1e82ed0152a5ac980076d19317d4269db149cbde057bb2",
                "quay.io/example/someimage@sha256:5db6d8b5f34d3cbdaa1e82ed0152a5ac980076d19317d4269db149cbde057bb2",
            ),
            (
                "localhost/someimage:latest@sha256:5db6d8b5f34d3cbdaa1e82ed0152a5ac980076d19317d4269db149cbde057bb2",
                "localhost/someimage@sha256:5db6d8b5f34d3cbdaa1e82ed0152a5ac980076d19317d4269db149cbde057bb2",
            ),
        ];
        for &v in passthrough.iter() {
            let reference = Reference::from_str(v).unwrap();
            assert!(reference.tag().is_none() || reference.digest().is_none());
            assert!(canonicalize_reference(reference).is_none());
        }
        for &(initial, expected) in mapped.iter() {
            let reference = Reference::from_str(initial).unwrap();
            assert!(reference.tag().is_some());
            assert!(reference.digest().is_some());
            let canonicalized = canonicalize_reference(reference).unwrap();
            assert_eq!(canonicalized.to_string(), expected);
        }
    }

    #[test]
    fn test_image_reference_canonicalize() {
        let sample_digest =
            "sha256:5db6d8b5f34d3cbdaa1e82ed0152a5ac980076d19317d4269db149cbde057bb2";

        let test_cases = [
            // When both a tag and digest are present, the digest should be used
            (
                format!("quay.io/example/someimage:latest@{sample_digest}"),
                format!("quay.io/example/someimage@{sample_digest}"),
                "registry",
            ),
            // When only a digest is present, it should be used
            (
                format!("quay.io/example/someimage@{sample_digest}"),
                format!("quay.io/example/someimage@{sample_digest}"),
                "registry",
            ),
            // When only a tag is present, it should be preserved
            (
                "quay.io/example/someimage:latest".to_string(),
                "quay.io/example/someimage:latest".to_string(),
                "registry",
            ),
            // When no tag or digest is present, preserve the original image name
            (
                "quay.io/example/someimage".to_string(),
                "quay.io/example/someimage".to_string(),
                "registry",
            ),
            // When used with a local image (i.e. from containers-storage), the functionality should
            // be the same as previous cases
            (
                "localhost/someimage:latest".to_string(),
                "localhost/someimage:latest".to_string(),
                "registry",
            ),
            (
                format!("localhost/someimage:latest@{sample_digest}"),
                format!("localhost/someimage@{sample_digest}"),
                "registry",
            ),
            // Other cases are not canonicalized
            (
                format!("quay.io/example/someimage:latest@{sample_digest}"),
                format!("quay.io/example/someimage:latest@{sample_digest}"),
                "containers-storage",
            ),
            (
                "/path/to/dir:latest".to_string(),
                "/path/to/dir:latest".to_string(),
                "oci",
            ),
            (
                "/tmp/repo".to_string(),
                "/tmp/repo".to_string(),
                "oci-archive",
            ),
            (
                "/tmp/image-dir".to_string(),
                "/tmp/image-dir".to_string(),
                "dir",
            ),
        ];

        for (initial, expected, transport) in test_cases {
            let imgref = ImageReference {
                image: initial.to_string(),
                transport: transport.to_string(),
                signature: None,
            };

            let canonicalized = imgref.canonicalize();
            if let Err(e) = canonicalized {
                panic!("Failed to canonicalize {initial} with transport {transport}: {e}");
            }
            let canonicalized = canonicalized.unwrap();
            assert_eq!(
                canonicalized.image, expected,
                "Mismatch for transport {transport}"
            );
            assert_eq!(canonicalized.transport, transport);
            assert_eq!(canonicalized.signature, None);
        }
    }

    #[test]
    fn test_unimplemented_oci_tagged_digested() {
        let imgref = ImageReference {
            image: "path/to/image:sometag@sha256:5db6d8b5f34d3cbdaa1e82ed0152a5ac980076d19317d4269db149cbde057bb2".to_string(),
            transport: "oci".to_string(),
            signature: None
        };
        let canonicalized = imgref.clone().canonicalize().unwrap();
        // TODO For now this is known to incorrectly pass
        assert_eq!(imgref, canonicalized);
    }

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
                soft_reboot_capable: false,
                pinned: false,
                download_only: false,
                store: None,
                ostree: None,
                composefs: None,
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

    #[test]
    fn test_to_transport_image() {
        // Test registry transport (should return only the image name)
        let registry_ref = ImageReference {
            transport: "registry".to_string(),
            image: "quay.io/example/foo:latest".to_string(),
            signature: None,
        };
        assert_eq!(
            registry_ref.to_transport_image().unwrap(),
            "quay.io/example/foo:latest"
        );

        // Test containers-storage transport
        let storage_ref = ImageReference {
            transport: "containers-storage".to_string(),
            image: "localhost/bootc".to_string(),
            signature: None,
        };
        assert_eq!(
            storage_ref.to_transport_image().unwrap(),
            "containers-storage:localhost/bootc"
        );

        // Test oci transport
        let oci_ref = ImageReference {
            transport: "oci".to_string(),
            image: "/path/to/image".to_string(),
            signature: None,
        };
        assert_eq!(oci_ref.to_transport_image().unwrap(), "oci:/path/to/image");
    }
}
