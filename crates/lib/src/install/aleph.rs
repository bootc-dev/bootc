use std::collections::BTreeMap;

use anyhow::{Context as _, Result};
use canon_json::CanonJsonSerialize as _;
use cap_std_ext::{cap_std::fs::Dir, dirext::CapStdExtDirExt as _};
use fn_error_context::context;
use ostree_ext::{container as ostree_container, oci_spec};
use serde::Serialize;

use super::SELinuxFinalState;

/// Path to initially deployed version information
pub(crate) const BOOTC_ALEPH_PATH: &str = ".bootc-aleph.json";

/// The "aleph" version information is injected into /root/.bootc-aleph.json
/// and contains the image ID that was initially used to install.  This can
/// be used to trace things like the specific version of `mkfs.ext4` or
/// kernel version that was used.
#[derive(Debug, Serialize)]
pub(crate) struct InstallAleph {
    /// Digested pull spec for installed image
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) image: Option<String>,
    /// The manifest digest of the installed image
    pub(crate) digest: String,
    /// The target image reference, used for subsequent updates
    #[serde(rename = "target-image")]
    pub(crate) target_image: String,
    /// The OCI image labels from the installed image
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) labels: BTreeMap<String, String>,
    /// The version number
    pub(crate) version: Option<String>,
    /// The timestamp
    pub(crate) timestamp: Option<chrono::DateTime<chrono::Utc>>,
    /// The `uname -r` of the kernel doing the installation
    pub(crate) kernel: String,
    /// The state of SELinux at install time
    pub(crate) selinux: String,
}

impl InstallAleph {
    #[context("Creating aleph data")]
    pub(crate) fn new(
        src_imageref: &ostree_container::OstreeImageReference,
        target_imgref: &ostree_container::OstreeImageReference,
        imgstate: &ostree_container::store::LayeredImageState,
        selinux_state: &SELinuxFinalState,
    ) -> Result<Self> {
        let uname = rustix::system::uname();
        let oci_labels = crate::status::labels_of_config(&imgstate.configuration);
        let timestamp = oci_labels
            .and_then(|l| {
                l.get(oci_spec::image::ANNOTATION_CREATED)
                    .map(|s| s.as_str())
            })
            .and_then(bootc_utils::try_deserialize_timestamp);
        let labels: BTreeMap<String, String> = oci_labels
            .map(|l| l.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();
        // When installing via osbuild, the source image is usually a
        // temporary local container storage path (e.g. `/tmp/...`) which is not useful.
        let image = if src_imageref.imgref.name.starts_with("/tmp") {
            tracing::debug!("Not serializing the source imageref as it's a local temporary image.");
            None
        } else {
            Some(src_imageref.imgref.name.clone())
        };
        let r = InstallAleph {
            image,
            target_image: target_imgref.imgref.name.clone(),
            digest: imgstate.manifest_digest.to_string(),
            labels,
            version: imgstate.version().as_ref().map(|s| s.to_string()),
            timestamp,
            kernel: uname.release().to_str()?.to_string(),
            selinux: selinux_state.to_aleph().to_string(),
        };
        Ok(r)
    }

    /// Serialize to a file in the target root.
    pub(crate) fn write_to(&self, root: &Dir) -> Result<()> {
        root.atomic_replace_with(BOOTC_ALEPH_PATH, |f| {
            anyhow::Ok(self.to_canon_json_writer(f)?)
        })
        .context("Writing aleph version")
    }
}
