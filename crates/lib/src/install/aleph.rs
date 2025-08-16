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
    pub(crate) image: String,
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
        imgstate: &ostree_container::store::LayeredImageState,
        selinux_state: &SELinuxFinalState,
    ) -> Result<Self> {
        let uname = rustix::system::uname();
        let labels = crate::status::labels_of_config(&imgstate.configuration);
        let timestamp = labels
            .and_then(|l| {
                l.get(oci_spec::image::ANNOTATION_CREATED)
                    .map(|s| s.as_str())
            })
            .and_then(bootc_utils::try_deserialize_timestamp);
        let r = InstallAleph {
            image: src_imageref.imgref.name.clone(),
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
