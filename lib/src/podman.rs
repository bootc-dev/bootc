#[cfg(feature = "install")]
use anyhow::Result;
#[cfg(feature = "install")]
use camino::Utf8Path;
#[cfg(feature = "install")]
use cap_std_ext::cap_std::fs::Dir;
use serde::Deserialize;

/// Where we look inside our container to find our own image
/// for use with `bootc install`.
#[cfg(feature = "install")]
pub(crate) const CONTAINER_STORAGE: &str = "/var/lib/containers";

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
#[cfg(feature = "install")]
pub(crate) struct Inspect {
    pub(crate) digest: String,
}

/// This is output from `podman image list --format=json`.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct ImageListEntry {
    pub(crate) id: String,
    pub(crate) names: Option<Vec<String>>,
}

/// Given an image ID, return its manifest digest
#[cfg(feature = "install")]
pub(crate) fn imageid_to_digest(imgid: &str) -> Result<String> {
    use bootc_utils::CommandRunExt;
    let o: Vec<Inspect> = std::process::Command::new("podman")
        .args(["inspect", imgid])
        .run_and_parse_json()?;
    let i = o
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No images returned for inspect"))?;
    Ok(i.digest)
}

/// Return true if there is apparently an active container store at the target path.
#[cfg(feature = "install")]
pub(crate) fn storage_exists(root: &Dir, path: impl AsRef<Utf8Path>) -> Result<bool> {
    fn impl_storage_exists(root: &Dir, path: &Utf8Path) -> Result<bool> {
        let lock = "storage.lock";
        root.try_exists(path.join(lock)).map_err(Into::into)
    }
    impl_storage_exists(root, path.as_ref())
}

/// Return true if there is apparently an active container store in the default path
/// for the target root.
///
/// Note this does not attempt to parse the root filesystem's container storage configuration,
/// this uses a hardcoded default path.
#[cfg(feature = "install")]
pub(crate) fn storage_exists_default(root: &Dir) -> Result<bool> {
    storage_exists(root, CONTAINER_STORAGE.trim_start_matches('/'))
}
