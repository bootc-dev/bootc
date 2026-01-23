//! # APIs bridging OSTree and container images
//!
//! This module provides the core infrastructure for bidirectionally mapping between
//! OCI/Docker container images and OSTree repositories. It enables bootable container
//! images to be fetched from registries, stored efficiently, and deployed as ostree
//! commits.
//!
//! ## Overview
//!
//! Container images are fundamentally layers of tarballs. This module leverages the
//! [`crate::tar`] module to import container layers as ostree content, and exports
//! ostree commits back to container images. The key insight is that ostree's
//! content-addressed object storage maps naturally to OCI layer deduplication.
//!
//! When a container image is imported ("pulled"), each layer becomes an ostree commit.
//! These layer commits are then merged into a single "merge commit" that represents
//! the complete filesystem state. This merge commit is what gets deployed as a
//! bootable system.
//!
//! ## On-Disk Storage Structure
//!
//! Container images are stored in the ostree repository (typically `/sysroot/ostree/repo/`)
//! using a structured reference (ref) namespace:
//!
//! ### Reference Namespace
//!
//! - **`ostree/container/blob/<escaped-digest>`**: Each OCI layer is stored as a
//!   separate ostree commit. The digest (e.g., `sha256:abc123...`) is escaped using
//!   [`crate::refescape`] to be valid as an ostree ref. For example:
//!   `ostree/container/blob/sha256_3A_abc123...`
//!
//! - **`ostree/container/image/<escaped-image-reference>`**: Points to the "merge
//!   commit" for a pulled image. The image reference (e.g., `docker://quay.io/org/image:tag`)
//!   is escaped similarly. This is the ref that deployments point to.
//!
//! - **`ostree/container/baseimage/<project>/<index>`**: Used to protect base images
//!   from garbage collection. Tooling that builds derived images locally should write
//!   refs under this prefix to prevent the base layers from being pruned.
//!
//! ### Layer Storage
//!
//! Each container layer is stored as an ostree commit with a special structure:
//!
//! - **OSTree "chunk" layers**: Layers that are part of the base ostree commit use
//!   the "object set" format - the filenames in the commit *are* the object checksums.
//!   This enables efficient reconstruction of the original ostree commit.
//!
//! - **Derived layers**: Non-ostree layers (e.g., from `RUN` commands in a Containerfile)
//!   are imported as regular filesystem trees and stored as standard ostree commits.
//!
//! ### The Merge Commit
//!
//! The merge commit (`ostree/container/image/...`) combines all layers into a single
//! filesystem tree. It contains critical metadata in its commit metadata:
//!
//! - `ostree.manifest-digest`: The OCI manifest digest (e.g., `sha256:...`)
//! - `ostree.manifest`: The complete OCI manifest as JSON
//! - `ostree.container.image-config`: The OCI image configuration as JSON
//!
//! This metadata enables round-tripping: an imported image can be re-exported with
//! its original manifest structure preserved.
//!
//! ## Import Flow
//!
//! The import process (implemented in [`store::ImageImporter`]) follows these steps:
//!
//! 1. **Manifest fetch**: Contact the registry via containers-image-proxy (skopeo)
//!    to retrieve the image manifest and configuration.
//!
//! 2. **Layout parsing**: Analyze the manifest to identify:
//!    - The base ostree layer (identified by the `ostree.final-diffid` label)
//!    - Component/chunk layers (split object sets)
//!    - Derived layers (non-ostree content)
//!
//! 3. **Layer caching check**: For each layer, check if an ostree ref already exists
//!    for that digest. Cached layers are skipped, enabling efficient incremental updates.
//!
//! 4. **Layer import**: For uncached layers:
//!    - Fetch the compressed tarball from the registry
//!    - Decompress and parse the tar stream
//!    - Import content into ostree (handling xattrs via `bare-split-xattrs` format)
//!    - Create an ostree commit and write the layer ref
//!
//! 5. **Merge commit creation**: Overlay all layers (processing OCI whiteout files)
//!    to create a unified filesystem tree. Apply SELinux labeling if needed.
//!    Store manifest/config metadata and write the image ref.
//!
//! 6. **Garbage collection**: Prune layer refs that are no longer referenced by any
//!    image or deployment.
//!
//! ## Tar Stream Format
//!
//! The tar format used for ostree layers is documented in [`crate::tar`]. Key points:
//!
//! - Uses `bare-split-xattrs` repository mode to handle extended attributes
//! - XAttrs are stored in separate `.file-xattrs` objects, avoiding tar xattr complexity
//! - `/etc` in container images maps to `/usr/etc` in ostree (the "3-way merge" location)
//! - Hardlinks are used for deduplication within layers
//!
//! ## Connection to Deployments
//!
//! When bootc deploys an image, it creates an ostree deployment whose "origin" file
//! references the container image. The origin contains:
//!
//! - The [`OstreeImageReference`] specifying the image and signature verification method
//! - The merge commit checksum
//!
//! On subsequent boots, bootc can compare the deployed commit against the registry
//! manifest to detect available updates.
//!
//! ## Signatures
//!
//! OSTree supports GPG and ed25519 signatures natively. When fetching container images,
//! signature verification can be configured via [`SignatureSource`]:
//!
//! - `OstreeRemote(name)`: Verify using the named ostree remote's keyring
//! - `ContainerPolicy`: Defer to containers-policy.json (requires explicit allow)
//! - `ContainerPolicyAllowInsecure`: Use containers-policy.json defaults (not recommended)
//!
//! This library defines a URL-like schema to combine signature verification with
//! image references:
//!
//! - `ostree-remote-registry:<remotename>:<containerimage>` - Verify via ostree remote
//! - `ostree-image-signed:<transport>:<image>` - Use container policy
//! - `ostree-unverified-registry:<image>` - No verification (not recommended)
//!
//! Example: `ostree-remote-registry:fedora:quay.io/fedora/fedora-bootc:latest`
//!
//! See [`OstreeImageReference`] for parsing and generating these strings.
//!
//! ## Layering and Derived Images
//!
//! Container image layering is fully supported. A typical bootable image structure:
//!
//! 1. **Base ostree layer**: Contains the core OS as an ostree commit
//! 2. **Chunk layers**: Split objects for efficient updates (optional)
//! 3. **Derived layers**: Additional content from Containerfile `RUN` commands
//!
//! The `ostree.final-diffid` label in the image configuration marks where the
//! ostree content ends and derived content begins. This enables:
//!
//! - Efficient layer sharing between images with the same base
//! - Proper SELinux labeling of derived content using the base policy
//! - Round-trip export preserving the layer structure
//!
//! ## Key Types
//!
//! - [`Transport`]: OCI/Docker transport (registry, oci-dir, containers-storage, etc.)
//! - [`ImageReference`]: Container image reference with transport
//! - [`OstreeImageReference`]: Image reference plus signature verification method
//! - [`SignatureSource`]: How to verify image signatures
//! - [`store::ImageImporter`]: Main import orchestrator
//! - [`store::PreparedImport`]: Analysis of layers to fetch
//! - [`store::LayeredImageState`]: State of a pulled image
//! - [`ManifestDiff`]: Comparison between two image manifests
//!
//! ## Submodules
//!
//! - [`store`]: Core storage and import logic
//! - [`deploy`]: Integration with ostree deployments
//! - [`skopeo`]: Skopeo subprocess management for registry operations

use anyhow::anyhow;
use cap_std_ext::cap_std;
use cap_std_ext::cap_std::fs::Dir;
use containers_image_proxy::oci_spec;
use ostree::glib;
use serde::Serialize;

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::Debug;
use std::ops::Deref;
use std::str::FromStr;

/// The label injected into a container image that contains the ostree commit SHA-256.
pub const OSTREE_COMMIT_LABEL: &str = "ostree.commit";

/// The name of an annotation attached to a layer which names the packages/components
/// which are part of it.
pub(crate) const CONTENT_ANNOTATION: &str = "ostree.components";
/// The character we use to separate values in [`CONTENT_ANNOTATION`].
pub(crate) const COMPONENT_SEPARATOR: char = ',';

/// Our generic catchall fatal error, expected to be converted
/// to a string to output to a terminal or logs.
type Result<T> = anyhow::Result<T>;

/// A backend/transport for OCI/Docker images.
#[derive(Copy, Clone, Hash, Debug, PartialEq, Eq)]
pub enum Transport {
    /// A remote Docker/OCI registry (`registry:` or `docker://`)
    Registry,
    /// A local OCI directory (`oci:`)
    OciDir,
    /// A local OCI archive tarball (`oci-archive:`)
    OciArchive,
    /// A local Docker archive tarball (`docker-archive:`)
    DockerArchive,
    /// Local container storage (`containers-storage:`)
    ContainerStorage,
    /// Local directory (`dir:`)
    Dir,
    /// Local Docker daemon (`docker-daemon:`)
    DockerDaemon,
}

/// Combination of a remote image reference and transport.
///
/// For example,
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ImageReference {
    /// The storage and transport for the image
    pub transport: Transport,
    /// The image name (e.g. `quay.io/somerepo/someimage:latest`)
    pub name: String,
}

/// Policy for signature verification.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SignatureSource {
    /// Fetches will use the named ostree remote for signature verification of the ostree commit.
    OstreeRemote(String),
    /// Fetches will defer to the `containers-policy.json`, but we make a best effort to reject `default: insecureAcceptAnything` policy.
    ContainerPolicy,
    /// NOT RECOMMENDED.  Fetches will defer to the `containers-policy.json` default which is usually `insecureAcceptAnything`.
    ContainerPolicyAllowInsecure,
}

/// A commonly used pre-OCI label for versions.
pub const LABEL_VERSION: &str = "version";

/// Combination of a signature verification mechanism, and a standard container image reference.
///
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OstreeImageReference {
    /// The signature verification mechanism.
    pub sigverify: SignatureSource,
    /// The container image reference.
    pub imgref: ImageReference,
}

impl TryFrom<&str> for Transport {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        Ok(match value {
            Self::REGISTRY_STR | "docker" => Self::Registry,
            Self::OCI_STR => Self::OciDir,
            Self::OCI_ARCHIVE_STR => Self::OciArchive,
            Self::DOCKER_ARCHIVE_STR => Self::DockerArchive,
            Self::CONTAINERS_STORAGE_STR => Self::ContainerStorage,
            Self::LOCAL_DIRECTORY_STR => Self::Dir,
            Self::DOCKER_DAEMON_STR => Self::DockerDaemon,
            o => return Err(anyhow!("Unknown transport '{}'", o)),
        })
    }
}

impl Transport {
    const OCI_STR: &'static str = "oci";
    const OCI_ARCHIVE_STR: &'static str = "oci-archive";
    const DOCKER_ARCHIVE_STR: &'static str = "docker-archive";
    const CONTAINERS_STORAGE_STR: &'static str = "containers-storage";
    const LOCAL_DIRECTORY_STR: &'static str = "dir";
    const REGISTRY_STR: &'static str = "registry";
    const DOCKER_DAEMON_STR: &'static str = "docker-daemon";

    /// Retrieve an identifier that can then be re-parsed from [`Transport::try_from::<&str>`].
    pub fn serializable_name(&self) -> &'static str {
        match self {
            Transport::Registry => Self::REGISTRY_STR,
            Transport::OciDir => Self::OCI_STR,
            Transport::OciArchive => Self::OCI_ARCHIVE_STR,
            Transport::DockerArchive => Self::DOCKER_ARCHIVE_STR,
            Transport::ContainerStorage => Self::CONTAINERS_STORAGE_STR,
            Transport::Dir => Self::LOCAL_DIRECTORY_STR,
            Transport::DockerDaemon => Self::DOCKER_DAEMON_STR,
        }
    }
}

impl TryFrom<&str> for ImageReference {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        let (transport_name, mut name) = value
            .split_once(':')
            .ok_or_else(|| anyhow!("Missing ':' in {}", value))?;
        let transport: Transport = transport_name.try_into()?;
        if name.is_empty() {
            return Err(anyhow!("Invalid empty name in {}", value));
        }
        if transport_name == "docker" {
            name = name
                .strip_prefix("//")
                .ok_or_else(|| anyhow!("Missing // in docker:// in {}", value))?;
        }
        Ok(Self {
            transport,
            name: name.to_string(),
        })
    }
}

impl FromStr for ImageReference {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::try_from(s)
    }
}

impl TryFrom<&str> for SignatureSource {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        match value {
            "ostree-image-signed" => Ok(Self::ContainerPolicy),
            "ostree-unverified-image" => Ok(Self::ContainerPolicyAllowInsecure),
            o => match o.strip_prefix("ostree-remote-image:") {
                Some(rest) => Ok(Self::OstreeRemote(rest.to_string())),
                _ => Err(anyhow!("Invalid signature source: {}", o)),
            },
        }
    }
}

impl FromStr for SignatureSource {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::try_from(s)
    }
}

impl TryFrom<&str> for OstreeImageReference {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        let (first, second) = value
            .split_once(':')
            .ok_or_else(|| anyhow!("Missing ':' in {}", value))?;
        let (sigverify, rest) = match first {
            "ostree-image-signed" => (SignatureSource::ContainerPolicy, Cow::Borrowed(second)),
            "ostree-unverified-image" => (
                SignatureSource::ContainerPolicyAllowInsecure,
                Cow::Borrowed(second),
            ),
            // Shorthand for ostree-unverified-image:registry:
            "ostree-unverified-registry" => (
                SignatureSource::ContainerPolicyAllowInsecure,
                Cow::Owned(format!("registry:{second}")),
            ),
            // This is a shorthand for ostree-remote-image with registry:
            "ostree-remote-registry" => {
                let (remote, rest) = second
                    .split_once(':')
                    .ok_or_else(|| anyhow!("Missing second ':' in {}", value))?;
                (
                    SignatureSource::OstreeRemote(remote.to_string()),
                    Cow::Owned(format!("registry:{rest}")),
                )
            }
            "ostree-remote-image" => {
                let (remote, rest) = second
                    .split_once(':')
                    .ok_or_else(|| anyhow!("Missing second ':' in {}", value))?;
                (
                    SignatureSource::OstreeRemote(remote.to_string()),
                    Cow::Borrowed(rest),
                )
            }
            o => {
                return Err(anyhow!("Invalid ostree image reference scheme: {}", o));
            }
        };
        let imgref = rest.deref().try_into()?;
        Ok(Self { sigverify, imgref })
    }
}

impl FromStr for OstreeImageReference {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::try_from(s)
    }
}

impl std::fmt::Display for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            // TODO once skopeo supports this, canonicalize as registry:
            Self::Registry => "docker://",
            Self::OciArchive => "oci-archive:",
            Self::DockerArchive => "docker-archive:",
            Self::OciDir => "oci:",
            Self::ContainerStorage => "containers-storage:",
            Self::Dir => "dir:",
            Self::DockerDaemon => "docker-daemon:",
        };
        f.write_str(s)
    }
}

impl std::fmt::Display for ImageReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.transport, self.name)
    }
}

impl std::fmt::Display for SignatureSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignatureSource::OstreeRemote(r) => write!(f, "ostree-remote-image:{r}"),
            SignatureSource::ContainerPolicy => write!(f, "ostree-image-signed"),
            SignatureSource::ContainerPolicyAllowInsecure => {
                write!(f, "ostree-unverified-image")
            }
        }
    }
}

impl std::fmt::Display for OstreeImageReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.sigverify, &self.imgref) {
            (SignatureSource::ContainerPolicyAllowInsecure, imgref)
                if imgref.transport == Transport::Registry =>
            {
                // Because allow-insecure is the effective default, allow formatting
                // without it.  Note this formatting is asymmetric and cannot be
                // re-parsed.
                if f.alternate() {
                    write!(f, "{}", self.imgref)
                } else {
                    write!(f, "ostree-unverified-registry:{}", self.imgref.name)
                }
            }
            (sigverify, imgref) => {
                write!(f, "{sigverify}:{imgref}")
            }
        }
    }
}

/// Represents the difference in layer/blob content between two OCI image manifests.
#[derive(Debug, Serialize)]
pub struct ManifestDiff<'a> {
    /// The source container image manifest.
    #[serde(skip)]
    pub from: &'a oci_spec::image::ImageManifest,
    /// The target container image manifest.
    #[serde(skip)]
    pub to: &'a oci_spec::image::ImageManifest,
    /// Layers which are present in the old image but not the new image.
    #[serde(skip)]
    pub removed: Vec<&'a oci_spec::image::Descriptor>,
    /// Layers which are present in the new image but not the old image.
    #[serde(skip)]
    pub added: Vec<&'a oci_spec::image::Descriptor>,
    /// Total number of layers
    pub total: u64,
    /// Size of total number of layers.
    pub total_size: u64,
    /// Number of layers removed
    pub n_removed: u64,
    /// Size of the number of layers removed
    pub removed_size: u64,
    /// Number of packages added
    pub n_added: u64,
    /// Size of the number of layers added
    pub added_size: u64,
}

impl<'a> ManifestDiff<'a> {
    /// Compute the layer difference between two OCI image manifests.
    pub fn new(
        src: &'a oci_spec::image::ImageManifest,
        dest: &'a oci_spec::image::ImageManifest,
    ) -> Self {
        let src_layers = src
            .layers()
            .iter()
            .map(|l| (l.digest().digest(), l))
            .collect::<HashMap<_, _>>();
        let dest_layers = dest
            .layers()
            .iter()
            .map(|l| (l.digest().digest(), l))
            .collect::<HashMap<_, _>>();
        let mut removed = Vec::new();
        let mut added = Vec::new();
        for (blobid, &descriptor) in src_layers.iter() {
            if !dest_layers.contains_key(blobid) {
                removed.push(descriptor);
            }
        }
        removed.sort_by(|a, b| a.digest().digest().cmp(b.digest().digest()));
        for (blobid, &descriptor) in dest_layers.iter() {
            if !src_layers.contains_key(blobid) {
                added.push(descriptor);
            }
        }
        added.sort_by(|a, b| a.digest().digest().cmp(b.digest().digest()));

        fn layersum<'a, I: Iterator<Item = &'a oci_spec::image::Descriptor>>(layers: I) -> u64 {
            layers.map(|layer| layer.size()).sum()
        }
        let total = dest_layers.len() as u64;
        let total_size = layersum(dest.layers().iter());
        let n_removed = removed.len() as u64;
        let n_added = added.len() as u64;
        let removed_size = layersum(removed.iter().copied());
        let added_size = layersum(added.iter().copied());
        ManifestDiff {
            from: src,
            to: dest,
            removed,
            added,
            total,
            total_size,
            n_removed,
            removed_size,
            n_added,
            added_size,
        }
    }
}

impl ManifestDiff<'_> {
    /// Prints the total, removed and added content between two OCI images
    pub fn print(&self) {
        let print_total = self.total;
        let print_total_size = glib::format_size(self.total_size);
        let print_n_removed = self.n_removed;
        let print_removed_size = glib::format_size(self.removed_size);
        let print_n_added = self.n_added;
        let print_added_size = glib::format_size(self.added_size);
        println!("Total new layers: {print_total:<4}  Size: {print_total_size}");
        println!("Removed layers:   {print_n_removed:<4}  Size: {print_removed_size}");
        println!("Added layers:     {print_n_added:<4}  Size: {print_added_size}");
    }
}

/// Apply default configuration for container image pulls to an existing configuration.
/// For example, if `authfile` is not set, and `auth_anonymous` is `false`, and a global configuration file exists, it will be used.
///
/// If there is no configured explicit subprocess for skopeo, and the process is running
/// as root, then a default isolation of running the process via `nobody` will be applied.
pub fn merge_default_container_proxy_opts(
    config: &mut containers_image_proxy::ImageProxyConfig,
) -> Result<()> {
    let user = rustix::process::getuid()
        .is_root()
        .then_some(isolation::DEFAULT_UNPRIVILEGED_USER);
    merge_default_container_proxy_opts_with_isolation(config, user)
}

/// Apply default configuration for container image pulls, with optional support
/// for isolation as an unprivileged user.
pub fn merge_default_container_proxy_opts_with_isolation(
    config: &mut containers_image_proxy::ImageProxyConfig,
    isolation_user: Option<&str>,
) -> Result<()> {
    let auth_specified =
        config.auth_anonymous || config.authfile.is_some() || config.auth_data.is_some();
    if !auth_specified {
        let root = &Dir::open_ambient_dir("/", cap_std::ambient_authority())?;
        config.auth_data = crate::globals::get_global_authfile(root)?.map(|a| a.1);
        // If there's no auth data, then force on anonymous pulls to ensure
        // that the container stack doesn't try to find it in the standard
        // container paths.
        if config.auth_data.is_none() {
            config.auth_anonymous = true;
        }
    }
    // By default, drop privileges, unless the higher level code
    // has configured the skopeo command explicitly.
    let isolation_user = config
        .skopeo_cmd
        .is_none()
        .then_some(isolation_user.as_ref())
        .flatten();
    if let Some(user) = isolation_user {
        // Read the default authfile if it exists and pass it via file descriptor
        // which will ensure it's readable when we drop privileges.
        if let Some(authfile) = config.authfile.take() {
            config.auth_data = Some(std::fs::File::open(authfile)?);
        }
        let cmd = crate::isolation::unprivileged_subprocess("skopeo", user);
        config.skopeo_cmd = Some(cmd);
    }
    Ok(())
}

/// Convenience helper to return the labels, if present.
pub(crate) fn labels_of(
    config: &oci_spec::image::ImageConfiguration,
) -> Option<&HashMap<String, String>> {
    config.config().as_ref().and_then(|c| c.labels().as_ref())
}

/// Retrieve the version number from an image configuration.
pub fn version_for_config(config: &oci_spec::image::ImageConfiguration) -> Option<&str> {
    if let Some(labels) = labels_of(config) {
        for k in [oci_spec::image::ANNOTATION_VERSION, LABEL_VERSION] {
            if let Some(v) = labels.get(k) {
                return Some(v.as_str());
            }
        }
    }
    None
}

pub mod deploy;
mod encapsulate;
pub use encapsulate::*;
mod unencapsulate;
pub use unencapsulate::*;
pub mod skopeo;
pub mod store;
mod update_detachedmeta;
pub use update_detachedmeta::*;

use crate::isolation;

#[cfg(test)]
mod tests {
    use std::process::Command;

    use containers_image_proxy::ImageProxyConfig;

    use super::*;

    #[test]
    fn test_serializable_transport() {
        for v in [
            Transport::Registry,
            Transport::ContainerStorage,
            Transport::OciArchive,
            Transport::DockerArchive,
            Transport::OciDir,
        ] {
            assert_eq!(Transport::try_from(v.serializable_name()).unwrap(), v);
        }
    }

    const INVALID_IRS: &[&str] = &["", "foo://", "docker:blah", "registry:", "foo:bar"];
    const VALID_IRS: &[&str] = &[
        "containers-storage:localhost/someimage",
        "docker://quay.io/exampleos/blah:sometag",
    ];

    #[test]
    fn test_imagereference() {
        let ir: ImageReference = "registry:quay.io/exampleos/blah".try_into().unwrap();
        assert_eq!(ir.transport, Transport::Registry);
        assert_eq!(ir.name, "quay.io/exampleos/blah");
        assert_eq!(ir.to_string(), "docker://quay.io/exampleos/blah");

        for &v in VALID_IRS {
            ImageReference::try_from(v).unwrap();
        }

        for &v in INVALID_IRS {
            if ImageReference::try_from(v).is_ok() {
                panic!("Should fail to parse: {v}")
            }
        }
        struct Case {
            s: &'static str,
            transport: Transport,
            name: &'static str,
        }
        for case in [
            Case {
                s: "oci:somedir",
                transport: Transport::OciDir,
                name: "somedir",
            },
            Case {
                s: "dir:/some/dir/blah",
                transport: Transport::Dir,
                name: "/some/dir/blah",
            },
            Case {
                s: "oci-archive:/path/to/foo.ociarchive",
                transport: Transport::OciArchive,
                name: "/path/to/foo.ociarchive",
            },
            Case {
                s: "docker-archive:/path/to/foo.dockerarchive",
                transport: Transport::DockerArchive,
                name: "/path/to/foo.dockerarchive",
            },
            Case {
                s: "containers-storage:localhost/someimage:blah",
                transport: Transport::ContainerStorage,
                name: "localhost/someimage:blah",
            },
        ] {
            let ir: ImageReference = case.s.try_into().unwrap();
            assert_eq!(ir.transport, case.transport);
            assert_eq!(ir.name, case.name);
            let reserialized = ir.to_string();
            assert_eq!(case.s, reserialized.as_str());
        }
    }

    #[test]
    fn test_ostreeimagereference() {
        // Test both long form `ostree-remote-image:$myremote:registry` and the
        // shorthand `ostree-remote-registry:$myremote`.
        let ir_s = "ostree-remote-image:myremote:registry:quay.io/exampleos/blah";
        let ir_registry = "ostree-remote-registry:myremote:quay.io/exampleos/blah";
        for &ir_s in &[ir_s, ir_registry] {
            let ir: OstreeImageReference = ir_s.try_into().unwrap();
            assert_eq!(
                ir.sigverify,
                SignatureSource::OstreeRemote("myremote".to_string())
            );
            assert_eq!(ir.imgref.transport, Transport::Registry);
            assert_eq!(ir.imgref.name, "quay.io/exampleos/blah");
            assert_eq!(
                ir.to_string(),
                "ostree-remote-image:myremote:docker://quay.io/exampleos/blah"
            );
        }

        // Also verify our FromStr impls

        let ir: OstreeImageReference = ir_s.try_into().unwrap();
        assert_eq!(ir, OstreeImageReference::from_str(ir_s).unwrap());
        // test our Eq implementation
        assert_eq!(&ir, &OstreeImageReference::try_from(ir_registry).unwrap());

        let ir_s = "ostree-image-signed:docker://quay.io/exampleos/blah";
        let ir: OstreeImageReference = ir_s.try_into().unwrap();
        assert_eq!(ir.sigverify, SignatureSource::ContainerPolicy);
        assert_eq!(ir.imgref.transport, Transport::Registry);
        assert_eq!(ir.imgref.name, "quay.io/exampleos/blah");
        assert_eq!(ir.to_string(), ir_s);
        assert_eq!(format!("{:#}", &ir), ir_s);

        let ir_s = "ostree-unverified-image:docker://quay.io/exampleos/blah";
        let ir: OstreeImageReference = ir_s.try_into().unwrap();
        assert_eq!(ir.sigverify, SignatureSource::ContainerPolicyAllowInsecure);
        assert_eq!(ir.imgref.transport, Transport::Registry);
        assert_eq!(ir.imgref.name, "quay.io/exampleos/blah");
        assert_eq!(
            ir.to_string(),
            "ostree-unverified-registry:quay.io/exampleos/blah"
        );
        let ir_shorthand =
            OstreeImageReference::try_from("ostree-unverified-registry:quay.io/exampleos/blah")
                .unwrap();
        assert_eq!(&ir_shorthand, &ir);
        assert_eq!(format!("{:#}", &ir), "docker://quay.io/exampleos/blah");
    }

    #[test]
    fn test_merge_authopts() {
        // Verify idempotence of authentication processing
        let mut c = ImageProxyConfig::default();
        let authf = std::fs::File::open("/dev/null").unwrap();
        c.auth_data = Some(authf);
        super::merge_default_container_proxy_opts_with_isolation(&mut c, None).unwrap();
        assert!(!c.auth_anonymous);
        assert!(c.authfile.is_none());
        assert!(c.auth_data.is_some());
        assert!(c.skopeo_cmd.is_none());
        super::merge_default_container_proxy_opts_with_isolation(&mut c, None).unwrap();
        assert!(!c.auth_anonymous);
        assert!(c.authfile.is_none());
        assert!(c.auth_data.is_some());
        assert!(c.skopeo_cmd.is_none());

        // Verify interaction with explicit isolation
        let mut c = ImageProxyConfig {
            skopeo_cmd: Some(Command::new("skopeo")),
            ..Default::default()
        };
        super::merge_default_container_proxy_opts_with_isolation(&mut c, Some("foo")).unwrap();
        assert_eq!(c.skopeo_cmd.unwrap().get_program(), "skopeo");
    }
}
