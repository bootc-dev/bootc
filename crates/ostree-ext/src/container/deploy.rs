//! Perform initial setup for a container image based system root

use anyhow::Result;
use fn_error_context::context;
use ostree::glib;
use std::collections::HashSet;

use super::store::{LayeredImageState, gc_image_layers};
use super::{ImageReference, OstreeImageReference};
use crate::container::store::PrepareResult;
use crate::keyfileext::KeyFileExt;
use crate::sysroot::SysrootLock;

/// The key in the OSTree origin which holds a serialized [`super::OstreeImageReference`].
pub const ORIGIN_CONTAINER: &str = "container-image-reference";

/// The name of the default stateroot.
// xref https://github.com/ostreedev/ostree/issues/2794
pub const STATEROOT_DEFAULT: &str = "default";

/// Options configuring deployment.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct DeployOpts<'a> {
    /// Kernel arguments to use.
    pub kargs: Option<&'a [&'a str]>,
    /// Target image reference, as distinct from the source.
    ///
    /// In many cases, one may want a workflow where a system is provisioned from
    /// an image with a specific digest (e.g. `quay.io/example/os@sha256:...) for
    /// reproducibilty.  However, one would want `ostree admin upgrade` to fetch
    /// `quay.io/example/os:latest`.
    ///
    /// To implement this, use this option for the latter `:latest` tag.
    pub target_imgref: Option<&'a OstreeImageReference>,

    /// Configuration for fetching containers.
    pub proxy_cfg: Option<super::store::ImageProxyConfig>,

    /// If true, then no image reference will be written; but there will be refs
    /// for the fetched layers.  This ensures that if the machine is later updated
    /// to a different container image, the fetch process will reuse shared layers, but
    /// it will not be necessary to remove the previous image.
    pub no_imgref: bool,

    /// Do not invoke bootc completion
    pub skip_completion: bool,

    /// Do not cleanup deployments
    pub no_clean: bool,
}

/// Write a container image to an OSTree deployment.
///
/// This API is currently intended for only an initial deployment.
#[context("Performing deployment")]
pub async fn deploy(
    sysroot: &ostree::Sysroot,
    stateroot: &str,
    imgref: &OstreeImageReference,
    options: Option<DeployOpts<'_>>,
) -> Result<Box<LayeredImageState>> {
    // Log the deployment operation to systemd journal (Debug level since staging already logged the main info)

    const DEPLOY_JOURNAL_ID: &str = "9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3";

    tracing::debug!(
        message_id = DEPLOY_JOURNAL_ID,
        bootc.image.reference = &imgref.imgref.name,
        bootc.image.transport = &imgref.imgref.transport.to_string(),
        bootc.stateroot = stateroot,
        "Deploying container image to OSTree: {}",
        imgref
    );

    let cancellable = ostree::gio::Cancellable::NONE;
    let options = options.unwrap_or_default();
    let repo = &sysroot.repo();
    let merge_deployment = sysroot.merge_deployment(Some(stateroot));
    let mut imp =
        super::store::ImageImporter::new(repo, imgref, options.proxy_cfg.unwrap_or_default())
            .await?;
    imp.require_bootable();
    if let Some(target) = options.target_imgref {
        imp.set_target(target);
    }
    if options.no_imgref {
        imp.set_no_imgref();
    }
    let state = match imp.prepare().await? {
        PrepareResult::AlreadyPresent(r) => r,
        PrepareResult::Ready(prep) => {
            if let Some(warning) = prep.deprecated_warning() {
                crate::cli::print_deprecated_warning(warning).await;
            }

            imp.import(prep).await?
        }
    };
    let commit = state.merge_commit.as_str();
    let origin = glib::KeyFile::new();
    let target_imgref = options.target_imgref.unwrap_or(imgref);
    origin.set_string("origin", ORIGIN_CONTAINER, &target_imgref.to_string());

    let opts = ostree::SysrootDeployTreeOpts {
        override_kernel_argv: options.kargs,
        ..Default::default()
    };

    if sysroot.booted_deployment().is_some() {
        sysroot.stage_tree_with_options(
            Some(stateroot),
            commit,
            Some(&origin),
            merge_deployment.as_ref(),
            &opts,
            cancellable,
        )?;
    } else {
        let deployment = &sysroot.deploy_tree_with_options(
            Some(stateroot),
            commit,
            Some(&origin),
            merge_deployment.as_ref(),
            Some(&opts),
            cancellable,
        )?;
        let flags = if options.no_clean {
            ostree::SysrootSimpleWriteDeploymentFlags::NO_CLEAN
        } else {
            ostree::SysrootSimpleWriteDeploymentFlags::NONE
        };
        sysroot.simple_write_deployment(
            Some(stateroot),
            deployment,
            merge_deployment.as_ref(),
            flags,
            cancellable,
        )?;

        // We end up re-executing ourselves as a subprocess because
        // otherwise right now we end up with a circular dependency between
        // crates. We need an option to skip though so when the *main*
        // bootc install code calls this API, we don't do this as it
        // will have already been handled.
        // Note also we do this under a feature gate to ensure rpm-ostree
        // doesn't try to invoke this, as that won't work right now.
        #[cfg(feature = "bootc")]
        if !options.skip_completion {
            use bootc_utils::CommandRunExt;
            use cap_std_ext::cmdext::CapStdExtCommandExt;
            use ocidir::cap_std::fs::Dir;

            let sysroot_dir = &Dir::reopen_dir(&crate::sysroot::sysroot_fd(sysroot))?;

            // Note that the sysroot is provided as `.`  but we use cwd_dir to
            // make the process current working directory the sysroot.
            let st = std::process::Command::new(std::env::current_exe()?)
                .args(["internals", "bootc-install-completion", ".", stateroot])
                .cwd_dir(sysroot_dir.try_clone()?)
                .lifecycle_bind()
                .status()?;
            if !st.success() {
                anyhow::bail!("Failed to complete bootc install");
            }
        }

        if !options.no_clean {
            sysroot.cleanup(cancellable)?;
        }
    }

    Ok(state)
}

/// Query the container image reference for a deployment
fn deployment_origin_container(
    deploy: &ostree::Deployment,
) -> Result<Option<OstreeImageReference>> {
    let origin = deploy
        .origin()
        .map(|o| o.optional_string("origin", ORIGIN_CONTAINER))
        .transpose()?
        .flatten();
    let r = origin
        .map(|v| OstreeImageReference::try_from(v.as_str()))
        .transpose()?;
    Ok(r)
}

/// Remove all container images which are not the target of a deployment.
/// This acts equivalently to [`super::store::remove_images()`] - the underlying layers
/// are not pruned.
///
/// The set of removed images is returned.
pub fn remove_undeployed_images(sysroot: &SysrootLock) -> Result<Vec<ImageReference>> {
    let repo = &sysroot.repo();
    let deployment_origins: Result<HashSet<_>> = sysroot
        .deployments()
        .into_iter()
        .filter_map(|deploy| {
            deployment_origin_container(&deploy)
                .map(|v| v.map(|v| v.imgref))
                .transpose()
        })
        .collect();
    let deployment_origins = deployment_origins?;
    // TODO add an API that returns ImageReference instead
    let all_images = super::store::list_images(&sysroot.repo())?
        .into_iter()
        .filter_map(|img| ImageReference::try_from(img.as_str()).ok());
    let mut removed = Vec::new();
    for image in all_images {
        if !deployment_origins.contains(&image) {
            super::store::remove_image(repo, &image)?;
            removed.push(image);
        }
    }
    Ok(removed)
}

/// The result of a prune operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pruned {
    /// The number of images that were pruned
    pub n_images: u32,
    /// The number of image layers that were pruned
    pub n_layers: u32,
    /// The number of OSTree objects that were pruned
    pub n_objects_pruned: u32,
    /// The total size of pruned objects
    pub objsize: u64,
}

impl Pruned {
    /// Whether this prune was a no-op (i.e. no images, layers or objects were pruned).
    pub fn is_empty(&self) -> bool {
        self.n_images == 0 && self.n_layers == 0 && self.n_objects_pruned == 0
    }
}

/// This combines the functionality of [`remove_undeployed_images()`] with [`super::store::gc_image_layers()`].
pub fn prune(sysroot: &SysrootLock) -> Result<Pruned> {
    let repo = &sysroot.repo();
    // Prune container images which are not deployed.
    // SAFETY: There should never be more than u32 images
    let n_images = remove_undeployed_images(sysroot)?.len().try_into().unwrap();
    // Prune unreferenced layer branches.
    let n_layers = gc_image_layers(repo)?;
    // Prune the objects in the repo; the above just removed refs (branches).
    let (_, n_objects_pruned, objsize) = repo.prune(
        ostree::RepoPruneFlags::REFS_ONLY,
        0,
        ostree::gio::Cancellable::NONE,
    )?;
    // SAFETY: The number of pruned objects should never be negative
    let n_objects_pruned = u32::try_from(n_objects_pruned).unwrap();
    Ok(Pruned {
        n_images,
        n_layers,
        n_objects_pruned,
        objsize,
    })
}
