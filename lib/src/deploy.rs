//! # Write deployments merging image with configmap
//!
//! Create a merged filesystem tree with the image and mounted configmaps.

use anyhow::{Context, Result};

use fn_error_context::context;
use ostree::{gio, glib};
use ostree_container::store::LayeredImageState;
use ostree_container::OstreeImageReference;
use ostree_ext::container as ostree_container;
use ostree_ext::ostree;
use ostree_ext::ostree::Deployment;
use ostree_ext::sysroot::SysrootLock;

use crate::spec::HostSpec;

// TODO use https://github.com/ostreedev/ostree-rs-ext/pull/493/commits/afc1837ff383681b947de30c0cefc70080a4f87a
const BASE_IMAGE_PREFIX: &str = "ostree/container/baseimage/bootc";

/// Set on an ostree commit if this is a derived commit
const BOOTC_DERIVED_KEY: &str = "bootc.derived";

pub(crate) async fn cleanup(sysroot: &SysrootLock) -> Result<()> {
    let repo = sysroot.repo();
    let sysroot = sysroot.sysroot.clone();
    ostree_ext::tokio_util::spawn_blocking_cancellable_flatten(move |cancellable| {
        let cancellable = Some(cancellable);
        let repo = &repo;
        let txn = repo.auto_transaction(cancellable)?;
        let repo = txn.repo();

        // Regenerate our base references.  First, we delete the ones that exist
        for ref_entry in repo
            .list_refs_ext(
                Some(BASE_IMAGE_PREFIX),
                ostree::RepoListRefsExtFlags::NONE,
                cancellable,
            )
            .context("Listing refs")?
            .keys()
        {
            repo.transaction_set_refspec(ref_entry, None);
        }

        // Then, for each deployment which is derived (e.g. has configmaps) we synthesize
        // a base ref to ensure that it's not GC'd.
        for (i, deployment) in sysroot.deployments().into_iter().enumerate() {
            let commit = deployment.csum();
            if let Some(base) = get_base_commit(repo, &commit)? {
                repo.transaction_set_refspec(&format!("{BASE_IMAGE_PREFIX}/{i}"), Some(&base));
            }
        }

        Ok(())
    })
    .await
}

/// If commit is a bootc-derived commit (e.g. has configmaps), return its base.
#[context("Finding base commit")]
pub(crate) fn get_base_commit<'a>(repo: &ostree::Repo, commit: &'a str) -> Result<Option<String>> {
    let commitv = repo.load_commit(&commit)?.0;
    let commitmeta = commitv.child_value(0);
    let commitmeta = &glib::VariantDict::new(Some(&commitmeta));
    let r = commitmeta
        .lookup::<String>(BOOTC_DERIVED_KEY)?
        .map(|v| v.to_string());
    Ok(r)
}

#[context("Writing deployment")]
async fn deploy(
    sysroot: &SysrootLock,
    merge_deployment: Option<&Deployment>,
    stateroot: &str,
    image: Box<LayeredImageState>,
    origin: &glib::KeyFile,
) -> Result<()> {
    let stateroot = Some(stateroot);
    // Copy to move into thread
    let base_commit = image.get_commit().to_owned();
    let cancellable = gio::Cancellable::NONE;
    let _new_deployment = sysroot.stage_tree_with_options(
        stateroot,
        &base_commit,
        Some(origin),
        merge_deployment,
        &Default::default(),
        cancellable,
    )?;
    Ok(())
}

/// Stage (queue deployment of) a fetched container image.
#[context("Staging")]
pub(crate) async fn stage(
    sysroot: &SysrootLock,
    stateroot: &str,
    image: Box<LayeredImageState>,
    spec: &HostSpec,
) -> Result<()> {
    let merge_deployment = sysroot.merge_deployment(Some(stateroot));
    let origin = glib::KeyFile::new();
    let ostree_imgref = spec
        .image
        .as_ref()
        .map(|imgref| OstreeImageReference::from(imgref.clone()));
    if let Some(imgref) = ostree_imgref.as_ref() {
        origin.set_string(
            "origin",
            ostree_container::deploy::ORIGIN_CONTAINER,
            imgref.to_string().as_str(),
        );
    }
    crate::deploy::deploy(
        sysroot,
        merge_deployment.as_ref(),
        stateroot,
        image,
        &origin,
    )
    .await?;
    crate::deploy::cleanup(sysroot).await?;
    if let Some(imgref) = ostree_imgref.as_ref() {
        println!("Queued for next boot: {imgref}");
    }
    ostree_container::deploy::remove_undeployed_images(sysroot).context("Pruning images")?;

    Ok(())
}
