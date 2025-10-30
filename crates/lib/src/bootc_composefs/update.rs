use anyhow::{Context, Result};
use camino::Utf8PathBuf;
use composefs::util::{parse_sha256, Sha256Digest};
use fn_error_context::context;
use ostree_ext::oci_spec::image::{ImageConfiguration, ImageManifest};

use crate::{
    bootc_composefs::{
        boot::{setup_composefs_bls_boot, setup_composefs_uki_boot, BootSetupType, BootType},
        repo::{get_imgref, open_composefs_repo, pull_composefs_repo},
        service::start_finalize_stated_svc,
        state::write_composefs_state,
        status::{composefs_deployment_status, get_container_manifest_and_config},
    },
    cli::UpgradeOpts,
    spec::ImageReference,
    store::ComposefsRepository,
};

use cap_std_ext::cap_std::{ambient_authority, fs::Dir};

#[context("Getting SHA256 Digest for {id}")]
pub fn str_to_sha256digest(id: &str) -> Result<Sha256Digest> {
    let id = id.strip_prefix("sha256:").unwrap_or(id);
    Ok(parse_sha256(&id)?)
}

/// Checks if a container image has been pulled to the local composefs repository.
///
/// This function verifies whether the specified container image exists in the local
/// composefs repository by checking if the image's configuration digest stream is
/// available. It retrieves the image manifest and configuration from the container
/// registry and uses the configuration digest to perform the local availability check.
///
/// # Arguments
///
/// * `repo` - The composefs repository
/// * `imgref` - Reference to the container image to check
///
/// # Returns
///
/// Returns a tuple containing:
/// * `true` if the image is pulled/available locally, `false` otherwise
/// * The container image manifest
/// * The container image configuration
#[context("Checking if image {} is pulled", imgref.image)]
async fn is_image_pulled(
    repo: &ComposefsRepository,
    imgref: &ImageReference,
) -> Result<(bool, ImageManifest, ImageConfiguration)> {
    let imgref_repr = get_imgref(&imgref.transport, &imgref.image);
    let (manifest, config) = get_container_manifest_and_config(&imgref_repr).await?;

    let img_digest = manifest.config().digest().digest();
    let img_sha256 = str_to_sha256digest(&img_digest)?;

    // check_stream is expensive to run, but probably a good idea
    let container_pulled = repo.check_stream(&img_sha256).context("Checking stream")?;

    Ok((container_pulled.is_some(), manifest, config))
}

#[context("Upgrading composefs")]
pub(crate) async fn upgrade_composefs(opts: UpgradeOpts) -> Result<()> {
    let host = composefs_deployment_status()
        .await
        .context("Getting composefs deployment status")?;

    let mut imgref = host
        .spec
        .image
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No image source specified"))?;

    let sysroot =
        Dir::open_ambient_dir("/sysroot", ambient_authority()).context("Opening sysroot")?;
    let repo = open_composefs_repo(&sysroot)?;

    let (img_pulled, mut manifest, mut config) = is_image_pulled(&repo, imgref).await?;
    let booted_img_digest = manifest.config().digest().digest();

    // We already have this container config. No update available
    if img_pulled {
        println!("No changes in: {imgref:#}");
        // TODO(Johan-Liebert1): What if we have the config but we failed the previous update in the middle?
        return Ok(());
    }

    // Check if we already have this update staged
    let staged_image = host.status.staged.as_ref().and_then(|i| i.image.as_ref());

    if let Some(staged_image) = staged_image {
        // We have a staged image and it has the same digest as the currently booted image's latest
        // digest
        if staged_image.image_digest == booted_img_digest {
            if opts.apply {
                return crate::reboot::reboot();
            }

            println!("Update already staged. To apply update run `bootc update --apply`");

            return Ok(());
        }

        // We have a staged image but it's not the update image.
        // Maybe it's something we got by `bootc switch`
        // Switch takes precedence over update, so we change the imgref
        imgref = &staged_image.image;

        let (img_pulled, staged_manifest, staged_cfg) = is_image_pulled(&repo, imgref).await?;
        manifest = staged_manifest;
        config = staged_cfg;

        // We already have this container config. No update available
        if img_pulled {
            println!("No changes in staged image: {imgref:#}");
            return Ok(());
        }
    }

    if opts.check {
        // TODO(Johan-Liebert1): If we have the previous, i.e. the current manifest with us then we can replace the
        // following with [`ostree_container::ManifestDiff::new`] which will be much cleaner
        for (idx, diff_id) in config.rootfs().diff_ids().iter().enumerate() {
            let diff_id = str_to_sha256digest(diff_id)?;

            // we could use `check_stream` here but that will most probably take forever as it
            // usually takes ~3s to verify one single layer
            let have_layer = repo.has_stream(&diff_id)?;

            if have_layer.is_none() {
                if idx >= manifest.layers().len() {
                    anyhow::bail!("Length mismatch between rootfs diff layers and manifest layers");
                }

                let layer = &manifest.layers()[idx];

                println!(
                    "Added layer: {}\tSize: {}",
                    layer.digest(),
                    layer.size().to_string()
                );
            }
        }

        return Ok(());
    }

    start_finalize_stated_svc()?;

    let (repo, entries, id, fs) = pull_composefs_repo(&imgref.transport, &imgref.image).await?;

    let Some(entry) = entries.iter().next() else {
        anyhow::bail!("No boot entries!");
    };

    let boot_type = BootType::from(entry);
    let mut boot_digest = None;

    match boot_type {
        BootType::Bls => {
            boot_digest = Some(setup_composefs_bls_boot(
                BootSetupType::Upgrade((&fs, &host)),
                repo,
                &id,
                entry,
            )?)
        }

        BootType::Uki => {
            setup_composefs_uki_boot(BootSetupType::Upgrade((&fs, &host)), repo, &id, entries)?
        }
    };

    write_composefs_state(
        &Utf8PathBuf::from("/sysroot"),
        id,
        imgref,
        true,
        boot_type,
        boot_digest,
    )?;

    if opts.apply {
        return crate::reboot::reboot();
    }

    Ok(())
}
