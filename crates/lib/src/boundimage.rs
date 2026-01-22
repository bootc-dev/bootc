//! # Implementation of "logically bound" container images
//!
//! This module implements the design in <https://github.com/bootc-dev/bootc/issues/128>
//! for "logically bound" container images. These container images are
//! pre-pulled (and in the future, pinned) before a new image root
//! is considered ready.

use anyhow::{Context, Result};
use camino::Utf8Path;
use cap_std_ext::cap_std::fs::Dir;
use cap_std_ext::dirext::CapStdExtDirExt;
use fn_error_context::context;
use ostree_ext::containers_image_proxy;
use ostree_ext::ostree::Deployment;

use crate::podstorage::{CStorage, PullMode};
use crate::store::Storage;

/// The path in a root for bound images; this directory should only contain
/// symbolic links to `.container` or `.image` files.
const BOUND_IMAGE_DIR: &str = "usr/lib/bootc/bound-images.d";

/// A subset of data parsed from a `.image` or `.container` file with
/// the minimal information necessary to fetch the image.
///
/// In the future this may be extended to include e.g. certificates or
/// other pull options.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct BoundImage {
    pub(crate) image: String,
    pub(crate) auth_file: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ResolvedBoundImage {
    pub(crate) image: String,
    pub(crate) digest: String,
}

/// Given a deployment, pull all container images it references.
pub(crate) async fn pull_bound_images(sysroot: &Storage, deployment: &Deployment) -> Result<()> {
    // Log the bound images operation to systemd journal
    const BOUND_IMAGES_JOURNAL_ID: &str = "1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5";
    tracing::info!(
        message_id = BOUND_IMAGES_JOURNAL_ID,
        bootc.deployment.osname = deployment.osname().as_str(),
        bootc.deployment.checksum = deployment.csum().as_str(),
        "Starting pull of bound images for deployment"
    );

    let ostree = sysroot.get_ostree()?;
    let bound_images = query_bound_images_for_deployment(ostree, deployment)?;
    tracing::info!(
        message_id = BOUND_IMAGES_JOURNAL_ID,
        bootc.bound_images_count = bound_images.len(),
        "Found {} bound images to pull",
        bound_images.len()
    );
    pull_images(sysroot, bound_images).await
}

#[context("Querying bound images")]
pub(crate) fn query_bound_images_for_deployment(
    sysroot: &ostree_ext::ostree::Sysroot,
    deployment: &Deployment,
) -> Result<Vec<BoundImage>> {
    let deployment_root = &crate::utils::deployment_fd(sysroot, deployment)?;
    query_bound_images(deployment_root)
}

#[context("Querying bound images")]
pub(crate) fn query_bound_images(root: &Dir) -> Result<Vec<BoundImage>> {
    let spec_dir = BOUND_IMAGE_DIR;
    let Some(bound_images_dir) = root.open_dir_optional(spec_dir)? else {
        tracing::debug!("Missing {spec_dir}");
        return Ok(Default::default());
    };
    // And open a view of the dir that uses RESOLVE_IN_ROOT so we
    // handle absolute symlinks.
    let absroot = &root.open_dir_rooted_ext(".")?;

    let mut bound_images = Vec::new();

    for entry in bound_images_dir
        .entries()
        .context("Unable to read entries")?
    {
        //validate entry is a symlink with correct extension
        let entry = entry?;
        let file_name = entry.file_name();
        let file_name = if let Some(n) = file_name.to_str() {
            n
        } else {
            anyhow::bail!("Invalid non-UTF8 filename: {file_name:?} in {}", spec_dir);
        };

        if !entry.file_type()?.is_symlink() {
            anyhow::bail!("Not a symlink: {file_name}");
        }

        //parse the file contents
        let path = Utf8Path::new(spec_dir).join(file_name);
        let file_contents = absroot.read_to_string(&path)?;

        let file_ini = tini::Ini::from_string(&file_contents).context("Parse to ini")?;
        let file_extension = Utf8Path::new(file_name).extension();
        let bound_image = match file_extension {
            Some("image") => parse_image_file(&file_ini).with_context(|| format!("Parsing {path}")),
            Some("container") => {
                parse_container_file(&file_ini).with_context(|| format!("Parsing {path}"))
            }
            _ => anyhow::bail!("Invalid file extension: {file_name}"),
        }?;

        bound_images.push(bound_image);
    }

    Ok(bound_images)
}

impl ResolvedBoundImage {
    #[context("resolving bound image {}", src.image)]
    pub(crate) async fn from_image(src: &BoundImage) -> Result<Self> {
        let config = crate::deploy::new_proxy_config();
        let proxy = containers_image_proxy::ImageProxy::new_with_config(config).await?;
        let img = proxy
            .open_image(&format!("containers-storage:{}", src.image))
            .await?;
        let digest = proxy.fetch_manifest(&img).await?.0;
        Ok(Self {
            image: src.image.clone(),
            digest,
        })
    }
}

fn parse_image_file(file_contents: &tini::Ini) -> Result<BoundImage> {
    let image: String = file_contents
        .get("Image", "Image")
        .ok_or_else(|| anyhow::anyhow!("Missing Image field"))?;

    //TODO: auth_files have some semi-complicated edge cases that we need to handle,
    //      so for now let's bail out if we see one since the existence of an authfile
    //      will most likely result in a failure to pull the image
    let auth_file: Option<String> = file_contents.get("Image", "AuthFile");
    if auth_file.is_some() {
        anyhow::bail!("AuthFile is not supported by bound bootc images");
    }

    let bound_image = BoundImage::new(image.to_string(), None)?;
    Ok(bound_image)
}

fn parse_container_file(file_contents: &tini::Ini) -> Result<BoundImage> {
    let image: String = file_contents
        .get("Container", "Image")
        .ok_or_else(|| anyhow::anyhow!("Missing Image field"))?;

    let bound_image = BoundImage::new(image.to_string(), None)?;
    Ok(bound_image)
}

#[context("Pulling bound images")]
pub(crate) async fn pull_images(
    sysroot: &Storage,
    bound_images: Vec<crate::boundimage::BoundImage>,
) -> Result<()> {
    // Always initialize the img store to ensure labels are set when upgrading
    let imgstore = sysroot.get_ensure_imgstore()?;
    if bound_images.is_empty() {
        return Ok(());
    }
    pull_images_impl(imgstore, bound_images).await
}

#[context("Pulling bound images")]
pub(crate) async fn pull_images_impl(
    imgstore: &CStorage,
    bound_images: Vec<crate::boundimage::BoundImage>,
) -> Result<()> {
    let n = bound_images.len();
    tracing::debug!("Pulling bound images: {n}");
    // TODO: do this in parallel
    for bound_image in bound_images {
        let image = &bound_image.image;
        if imgstore.exists(image).await? {
            tracing::debug!("Bound image already present: {image}");
            continue;
        }
        let desc = format!("Fetching bound image: {image}");
        crate::utils::async_task_with_spinner(&desc, async move {
            imgstore
                .pull(&bound_image.image, PullMode::IfNotExists)
                .await
        })
        .await?;
    }

    println!("Bound images stored: {n}");

    Ok(())
}

impl BoundImage {
    fn new(image: String, auth_file: Option<String>) -> Result<BoundImage> {
        let image = parse_spec_value(&image).context("Invalid image value")?;

        let auth_file = if let Some(auth_file) = &auth_file {
            Some(parse_spec_value(auth_file).context("Invalid auth_file value")?)
        } else {
            None
        };

        Ok(BoundImage { image, auth_file })
    }
}

/// Given a string, parse it in a way similar to how systemd would do it.
/// The primary thing here is that we reject any "specifiers" such as `%a`
/// etc. We do allow a quoted `%%` to appear in the string, which will
/// result in a single unquoted `%`.
fn parse_spec_value(value: &str) -> Result<String> {
    let mut it = value.chars();
    let mut ret = String::new();
    while let Some(c) = it.next() {
        if c != '%' {
            ret.push(c);
            continue;
        }
        let c = it.next().ok_or_else(|| anyhow::anyhow!("Unterminated %"))?;
        match c {
            '%' => {
                ret.push('%');
            }
            _ => {
                anyhow::bail!("Systemd specifiers are not supported by bound bootc images: {value}")
            }
        }
    }
    Ok(ret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std_ext::cap_std;

    #[test]
    fn test_parse_spec_dir() -> Result<()> {
        const CONTAINER_IMAGE_DIR: &str = "usr/share/containers/systemd";

        // Empty dir should return an empty vector
        let td = &cap_std_ext::cap_tempfile::TempDir::new(cap_std::ambient_authority())?;
        let images = query_bound_images(td).unwrap();
        assert_eq!(images.len(), 0);

        td.create_dir_all(BOUND_IMAGE_DIR).unwrap();
        td.create_dir_all(CONTAINER_IMAGE_DIR).unwrap();
        let images = query_bound_images(td).unwrap();
        assert_eq!(images.len(), 0);

        // Should return BoundImages
        td.write(
            format!("{CONTAINER_IMAGE_DIR}/foo.image"),
            indoc::indoc! { r#"
            [Image]
            Image=quay.io/foo/foo:latest
        "# },
        )
        .unwrap();
        td.symlink_contents(
            format!("/{CONTAINER_IMAGE_DIR}/foo.image"),
            format!("{BOUND_IMAGE_DIR}/foo.image"),
        )
        .unwrap();

        td.write(
            format!("{CONTAINER_IMAGE_DIR}/bar.image"),
            indoc::indoc! { r#"
            [Image]
            Image=quay.io/bar/bar:latest
            "# },
        )
        .unwrap();
        td.symlink_contents(
            format!("/{CONTAINER_IMAGE_DIR}/bar.image"),
            format!("{BOUND_IMAGE_DIR}/bar.image"),
        )
        .unwrap();

        let mut images = query_bound_images(td).unwrap();
        images.sort_by(|a, b| a.image.as_str().cmp(&b.image.as_str()));
        assert_eq!(images.len(), 2);
        assert_eq!(images[0].image, "quay.io/bar/bar:latest");
        assert_eq!(images[1].image, "quay.io/foo/foo:latest");

        // Invalid symlink should return an error
        td.symlink("./blah", format!("{BOUND_IMAGE_DIR}/blah.image"))
            .unwrap();
        assert!(query_bound_images(td).is_err());

        // Invalid image contents should return an error
        td.write("error.image", "[Image]\n").unwrap();
        td.symlink_contents("/error.image", format!("{BOUND_IMAGE_DIR}/error.image"))
            .unwrap();
        assert!(query_bound_images(td).is_err());

        Ok(())
    }

    #[test]
    fn test_parse_spec_value() -> Result<()> {
        //should parse string with no % characters
        let value = String::from("quay.io/foo/foo:latest");
        assert_eq!(parse_spec_value(&value).unwrap(), value);

        //should parse string with % followed by another %
        let value = String::from("quay.io/foo/%%foo:latest");
        assert_eq!(parse_spec_value(&value).unwrap(), "quay.io/foo/%foo:latest");

        //should parse string with multiple separate %%
        let value = String::from("quay.io/foo/%%foo:%%latest");
        assert_eq!(
            parse_spec_value(&value).unwrap(),
            "quay.io/foo/%foo:%latest"
        );

        //should parse the string with %% at the start or end
        let value = String::from("%%quay.io/foo/foo:latest%%");
        assert_eq!(
            parse_spec_value(&value).unwrap(),
            "%quay.io/foo/foo:latest%"
        );

        //should not return an error with multiple %% in a row
        let value = String::from("quay.io/foo/%%%%foo:latest");
        assert_eq!(
            parse_spec_value(&value).unwrap(),
            "quay.io/foo/%%foo:latest"
        );

        //should return error when % is NOT followed by another %
        let value = String::from("quay.io/foo/%foo:latest");
        assert!(parse_spec_value(&value).is_err());

        //should return an error when %% is followed by a specifier
        let value = String::from("quay.io/foo/%%%foo:latest");
        assert!(parse_spec_value(&value).is_err());

        //should return an error when there are two specifiers
        let value = String::from("quay.io/foo/%f%ooo:latest");
        assert!(parse_spec_value(&value).is_err());

        //should return an error with a specifier at the start
        let value = String::from("%fquay.io/foo/foo:latest");
        assert!(parse_spec_value(&value).is_err());

        //should return an error with a specifier at the end
        let value = String::from("quay.io/foo/foo:latest%f");
        assert!(parse_spec_value(&value).is_err());

        //should return an error with a single % at the end
        let value = String::from("quay.io/foo/foo:latest%");
        assert!(parse_spec_value(&value).is_err());

        Ok(())
    }

    #[test]
    fn test_parse_image_file() -> Result<()> {
        //should return BoundImage when no auth_file is present
        let file_contents =
            tini::Ini::from_string("[Image]\nImage=quay.io/foo/foo:latest").unwrap();
        let bound_image = parse_image_file(&file_contents).unwrap();
        assert_eq!(bound_image.image, "quay.io/foo/foo:latest");
        assert_eq!(bound_image.auth_file, None);

        //should error when auth_file is present
        let file_contents = tini::Ini::from_string(indoc::indoc! { "
            [Image]
            Image=quay.io/foo/foo:latest
            AuthFile=/etc/containers/auth.json
        " })
        .unwrap();
        assert!(parse_image_file(&file_contents).is_err());

        //should return error when missing image field
        let file_contents = tini::Ini::from_string("[Image]\n").unwrap();
        assert!(parse_image_file(&file_contents).is_err());

        Ok(())
    }

    #[test]
    fn test_parse_container_file() -> Result<()> {
        //should return BoundImage
        let file_contents =
            tini::Ini::from_string("[Container]\nImage=quay.io/foo/foo:latest").unwrap();
        let bound_image = parse_container_file(&file_contents).unwrap();
        assert_eq!(bound_image.image, "quay.io/foo/foo:latest");
        assert_eq!(bound_image.auth_file, None);

        //should return error when missing image field
        let file_contents = tini::Ini::from_string("[Container]\n").unwrap();
        assert!(parse_container_file(&file_contents).is_err());

        Ok(())
    }
}
