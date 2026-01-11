//! Module used for integration tests; should not be public.

use std::path::Path;

use crate::container_utils::{is_ostree_container, ostree_booted};
use anyhow::{Context, Result, anyhow};
use camino::Utf8Path;
use cap_std::fs::Dir;
use cap_std_ext::cap_std;
use containers_image_proxy::oci_spec;
use flate2::write::GzEncoder;
use fn_error_context::context;
use gio::prelude::*;
use oci_spec::image as oci_image;
use ocidir::{
    LayerWriter,
    oci_spec::image::{Arch, Platform},
};
use ostree::gio;
use xshell::cmd;

pub(crate) fn detectenv() -> Result<&'static str> {
    let r = if is_ostree_container()? {
        "ostree-container"
    } else if ostree_booted()? {
        "ostree"
    } else if crate::container_utils::running_in_container() {
        "container"
    } else {
        "none"
    };
    Ok(r)
}

/// Using `src` as a base, take append `dir` into OCI image.
/// Should only be enabled for testing.
#[context("Generating derived oci")]
pub fn generate_derived_oci(
    src: impl AsRef<Utf8Path>,
    dir: impl AsRef<Path>,
    tag: Option<&str>,
) -> Result<()> {
    generate_derived_oci_from_tar(
        src,
        move |w| {
            let dir = dir.as_ref();
            let mut layer_tar = tar::Builder::new(w);
            layer_tar.append_dir_all("./", dir)?;
            layer_tar.finish()?;
            Ok(())
        },
        tag,
        None,
    )
}

/// Using `src` as a base, take append `dir` into OCI image.
/// Should only be enabled for testing.
#[context("Generating derived oci")]
pub fn generate_derived_oci_from_tar<F>(
    src: impl AsRef<Utf8Path>,
    f: F,
    tag: Option<&str>,
    arch: Option<Arch>,
) -> Result<()>
where
    F: for<'a> FnOnce(&mut LayerWriter<'a, GzEncoder<ocidir::BlobWriter<'a>>>) -> Result<()>,
{
    let src = src.as_ref();
    let src = Dir::open_ambient_dir(src, cap_std::ambient_authority())?;
    let src = ocidir::OciDir::open(src)?;

    let idx = src.read_index()?;
    let manifest_descriptor = idx
        .manifests()
        .first()
        .ok_or(anyhow!("No manifests in index"))?;
    let mut manifest: oci_image::ImageManifest = src
        .read_json_blob(manifest_descriptor)
        .context("Reading manifest json blob")?;
    let mut config: oci_image::ImageConfiguration = src.read_json_blob(manifest.config())?;

    if let Some(arch) = arch.as_ref() {
        config.set_architecture(arch.clone());
    }

    let mut bw = src.create_gzip_layer(None)?;
    f(&mut bw)?;
    let new_layer = bw.complete()?;

    manifest.layers_mut().push(
        new_layer
            .blob
            .descriptor()
            .media_type(oci_spec::image::MediaType::ImageLayerGzip)
            .build()
            .unwrap(),
    );
    config.history_mut().get_or_insert_default().push(
        oci_spec::image::HistoryBuilder::default()
            .created_by("generate_derived_oci")
            .build()
            .unwrap(),
    );
    config
        .rootfs_mut()
        .diff_ids_mut()
        .push(new_layer.uncompressed_sha256.digest().to_string());
    let new_config_desc = src.write_config(config)?;
    manifest.set_config(new_config_desc);

    let mut platform = Platform::default();
    if let Some(arch) = arch.as_ref() {
        platform.set_architecture(arch.clone());
    }

    if let Some(tag) = tag {
        src.insert_manifest(manifest, Some(tag), platform)?;
    } else {
        src.replace_with_single_manifest(manifest, platform)?;
    }
    Ok(())
}

fn test_proxy_auth() -> Result<()> {
    use containers_image_proxy::ImageProxyConfig;
    let merge = crate::container::merge_default_container_proxy_opts;
    let mut c = ImageProxyConfig::default();
    merge(&mut c)?;
    assert_eq!(c.authfile, None);
    std::fs::create_dir_all("/etc/ostree")?;
    let authpath = Path::new("/etc/ostree/auth.json");
    std::fs::write(authpath, "{}")?;
    let mut c = ImageProxyConfig::default();
    merge(&mut c)?;
    if rustix::process::getuid().is_root() {
        assert!(c.auth_data.is_some());
    } else {
        assert_eq!(c.authfile.unwrap().as_path(), authpath,);
    }
    let c = ImageProxyConfig {
        auth_anonymous: true,
        ..Default::default()
    };
    assert_eq!(c.authfile, None);
    std::fs::remove_file(authpath)?;
    let mut c = ImageProxyConfig::default();
    merge(&mut c)?;
    assert_eq!(c.authfile, None);
    Ok(())
}

/// Create a test fixture in the same way our unit tests does, and print
/// the location of the temporary directory.  Also export a chunked image.
/// Useful for debugging things interactively.
pub(crate) async fn create_fixture() -> Result<()> {
    let fixture = crate::fixture::Fixture::new_v1()?;
    let imgref = fixture.export_container().await?.0;
    println!("Wrote: {imgref:?}");
    let path = fixture.into_tempdir().keep();
    println!("Wrote: {path:?}");
    Ok(())
}

pub(crate) fn test_ima() -> Result<()> {
    use gvariant::aligned_bytes::TryAsAligned;
    use gvariant::{Marker, Structure, gv};

    let cancellable = gio::Cancellable::NONE;
    let fixture = crate::fixture::Fixture::new_v1()?;

    let config = indoc::indoc! { r#"
    [ req ]
    default_bits = 3048
    distinguished_name = req_distinguished_name
    prompt = no
    string_mask = utf8only
    x509_extensions = myexts
    [ req_distinguished_name ]
    O = Test
    CN = Test key
    emailAddress = example@example.com
    [ myexts ]
    basicConstraints=critical,CA:FALSE
    keyUsage=digitalSignature
    subjectKeyIdentifier=hash
    authorityKeyIdentifier=keyid
    "#};
    std::fs::write(fixture.path.join("genkey.config"), config)?;
    let sh = xshell::Shell::new()?;
    sh.change_dir(&fixture.path);
    cmd!(
        sh,
        "openssl req -new -nodes -utf8 -sha256 -days 36500 -batch -x509 -config genkey.config -outform DER -out ima.der -keyout privkey_ima.pem"
    )
    .ignore_stderr()
    .ignore_stdout()
    .run()?;

    let imaopts = crate::ima::ImaOpts {
        algorithm: "sha256".into(),
        key: fixture.path.join("privkey_ima.pem"),
        overwrite: false,
    };
    let rewritten_commit =
        crate::ima::ima_sign(fixture.srcrepo(), fixture.testref(), &imaopts).unwrap();

    let root = fixture
        .srcrepo()
        .read_commit(&rewritten_commit, cancellable)?
        .0;
    let bash = root.resolve_relative_path("/usr/bin/bash");
    let bash = bash.downcast_ref::<ostree::RepoFile>().unwrap();
    let xattrs = bash.xattrs(cancellable).unwrap();
    let v = xattrs.data_as_bytes();
    let v = v.try_as_aligned().unwrap();
    let v = gv!("a(ayay)").cast(v);
    let mut found_ima = false;
    for xattr in v.iter() {
        let k = xattr.to_tuple().0;
        if k != b"security.ima" {
            continue;
        }
        found_ima = true;
        break;
    }
    if !found_ima {
        anyhow::bail!("Failed to find IMA xattr");
    }
    println!("ok IMA");
    Ok(())
}

#[cfg(feature = "internal-testing-api")]
#[context("Running integration tests")]
pub(crate) fn run_tests() -> Result<()> {
    crate::container_utils::require_ostree_container()?;
    // When there's a new integration test to run, add it here.
    test_proxy_auth()?;
    println!("integration tests succeeded.");
    Ok(())
}
