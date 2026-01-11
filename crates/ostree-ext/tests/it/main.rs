//! Main integration tests that use the public APIs.

use anyhow::{Context, Result};
use camino::Utf8Path;
use cap_std::fs::{Dir, DirBuilder, DirBuilderExt};
use cap_std_ext::cap_std;
use containers_image_proxy::oci_spec;
use gvariant::aligned_bytes::TryAsAligned;
use gvariant::{Marker, Structure};
use oci_image::ImageManifest;
use oci_spec::image as oci_image;
use ocidir::oci_spec::distribution::Reference;
use ocidir::oci_spec::image::{Arch, DigestAlgorithm};
use ostree_ext::chunking::ObjectMetaSized;
use ostree_ext::container::{
    Config, ExportOpts, ImageReference, OstreeImageReference, SignatureSource, Transport,
};
use ostree_ext::container::{ManifestDiff, OSTREE_COMMIT_LABEL, store};
use ostree_ext::prelude::{Cast, FileExt};
use ostree_ext::tar::TarImportOptions;
use ostree_ext::{fixture, ostree_manual};
use ostree_ext::{gio, glib};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::io::{BufReader, BufWriter};
use std::process::{Command, Stdio};
use std::sync::{LazyLock, OnceLock};
use std::time::SystemTime;
use xshell::cmd;

use ostree_ext::fixture::{
    CONTENTS_CHECKSUM_V0, FileDef, Fixture, LAYERS_V0_LEN, NonOstreeFixture, PKGS_V0_LEN,
};

const EXAMPLE_TAR_LAYER: &[u8] = include_bytes!("fixtures/hlinks.tar.gz");
const TEST_REGISTRY_DEFAULT: &str = "localhost:5000";

/// Check if we have skopeo
fn check_skopeo() -> bool {
    static HAVE_SKOPEO: OnceLock<bool> = OnceLock::new();
    *HAVE_SKOPEO.get_or_init(|| {
        Command::new("skopeo")
            .arg("--help")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
    })
}

#[track_caller]
fn assert_err_contains<T>(r: Result<T>, s: impl AsRef<str>) {
    let s = s.as_ref();
    let msg = format!("{:#}", r.err().expect("Expecting an error"));
    if !msg.contains(s) {
        panic!(r#"Error message "{msg}" did not contain "{s}""#);
    }
}

static TEST_REGISTRY: LazyLock<String> =
    LazyLock::new(|| match std::env::var_os("TEST_REGISTRY") {
        Some(t) => t.to_str().unwrap().to_owned(),
        None => TEST_REGISTRY_DEFAULT.to_string(),
    });

// This is mostly just sanity checking these functions are publicly accessible
#[test]
fn test_cli_fns() -> Result<()> {
    let fixture = Fixture::new_v1()?;
    let srcpath = fixture.path.join("src/repo");
    let srcrepo_parsed = ostree_ext::cli::parse_repo(&srcpath).unwrap();
    assert_eq!(srcrepo_parsed.mode(), fixture.srcrepo().mode());

    let ir =
        ostree_ext::cli::parse_imgref("ostree-unverified-registry:quay.io/examplens/exampleos")
            .unwrap();
    assert_eq!(ir.imgref.transport, Transport::Registry);

    let ir = ostree_ext::cli::parse_base_imgref("docker://quay.io/examplens/exampleos").unwrap();
    assert_eq!(ir.transport, Transport::Registry);
    Ok(())
}

#[tokio::test]
async fn test_tar_import_empty() -> Result<()> {
    let fixture = Fixture::new_v1()?;
    let r = ostree_ext::tar::import_tar(fixture.destrepo(), tokio::io::empty(), None).await;
    assert_err_contains(r, "Commit object not found");
    Ok(())
}

#[tokio::test]
async fn test_tar_export_reproducible() -> Result<()> {
    let fixture = Fixture::new_v1()?;
    let (_, rev) = fixture
        .srcrepo()
        .read_commit(fixture.testref(), gio::Cancellable::NONE)?;
    let export1 = {
        let mut h = openssl::hash::Hasher::new(openssl::hash::MessageDigest::sha256())?;
        ostree_ext::tar::export_commit(fixture.srcrepo(), rev.as_str(), &mut h, None)?;
        h.finish()?
    };
    // Artificial delay to flush out mtimes (one second granularity baseline, plus another 100ms for good measure).
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let export2 = {
        let mut h = openssl::hash::Hasher::new(openssl::hash::MessageDigest::sha256())?;
        ostree_ext::tar::export_commit(fixture.srcrepo(), rev.as_str(), &mut h, None)?;
        h.finish()?
    };
    assert_eq!(*export1, *export2);
    Ok(())
}

#[tokio::test]
async fn test_tar_import_signed() -> Result<()> {
    let fixture = Fixture::new_v1()?;
    let sh = fixture.new_shell()?;
    let test_tar = fixture.export_tar()?;

    let rev = fixture.srcrepo().require_rev(fixture.testref())?;
    let (commitv, _) = fixture.srcrepo().load_commit(rev.as_str())?;
    assert_eq!(
        ostree::commit_get_content_checksum(&commitv)
            .unwrap()
            .as_str(),
        CONTENTS_CHECKSUM_V0
    );

    // Verify we fail with an unknown remote.
    let src_tar = tokio::fs::File::from_std(fixture.dir.open(test_tar)?.into_std());
    let mut taropts = TarImportOptions::default();
    taropts.remote = Some("nosuchremote".to_string());
    let r = ostree_ext::tar::import_tar(fixture.destrepo(), src_tar, Some(taropts)).await;
    assert_err_contains(r, r#"Remote "nosuchremote" not found"#);

    // Test a remote, but without a key
    let opts = glib::VariantDict::new(None);
    opts.insert("gpg-verify", &true);
    opts.insert("custom-backend", &"ostree-rs-ext");
    fixture
        .destrepo()
        .remote_add("myremote", None, Some(&opts.end()), gio::Cancellable::NONE)?;
    let src_tar = tokio::fs::File::from_std(fixture.dir.open(test_tar)?.into_std());
    let mut taropts = TarImportOptions::default();
    taropts.remote = Some("myremote".to_string());
    let r = ostree_ext::tar::import_tar(fixture.destrepo(), src_tar, Some(taropts)).await;
    assert_err_contains(r, r#"Can't check signature: public key not found"#);

    // And signed correctly
    cmd!(
        sh,
        "ostree --repo=dest/repo remote gpg-import --stdin myremote"
    )
    .stdin(sh.read_file("src/gpghome/key1.asc")?)
    .ignore_stdout()
    .run()?;
    let src_tar = tokio::fs::File::from_std(fixture.dir.open(test_tar)?.into_std());
    let mut taropts = TarImportOptions::default();
    taropts.remote = Some("myremote".to_string());
    let imported = ostree_ext::tar::import_tar(fixture.destrepo(), src_tar, Some(taropts)).await?;
    let (commitdata, state) = fixture.destrepo().load_commit(&imported)?;
    assert_eq!(
        CONTENTS_CHECKSUM_V0,
        ostree::commit_get_content_checksum(&commitdata)
            .unwrap()
            .as_str()
    );
    assert_eq!(state, ostree::RepoCommitState::NORMAL);

    // Drop the commit metadata, and verify that import fails
    fixture.clear_destrepo()?;
    let nometa = "test-no-commitmeta.tar";
    let srcf = fixture.dir.open(test_tar)?;
    let destf = fixture.dir.create(nometa)?;
    tokio::task::spawn_blocking(move || -> Result<_> {
        let src = BufReader::new(srcf);
        let f = BufWriter::new(destf);
        ostree_ext::tar::update_detached_metadata(src, f, None, gio::Cancellable::NONE).unwrap();
        Ok(())
    })
    .await??;
    let src_tar = tokio::fs::File::from_std(fixture.dir.open(nometa)?.into_std());
    let mut taropts = TarImportOptions::default();
    taropts.remote = Some("myremote".to_string());
    let r = ostree_ext::tar::import_tar(fixture.destrepo(), src_tar, Some(taropts)).await;
    assert_err_contains(r, "Expected commitmeta object");

    // Now inject garbage into the commitmeta by flipping some bits in the signature
    let rev = fixture.srcrepo().require_rev(fixture.testref())?;
    let commitmeta = fixture
        .srcrepo()
        .read_commit_detached_metadata(&rev, gio::Cancellable::NONE)?
        .unwrap();
    let mut commitmeta = Vec::from(&*commitmeta.data_as_bytes());
    let len = commitmeta.len() / 2;
    let last = commitmeta.get_mut(len).unwrap();
    (*last) = last.wrapping_add(1);

    let srcf = fixture.dir.open(test_tar)?;
    let destf = fixture.dir.create(nometa)?;
    tokio::task::spawn_blocking(move || -> Result<_> {
        let src = BufReader::new(srcf);
        let f = BufWriter::new(destf);
        ostree_ext::tar::update_detached_metadata(
            src,
            f,
            Some(&commitmeta),
            gio::Cancellable::NONE,
        )
        .unwrap();
        Ok(())
    })
    .await??;
    let src_tar = tokio::fs::File::from_std(fixture.dir.open(nometa)?.into_std());
    let mut taropts = TarImportOptions::default();
    taropts.remote = Some("myremote".to_string());
    let r = ostree_ext::tar::import_tar(fixture.destrepo(), src_tar, Some(taropts)).await;
    assert_err_contains(r, "BAD signature");

    Ok(())
}

#[derive(Debug)]
struct TarExpected {
    path: &'static str,
    etype: tar::EntryType,
    mode: u32,
    should_have_security_capability: bool,
}

#[allow(clippy::from_over_into)]
impl Into<TarExpected> for (&'static str, tar::EntryType, u32) {
    fn into(self) -> TarExpected {
        TarExpected {
            path: self.0,
            etype: self.1,
            mode: self.2,
            should_have_security_capability: false,
        }
    }
}

#[allow(clippy::from_over_into)]
impl Into<TarExpected> for (&'static str, tar::EntryType, u32, bool) {
    fn into(self) -> TarExpected {
        TarExpected {
            path: self.0,
            etype: self.1,
            mode: self.2,
            should_have_security_capability: self.3,
        }
    }
}

fn validate_tar_expected<T: std::io::Read>(
    t: &mut tar::Entries<T>,
    expected: impl IntoIterator<Item = TarExpected>,
) -> Result<()> {
    let mut expected: HashMap<&'static str, TarExpected> =
        expected.into_iter().map(|exp| (exp.path, exp)).collect();
    let entries = t.map(|e| e.unwrap());
    let mut seen_paths = HashSet::new();
    // Verify we're injecting directories, fixes the absence of `/tmp` in our
    // images for example.
    for mut entry in entries {
        if expected.is_empty() {
            return Ok(());
        }
        let header = entry.header();
        let entry_path = entry.path().unwrap().to_string_lossy().into_owned();
        if seen_paths.contains(&entry_path) {
            anyhow::bail!("Duplicate path: {}", entry_path);
        }
        seen_paths.insert(entry_path.clone());
        if let Some(exp) = expected.remove(entry_path.as_str()) {
            assert_eq!(header.entry_type(), exp.etype, "{entry_path}");
            let expected_mode = exp.mode;
            let header_mode = header.mode().unwrap();
            assert_eq!(
                header_mode,
                expected_mode,
                "h={header_mode:o} e={expected_mode:o} type: {:?} path: {}",
                header.entry_type(),
                entry_path
            );
            if exp.should_have_security_capability {
                let pax = entry
                    .pax_extensions()?
                    .ok_or_else(|| anyhow::anyhow!("Missing pax extensions for {entry_path}"))?;
                let mut found = false;
                for ent in pax {
                    let ent = ent?;
                    if ent.key_bytes() != b"SCHILY.xattr.security.capability" {
                        continue;
                    }
                    found = true;
                    break;
                }
                assert!(found, "Expected security.capability in {entry_path}");
            }
        }
    }

    assert!(expected.is_empty(), "Expected but not found:\n{expected:?}");
    Ok(())
}

fn common_tar_structure() -> impl Iterator<Item = TarExpected> {
    use tar::EntryType::Directory;
    [
        ("sysroot/ostree/repo/objects/00", Directory, 0o755),
        ("sysroot/ostree/repo/objects/23", Directory, 0o755),
        ("sysroot/ostree/repo/objects/77", Directory, 0o755),
        ("sysroot/ostree/repo/objects/bc", Directory, 0o755),
        ("sysroot/ostree/repo/objects/ff", Directory, 0o755),
        ("sysroot/ostree/repo/refs", Directory, 0o755),
        ("sysroot/ostree/repo/refs", Directory, 0o755),
        ("sysroot/ostree/repo/refs/heads", Directory, 0o755),
        ("sysroot/ostree/repo/refs/mirrors", Directory, 0o755),
        ("sysroot/ostree/repo/refs/remotes", Directory, 0o755),
        ("sysroot/ostree/repo/state", Directory, 0o755),
        ("sysroot/ostree/repo/tmp", Directory, 0o755),
        ("sysroot/ostree/repo/tmp/cache", Directory, 0o755),
    ]
    .into_iter()
    .map(Into::into)
}

// Find various expected files
fn common_tar_contents_all() -> impl Iterator<Item = TarExpected> {
    use tar::EntryType::{Directory, Link, Regular};
    [
        ("boot", Directory, 0o755),
        ("usr", Directory, 0o755),
        ("usr/lib/emptyfile", Regular, 0o644),
        ("usr/lib64/emptyfile2", Regular, 0o644),
        ("usr/bin/bash", Link, 0o755),
        ("usr/bin/hardlink-a", Link, 0o644),
        ("usr/bin/hardlink-b", Link, 0o644),
        ("var/tmp", Directory, 0o1777),
    ]
    .into_iter()
    .map(Into::into)
    .chain(std::iter::once(
        ("sysroot/ostree/repo/objects/b0/48a4f451e9fdfaaec911c1fe07d5d1d39be02f932b827c25458d3b15ae589e.file", Regular, 0o755, true).into(),
    ))
}

/// Validate metadata (prelude) in a v1 tar.
fn validate_tar_v1_metadata<R: std::io::Read>(src: &mut tar::Entries<R>) -> Result<()> {
    use tar::EntryType::{Directory, Regular};
    let prelude = [
        ("sysroot/ostree/repo", Directory, 0o755),
        ("sysroot/ostree/repo/config", Regular, 0o644),
    ]
    .into_iter()
    .map(Into::into);

    validate_tar_expected(src, common_tar_structure().chain(prelude))?;

    Ok(())
}

/// Validate basic structure of the tar export.
#[test]
fn test_tar_export_structure() -> Result<()> {
    let fixture = Fixture::new_v1()?;

    let src_tar = fixture.export_tar()?;
    std::fs::copy(fixture.path.join(src_tar), "/tmp/test.tar").unwrap();
    let mut src_tar = fixture
        .dir
        .open(src_tar)
        .map(BufReader::new)
        .map(tar::Archive::new)?;
    let mut src_tar = src_tar.entries()?;
    validate_tar_v1_metadata(&mut src_tar).unwrap();
    validate_tar_expected(&mut src_tar, common_tar_contents_all())?;

    Ok(())
}

#[tokio::test]
async fn test_tar_import_export() -> Result<()> {
    let fixture = Fixture::new_v1()?;
    let sh = fixture.new_shell()?;
    let p = fixture.export_tar()?;
    let src_tar = tokio::fs::File::from_std(fixture.dir.open(p)?.into_std());

    let imported_commit: String =
        ostree_ext::tar::import_tar(fixture.destrepo(), src_tar, None).await?;
    let (commitdata, _) = fixture.destrepo().load_commit(&imported_commit)?;
    assert_eq!(
        CONTENTS_CHECKSUM_V0,
        ostree::commit_get_content_checksum(&commitdata)
            .unwrap()
            .as_str()
    );
    cmd!(sh, "ostree --repo=dest/repo ls -R {imported_commit}")
        .ignore_stdout()
        .run()?;
    let val = cmd!(sh, "ostree --repo=dest/repo show --print-detached-metadata-key=my-detached-key {imported_commit}").read()?;
    assert_eq!(val.as_str(), "'my-detached-value'");

    let (root, _) = fixture
        .destrepo()
        .read_commit(&imported_commit, gio::Cancellable::NONE)?;
    let kdir = ostree_ext::bootabletree::find_kernel_dir(&root, gio::Cancellable::NONE)?;
    let kdir = kdir.unwrap();
    assert_eq!(
        kdir.basename().unwrap().to_str().unwrap(),
        "5.10.18-200.x86_64"
    );

    Ok(())
}

#[tokio::test]
async fn test_tar_write() -> Result<()> {
    let fixture = Fixture::new_v1()?;
    let sh = fixture.new_shell()?;
    // Test translating /etc to /usr/etc
    fixture.dir.create_dir_all("tmproot/etc")?;
    let tmproot = &fixture.dir.open_dir("tmproot")?;
    let tmpetc = tmproot.open_dir("etc")?;
    tmpetc.write("someconfig.conf", b"some config")?;
    tmproot.create_dir_all("var/log")?;
    let tmpvarlog = tmproot.open_dir("var/log")?;
    tmpvarlog.write("foo.log", "foolog")?;
    tmpvarlog.write("bar.log", "barlog")?;
    tmproot.create_dir("run")?;
    tmproot.write("run/somefile", "somestate")?;
    let tmptar = "testlayer.tar";
    cmd!(sh, "tar cf {tmptar} -C tmproot .").run()?;
    let src = fixture.dir.open(tmptar)?;
    fixture.dir.remove_file(tmptar)?;
    let src = tokio::fs::File::from_std(src.into_std());
    let r = ostree_ext::tar::write_tar(
        fixture.destrepo(),
        src,
        oci_image::MediaType::ImageLayer,
        "layer",
        None,
    )
    .await?;
    let layer_commit = r.commit.as_str();
    cmd!(
        sh,
        "ostree --repo=dest/repo ls {layer_commit} /usr/etc/someconfig.conf"
    )
    .ignore_stdout()
    .run()?;
    assert_eq!(r.filtered.len(), 1);
    assert!(r.filtered.get("var").is_none());
    // TODO: change filter_tar to properly make this run/somefile, but eh...we're
    // just going to accept this stuff in the future but ignore it anyways.
    assert_eq!(*r.filtered.get("somefile").unwrap(), 1);

    Ok(())
}

#[tokio::test]
async fn test_tar_write_tar_layer() -> Result<()> {
    let fixture = Fixture::new_v1()?;
    let mut v = Vec::new();
    let mut dec = flate2::bufread::GzDecoder::new(std::io::Cursor::new(EXAMPLE_TAR_LAYER));
    let _n = std::io::copy(&mut dec, &mut v)?;
    let r = tokio::io::BufReader::new(std::io::Cursor::new(v));
    ostree_ext::tar::write_tar(
        fixture.destrepo(),
        r,
        oci_image::MediaType::ImageLayer,
        "test",
        None,
    )
    .await?;
    Ok(())
}

fn skopeo_inspect(imgref: &str) -> Result<String> {
    let out = Command::new("skopeo")
        .args(["inspect", imgref])
        .stdout(std::process::Stdio::piped())
        .output()?;
    Ok(String::from_utf8(out.stdout)?)
}

fn skopeo_inspect_config(imgref: &str) -> Result<oci_spec::image::ImageConfiguration> {
    let out = Command::new("skopeo")
        .args(["inspect", "--config", imgref])
        .stdout(std::process::Stdio::piped())
        .output()?;
    Ok(serde_json::from_slice(&out.stdout)?)
}

async fn impl_test_container_import_export(chunked: bool) -> Result<()> {
    let fixture = Fixture::new_v1()?;
    let sh = fixture.new_shell()?;
    let testrev = fixture
        .srcrepo()
        .require_rev(fixture.testref())
        .context("Failed to resolve ref")?;

    let srcoci_path = &fixture.path.join("oci");
    let srcoci_imgref = ImageReference {
        transport: Transport::OciDir,
        name: srcoci_path.as_str().to_string(),
    };
    let config = Config {
        labels: Some(
            [("foo", "bar"), ("test", "value")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        ),
        ..Default::default()
    };
    // If chunking is requested, compute object ownership and size mappings
    let contentmeta = chunked
        .then(|| {
            let meta = fixture.get_object_meta().context("Computing object meta")?;
            ObjectMetaSized::compute_sizes(fixture.srcrepo(), meta).context("Computing sizes")
        })
        .transpose()?;
    let mut opts = ExportOpts::default();
    let container_config = oci_spec::image::ConfigBuilder::default()
        .stop_signal("SIGRTMIN+3")
        .build()
        .unwrap();
    opts.copy_meta_keys = vec!["buildsys.checksum".to_string()];
    opts.copy_meta_opt_keys = vec!["nosuchvalue".to_string()];
    opts.max_layers = std::num::NonZeroU32::new(PKGS_V0_LEN as u32);
    opts.package_contentmeta = contentmeta.as_ref();
    opts.container_config = Some(container_config);
    let digest = ostree_ext::container::encapsulate(
        fixture.srcrepo(),
        fixture.testref(),
        &config,
        Some(opts),
        &srcoci_imgref,
    )
    .await
    .context("exporting")?;
    assert!(srcoci_path.exists());

    let inspect = skopeo_inspect(&srcoci_imgref.to_string())?;
    // Legacy path includes this
    assert!(!inspect.contains(r#""version": "42.0""#));
    // Also include the new standard version
    assert!(inspect.contains(r#""org.opencontainers.image.version": "42.0""#));
    assert!(inspect.contains(r#""foo": "bar""#));
    assert!(inspect.contains(r#""test": "value""#));
    assert!(inspect.contains(
        r#""buildsys.checksum": "41af286dc0b172ed2f1ca934fd2278de4a1192302ffa07087cea2682e7d372e3""#
    ));
    let cfg = skopeo_inspect_config(&srcoci_imgref.to_string())?;
    let creation_time =
        chrono::NaiveDateTime::parse_from_str(cfg.created().as_deref().unwrap(), "%+").unwrap();
    assert_eq!(creation_time.and_utc().timestamp(), 872879442);
    let found_cfg = cfg.config().as_ref().unwrap();
    // unwrap.  Unwrap.  UnWrap.  UNWRAP!!!!!!!
    assert_eq!(
        found_cfg
            .cmd()
            .as_ref()
            .unwrap()
            .first()
            .as_ref()
            .unwrap()
            .as_str(),
        "/usr/bin/bash"
    );
    assert_eq!(found_cfg.stop_signal().as_deref().unwrap(), "SIGRTMIN+3");

    let n_chunks = if chunked { LAYERS_V0_LEN } else { 1 };
    assert_eq!(cfg.rootfs().diff_ids().len(), n_chunks);
    assert_eq!(cfg.history().as_ref().unwrap().len(), n_chunks);

    // Verify exporting to ociarchive
    {
        let archivepath = &fixture.path.join("export.ociarchive");
        let ociarchive_dest = ImageReference {
            transport: Transport::OciArchive,
            name: archivepath.as_str().to_string(),
        };
        let _: oci_image::Digest = ostree_ext::container::encapsulate(
            fixture.srcrepo(),
            fixture.testref(),
            &config,
            None,
            &ociarchive_dest,
        )
        .await
        .context("exporting to ociarchive")
        .unwrap();
        assert!(archivepath.is_file());
    }

    let srcoci_unverified = OstreeImageReference {
        sigverify: SignatureSource::ContainerPolicyAllowInsecure,
        imgref: srcoci_imgref.clone(),
    };

    let (_, pushed_digest) = ostree_ext::container::fetch_manifest(&srcoci_unverified).await?;
    assert_eq!(pushed_digest, digest);

    let (_, pushed_digest, _config) =
        ostree_ext::container::fetch_manifest_and_config(&srcoci_unverified).await?;
    assert_eq!(pushed_digest, digest);

    // No remote matching
    let srcoci_unknownremote = OstreeImageReference {
        sigverify: SignatureSource::OstreeRemote("unknownremote".to_string()),
        imgref: srcoci_imgref.clone(),
    };
    let r = ostree_ext::container::unencapsulate(fixture.destrepo(), &srcoci_unknownremote)
        .await
        .context("importing");
    assert_err_contains(r, r#"Remote "unknownremote" not found"#);

    // Test with a signature
    let opts = glib::VariantDict::new(None);
    opts.insert("gpg-verify", &true);
    opts.insert("custom-backend", &"ostree-rs-ext");
    fixture
        .destrepo()
        .remote_add("myremote", None, Some(&opts.end()), gio::Cancellable::NONE)?;
    cmd!(
        sh,
        "ostree --repo=dest/repo remote gpg-import --stdin myremote"
    )
    .stdin(sh.read_file("src/gpghome/key1.asc")?)
    .run()?;
    let srcoci_verified = OstreeImageReference {
        sigverify: SignatureSource::OstreeRemote("myremote".to_string()),
        imgref: srcoci_imgref.clone(),
    };
    let import = ostree_ext::container::unencapsulate(fixture.destrepo(), &srcoci_verified)
        .await
        .context("importing")?;
    assert_eq!(import.ostree_commit, testrev.as_str());

    let temp_unsigned = ImageReference {
        transport: Transport::OciDir,
        name: fixture.path.join("unsigned.ocidir").to_string(),
    };
    let _ = ostree_ext::container::update_detached_metadata(&srcoci_imgref, &temp_unsigned, None)
        .await
        .unwrap();
    let temp_unsigned = OstreeImageReference {
        sigverify: SignatureSource::OstreeRemote("myremote".to_string()),
        imgref: temp_unsigned,
    };
    fixture.clear_destrepo()?;
    let r = ostree_ext::container::unencapsulate(fixture.destrepo(), &temp_unsigned).await;
    assert_err_contains(r, "Expected commitmeta object");

    // Test without signature verification
    // Create a new repo
    {
        let fixture = Fixture::new_v1()?;
        let import = ostree_ext::container::unencapsulate(fixture.destrepo(), &srcoci_unverified)
            .await
            .context("importing")?;
        assert_eq!(import.ostree_commit, testrev.as_str());
    }

    Ok(())
}

#[tokio::test]
async fn test_export_as_container_nonderived() -> Result<()> {
    if !check_skopeo() {
        return Ok(());
    }
    let fixture = Fixture::new_v1()?;
    // Export into an OCI directory
    let src_imgref = fixture.export_container().await.unwrap().0;

    let initimport = fixture.must_import(&src_imgref).await?;
    let initimport_ls = fixture::ostree_ls(fixture.destrepo(), &initimport.merge_commit).unwrap();

    let exported_ocidir_name = "exported.ocidir";
    let dest = ImageReference {
        transport: Transport::OciDir,
        name: format!("{}:exported-test", fixture.path.join(exported_ocidir_name)),
    };
    fixture.dir.create_dir(exported_ocidir_name)?;
    let ocidir = ocidir::OciDir::ensure(fixture.dir.open_dir(exported_ocidir_name)?)?;
    let exported = store::export(fixture.destrepo(), &src_imgref, &dest, None)
        .await
        .unwrap();

    let idx = ocidir.read_index()?;
    let desc = idx.manifests().first().unwrap();
    let new_manifest: oci_image::ImageManifest = ocidir.read_json_blob(desc).unwrap();

    assert_eq!(desc.digest().to_string(), exported.to_string());
    assert_eq!(new_manifest.layers().len(), fixture::LAYERS_V0_LEN);

    // Reset the destrepo
    fixture.clear_destrepo()?;
    // Clear out the original source
    std::fs::remove_dir_all(src_imgref.name.as_str())?;

    let reimported = fixture.must_import(&dest).await?;
    let reimport_ls = fixture::ostree_ls(fixture.destrepo(), &reimported.merge_commit).unwrap();
    similar_asserts::assert_eq!(initimport_ls, reimport_ls);
    Ok(())
}

/// Verify that fetches of a digested pull spec don't do networking
#[tokio::test]
async fn test_no_fetch_digested() -> Result<()> {
    if !check_skopeo() {
        return Ok(());
    }
    let fixture = Fixture::new_v1()?;
    let (src_imgref_oci, expected_digest) = fixture.export_container().await.unwrap();
    let mut imp = store::ImageImporter::new(
        fixture.destrepo(),
        &OstreeImageReference {
            sigverify: SignatureSource::ContainerPolicyAllowInsecure,
            imgref: src_imgref_oci.clone(),
        },
        Default::default(),
    )
    .await
    .unwrap();
    // Because oci: transport doesn't allow digested pull specs, we pull from OCI, but set the target
    // to a registry.
    let target_imgref_name = Reference::with_digest(
        "quay.io/exampleos".into(),
        "example".into(),
        expected_digest.to_string(),
    );
    let target_imgref = ImageReference {
        transport: Transport::Registry,
        name: target_imgref_name.to_string(),
    };
    let target_imgref = OstreeImageReference {
        sigverify: SignatureSource::ContainerPolicyAllowInsecure,
        imgref: target_imgref,
    };
    imp.set_target(&target_imgref);
    let prep = match imp.prepare().await? {
        store::PrepareResult::AlreadyPresent(_) => unreachable!(),
        store::PrepareResult::Ready(prep) => prep,
    };
    let r = imp.import(prep).await.unwrap();
    assert_eq!(r.manifest_digest, expected_digest);
    let mut imp = store::ImageImporter::new(fixture.destrepo(), &target_imgref, Default::default())
        .await
        .unwrap();
    // And the key test, we shouldn't reach out to the registry here
    imp.set_offline();
    match imp.prepare().await.context("Init prep derived").unwrap() {
        store::PrepareResult::AlreadyPresent(_) => {}
        store::PrepareResult::Ready(_) => panic!("Should have image already"),
    };

    Ok(())
}

#[tokio::test]
async fn test_export_as_container_derived() -> Result<()> {
    if !check_skopeo() {
        return Ok(());
    }
    let fixture = Fixture::new_v1()?;
    // Export into an OCI directory
    let src_imgref = fixture.export_container().await.unwrap().0;
    // Add a derived layer
    let derived_tag = "derived";
    // Build a derived image
    let srcpath = src_imgref.name.as_str();
    fixture.generate_test_derived_oci(srcpath, Some(&derived_tag))?;
    let derived_imgref = ImageReference {
        transport: src_imgref.transport,
        name: format!("{}:{derived_tag}", src_imgref.name.as_str()),
    };

    // The first import into destrepo of the derived OCI
    let initimport = fixture.must_import(&derived_imgref).await?;
    let initimport_ls = fixture::ostree_ls(fixture.destrepo(), &initimport.merge_commit).unwrap();
    // Export it
    let exported_ocidir_name = "exported.ocidir";
    let dest = ImageReference {
        transport: Transport::OciDir,
        name: format!("{}:exported-test", fixture.path.join(exported_ocidir_name)),
    };
    fixture.dir.create_dir(exported_ocidir_name)?;
    let ocidir = ocidir::OciDir::ensure(fixture.dir.open_dir(exported_ocidir_name)?)?;
    let exported = store::export(fixture.destrepo(), &derived_imgref, &dest, None)
        .await
        .unwrap();

    let idx = ocidir.read_index()?;
    let desc = idx.manifests().first().unwrap();
    let new_manifest: oci_image::ImageManifest = ocidir.read_json_blob(desc).unwrap();

    assert_eq!(desc.digest().digest(), exported.digest());
    assert_eq!(new_manifest.layers().len(), fixture::LAYERS_V0_LEN + 1);

    // Reset the destrepo
    fixture.clear_destrepo()?;
    // Clear out the original source
    std::fs::remove_dir_all(srcpath)?;

    let reimported = fixture.must_import(&dest).await?;
    let reimport_ls = fixture::ostree_ls(fixture.destrepo(), &reimported.merge_commit).unwrap();
    similar_asserts::assert_eq!(initimport_ls, reimport_ls);

    Ok(())
}

/// Verify that when we export a container image, /etc content is properly
/// remapped from /usr/etc back to /etc in the exported OCI layers.
/// This is a regression test for https://github.com/bootc-dev/bootc/issues/1864
#[tokio::test]
async fn test_export_etc_remapping() -> Result<()> {
    if !check_skopeo() {
        return Ok(());
    }
    let fixture = Fixture::new_v1()?;
    // Export into an OCI directory
    let src_imgref = fixture.export_container().await.unwrap().0;

    // Build a derived image with /etc content
    let derived_path = &fixture.path.join("derived.oci");
    let srcpath = src_imgref.name.as_str();
    oci_clone(srcpath, derived_path).await.unwrap();
    let test_etc_content = "test etc content for export";
    ostree_ext::integrationtest::generate_derived_oci_from_tar(
        derived_path,
        |w| {
            let mut layer_tar = tar::Builder::new(w);
            let mut h = tar::Header::new_gnu();
            h.set_uid(0);
            h.set_gid(0);
            h.set_size(0);
            h.set_mode(0o755);
            h.set_entry_type(tar::EntryType::Directory);
            layer_tar.append_data(&mut h.clone(), "etc", &mut std::io::empty())?;
            h.set_mode(0o644);
            h.set_size(test_etc_content.len().try_into().unwrap());
            h.set_entry_type(tar::EntryType::Regular);
            layer_tar.append_data(
                &mut h.clone(),
                "etc/export-test.conf",
                std::io::Cursor::new(test_etc_content.as_bytes()),
            )?;
            layer_tar.finish()?;
            Ok(())
        },
        None,
        None,
    )?;

    let derived_imgref = ImageReference {
        transport: Transport::OciDir,
        name: derived_path.to_string(),
    };

    // Import the derived image into the ostree store
    let initimport = fixture.must_import(&derived_imgref).await?;

    // Verify the file is in /usr/etc in the ostree commit (as expected)
    {
        let r = fixture
            .destrepo()
            .read_commit(&initimport.merge_commit, gio::Cancellable::NONE)?
            .0;
        let testfile = r.resolve_relative_path("usr/etc/export-test.conf");
        let testfile = testfile.downcast_ref::<ostree::RepoFile>().unwrap();
        testfile.ensure_resolved()?;
    }

    // Export it via store::export
    let exported_ocidir_name = "exported.ocidir";
    let dest = ImageReference {
        transport: Transport::OciDir,
        name: format!("{}:exported-test", fixture.path.join(exported_ocidir_name)),
    };
    fixture.dir.create_dir(exported_ocidir_name)?;
    let ocidir = ocidir::OciDir::ensure(fixture.dir.open_dir(exported_ocidir_name)?)?;
    let _exported = store::export(fixture.destrepo(), &derived_imgref, &dest, None)
        .await
        .unwrap();

    // Now verify the exported image has /etc/export-test.conf (not /usr/etc/export-test.conf)
    let idx = ocidir.read_index()?;
    let desc = idx.manifests().first().unwrap();
    let manifest: oci_image::ImageManifest = ocidir.read_json_blob(desc).unwrap();

    // Check all layers for our test file
    let mut found_etc_file = false;
    let mut found_usr_etc_file = false;
    for layer in manifest.layers() {
        let mut blob = ocidir
            .read_blob(layer)
            .map(BufReader::new)
            .map(flate2::read::GzDecoder::new)
            .map(tar::Archive::new)?;
        for entry in blob.entries()? {
            let entry = entry?;
            let path = entry.path()?;
            let path_str = path.to_string_lossy();
            if path_str == "etc/export-test.conf" {
                found_etc_file = true;
            }
            if path_str == "usr/etc/export-test.conf" {
                found_usr_etc_file = true;
            }
        }
    }

    // The file should be in /etc, not /usr/etc
    assert!(
        found_etc_file,
        "Expected /etc/export-test.conf in exported image, found_usr_etc_file={found_usr_etc_file}"
    );
    assert!(
        !found_usr_etc_file,
        "Did not expect /usr/etc/export-test.conf in exported image"
    );

    Ok(())
}

#[tokio::test]
async fn test_unencapsulate_unbootable() -> Result<()> {
    if !check_skopeo() {
        return Ok(());
    }
    let fixture = {
        let mut fixture = Fixture::new_base()?;
        fixture.bootable = false;
        fixture.commit_filedefs(FileDef::iter_from(ostree_ext::fixture::CONTENTS_V0))?;
        fixture
    };
    let testrev = fixture
        .srcrepo()
        .require_rev(fixture.testref())
        .context("Failed to resolve ref")?;
    let srcoci_path = &fixture.path.join("oci");
    let srcoci_imgref = ImageReference {
        transport: Transport::OciDir,
        name: srcoci_path.as_str().to_string(),
    };
    let srcoci_unverified = OstreeImageReference {
        sigverify: SignatureSource::ContainerPolicyAllowInsecure,
        imgref: srcoci_imgref.clone(),
    };

    let config = Config::default();
    let _digest = ostree_ext::container::encapsulate(
        fixture.srcrepo(),
        fixture.testref(),
        &config,
        None,
        &srcoci_imgref,
    )
    .await
    .context("exporting")?;
    assert!(srcoci_path.exists());

    assert!(
        fixture
            .destrepo()
            .resolve_rev(fixture.testref(), true)
            .unwrap()
            .is_none()
    );

    let target = ostree_ext::container::unencapsulate(fixture.destrepo(), &srcoci_unverified)
        .await
        .unwrap();

    assert_eq!(target.ostree_commit.as_str(), testrev.as_str());

    Ok(())
}

/// Parse a chunked container image and validate its structure; particularly
fn validate_chunked_structure(oci_path: &Utf8Path) -> Result<()> {
    use tar::EntryType::Link;

    let d = Dir::open_ambient_dir(oci_path, cap_std::ambient_authority())?;
    let d = ocidir::OciDir::open(d)?;
    let idx = d.read_index()?;
    let desc = idx.manifests().first().unwrap();
    let manifest: oci_image::ImageManifest = d.read_json_blob(desc).unwrap();

    assert_eq!(manifest.layers().len(), LAYERS_V0_LEN);
    let ostree_layer = manifest.layers().first().unwrap();
    let mut ostree_layer_blob = d
        .read_blob(ostree_layer)
        .map(BufReader::new)
        .map(flate2::read::GzDecoder::new)
        .map(tar::Archive::new)?;
    let mut ostree_layer_blob = ostree_layer_blob.entries()?;
    validate_tar_v1_metadata(&mut ostree_layer_blob)?;

    // This layer happens to be first
    let pkgdb_layer_offset = 1;
    let pkgdb_layer = &manifest.layers()[pkgdb_layer_offset];
    let mut pkgdb_blob = d
        .read_blob(pkgdb_layer)
        .map(BufReader::new)
        .map(flate2::read::GzDecoder::new)
        .map(tar::Archive::new)?;

    let pkgdb = [
        ("usr/lib/pkgdb/pkgdb", Link, 0o644),
        ("usr/lib/sysimage/pkgdb", Link, 0o644),
    ]
    .into_iter()
    .map(Into::into);

    validate_tar_expected(&mut pkgdb_blob.entries()?, pkgdb)?;

    Ok(())
}

#[tokio::test]
async fn test_container_arch_mismatch() -> Result<()> {
    if !check_skopeo() {
        return Ok(());
    }
    let fixture = Fixture::new_v1()?;

    let imgref = fixture.export_container().await.unwrap().0;

    // Build a derived image
    let derived_path = &fixture.path.join("derived.oci");
    let srcpath = imgref.name.as_str();
    oci_clone(srcpath, derived_path).await.unwrap();
    ostree_ext::integrationtest::generate_derived_oci_from_tar(
        derived_path,
        |w| {
            let mut layer_tar = tar::Builder::new(w);
            let mut h = tar::Header::new_gnu();
            h.set_uid(0);
            h.set_gid(0);
            h.set_size(0);
            h.set_mode(0o755);
            h.set_entry_type(tar::EntryType::Directory);
            layer_tar.append_data(
                &mut h.clone(),
                "etc/mips-operating-system",
                &mut std::io::empty(),
            )?;
            layer_tar.into_inner()?;
            Ok(())
        },
        None,
        Some(Arch::Mips64le),
    )?;

    let derived_imgref = OstreeImageReference {
        sigverify: SignatureSource::ContainerPolicyAllowInsecure,
        imgref: ImageReference {
            transport: Transport::OciDir,
            name: derived_path.to_string(),
        },
    };
    let mut imp =
        store::ImageImporter::new(fixture.destrepo(), &derived_imgref, Default::default()).await?;
    imp.require_bootable();
    imp.set_ostree_version(2023, 11);
    let r = imp.prepare().await;
    assert_err_contains(r, "Image has architecture mips64le");

    Ok(())
}

#[tokio::test]
async fn test_container_chunked() -> Result<()> {
    if !check_skopeo() {
        return Ok(());
    }
    let nlayers = LAYERS_V0_LEN - 1;
    let mut fixture = Fixture::new_v1()?;

    let (imgref, expected_digest) = fixture.export_container().await.unwrap();
    let exported_commit = fixture.srcrepo().require_rev(fixture.testref())?;
    let imgref = OstreeImageReference {
        sigverify: SignatureSource::ContainerPolicyAllowInsecure,
        imgref,
    };
    // Validate the structure of the image
    match &imgref.imgref {
        ImageReference {
            transport: Transport::OciDir,
            name,
        } => validate_chunked_structure(Utf8Path::new(name)).unwrap(),
        _ => unreachable!(),
    };

    let mut imp =
        store::ImageImporter::new(fixture.destrepo(), &imgref, Default::default()).await?;
    assert!(
        store::query_image(fixture.destrepo(), &imgref.imgref)
            .unwrap()
            .is_none()
    );
    let prep = match imp.prepare().await.context("Init prep derived")? {
        store::PrepareResult::AlreadyPresent(_) => panic!("should not be already imported"),
        store::PrepareResult::Ready(r) => r,
    };
    let labels = prep.config.labels_of_config().unwrap();
    assert!(prep.deprecated_warning().is_none());
    assert_eq!(
        labels.get(OSTREE_COMMIT_LABEL).unwrap(),
        exported_commit.as_str()
    );
    assert_eq!(prep.version(), Some("42.0"));
    let digest = prep.manifest_digest.clone();
    assert!(prep.ostree_commit_layer.as_ref().unwrap().commit.is_none());
    assert_eq!(prep.ostree_layers.len(), nlayers);
    assert_eq!(prep.layers.len(), 0);
    for layer in prep.layers.iter() {
        assert!(layer.commit.is_none());
    }
    assert_eq!(digest, expected_digest);
    {
        let mut layer_history = prep.layers_with_history();
        assert!(
            layer_history
                .next()
                .unwrap()?
                .1
                .created_by()
                .as_ref()
                .unwrap()
                .starts_with("ostree export")
        );
        assert_eq!(
            layer_history
                .next()
                .unwrap()?
                .1
                .created_by()
                .as_ref()
                .unwrap(),
            "9 components"
        );
    }
    let import = imp.import(prep).await.context("Init pull derived").unwrap();
    assert_eq!(import.manifest_digest, digest);
    // For now we never expect that these are the same
    assert_ne!(import.get_commit(), exported_commit.as_str());
    // But the parent should match
    let commit_obj = fixture.destrepo().load_commit(import.get_commit())?.0;
    assert_eq!(
        ostree::commit_get_parent(&commit_obj).unwrap(),
        exported_commit.as_str()
    );

    assert_eq!(store::list_images(fixture.destrepo()).unwrap().len(), 1);

    assert!(
        store::image_filtered_content_warning(&import.filtered_files)
            .unwrap()
            .is_none()
    );
    // Verify there are no updates.
    let mut imp =
        store::ImageImporter::new(fixture.destrepo(), &imgref, Default::default()).await?;
    let state = match imp.prepare().await? {
        store::PrepareResult::AlreadyPresent(i) => i,
        store::PrepareResult::Ready(_) => panic!("should be already imported"),
    };
    assert!(state.cached_update.is_none());

    const ADDITIONS: &str = indoc::indoc! { "
r usr/bin/bash bash-v0
"};
    fixture
        .update(FileDef::iter_from(ADDITIONS), std::iter::empty())
        .context("Failed to update")?;

    let expected_digest = fixture.export_container().await.unwrap().1;
    assert_ne!(digest, expected_digest);

    let mut imp =
        store::ImageImporter::new(fixture.destrepo(), &imgref, Default::default()).await?;
    let prep = match imp.prepare().await.context("Init prep derived")? {
        store::PrepareResult::AlreadyPresent(_) => panic!("should not be already imported"),
        store::PrepareResult::Ready(r) => r,
    };
    // Verify we also serialized the cached update
    {
        let cached = store::query_image(fixture.destrepo(), &imgref.imgref)
            .unwrap()
            .unwrap();
        assert_eq!(cached.version(), Some("42.0"));

        let cached_update = cached.cached_update.unwrap();
        assert_eq!(cached_update.manifest_digest, prep.manifest_digest);
        assert_eq!(cached_update.version(), Some("42.0"));
    }
    let to_fetch = prep.layers_to_fetch().collect::<Result<Vec<_>>>()?;
    assert_eq!(to_fetch.len(), 2);
    assert_eq!(expected_digest, prep.manifest_digest);
    assert!(prep.ostree_commit_layer.as_ref().unwrap().commit.is_none());
    assert_eq!(prep.ostree_layers.len(), nlayers);
    let (first, second) = (to_fetch[0], to_fetch[1]);
    assert!(first.0.commit.is_none());
    assert!(second.0.commit.is_none());
    assert_eq!(
        first.1,
        "ostree export of commit 6e6afc49d902daa2456c858818e0ad8bf9afe79cdcca738c5676c0e175c1def1"
    );
    assert_eq!(second.1, "9 components");

    assert_eq!(store::list_images(fixture.destrepo()).unwrap().len(), 1);
    let n = store::count_layer_references(fixture.destrepo())? as i64;
    let _import = imp.import(prep).await.unwrap();

    assert_eq!(store::list_images(fixture.destrepo()).unwrap().len(), 1);

    let n2 = store::count_layer_references(fixture.destrepo())? as i64;
    assert_eq!(n, n2);
    fixture
        .destrepo()
        .prune(ostree::RepoPruneFlags::REFS_ONLY, 0, gio::Cancellable::NONE)?;

    // Build a derived image
    let srcpath = imgref.imgref.name.as_str();
    let derived_tag = "derived";
    fixture.generate_test_derived_oci(srcpath, Some(&derived_tag))?;

    let derived_imgref = OstreeImageReference {
        sigverify: SignatureSource::ContainerPolicyAllowInsecure,
        imgref: ImageReference {
            transport: Transport::OciDir,
            name: format!("{srcpath}:{derived_tag}"),
        },
    };
    let mut imp =
        store::ImageImporter::new(fixture.destrepo(), &derived_imgref, Default::default()).await?;
    let prep = match imp.prepare().await.unwrap() {
        store::PrepareResult::AlreadyPresent(_) => panic!("should not be already imported"),
        store::PrepareResult::Ready(r) => r,
    };
    let to_fetch = prep.layers_to_fetch().collect::<Result<Vec<_>>>()?;
    assert_eq!(to_fetch.len(), 1);
    assert!(prep.ostree_commit_layer.as_ref().unwrap().commit.is_some());
    assert_eq!(prep.ostree_layers.len(), nlayers);

    // We want to test explicit layer pruning
    imp.disable_gc();
    let import = imp.import(prep).await.unwrap();
    assert_eq!(store::list_images(fixture.destrepo()).unwrap().len(), 2);

    assert_eq!(
        store::image_filtered_content_warning(&import.filtered_files)
            .unwrap()
            .unwrap(),
        "Image contains non-ostree compatible file paths: filtered: 1"
    );

    // redo it but with the layers already imported and sanity-check that the
    // merge commit is the same
    let merge_commit = import.merge_commit;
    store::remove_image(fixture.destrepo(), &derived_imgref.imgref).unwrap();
    let mut imp =
        store::ImageImporter::new(fixture.destrepo(), &derived_imgref, Default::default()).await?;
    let prep = match imp.prepare().await.unwrap() {
        store::PrepareResult::AlreadyPresent(_) => panic!("should not be already imported"),
        store::PrepareResult::Ready(r) => r,
    };
    let import = imp.import(prep).await.context("reimport").unwrap();
    assert_eq!(import.merge_commit, merge_commit);

    // but this time we don't get the warning because we didn't reimport the derived layer
    assert!(
        store::image_filtered_content_warning(&import.filtered_files)
            .unwrap()
            .is_none()
    );

    // Should only be new layers
    let n_removed = store::gc_image_layers(fixture.destrepo())?;
    assert_eq!(n_removed, 0);
    // Also test idempotence
    store::remove_image(fixture.destrepo(), &imgref.imgref).unwrap();
    store::remove_image(fixture.destrepo(), &imgref.imgref).unwrap();
    assert_eq!(store::list_images(fixture.destrepo()).unwrap().len(), 1);
    // Still no removed layers after removing the base image
    let n_removed = store::gc_image_layers(fixture.destrepo())?;
    assert_eq!(n_removed, 0);
    store::remove_images(fixture.destrepo(), [&derived_imgref.imgref]).unwrap();
    assert_eq!(store::list_images(fixture.destrepo()).unwrap().len(), 0);
    let n_removed = store::gc_image_layers(fixture.destrepo())?;
    assert_eq!(n_removed, (LAYERS_V0_LEN + 1) as u32);

    // Repo should be clean now
    assert_eq!(store::count_layer_references(fixture.destrepo())?, 0);
    assert_eq!(
        fixture
            .destrepo()
            .list_refs(None, gio::Cancellable::NONE)
            .unwrap()
            .len(),
        0
    );

    Ok(())
}

#[tokio::test]
async fn test_container_var_content() -> Result<()> {
    if !check_skopeo() {
        return Ok(());
    }
    let fixture = Fixture::new_v1()?;

    let imgref = fixture.export_container().await.unwrap().0;
    let imgref = OstreeImageReference {
        sigverify: SignatureSource::ContainerPolicyAllowInsecure,
        imgref,
    };

    // Build a derived image
    let derived_path = &fixture.path.join("derived.oci");
    let srcpath = imgref.imgref.name.as_str();
    oci_clone(srcpath, derived_path).await.unwrap();
    let temproot = &fixture.path.join("temproot");
    let junk_var_data = "junk var data";
    || -> Result<_> {
        std::fs::create_dir(temproot)?;
        let temprootd = Dir::open_ambient_dir(temproot, cap_std::ambient_authority())?;
        let mut db = DirBuilder::new();
        db.mode(0o755);
        db.recursive(true);
        temprootd.create_dir_with("var/lib", &db)?;
        temprootd.write("var/lib/foo", junk_var_data)?;
        Ok(())
    }()
    .context("generating temp content")?;
    ostree_ext::integrationtest::generate_derived_oci(derived_path, temproot, None)?;

    let derived_imgref = OstreeImageReference {
        sigverify: SignatureSource::ContainerPolicyAllowInsecure,
        imgref: ImageReference {
            transport: Transport::OciDir,
            name: derived_path.to_string(),
        },
    };
    let mut imp =
        store::ImageImporter::new(fixture.destrepo(), &derived_imgref, Default::default()).await?;
    imp.set_ostree_version(2023, 11);
    let prep = match imp.prepare().await.unwrap() {
        store::PrepareResult::AlreadyPresent(_) => panic!("should not be already imported"),
        store::PrepareResult::Ready(r) => r,
    };
    let import = imp.import(prep).await.unwrap();

    let ostree_root = fixture
        .destrepo()
        .read_commit(&import.merge_commit, gio::Cancellable::NONE)?
        .0;
    let varfile = ostree_root
        .child("usr/share/factory/var/lib/foo")
        .downcast::<ostree::RepoFile>()
        .unwrap();
    assert_eq!(
        ostree_manual::repo_file_read_to_string(&varfile)?,
        junk_var_data
    );
    assert!(
        !ostree_root
            .child("var/lib/foo")
            .query_exists(gio::Cancellable::NONE)
    );

    assert!(
        store::image_filtered_content_warning(&import.filtered_files)
            .unwrap()
            .is_none()
    );

    // Reset things
    fixture.clear_destrepo()?;

    let mut imp =
        store::ImageImporter::new(fixture.destrepo(), &derived_imgref, Default::default()).await?;
    imp.set_ostree_version(2024, 3);
    let prep = match imp.prepare().await.unwrap() {
        store::PrepareResult::AlreadyPresent(_) => panic!("should not be already imported"),
        store::PrepareResult::Ready(r) => r,
    };
    let import = imp.import(prep).await.unwrap();
    let ostree_root = fixture
        .destrepo()
        .read_commit(&import.merge_commit, gio::Cancellable::NONE)?
        .0;
    let varfile = ostree_root
        .child("usr/share/factory/var/lib/foo")
        .downcast::<ostree::RepoFile>()
        .unwrap();
    assert!(!varfile.query_exists(gio::Cancellable::NONE));
    assert!(
        ostree_root
            .child("var/lib/foo")
            .query_exists(gio::Cancellable::NONE)
    );
    Ok(())
}

#[tokio::test]
async fn test_container_etc_hardlinked_absolute() -> Result<()> {
    test_container_etc_hardlinked(true).await
}

#[tokio::test]
async fn test_container_etc_hardlinked_relative() -> Result<()> {
    test_container_etc_hardlinked(false).await
}

async fn test_container_etc_hardlinked(absolute: bool) -> Result<()> {
    if !check_skopeo() {
        return Ok(());
    }
    let fixture = Fixture::new_v1()?;

    let imgref = fixture.export_container().await.unwrap().0;
    let imgref = OstreeImageReference {
        sigverify: SignatureSource::ContainerPolicyAllowInsecure,
        imgref,
    };

    // Build a derived image
    let derived_path = &fixture.path.join("derived.oci");
    let srcpath = imgref.imgref.name.as_str();
    oci_clone(srcpath, derived_path).await.unwrap();
    ostree_ext::integrationtest::generate_derived_oci_from_tar(
        derived_path,
        |w| {
            let mut layer_tar = tar::Builder::new(w);
            // Create a simple hardlinked file /etc/foo and /etc/bar in the tar stream, which
            // needs usr/etc processing.
            let mut h = tar::Header::new_gnu();
            h.set_uid(0);
            h.set_gid(0);
            h.set_size(0);
            h.set_mode(0o755);
            h.set_entry_type(tar::EntryType::Directory);
            layer_tar.append_data(&mut h.clone(), "etc", &mut std::io::empty())?;
            let testdata = "hardlinked test data";
            h.set_mode(0o644);
            h.set_size(testdata.len().try_into().unwrap());
            h.set_entry_type(tar::EntryType::Regular);
            layer_tar.append_data(
                &mut h.clone(),
                "etc/foo",
                std::io::Cursor::new(testdata.as_bytes()),
            )?;
            h.set_entry_type(tar::EntryType::Link);
            h.set_size(0);
            layer_tar.append_link(&mut h.clone(), "etc/bar", "etc/foo")?;

            // Another case where we have /etc/dnf.conf and a hardlinked /ostree/repo/objects
            // link into it - in this case we should ignore the hardlinked one.
            let testdata = "hardlinked into object store";
            let mut h = tar::Header::new_ustar();
            h.set_mode(0o644);
            h.set_mtime(42);
            h.set_size(testdata.len().try_into().unwrap());
            h.set_entry_type(tar::EntryType::Regular);
            layer_tar.append_data(
                &mut h.clone(),
                "etc/dnf.conf",
                std::io::Cursor::new(testdata.as_bytes()),
            )?;
            h.set_entry_type(tar::EntryType::Link);
            h.set_mtime(42);
            h.set_size(0);
            let path = "sysroot/ostree/repo/objects/45/7279b28b541ca20358bec8487c81baac6a3d5ed3cea019aee675137fab53cb.file";
            let target = "etc/dnf.conf";
            if absolute {
                let ustarname = &mut h.as_ustar_mut().unwrap().name;
                // The tar crate doesn't let us set absolute paths in tar archives, so we bypass
                // it and just write to the path buffer directly.
                assert!(path.len() < ustarname.len());
                ustarname[0..path.len()].copy_from_slice(path.as_bytes());
                h.set_link_name(target)?;
                h.set_cksum();
                layer_tar.append(&mut h.clone(), std::io::empty())?;
            } else {
                layer_tar.append_link(&mut h.clone(), path, target)?;
            }
            layer_tar.finish()?;
            Ok(())
        },
        None,
        None,
    )?;

    let derived_imgref = OstreeImageReference {
        sigverify: SignatureSource::ContainerPolicyAllowInsecure,
        imgref: ImageReference {
            transport: Transport::OciDir,
            name: derived_path.to_string(),
        },
    };
    let mut imp =
        store::ImageImporter::new(fixture.destrepo(), &derived_imgref, Default::default()).await?;
    imp.set_ostree_version(2023, 11);
    let prep = match imp.prepare().await.unwrap() {
        store::PrepareResult::AlreadyPresent(_) => panic!("should not be already imported"),
        store::PrepareResult::Ready(r) => r,
    };
    let import = imp.import(prep).await.unwrap();
    let r = fixture
        .destrepo()
        .read_commit(import.get_commit(), gio::Cancellable::NONE)?
        .0;
    let foo = r.resolve_relative_path("usr/etc/foo");
    let foo = foo.downcast_ref::<ostree::RepoFile>().unwrap();
    foo.ensure_resolved()?;
    let bar = r.resolve_relative_path("usr/etc/bar");
    let bar = bar.downcast_ref::<ostree::RepoFile>().unwrap();
    bar.ensure_resolved()?;
    assert_eq!(foo.checksum(), bar.checksum());

    let dnfconf = r.resolve_relative_path("usr/etc/dnf.conf");
    let dnfconf: &ostree::RepoFile = dnfconf.downcast_ref::<ostree::RepoFile>().unwrap();
    dnfconf.ensure_resolved()?;

    Ok(())
}

#[tokio::test]
async fn test_non_ostree() -> Result<()> {
    if !check_skopeo() {
        return Ok(());
    }
    let fixture = NonOstreeFixture::new_base()?;
    let (imgref, src_digest) = fixture.export_container().await.unwrap();
    let imp = fixture.must_import(&imgref).await?;
    if imp.manifest_digest != src_digest {
        let src_manifest: oci_image::ImageManifest = {
            let idx = fixture.src_oci.read_index()?;
            let manifest = idx
                .manifests()
                .iter()
                .find(|m| m.digest() == &src_digest)
                .unwrap();
            fixture.src_oci.read_json_blob(manifest)?
        };
        let src_manifest = serde_json::to_string_pretty(&src_manifest).unwrap();
        let dest_manifest = serde_json::to_string_pretty(&imp.manifest).unwrap();
        similar_asserts::assert_eq!(&src_manifest, &dest_manifest);
    }
    assert_eq!(imp.manifest_digest, src_digest);
    Ok(())
}

/// Copy an OCI directory.
async fn oci_clone(src: impl AsRef<Utf8Path>, dest: impl AsRef<Utf8Path>) -> Result<()> {
    let src = src.as_ref();
    let dest = dest.as_ref();
    // For now we just fork off `cp` and rely on reflinks, but we could and should
    // explicitly hardlink blobs/sha256 e.g.
    let cmd = tokio::process::Command::new("cp")
        .args(["-a", "--reflink=auto"])
        .args([src, dest])
        .status()
        .await?;
    if !cmd.success() {
        anyhow::bail!("cp failed");
    }
    Ok(())
}

#[tokio::test]
async fn test_container_import_export_v1() {
    if !check_skopeo() {
        return;
    }
    impl_test_container_import_export(false).await.unwrap();
    impl_test_container_import_export(true).await.unwrap();
}

/// But layers work via the container::write module.
#[tokio::test]
async fn test_container_write_derive() -> Result<()> {
    if !check_skopeo() {
        return Ok(());
    }
    let cancellable = gio::Cancellable::NONE;
    let fixture = Fixture::new_v1()?;
    let sh = fixture.new_shell()?;
    let base_oci_path = &fixture.path.join("exampleos.oci");
    let _digest = ostree_ext::container::encapsulate(
        fixture.srcrepo(),
        fixture.testref(),
        &Config {
            cmd: Some(vec!["/bin/bash".to_string()]),
            ..Default::default()
        },
        None,
        &ImageReference {
            transport: Transport::OciDir,
            name: base_oci_path.to_string(),
        },
    )
    .await
    .context("exporting")?;
    assert!(base_oci_path.exists());

    // Build the derived images
    let derived_path = &fixture.path.join("derived.oci");
    oci_clone(base_oci_path, derived_path).await?;
    let temproot = &fixture.path.join("temproot");
    std::fs::create_dir_all(temproot.join("usr/bin"))?;
    let newderivedfile_contents = "newderivedfile v0";
    std::fs::write(
        temproot.join("usr/bin/newderivedfile"),
        newderivedfile_contents,
    )?;
    std::fs::write(
        temproot.join("usr/bin/newderivedfile3"),
        "newderivedfile3 v0",
    )?;
    // Remove the kernel directory and make a new one
    let moddir = temproot.join("usr/lib/modules");
    let oldkernel = "5.10.18-200.x86_64";
    std::fs::create_dir_all(&moddir)?;
    let oldkernel_wh = &format!(".wh.{oldkernel}");
    std::fs::write(moddir.join(oldkernel_wh), "")?;
    let newkdir = moddir.join("5.12.7-42.x86_64");
    std::fs::create_dir_all(&newkdir)?;
    std::fs::write(newkdir.join("vmlinuz"), "a new kernel")?;
    ostree_ext::integrationtest::generate_derived_oci(derived_path, temproot, None)?;
    // And v2
    let derived2_path = &fixture.path.join("derived2.oci");
    oci_clone(base_oci_path, derived2_path).await?;
    std::fs::remove_dir_all(temproot)?;
    std::fs::create_dir_all(temproot.join("usr/bin"))?;
    std::fs::write(temproot.join("usr/bin/newderivedfile"), "newderivedfile v1")?;
    std::fs::write(
        temproot.join("usr/bin/newderivedfile2"),
        "newderivedfile2 v0",
    )?;
    ostree_ext::integrationtest::generate_derived_oci(derived2_path, temproot, None)?;

    let derived_ref = OstreeImageReference {
        sigverify: SignatureSource::ContainerPolicyAllowInsecure,
        imgref: ImageReference {
            transport: Transport::OciDir,
            name: derived_path.to_string(),
        },
    };
    // There shouldn't be any container images stored yet.
    let images = store::list_images(fixture.destrepo())?;
    assert!(images.is_empty());

    // Verify importing a derived image fails
    let r = ostree_ext::container::unencapsulate(fixture.destrepo(), &derived_ref).await;
    assert_err_contains(r, "Image has 1 non-ostree layers");

    // Pull a derived image - two layers, new base plus one layer.
    let mut imp =
        store::ImageImporter::new(fixture.destrepo(), &derived_ref, Default::default()).await?;
    let prep = match imp.prepare().await.context("Init prep derived")? {
        store::PrepareResult::AlreadyPresent(_) => panic!("should not be already imported"),
        store::PrepareResult::Ready(r) => r,
    };
    let expected_digest = prep.manifest_digest.clone();
    assert!(prep.ostree_commit_layer.as_ref().unwrap().commit.is_none());
    assert_eq!(prep.layers.len(), 1);
    for layer in prep.layers.iter() {
        assert!(layer.commit.is_none());
    }
    let import = imp.import(prep).await.context("Init pull derived")?;
    // We should have exactly one image stored.
    let images = store::list_images(fixture.destrepo())?;
    assert_eq!(images.len(), 1);
    assert_eq!(images[0], derived_ref.imgref.to_string());

    let imported_commit = &fixture
        .destrepo()
        .load_commit(import.merge_commit.as_str())?
        .0;
    let digest = store::manifest_digest_from_commit(imported_commit)?;
    assert_eq!(digest.algorithm(), &DigestAlgorithm::Sha256);
    assert_eq!(digest, expected_digest);

    let commit_meta = &imported_commit.child_value(0);
    let commit_meta = glib::VariantDict::new(Some(commit_meta));
    let config = commit_meta
        .lookup::<String>("ostree.container.image-config")?
        .unwrap();
    let config: oci_spec::image::ImageConfiguration = serde_json::from_str(&config)?;
    assert_eq!(config.os(), &oci_spec::image::Os::Linux);

    // Parse the commit and verify we pulled the derived content.
    let root = fixture
        .destrepo()
        .read_commit(&import.merge_commit, cancellable)?
        .0;
    let root = root.downcast_ref::<ostree::RepoFile>().unwrap();
    {
        let derived = root.resolve_relative_path("usr/bin/newderivedfile");
        let derived = derived.downcast_ref::<ostree::RepoFile>().unwrap();
        let found_newderived_contents =
            ostree_ext::ostree_manual::repo_file_read_to_string(derived)?;
        assert_eq!(found_newderived_contents, newderivedfile_contents);

        let kver = ostree_ext::bootabletree::find_kernel_dir(root.upcast_ref(), cancellable)
            .unwrap()
            .unwrap()
            .basename()
            .unwrap();
        let kver = Utf8Path::from_path(&kver).unwrap();
        assert_eq!(kver, newkdir.file_name().unwrap());

        let old_kernel_dir = root.resolve_relative_path(format!("usr/lib/modules/{oldkernel}"));
        assert!(!old_kernel_dir.query_exists(cancellable));
    }

    // Import again, but there should be no changes.
    let mut imp =
        store::ImageImporter::new(fixture.destrepo(), &derived_ref, Default::default()).await?;
    let already_present = match imp.prepare().await? {
        store::PrepareResult::AlreadyPresent(c) => c,
        store::PrepareResult::Ready(_) => {
            panic!("Should have already imported {}", &derived_ref)
        }
    };
    assert_eq!(import.merge_commit, already_present.merge_commit);

    // Test upgrades; replace the oci-archive with new content.
    std::fs::remove_dir_all(derived_path)?;
    std::fs::rename(derived2_path, derived_path)?;
    let mut imp =
        store::ImageImporter::new(fixture.destrepo(), &derived_ref, Default::default()).await?;
    let prep = match imp.prepare().await? {
        store::PrepareResult::AlreadyPresent(_) => panic!("should not be already imported"),
        store::PrepareResult::Ready(r) => r,
    };
    // We *should* already have the base layer.
    assert!(prep.ostree_commit_layer.as_ref().unwrap().commit.is_some());
    // One new layer
    assert_eq!(prep.layers.len(), 1);
    for layer in prep.layers.iter() {
        assert!(layer.commit.is_none());
    }
    let import = imp.import(prep).await?;
    // New commit.
    assert_ne!(import.merge_commit, already_present.merge_commit);
    // We should still have exactly one image stored.
    let images = store::list_images(fixture.destrepo())?;
    assert_eq!(images[0], derived_ref.imgref.to_string());
    assert_eq!(images.len(), 1);

    // Verify we have the new file and *not* the old one
    let merge_commit = import.merge_commit.as_str();
    cmd!(
        sh,
        "ostree --repo=dest/repo ls {merge_commit} /usr/bin/newderivedfile2"
    )
    .ignore_stdout()
    .run()?;
    let c = cmd!(
        sh,
        "ostree --repo=dest/repo cat {merge_commit} /usr/bin/newderivedfile"
    )
    .read()?;
    assert_eq!(c.as_str(), "newderivedfile v1");
    assert!(
        cmd!(
            sh,
            "ostree --repo=dest/repo ls {merge_commit} /usr/bin/newderivedfile3"
        )
        .ignore_stderr()
        .run()
        .is_err()
    );

    // And there should be no changes on upgrade again.
    let mut imp =
        store::ImageImporter::new(fixture.destrepo(), &derived_ref, Default::default()).await?;
    let already_present = match imp.prepare().await? {
        store::PrepareResult::AlreadyPresent(c) => c,
        store::PrepareResult::Ready(_) => {
            panic!("Should have already imported {}", &derived_ref)
        }
    };
    assert_eq!(import.merge_commit, already_present.merge_commit);

    // Create a new repo, and copy to it
    let destrepo2 = ostree::Repo::create_at(
        ostree::AT_FDCWD,
        fixture.path.join("destrepo2").as_str(),
        ostree::RepoMode::Archive,
        None,
        gio::Cancellable::NONE,
    )?;
    #[allow(deprecated)]
    store::copy(
        fixture.destrepo(),
        &derived_ref.imgref,
        &destrepo2,
        &derived_ref.imgref,
    )
    .await
    .context("Copying")?;

    let images = store::list_images(&destrepo2)?;
    assert_eq!(images.len(), 1);
    assert_eq!(images[0], derived_ref.imgref.to_string());

    // And test copy_as
    let target_name = "quay.io/exampleos/centos:stream9";
    let registry_ref = ImageReference {
        transport: Transport::Registry,
        name: target_name.to_string(),
    };
    store::copy(
        fixture.destrepo(),
        &derived_ref.imgref,
        &destrepo2,
        &registry_ref,
    )
    .await
    .context("Copying")?;

    let mut images = store::list_images(&destrepo2)?;
    images.sort_unstable();
    assert_eq!(images[0], registry_ref.to_string());
    assert_eq!(images[1], derived_ref.imgref.to_string());

    Ok(())
}

/// Implementation of a test case for non-gzip (i.e. zstd or zstd:chunked) compression
async fn test_non_gzip(format: &str) -> Result<()> {
    if !check_skopeo() {
        return Ok(());
    }
    let fixture = Fixture::new_v1()?;
    let baseimg = &fixture.export_container().await?.0;
    let basepath = &match baseimg.transport {
        Transport::OciDir => fixture.path.join(baseimg.name.as_str()),
        _ => unreachable!(),
    };
    let baseimg_ref = format!("oci:{basepath}");
    let zstd_image_path = &fixture.path.join("zstd.oci");
    let st = tokio::process::Command::new("skopeo")
        .args([
            "copy",
            &format!("--dest-compress-format={format}"),
            baseimg_ref.as_str(),
            &format!("oci:{zstd_image_path}"),
        ])
        .status()
        .await?;
    assert!(st.success());

    let zstdref = &OstreeImageReference {
        sigverify: SignatureSource::ContainerPolicyAllowInsecure,
        imgref: ImageReference {
            transport: Transport::OciDir,
            name: zstd_image_path.to_string(),
        },
    };
    let mut imp =
        store::ImageImporter::new(fixture.destrepo(), zstdref, Default::default()).await?;
    let prep = match imp.prepare().await.context("Init prep derived")? {
        store::PrepareResult::AlreadyPresent(_) => panic!("should not be already imported"),
        store::PrepareResult::Ready(r) => r,
    };
    let _ = imp.import(prep).await.unwrap();

    Ok(())
}

/// Test for zstd
#[tokio::test]
async fn test_container_zstd() -> Result<()> {
    test_non_gzip("zstd").await
}

/// Test for zstd:chunked
#[tokio::test]
async fn test_container_zstd_chunked() -> Result<()> {
    test_non_gzip("zstd:chunked").await
}

/// Test for https://github.com/ostreedev/ostree-rs-ext/issues/405
/// We need to handle the case of modified hardlinks into /sysroot
#[tokio::test]
async fn test_container_write_derive_sysroot_hardlink() -> Result<()> {
    if !check_skopeo() {
        return Ok(());
    }
    let fixture = Fixture::new_v1()?;
    let sh = fixture.new_shell()?;
    let baseimg = &fixture.export_container().await?.0;
    let basepath = &match baseimg.transport {
        Transport::OciDir => fixture.path.join(baseimg.name.as_str()),
        _ => unreachable!(),
    };

    // Build a derived image
    let derived_path = &fixture.path.join("derived.oci");
    oci_clone(basepath, derived_path).await?;
    ostree_ext::integrationtest::generate_derived_oci_from_tar(
        derived_path,
        |w| {
            let mut tar = tar::Builder::new(w);
            let objpath = Utf8Path::new(
                "sysroot/ostree/repo/objects/60/feb13e826d2f9b62490ab24cea0f4a2d09615fb57027e55f713c18c59f4796.file",
            );
            let d = objpath.parent().unwrap();
            fn mkparents<F: std::io::Write>(
                t: &mut tar::Builder<F>,
                path: &Utf8Path,
            ) -> std::io::Result<()> {
                if let Some(parent) = path.parent().filter(|p| !p.as_str().is_empty()) {
                    mkparents(t, parent)?;
                }
                let mut h = tar::Header::new_gnu();
                h.set_entry_type(tar::EntryType::Directory);
                h.set_uid(0);
                h.set_gid(0);
                h.set_mode(0o755);
                h.set_size(0);
                t.append_data(&mut h, path, std::io::empty())
            }
            mkparents(&mut tar, d).context("Appending parent")?;

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs();
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Regular);
            h.set_uid(0);
            h.set_gid(0);
            h.set_mode(0o644);
            h.set_mtime(now);
            let data = b"hello";
            h.set_size(data.len() as u64);
            tar.append_data(&mut h, objpath, std::io::Cursor::new(data))
                .context("appending object")?;
            for path in ["usr/bin/bash", "usr/bin/bash-hardlinked"] {
                let targetpath = Utf8Path::new(path);
                h.set_size(0);
                h.set_mtime(now);
                h.set_entry_type(tar::EntryType::Link);
                tar.append_link(&mut h, targetpath, objpath)
                    .context("appending target")?;
            }
            Ok::<_, anyhow::Error>(())
        },
        None,
        None,
    )?;
    let derived_ref = &OstreeImageReference {
        sigverify: SignatureSource::ContainerPolicyAllowInsecure,
        imgref: ImageReference {
            transport: Transport::OciDir,
            name: derived_path.to_string(),
        },
    };
    let mut imp =
        store::ImageImporter::new(fixture.destrepo(), derived_ref, Default::default()).await?;
    let prep = match imp.prepare().await.context("Init prep derived")? {
        store::PrepareResult::AlreadyPresent(_) => panic!("should not be already imported"),
        store::PrepareResult::Ready(r) => r,
    };
    let import = imp.import(prep).await.unwrap();

    // Verify we have the new file
    let merge_commit = import.merge_commit.as_str();
    cmd!(
        sh,
        "ostree --repo=dest/repo ls {merge_commit} /usr/bin/bash"
    )
    .ignore_stdout()
    .run()?;
    for path in ["/usr/bin/bash", "/usr/bin/bash-hardlinked"] {
        let r = cmd!(sh, "ostree --repo=dest/repo cat {merge_commit} {path}").read()?;
        assert_eq!(r.as_str(), "hello");
    }

    Ok(())
}

#[tokio::test]
// Today rpm-ostree vendors a stable ostree-rs-ext; this test
// verifies that the old ostree-rs-ext code can parse the containers
// generated by the new ostree code.
async fn test_old_code_parses_new_export() -> Result<()> {
    if !check_skopeo() {
        return Ok(());
    }
    let rpmostree = Utf8Path::new("/usr/bin/rpm-ostree");
    if !rpmostree.exists() {
        return Ok(());
    }
    let fixture = Fixture::new_v1()?;
    let imgref = fixture.export_container().await?.0;
    let imgref = OstreeImageReference {
        sigverify: SignatureSource::ContainerPolicyAllowInsecure,
        imgref,
    };
    fixture.clear_destrepo()?;
    let destrepo_path = fixture.path.join("dest/repo");
    let s = Command::new("ostree")
        .args([
            "container",
            "unencapsulate",
            "--repo",
            destrepo_path.as_str(),
            imgref.to_string().as_str(),
        ])
        .output()?;
    if !s.status.success() {
        anyhow::bail!(
            "Failed to run ostree: {:?}: {}",
            s,
            String::from_utf8_lossy(&s.stderr)
        );
    }
    Ok(())
}

/// Test for https://github.com/ostreedev/ostree-rs-ext/issues/655
#[tokio::test]
async fn test_container_xattr() -> Result<()> {
    if !check_skopeo() {
        return Ok(());
    }
    let fixture = Fixture::new_v1()?;
    let sh = fixture.new_shell()?;
    let baseimg = &fixture.export_container().await?.0;
    let basepath = &match baseimg.transport {
        Transport::OciDir => fixture.path.join(baseimg.name.as_str()),
        _ => unreachable!(),
    };

    // Verify security.capability is in the ostree commit
    let arping = "/usr/bin/arping";
    {
        let ostree_root = fixture
            .srcrepo()
            .read_commit(fixture.testref(), gio::Cancellable::NONE)?
            .0;
        let arping_ostree = ostree_root.resolve_relative_path(arping);
        assert_eq!(
            arping_ostree.query_file_type(
                gio::FileQueryInfoFlags::NOFOLLOW_SYMLINKS,
                gio::Cancellable::NONE
            ),
            gio::FileType::Regular
        );
        let arping_ostree = arping_ostree.downcast_ref::<ostree::RepoFile>().unwrap();
        let arping_ostree_xattrs = arping_ostree.xattrs(gio::Cancellable::NONE)?;
        let v = arping_ostree_xattrs.data_as_bytes();
        let v = v.try_as_aligned().unwrap();
        let v = gvariant::gv!("a(ayay)").cast(v);
        assert!(
            v.iter()
                .find(|entry| {
                    let k = entry.to_tuple().0;
                    let k = std::ffi::CStr::from_bytes_with_nul(k).unwrap();
                    k.to_str().ok() == Some("security.capability")
                })
                .is_some()
        );
    }

    // Build a derived image
    let derived_path = &fixture.path.join("derived.oci");
    oci_clone(basepath, derived_path).await?;
    ostree_ext::integrationtest::generate_derived_oci_from_tar(
        derived_path,
        |w| {
            let mut tar = tar::Builder::new(w);
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Regular);
            h.set_uid(0);
            h.set_gid(0);
            h.set_mode(0o644);
            h.set_mtime(0);
            let data = b"hello";
            h.set_size(data.len() as u64);
            tar.append_pax_extensions([("SCHILY.xattr.user.foo", b"bar".as_slice())])
                .unwrap();
            tar.append_data(&mut h, "usr/bin/testxattr", std::io::Cursor::new(data))
                .unwrap();
            Ok::<_, anyhow::Error>(())
        },
        None,
        None,
    )?;
    let derived_ref = &OstreeImageReference {
        sigverify: SignatureSource::ContainerPolicyAllowInsecure,
        imgref: ImageReference {
            transport: Transport::OciDir,
            name: derived_path.to_string(),
        },
    };
    let mut imp =
        store::ImageImporter::new(fixture.destrepo(), derived_ref, Default::default()).await?;
    let prep = match imp.prepare().await.context("Init prep derived")? {
        store::PrepareResult::AlreadyPresent(_) => panic!("should not be already imported"),
        store::PrepareResult::Ready(r) => r,
    };
    let import = imp.import(prep).await.unwrap();
    let merge_commit = import.merge_commit;

    // Yeah we just scrape the output of ostree because it's easy
    let out = cmd!(
        sh,
        "ostree --repo=dest/repo ls -X {merge_commit} /usr/bin/testxattr"
    )
    .read()?;
    assert!(out.contains("'user.foo', [byte 0x62, 0x61, 0x72]"));
    let out = cmd!(sh, "ostree --repo=dest/repo ls -X {merge_commit} {arping}").read()?;
    assert!(out.contains("'security.capability'"));

    Ok(())
}

#[ignore]
#[tokio::test]
// Verify that we can push and pull to a registry, not just oci-archive:.
// This requires a registry set up externally right now.  One can run a HTTP registry via e.g.
// `podman run --rm -ti -p 5000:5000 --name registry docker.io/library/registry:2`
// but that doesn't speak HTTPS and adding that is complex.
// A simple option is setting up e.g. quay.io/$myuser/exampleos and then do:
// Then you can run this test via `env TEST_REGISTRY=quay.io/$myuser cargo test -- --ignored`.
async fn test_container_import_export_registry() -> Result<()> {
    let tr = &*TEST_REGISTRY;
    let fixture = Fixture::new_v1()?;
    let testref = fixture.testref();
    let testrev = fixture
        .srcrepo()
        .require_rev(testref)
        .context("Failed to resolve ref")?;
    let src_imgref = ImageReference {
        transport: Transport::Registry,
        name: format!("{tr}/exampleos"),
    };
    let config = Config {
        cmd: Some(vec!["/bin/bash".to_string()]),
        ..Default::default()
    };
    let digest =
        ostree_ext::container::encapsulate(fixture.srcrepo(), testref, &config, None, &src_imgref)
            .await
            .context("exporting to registry")?;
    let mut digested_imgref = src_imgref.clone();
    digested_imgref.name = format!("{}@{}", src_imgref.name, digest);

    let import_ref = OstreeImageReference {
        sigverify: SignatureSource::ContainerPolicyAllowInsecure,
        imgref: digested_imgref,
    };
    let import = ostree_ext::container::unencapsulate(fixture.destrepo(), &import_ref)
        .await
        .context("importing")?;
    assert_eq!(import.ostree_commit, testrev.as_str());
    Ok(())
}

#[test]
fn test_diff() -> Result<()> {
    let mut fixture = Fixture::new_v1()?;
    const ADDITIONS: &str = indoc::indoc! { "
r /usr/bin/newbin some-new-binary
d /usr/share
"};
    fixture
        .update(
            FileDef::iter_from(ADDITIONS),
            [Cow::Borrowed("/usr/bin/bash".into())].into_iter(),
        )
        .context("Failed to update")?;
    let from = &format!("{}^", fixture.testref());
    let repo = fixture.srcrepo();
    let subdir: Option<&str> = None;
    let diff = ostree_ext::diff::diff(repo, from, fixture.testref(), subdir)?;
    assert!(diff.subdir.is_none());
    assert_eq!(diff.added_dirs.len(), 1);
    assert_eq!(diff.added_dirs.iter().next().unwrap(), "/usr/share");
    assert_eq!(diff.added_files.len(), 1);
    assert_eq!(diff.added_files.iter().next().unwrap(), "/usr/bin/newbin");
    assert_eq!(diff.removed_files.len(), 1);
    assert_eq!(diff.removed_files.iter().next().unwrap(), "/usr/bin/bash");
    let diff = ostree_ext::diff::diff(repo, from, fixture.testref(), Some("/usr"))?;
    assert_eq!(diff.subdir.as_ref().unwrap(), "/usr");
    assert_eq!(diff.added_dirs.len(), 1);
    assert_eq!(diff.added_dirs.iter().next().unwrap(), "/share");
    assert_eq!(diff.added_files.len(), 1);
    assert_eq!(diff.added_files.iter().next().unwrap(), "/bin/newbin");
    assert_eq!(diff.removed_files.len(), 1);
    assert_eq!(diff.removed_files.iter().next().unwrap(), "/bin/bash");
    Ok(())
}

#[test]
fn test_manifest_diff() {
    let a: ImageManifest = serde_json::from_str(include_str!("fixtures/manifest1.json")).unwrap();
    let b: ImageManifest = serde_json::from_str(include_str!("fixtures/manifest2.json")).unwrap();

    let d = ManifestDiff::new(&a, &b);
    assert_eq!(d.from, &a);
    assert_eq!(d.to, &b);
    assert_eq!(d.added.len(), 4);
    assert_eq!(
        d.added[0].digest().to_string(),
        "sha256:0b5d930ffc92d444b0a7b39beed322945a3038603fbe2a56415a6d02d598df1f"
    );
    assert_eq!(
        d.added[3].digest().to_string(),
        "sha256:cb9b8a4ac4a8df62df79e6f0348a14b3ec239816d42985631c88e76d4e3ff815"
    );
    assert_eq!(d.removed.len(), 4);
    assert_eq!(
        d.removed[0].digest().to_string(),
        "sha256:0ff8b1fdd38e5cfb6390024de23ba4b947cd872055f62e70f2c21dad5c928925"
    );
    assert_eq!(
        d.removed[3].digest().to_string(),
        "sha256:76b83eea62b7b93200a056b5e0201ef486c67f1eeebcf2c7678ced4d614cece2"
    );
}
