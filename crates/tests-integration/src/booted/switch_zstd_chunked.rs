// number: 50
// tmt:
//   summary: Switch to an image with zstd:chunked compressed layers
//   duration: 30m
//   adjust:
//     - when: running_env != image_mode
//       enabled: false
//       because: only the image_mode test image installs bootc-tests
// extra:
//   skip_if_ostree: true
//
//! zstd:chunked layers are multi-frame zstd streams with skippable frames
//! holding a table of contents, which a naive zstd decoder truncates; see
//! <https://github.com/bootc-dev/bootc/issues/2408>
//!
//! This test does:
//!
//! ```text
//! podman build <derived from the booted image>
//! podman push --compression-format zstd:chunked <to an OCI directory>
//! bootc switch <to that OCI directory>
//! Verify we boot into the new image
//! ```
//!
//! An OCI directory is used rather than a registry to avoid a network
//! dependency. The layers still go through the same decompression code
//! as a registry pull.
//!
//! This is composefs-only for now: on ostree it trips over
//! <https://github.com/bootc-dev/bootc/issues/2402> (a /boot automount that
//! has idled out loses the staged deployment). Enable it there too once
//! that is fixed in the base images.

use anyhow::{Context, Result};
use oci_spec::image::{ImageManifest, MediaType};
use xshell::{Shell, cmd};

use super::{host_status, make_uki_containerfile, reboot_count, tap_begin, tap_ok};

const IMAGE_DIR: &str = "/var/tmp/bootc-zstd-chunked";
const DATA_DIR: &str = "/usr/share/testing-bootc-zstd-chunked";
const DERIVED_IMAGE: &str = "localhost/bootc-zstd-chunked";
/// Annotation that c/image adds to each zstd:chunked layer
const CHUNKED_ANNOTATION: &str = "io.github.containers.zstd-chunked.manifest-checksum";

pub(crate) fn run(sh: &Shell) -> Result<()> {
    // This code runs on *each* boot.
    cmd!(sh, "bootc status").run()?;
    let st = host_status(sh)?;
    match reboot_count()? {
        0 => initial_build(sh),
        1 => second_boot(sh, &st),
        n => anyhow::bail!("Invalid TMT_REBOOT_COUNT {n}"),
    }
}

fn initial_build(sh: &Shell) -> Result<()> {
    tap_begin("switch to zstd:chunked image");

    let td = tempfile::tempdir()?;
    let _dir = sh.push_dir(td.path());

    cmd!(sh, "bootc image copy-to-storage").run()?;
    // Layers we already have (i.e. all the base image ones) are skipped when
    // pulling, so only the layer added here is actually decompressed. Put a
    // number of files in it: zstd:chunked compresses each into its own
    // frame(s), so this layer is multi-frame too. The checksums verify
    // nothing got silently truncated.
    let gen_data = "for i in $(seq 64); do head -c 65536 /dev/urandom > data$i; done && sha256sum data* > SHA256SUMS";
    let containerfile = format!(
        "FROM localhost/bootc as base\nRUN mkdir -p {DATA_DIR} && cd {DATA_DIR} && {gen_data}\n"
    );
    sh.write_file("Dockerfile", make_uki_containerfile(sh, &containerfile)?)?;
    cmd!(sh, "podman build -t {DERIVED_IMAGE} .").run()?;

    sh.remove_path(IMAGE_DIR)?;
    let oci_dir = format!("oci:{IMAGE_DIR}");
    cmd!(
        sh,
        "podman push --compression-format zstd:chunked --force-compression {DERIVED_IMAGE} {oci_dir}"
    )
    .run()?;
    // Free up space; we only need the OCI directory from here on
    cmd!(sh, "podman rmi {DERIVED_IMAGE} localhost/bootc").run()?;

    // Make sure we're actually testing what we think we are
    let manifest = cmd!(sh, "skopeo inspect --raw {oci_dir}").read()?;
    verify_zstd_chunked(&manifest)?;

    cmd!(sh, "bootc switch --transport oci {IMAGE_DIR}").run()?;
    let st = host_status(sh)?;
    let transport = st.pointer("/status/staged/image/image/transport");
    let transport = transport.and_then(|v| v.as_str());
    anyhow::ensure!(transport == Some("oci"), "Staged transport {transport:?}");
    cmd!(sh, "tmt-reboot").run()?;
    Ok(())
}

fn second_boot(sh: &Shell, st: &serde_json::Value) -> Result<()> {
    println!("verifying second boot");
    let booted = st
        .pointer("/status/booted/image/image")
        .context("Missing booted image")?;
    let transport = booted.get("transport").and_then(|v| v.as_str());
    anyhow::ensure!(transport == Some("oci"), "Booted transport {transport:?}");
    let image = booted.get("image").and_then(|v| v.as_str());
    anyhow::ensure!(image == Some(IMAGE_DIR), "Booted image {image:?}");
    let _dir = sh.push_dir(DATA_DIR);
    cmd!(sh, "sha256sum --check --quiet SHA256SUMS").run()?;
    cmd!(sh, "bootc internals fsck").run()?;
    tap_ok();
    Ok(())
}

fn verify_zstd_chunked(manifest: &str) -> Result<()> {
    let manifest: ImageManifest = serde_json::from_str(manifest).context("Parsing manifest")?;
    anyhow::ensure!(!manifest.layers().is_empty(), "No layers in manifest");
    for layer in manifest.layers() {
        let digest = layer.digest();
        anyhow::ensure!(
            layer.media_type() == &MediaType::ImageLayerZstd,
            "layer {digest} has media type {}",
            layer.media_type()
        );
        let chunked = layer
            .annotations()
            .as_ref()
            .is_some_and(|a| a.contains_key(CHUNKED_ANNOTATION));
        anyhow::ensure!(chunked, "layer {digest} is not zstd:chunked");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    fn layer(media_type: &str, annotations: Value) -> Value {
        json!({
            "mediaType": media_type,
            "digest": DIGEST,
            "size": 1,
            "annotations": annotations,
        })
    }

    #[test]
    fn test_verify_zstd_chunked() {
        let zstd = "application/vnd.oci.image.layer.v1.tar+zstd";
        let gzip = "application/vnd.oci.image.layer.v1.tar+gzip";
        let chunked = || json!({CHUNKED_ANNOTATION: "sha256:1"});
        let cases = [
            (vec![layer(zstd, chunked())], true),
            (vec![layer(zstd, chunked()), layer(zstd, json!({}))], false),
            (vec![layer(zstd, Value::Null)], false),
            (vec![layer(gzip, chunked())], false),
            (vec![], false),
        ];
        for (layers, ok) in cases {
            let manifest = json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": DIGEST,
                    "size": 1,
                },
                "layers": layers,
            });
            let r = verify_zstd_chunked(&manifest.to_string());
            assert_eq!(r.is_ok(), ok, "{manifest}: {r:?}");
        }
    }
}
