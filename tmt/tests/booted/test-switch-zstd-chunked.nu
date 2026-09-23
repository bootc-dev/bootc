# number: 50
# tmt:
#   summary: Switch to an image with zstd:chunked compressed layers
#   duration: 30m
#
# zstd:chunked layers are multi-frame zstd streams with skippable frames
# holding a table of contents, which a naive zstd decoder truncates; see
# https://github.com/bootc-dev/bootc/issues/2408
#
# This test does:
# podman build <derived from the booted image>
# podman push --compression-format zstd:chunked <to an OCI directory>
# bootc switch <to that OCI directory>
# Verify we boot into the new image
#
# An OCI directory is used rather than a registry to avoid a network
# dependency. The layers still go through the same decompression code
# as a registry pull on both backends.
use std assert
use tap.nu

const image_dir = "/var/tmp/bootc-zstd-chunked"
const data_dir = "/usr/share/testing-bootc-zstd-chunked"
const zstd_media_type = "application/vnd.oci.image.layer.v1.tar+zstd"
# Annotation that c/image adds to each zstd:chunked layer
const chunked_annotation = "io.github.containers.zstd-chunked.manifest-checksum"

# This code runs on *each* boot.
bootc status
let st = bootc status --json | from json
let booted = $st.status.booted.image

def initial_build [] {
    tap begin "switch to zstd:chunked image"

    let td = mktemp -d
    cd $td

    bootc image copy-to-storage
    # Layers we already have (i.e. all the base image ones) are skipped when
    # pulling, so only the layer added here is actually decompressed. Put a
    # number of files in it: zstd:chunked compresses each into its own
    # frame(s), so this layer is multi-frame too. The checksums verify
    # nothing got silently truncated.
    let gen_data = 'for i in $(seq 64); do head -c 65536 /dev/urandom > data$i; done && sha256sum data* > SHA256SUMS'
    (
        tap make_uki_containerfile $"
            FROM localhost/bootc as base
            RUN mkdir -p ($data_dir) && cd ($data_dir) && ($gen_data)
    ") | save Dockerfile
    podman build -t localhost/bootc-zstd-chunked .

    rm -rf $image_dir
    podman push --compression-format zstd:chunked --force-compression localhost/bootc-zstd-chunked $"oci:($image_dir)"
    # Free up space; we only need the OCI directory from here on
    podman rmi localhost/bootc-zstd-chunked localhost/bootc

    # Make sure we're actually testing what we think we are
    let manifest = skopeo inspect --raw $"oci:($image_dir)" | from json
    assert (($manifest.layers | length) > 0)
    for layer in $manifest.layers {
        assert equal $layer.mediaType $zstd_media_type
        assert ($chunked_annotation in ($layer.annotations? | default {} | columns)) $"layer ($layer.digest) is not zstd:chunked"
    }

    bootc switch --transport oci $image_dir
    let st = bootc status --json | from json
    assert equal $st.status.staged.image.image.transport oci
    tmt-reboot
}

def second_boot [] {
    print "verifying second boot"
    assert equal $booted.image.transport oci
    assert equal $booted.image.image $image_dir
    cd $data_dir
    sha256sum --check --quiet SHA256SUMS
    bootc internals fsck
    tap ok
}

def main [] {
    # See https://tmt.readthedocs.io/en/stable/stories/features.html#reboot-during-test
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => initial_build,
        "1" => second_boot,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
