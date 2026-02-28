# number: 35
# tmt:
#   summary: Verify pre-flight disk space check rejects images with inflated layer sizes
#   duration: 10m
#
# This test does NOT require a reboot.
# It constructs a minimal fake OCI image directory that claims to have an
# astronomically large layer (999 TiB), then verifies that bootc switch fails
# with "Insufficient free space" before attempting to fetch any data.
use std assert
use tap.nu

tap begin "pre-flight disk space check"

def main [] {
    let td = mktemp -d

    # --- Build a minimal but valid fake OCI image layout ---
    #
    # The config blob must be real (containers-image-proxy fetches it to
    # parse ImageConfiguration).  The layer blob need not exist because
    # the disk-space check fires before any layer is fetched.

    # Minimal OCI image config (empty rootfs, no layers referenced inside config)
    # The config must include a bootable label ("containers.bootc" or "ostree.bootable")
    # so that bootc's require_bootable() check in prepare() passes.
    let config_content = '{"architecture":"amd64","os":"linux","config":{"Labels":{"containers.bootc":"1"}},"rootfs":{"type":"layers","diff_ids":[]},"history":[{"created_by":"fake layer"}]}'
    let config_digest = $config_content | hash sha256
    let config_size = ($config_content | str length)

    # Write config blob
    mkdir $"($td)/blobs/sha256"
    $config_content | save $"($td)/blobs/sha256/($config_digest)"

    # Fake layer: a digest that points to a non-existent blob is fine because
    # the preflight check reads the declared size from the manifest only.
    let fake_layer_digest = "0000000000000000000000000000000000000000000000000000000000000000"
    let fake_layer_size = 999_999_999_999_999  # ~999 TiB — will never fit on disk

    # OCI image manifest pointing to the real config + one fake large layer
    let manifest_content = $'{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:($config_digest)","size":($config_size)},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:($fake_layer_digest)","size":($fake_layer_size)}]}'
    let manifest_digest = $manifest_content | hash sha256
    let manifest_size = ($manifest_content | str length)

    # Write manifest blob
    $manifest_content | save $"($td)/blobs/sha256/($manifest_digest)"

    # OCI layout marker
    '{"imageLayoutVersion":"1.0.0"}' | save $"($td)/oci-layout"

    # Index pointing to our manifest
    let index_content = $'{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:($manifest_digest)","size":($manifest_size)}]}'
    $index_content | save $"($td)/index.json"

    # --- Attempt bootc switch; expect pre-flight failure ---
    let result = do { bootc switch --transport oci $td } | complete
    print $"exit_code: ($result.exit_code)"
    print $"stderr: ($result.stderr)"

    assert ($result.exit_code != 0) "bootc switch should have failed due to insufficient disk space"
    assert ($result.stderr | str contains "Insufficient free space") $"Expected 'Insufficient free space' in stderr, got: ($result.stderr)"

    tap ok
}

main
