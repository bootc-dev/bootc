# number: 64
# tmt:
#   summary: Offline switch preserves the update origin and survives repeated requests
#   duration: 40m
#
use std assert
use tap.nu

const source = "localhost/target-imgref-source:v2"
const origin = "localhost:5555/target-imgref:latest"
const next_origin = "localhost:5555/target-imgref:redirected"
const archive = "/var/tmp/target-imgref-source.tar"
const registry = "bootc-target-imgref-registry"
const marker = "/usr/share/testing-target-imgref"

def status [] { bootc status --json | from json }

def build_image [version: string, image: string] {
    let containerfile = $"FROM localhost/bootc as base\nRUN echo ($version) > ($marker)\n"
    (tap make_uki_containerfile $containerfile) | save --force Containerfile
    podman build -t $image -f Containerfile .
}

def stage [] {
    bootc switch --download-only --transport containers-storage --target-imgref $origin $source
}

def first_boot [] {
    tap begin "offline source and persistent update origin"
    bootc image copy-to-storage
    cd (mktemp -d)
    build_image "v1" "localhost/target-imgref-source:v1"
    build_image "v2" $source

    mkdir /etc/containers/registries.conf.d
    '[[registry]]
location = "localhost:5555"
insecure = true
' | save /etc/containers/registries.conf.d/target-imgref-test.conf
    podman run -d --name $registry -p 127.0.0.1:5555:5000 docker.io/library/registry:2
    # Retry startup readiness through podman's push retry handling.
    podman push --tls-verify=false $source $origin
    # Deliver the exact registry manifest through local storage, as with an
    # offline archive. A push can change layer compression and manifest digests.
    podman pull --tls-verify=false $origin
    podman tag $origin $source
    podman rmi $origin
    podman save --format oci-archive -o $archive $source
    podman stop $registry

    # A new source must still be processed when the update origin is unchanged.
    bootc switch --download-only --transport containers-storage --target-imgref $origin localhost/target-imgref-source:v1
    let previous = (status).status.staged.image.imageDigest
    # A new source must still be processed when the update origin is unchanged.
    stage
    let staged = (status).status.staged
    assert ($staged.image.imageDigest != $previous)
    assert equal $staged.image.image.image $origin
    assert equal $staged.image.image.transport "registry"
    assert $staged.downloadOnly

    # Remove the source while the target registry is also unavailable. A repeat
    # must use deployment metadata without contacting either image location.
    podman rmi $source
    stage
    assert equal (status).status.staged $staged
    let applied = do { bootc switch --apply --transport containers-storage --target-imgref $origin $source } | complete
    assert ($applied.exit_code != 0) "--apply must not bypass a download-only lock"
    assert equal (status).status.staged $staged

    bootc switch --from-downloaded
    assert (not (status).status.staged.downloadOnly)
    tmt-reboot
}

def second_boot [] {
    let booted = (status).status.booted
    assert equal $booted.image.image.image $origin
    assert equal (open $marker | str trim) "v2"

    # Provenance survives reboot. The source remains absent and registry stopped.
    bootc switch --transport containers-storage --target-imgref $origin $source
    assert equal (status).status.booted $booted
    assert equal (status).status.staged null

    podman rm $registry
    tap ok
}

def main [] {
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => first_boot,
        "1" => second_boot,
        $n => { error make { msg: $"Invalid reboot count ($n)" } },
    }
}
