# number: 51
# tmt:
#   summary: Switch to a derived image using an OCI delta and verify after reboot
#   duration: 30m
#   adjust:
#     - when: distro != fedora
#       enabled: false
#       because: oci-delta is packaged in Fedora
#     - when: boot_type == uki and seal_state == sealed
#       enabled: false
#       because: the guest-local UKI builder produces unsigned images
#
use std assert
use tap.nu

const source_image = "localhost/bootc-delta-source:latest"
const image = "localhost/bootc-delta-target:latest"
const delta = "/var/tmp/image-1-to-2.oci-delta"
const state = "/var/tmp/bootc-delta-state.json"
const marker = "/usr/share/testing-bootc-delta"

def initial_switch [] {
    tap begin "switch from OCI delta"
    assert (not ($marker | path exists))

    bootc image copy-to-storage
    # The composefs export rewrites the config; deploy an exact delta source first.
    (tap make_uki_containerfile $"
        FROM localhost/bootc as base
        RUN echo delta-source > ($marker)
    ") | save Dockerfile
    podman build --network=none -t $source_image .
    bootc switch --transport containers-storage $source_image
    tmt-reboot
}

def delta_switch [] {
    let st = bootc status --json | from json
    let source = skopeo inspect $"containers-storage:($source_image)" | from json
    assert equal $st.status.booted.image.imageDigest $source.Digest
    assert equal (open $marker | str trim) delta-source

    (tap make_uki_containerfile $"
        FROM ($source_image) as base
        RUN echo delta-upgrade > ($marker)
    ") | save --force Dockerfile
    podman build --network=none -t $image .

    let target = skopeo inspect $"containers-storage:($image)" | from json
    let reference = $"localhost/bootc-delta-target@($target.Digest)"
    assert ($target.Digest != $st.status.booted.image.imageDigest)

    oci-delta create $"containers-storage:($source_image)" $"containers-storage:($image)" $delta
    # Keep the target available only through the delta.
    podman rmi $image

    {
        image: $reference
        digest: $target.Digest
        composefs: (tap is_composefs)
    } | to json | save $state

    bootc switch --from-delta $delta $reference
    let staged = (bootc status --json | from json).status.staged.image
    assert equal $staged.image.transport registry
    assert equal $staged.image.image $reference
    assert equal $staged.imageDigest $target.Digest
    assert equal (open $marker | str trim) delta-source
    tmt-reboot
}

def verify_delta [] {
    let expected = open $state
    let booted = (bootc status --json | from json).status.booted.image
    assert equal $booted.image.transport registry
    assert equal $booted.image.image $expected.image
    assert equal $booted.imageDigest $expected.digest
    assert equal (open $marker | str trim) delta-upgrade
    assert equal (tap is_composefs) $expected.composefs
    bootc internals fsck
    tap ok
}

def main [] {
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => initial_switch,
        "1" => delta_switch,
        "2" => verify_delta,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
