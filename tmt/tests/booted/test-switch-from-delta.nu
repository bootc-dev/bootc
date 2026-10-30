# number: 51
# extra:
#   export_image: true
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

const image = "localhost/bootc-delta-target:latest"
const delta = "/var/tmp/image-1-to-2.oci-delta"
const state = "/var/tmp/bootc-delta-state.json"
const marker = "/usr/share/testing-bootc-delta"

def initial_build [] {
    tap begin "switch from OCI delta"
    assert (not ($marker | path exists))
    let st = bootc status --json | from json

    if not (tap is_composefs) {
        let automounted = (
            do { ^findmnt --mountpoint /boot --types autofs --noheadings } | complete
        ).exit_code == 0
        if $automounted {
            # An expired /boot breaks ostree finalization: https://github.com/bootc-dev/bootc/issues/2402
            let dropin = "/etc/systemd/system/boot.automount.d/bootc-delta-test.conf"
            mkdir ($dropin | path dirname)
            "[Automount]\nTimeoutIdleSec=0\n" | save $dropin
            systemctl daemon-reload
            systemctl restart boot.automount
        }
    }

    let source_archive = $env.BOOTC_source_image_archive? | default "/sysroot/bootc-source.oci.tar"
    assert ($source_archive | path exists) $"Missing source image archive: ($source_archive)"
    skopeo copy $"oci-archive:($source_archive)" containers-storage:localhost/bootc

    (tap make_uki_containerfile $"
        FROM localhost/bootc as base
        RUN echo delta-upgrade > ($marker)
    ") | save Dockerfile
    podman build --network=none -t $image .

    let target = skopeo inspect $"containers-storage:($image)" | from json
    let reference = $"localhost/bootc-delta-target@($target.Digest)"
    assert ($target.Digest != $st.status.booted.image.imageDigest)

    oci-delta create $"oci-archive:($source_archive)" $"containers-storage:($image)" $delta
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
    assert (not ($marker | path exists))
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
        null | "0" => initial_build,
        "1" => verify_delta,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
