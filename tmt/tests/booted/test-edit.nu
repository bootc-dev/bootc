# number: 50
# tmt:
#   summary: Test bootc edit for image changes and rollback
#   duration: 30m
#
# This test verifies `bootc edit --filename` on both backends:
# 1. An unchanged spec is a no-op, and an edit changing both the image and
#    the boot order is rejected
# 2. Changing spec.image stages that image, and we boot into it
# 3. Flipping spec.bootOrder queues a rollback, and we boot back
use std assert
use tap.nu

const target_image = "localhost/bootc-edit-target"
const marker = "/usr/share/bootc-edit-marker"
const initial_state = "/var/bootc-edit-initial-state.json"
const spec_file = "/var/tmp/bootc-edit-host.yaml"

def status_json [] {
    bootc status --json | from json
}

# Run `bootc edit` with the given host definition
def bootc_edit [host: record] {
    $host | to yaml | save -f $spec_file
    bootc edit --filename $spec_file
}

def first_boot [] {
    tap begin "bootc edit"

    let initial = status_json
    $initial.status.booted.image | to json | save -f $initial_state

    let out = bootc_edit $initial
    assert str contains $out "Edit cancelled"
    assert ((status_json).status.staged | is-empty)

    bootc image copy-to-storage
    let dockerfile = $"FROM localhost/bootc as base
RUN echo 'bootc edit target' > ($marker)
"
    (tap make_uki_containerfile $dockerfile) | podman build -t $target_image -f - .

    let target = $initial
        | update spec.image.image $target_image
        | update spec.image.transport "containers-storage"

    # Changing the image and the boot order at once is not a valid transition
    let r = do { bootc_edit ($target | update spec.bootOrder "rollback") } | complete
    assert ($r.exit_code != 0) "Expected image change + rollback to be rejected"
    assert str contains $r.stderr "Invalid state transition"
    assert ((status_json).status.staged | is-empty)

    bootc_edit $target
    let staged = (status_json).status.staged
    assert equal $staged.image.image.image $target_image
    assert equal $staged.image.image.transport "containers-storage"

    tmt-reboot
}

def second_boot [] {
    let st = status_json
    assert equal $st.status.booted.image.image.image $target_image
    assert ($marker | path exists)
    assert equal $st.spec.bootOrder "default"

    bootc_edit ($st | update spec.bootOrder "rollback")
    let st = status_json
    assert equal $st.spec.bootOrder "rollback"
    assert equal $st.status.rollbackQueued true

    tmt-reboot
}

def third_boot [] {
    let st = status_json
    let initial = open $initial_state
    assert equal $st.status.booted.image $initial
    assert (not ($marker | path exists))
    assert equal $st.status.rollbackQueued false

    tap ok
}

def main [] {
    # See https://tmt.readthedocs.io/en/stable/stories/features.html#reboot-during-test
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => first_boot,
        "1" => second_boot,
        "2" => third_boot,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
