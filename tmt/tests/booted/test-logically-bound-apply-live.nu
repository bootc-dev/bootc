# number: 49
# tmt:
#   summary: Execute logically bound images tests for bootc apply-live bound-images
#   duration: 30m
# extra:
#   fixme_skip_if_composefs: true
#
# This test does:
# bootc switch to an image with a bound .container (v1)
# <reboot>
# <verify the container runs v1>
# bootc upgrade to an image whose only change is the bound .container (v2)
# bootc apply-live bound-images --dry-run / --no-restart / (plain)
# <verify the container runs v2 without a reboot, and status/GC state>
# bootc upgrade to an image with an unrelated change
# <verify apply-live refuses>
# <reboot>
# <verify the /run override is gone and v2 is booted>

use std assert
use tap.nu

# This code runs on *each* boot.
bootc status
let st = bootc status --json | from json
let booted = $st.status.booted.image

# Two distinct tags of the same small image so we can tell which one a
# container was started from.
const image_v1 = "registry.access.redhat.com/ubi9/ubi-minimal:9.4"
const image_v2 = "registry.access.redhat.com/ubi9/ubi-minimal:9.3"
const quadlet = "/usr/share/containers/systemd/lbi-sleeper.container"
const run_quadlet = "/run/containers/systemd/lbi-sleeper.container"
const unit = "lbi-sleeper.service"
const state_file = "/run/bootc/apply-live/bound-images.json"

def initial_setup [] {
    bootc image copy-to-storage
    podman images
    podman image inspect localhost/bootc | from json
}

# Build a bootc image on top of the booted one with a single bound
# .container that just sleeps, referencing $image. If $extra is set, also
# add an unrelated file so the diff is out of scope for apply-live.
def build_image [name image extra] {
    let td = mktemp -d
    cd $td
    mkdir usr/share/containers/systemd
    $"[Container]
Image=($image)
Exec=sleep infinity
GlobalArgs=--storage-opt=additionalimagestore=/usr/lib/bootc/storage

[Install]
WantedBy=multi-user.target
" | save usr/share/containers/systemd/lbi-sleeper.container

    mut dockerfile = "FROM localhost/bootc
COPY usr/ /usr/
RUN ln -s /usr/share/containers/systemd/lbi-sleeper.container /usr/lib/bootc/bound-images.d/lbi-sleeper.container
"
    if $extra {
        $dockerfile = $dockerfile + "RUN echo unrelated > /usr/share/apply-live-out-of-scope.txt\n"
    }
    $dockerfile | save Dockerfile
    podman build -t $name .
}

# Return the image a running container was created from. The image lives in
# the bootc storage, so podman needs the same additional store the quadlet uses.
def running_image [] {
    podman --storage-opt=additionalimagestore=/usr/lib/bootc/storage inspect systemd-lbi-sleeper --format '{{.ImageName}}' | str trim
}

def first_boot [] {
    tap begin "bootc apply-live bound-images"
    initial_setup
    build_image localhost/bootc-lbi-live $image_v1 false
    bootc switch --transport containers-storage localhost/bootc-lbi-live
    tmt-reboot
}

def second_boot [] {
    print "verifying second boot after switch"
    assert equal $booted.image.image localhost/bootc-lbi-live
    systemctl is-active $unit
    assert equal (running_image) $image_v1
    assert not ($run_quadlet | path exists)
    assert equal $st.status.liveBoundImages? null

    # Without a staged deployment there's nothing to apply
    let r = do { bootc apply-live bound-images } | complete
    assert not equal $r.exit_code 0
    assert ($r.stderr | str contains "No staged deployment")

    # Stage an image whose only change is the bound container's image
    print "bootc upgrade to v2 of the bound image"
    build_image localhost/bootc-lbi-live $image_v2 false
    bootc upgrade
    let st = bootc status --json | from json
    assert not equal $st.status.staged null
    let staged_checksum = $st.status.staged.ostree.checksum

    # Dry run changes nothing
    let out = bootc apply-live bound-images --dry-run
    print $out
    assert ($out | str contains $"updated: ($image_v2) \(($unit)\)")
    assert not ($run_quadlet | path exists)
    assert equal (running_image) $image_v1

    # --no-restart writes the definition but leaves the unit alone
    bootc apply-live lbi --no-restart
    assert ($run_quadlet | path exists)
    assert (open $run_quadlet | str contains $image_v2)
    assert equal (getfattr --only-values -n security.selinux $run_quadlet | split row ':' | get 2) container_var_run_t
    assert equal (running_image) $image_v1
    let state = open $state_file
    assert equal $state.checksum $staged_checksum
    let entry = $state.images | where unit? == $unit | first
    assert equal $entry.pending true
    let live = bootc status --json | from json | get status.liveBoundImages
    assert equal $live.checksum $staged_checksum

    # A plain re-run restarts the pending unit
    let out = bootc apply-live bound-images
    print $out
    assert ($out | str contains $"restart pending: ($unit)")
    systemctl is-active $unit
    assert equal (running_image) $image_v2
    let state = open $state_file
    let entry = $state.images | where unit? == $unit | first
    assert equal ($entry.pending? | default false) false
    let human = bootc status --format humanreadable
    print $human
    assert ($human | str contains "Live bound images")

    # And is idempotent afterwards
    let out = bootc apply-live bound-images
    assert ($out | str contains "already applied")
    assert equal (running_image) $image_v2

    # The live-applied images survive garbage collection even without the
    # staged deployment: rollback discards it (then revert the queued rollback
    # so we still boot the default), and cleanup prunes the store.
    bootc rollback
    bootc rollback
    let st = bootc status --json | from json
    assert equal $st.status.staged null
    assert equal $st.status.rollbackQueued false
    bootc internals cleanup
    let names = podman --storage-opt=additionalimagestore=/usr/lib/bootc/storage images --format '{{.Repository}}:{{.Tag}}' | lines
    assert ($image_v2 in $names)
    assert equal (running_image) $image_v2

    # A staged deployment with an unrelated change is refused
    print "bootc upgrade with an out-of-scope change"
    build_image localhost/bootc-lbi-live $image_v2 true
    bootc upgrade
    let r = do { bootc apply-live bound-images } | complete
    print $r.stderr
    assert not equal $r.exit_code 0
    assert ($r.stderr | str contains "reboot is required")
    assert ($r.stderr | str contains "/usr/share/apply-live-out-of-scope.txt")
    # The previously applied definition is still live
    assert equal (running_image) $image_v2

    tmt-reboot
}

def third_boot [] {
    print "verifying third boot after upgrade"
    # /run is fresh: no override, no state, and the deployment's own
    # definition (v2) is what runs.
    assert not ($run_quadlet | path exists)
    assert not ($state_file | path exists)
    assert equal $st.status.liveBoundImages? null
    assert (open $quadlet | str contains $image_v2)
    systemctl is-active $unit
    assert equal (running_image) $image_v2
    tap ok
}

def main [] {
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => first_boot,
        "1" => second_boot,
        "2" => third_boot,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
