# number: 21
# tmt:
#   summary: Execute logically bound images tests for switching images
#   duration: 30m
# extra:
#   fixme_skip_if_composefs: true
#
# This test does:
# bootc image switch bootc-bound-image
# <verify bound images are pulled>
# <reboot>
# <verify booted state>
# bootc upgrade
# <verify new bound images are pulled>
# <reboot>
# <verify booted state>
#
# This test also verifies that authenticated LBIs work in two scenarios:
# 1. Auth credentials stored in the image itself
# 2. Auth credentials stored on the running system
#
# The test uses cstor-dist to serve images from containers-storage via an
# authenticated OCI registry endpoint.

use std assert
use tap.nu
use bootc_testlib.nu [CSTOR_DIST_REGISTRY, start_cstor_dist, get_cstor_auth, setup_insecure_registry, setup_system_auth]

# This code runs on *each* boot.
bootc status
let st = bootc status --json | from json
let booted = $st.status.booted.image

def initial_setup [] {
    bootc image copy-to-storage
    podman images
    podman image inspect localhost/bootc | from json
}

# Build an image with optional auth.json baked in
def build_image [name images containers --with-auth] {
    let td = mktemp -d
    cd $td
    mkdir usr/share/containers/systemd

    mut dockerfile = "FROM localhost/bootc
COPY usr/ /usr/
RUN echo sanity check > /usr/share/bound-image-sanity-check.txt
" | save Dockerfile

    for image in $images {
        echo $"[Image]\nImage=($image.image)" | save $"usr/share/containers/systemd/($image.name).image"
        if $image.bound == true {
            # these extra RUNs are suboptimal
            # however, this is just a test image and the extra RUNs will only add a couple extra layers
            # the benefit is simplified file creation, i.e. we don't need to handle adding "&& \" to each line
            echo $"RUN ln -s /usr/share/containers/systemd/($image.name).image /usr/lib/bootc/bound-images.d/($image.name).image\n" | save Dockerfile --append
        }
    }

    for container in $containers {
        echo $"[Container]\nImage=($container.image)" | save $"usr/share/containers/systemd/($container.name).container"
        if $container.bound == true {
            echo $"RUN ln -s /usr/share/containers/systemd/($container.name).container /usr/lib/bootc/bound-images.d/($container.name).container\n" | save Dockerfile --append
        }
    }

    # Optionally bake auth.json into the image
    if $with_auth {
        let cstor = get_cstor_auth
        print "Baking auth.json into the image"
        mkdir etc/ostree
        let auth_json = $'{"auths": {"($cstor.registry)": {"auth": "($cstor.auth_b64)"}}}'
        echo $auth_json | save etc/ostree/auth.json
        echo "COPY etc/ /etc/\n" | save Dockerfile --append
    }

    # Build it
    podman build -t $name .
    # Just sanity check it
    let v = podman run --rm $name cat /usr/share/bound-image-sanity-check.txt | str trim
    assert equal $v "sanity check"
}

def verify_images [images containers] {
    let bound_images = $images | where bound == true
    let bound_containers = $containers | where bound == true
    let num_bound = ($bound_images | length) + ($bound_containers | length)

    let image_names = podman --storage-opt=additionalimagestore=/usr/lib/bootc/storage images --format json | from json | select -i Names

    for $image in $bound_images {
        # Check if the expected image name is IN the Names array (not exact match)
        let found = $image_names | where { |row| $image.image in $row.Names }
        assert (($found | length) > 0) $"($image.image) not found"
    }

    for $container in $bound_containers {
        let found = $image_names | where { |row| $container.image in $row.Names }
        assert (($found | length) > 0) $"($container.image) not found"
    }
}

def first_boot [] {
    tap begin "bootc switch with bound images"

    initial_setup

    # Start cstor-dist for authenticated LBI testing
    start_cstor_dist
    setup_insecure_registry

    # Set up auth on running system for the switch operation
    # The image will also have auth baked in - both should work
    setup_system_auth

    # Build a bootc image that includes bound images
    # Include an authenticated LBI from cstor-dist with auth baked into the image
    let images = [
        { "bound": true, "image": "registry.access.redhat.com/ubi9/ubi-minimal:9.4", "name": "ubi-minimal" },
        { "bound": false, "image": "quay.io/centos-bootc/centos-bootc:stream9", "name": "centos-bootc" },
        { "bound": true, "image": $"($CSTOR_DIST_REGISTRY)/docker.io/library/alpine:latest", "name": "cstor-alpine" }
    ]

    let containers = [{
        "bound": true, "image": "docker.io/library/alpine:latest", "name": "alpine"
    }]

    let image_name = "localhost/bootc-bound"
    print "Building image WITH auth.json baked in (tests auth from image)"
    build_image $image_name $images $containers --with-auth
    bootc switch --transport containers-storage $image_name
    verify_images $images $containers
    tmt-reboot
}

def second_boot [] {
    print "verifying second boot after switch"
    assert equal $booted.image.transport containers-storage
    assert equal $booted.image.image localhost/bootc-bound

    # Start cstor-dist again (container doesn't survive reboot)
    start_cstor_dist
    setup_insecure_registry

    # Set up auth on the RUNNING SYSTEM for the upgrade
    # The new image will NOT have auth baked in, so the fallback to system auth is needed
    setup_system_auth

    # Verify images from first switch are still there
    let images = [
        { "bound": true, "image": "registry.access.redhat.com/ubi9/ubi-minimal:9.4", "name": "ubi-minimal" },
        { "bound": false, "image": "quay.io/centos-bootc/centos-bootc:stream9", "name": "centos-bootc" },
        { "bound": true, "image": $"($CSTOR_DIST_REGISTRY)/docker.io/library/alpine:latest", "name": "cstor-alpine" }
    ]

    let containers = [{
        "bound": true, "image": "docker.io/library/alpine:latest", "name": "alpine"
    }]
    verify_images $images $containers

    # Build a NEW bootc image WITHOUT auth baked in
    # Add a DIFFERENT authenticated LBI (busybox instead of alpine)
    # This tests that auth from the running system works (the fallback fix)
    print "bootc upgrade with another bound image"
    let image_name = "localhost/bootc-bound"
    let more_images = [
        { "bound": true, "image": "registry.access.redhat.com/ubi9/ubi-minimal:9.4", "name": "ubi-minimal" },
        { "bound": true, "image": "registry.access.redhat.com/ubi9/ubi-minimal:9.3", "name": "ubi-minimal-9-3" },
        { "bound": false, "image": "quay.io/centos-bootc/centos-bootc:stream9", "name": "centos-bootc" },
        { "bound": true, "image": $"($CSTOR_DIST_REGISTRY)/docker.io/library/alpine:latest", "name": "cstor-alpine" },
        { "bound": true, "image": $"($CSTOR_DIST_REGISTRY)/docker.io/library/busybox:latest", "name": "cstor-busybox" }
    ]
    print "Building image WITHOUT auth.json (tests auth fallback from running system)"
    build_image $image_name $more_images $containers
    bootc upgrade
    verify_images $more_images $containers
    tmt-reboot
}

def third_boot [] {
    print "verifying third boot after upgrade"
    assert equal $booted.image.transport containers-storage
    assert equal $booted.image.image localhost/bootc-bound

    # No need to start cstor-dist - we're just verifying the images are in storage
    let images = [
        { "bound": true, "image": "registry.access.redhat.com/ubi9/ubi-minimal:9.4", "name": "ubi-minimal" },
        { "bound": true, "image": "registry.access.redhat.com/ubi9/ubi-minimal:9.3", "name": "ubi-minimal-9-3" },
        { "bound": false, "image": "quay.io/centos-bootc/centos-bootc:stream9", "name": "centos-bootc" },
        { "bound": true, "image": $"($CSTOR_DIST_REGISTRY)/docker.io/library/alpine:latest", "name": "cstor-alpine" },
        { "bound": true, "image": $"($CSTOR_DIST_REGISTRY)/docker.io/library/busybox:latest", "name": "cstor-busybox" }
    ]

    let containers = [{
        "bound": true, "image": "docker.io/library/alpine:latest", "name": "alpine"
    }]

    verify_images $images $containers
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
