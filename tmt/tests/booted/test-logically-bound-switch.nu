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

use std assert
use tap.nu

# This code runs on *each* boot.
bootc status
let st = bootc status --json | from json
let booted = $st.status.booted.image

# The tests here aren't fetching from a registry which requires auth by default,
# but we can replicate the failure in https://github.com/bootc-dev/bootc/pull/1852
# by just injecting any auth file.
echo '{}' | save -f /run/ostree/auth.json

def initial_setup [] {
    bootc image copy-to-storage
    podman images
    podman image inspect localhost/bootc | from json
}

def build_image [name images containers] {
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
        let found = $image_names | where Names == [$image.image]
        assert (($found | length) > 0) $"($image.image) not found"
    }

    for $container in $bound_containers {
        let found = $image_names | where Names == [$container.image]
        assert (($found | length) > 0) $"($container.image) not found"
    }
}

def first_boot [] {
    tap begin "bootc switch with bound images"

    initial_setup

    # build a bootc image that includes bound images
    let images = [
        { "bound": true, "image": "registry.access.redhat.com/ubi9/ubi-minimal:9.4", "name": "ubi-minimal" },
        { "bound": false, "image": "quay.io/centos-bootc/centos-bootc:stream9", "name": "centos-bootc" }
    ]

    let containers = [{
        "bound": true, "image": "docker.io/library/alpine:latest", "name": "alpine" 
    }]

    let image_name = "localhost/bootc-bound"
    build_image $image_name $images $containers
    bootc switch --transport containers-storage $image_name
    verify_images $images $containers
    tmt-reboot
}

def second_boot [] {
    print "verifying second boot after switch"
    assert equal $booted.image.transport containers-storage
    assert equal $booted.image.image localhost/bootc-bound

    # verify images are still there after boot
    let images = [
        { "bound": true, "image": "registry.access.redhat.com/ubi9/ubi-minimal:9.4", "name": "ubi-minimal" },
        { "bound": false, "image": "quay.io/centos-bootc/centos-bootc:stream9", "name": "centos-bootc" }
    ]

    let containers = [{
        "bound": true, "image": "docker.io/library/alpine:latest", "name": "alpine" 
    }]
    verify_images $images $containers

    # build a new bootc image with an additional bound image
    print "bootc upgrade with another bound image"
    let image_name = "localhost/bootc-bound"
    let more_images = $images | append [{ "bound": true, "image": "registry.access.redhat.com/ubi9/ubi-minimal:9.3", "name": "ubi-minimal-9-3" }]
    build_image $image_name $more_images $containers
    bootc upgrade
    verify_images $more_images $containers
    tmt-reboot
}

def third_boot [] {
    print "verifying third boot after upgrade"
    assert equal $booted.image.transport containers-storage
    assert equal $booted.image.image localhost/bootc-bound

    let images = [
        { "bound": true, "image": "registry.access.redhat.com/ubi9/ubi-minimal:9.4", "name": "ubi-minimal" },
        { "bound": true, "image": "registry.access.redhat.com/ubi9/ubi-minimal:9.3", "name": "ubi-minimal-9-3" },
        { "bound": false, "image": "quay.io/centos-bootc/centos-bootc:stream9", "name": "centos-bootc" }
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
