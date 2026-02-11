# number: 22
# tmt:
#   summary: Execute logically bound images tests for installing image
#   duration: 30m
# extra:
#   fixme_skip_if_composefs: true
#
use std assert
use tap.nu

# This list reflects the LBIs specified in bootc/tests/containerfiles/lbi/usr/share/containers/systemd
let expected_images = [
    "quay.io/curl/curl:latest",
    "quay.io/curl/curl-base:latest",
    "registry.access.redhat.com/ubi9/podman:latest" # this image is signed
]

def validate_images [images: list<string>] {
    print $"Validating images ($images)"
    for expected in $expected_images {
        assert ($expected in $images)
    }
}

# This test checks that bootc actually populated the bootc storage with the LBI images
def test_logically_bound_images_in_storage [] {
    # Use podman to list the images in the bootc storage
    let images = podman --storage-opt=additionalimagestore=/usr/lib/bootc/storage images --format {{.Repository}}:{{.Tag}} | split row "\n"

    # Debug print
    print "IMAGES:"
    podman --storage-opt=additionalimagestore=/usr/lib/bootc/storage images

    validate_images $images
}

# This test makes sure that bootc itself knows how to list the LBI images in the bootc storage
def test_bootc_image_list [] {
    # Use bootc to list the images in the bootc storage
    let images = bootc image list --type logical --format json | from json | get image

    validate_images $images
}

# Get just the type (foo_t) from a security context
def get_file_selinux_type [p] {
    getfattr --only-values -n security.selinux $p | split row ':' | get 2
}

# Verify that the SELinux labels on the main "containers-storage:" instance match ours.
# See the relabeling we do in imgstorage.rs. We only verify types, because the role
# may depend on the creating user.
def test_storage_labels [] {
    for v in [".", "overlay-images", "defaultNetworkBackend"] {
        let base = (get_file_selinux_type $"/var/lib/containers/storage/($v)")
        let target = (get_file_selinux_type $"/usr/lib/bootc/storage/($v)")
        assert equal $base $target
    }
    # Verify the stamp file exists
    test -f /usr/lib/bootc/storage/.bootc_labeled
}

test_logically_bound_images_in_storage
test_bootc_image_list
test_storage_labels

tap ok
