# number: 46
# tmt:
#   summary: Test etc merge strategy (skip/replace/fail)
#   duration: 30m

use std assert
use tap.nu
use bootc_testlib.nu

if not (tap is_composefs) {
    tap ok
    exit 0
}

# Image that changes a file to a directory and a directory to a file
const DOCKERFILE_CONFLICT = '
FROM localhost/bootc as base

# file-to-dir: /etc/test-file-to-dir was a file in base, now becomes a directory
RUN rm -f /etc/test-file-to-dir && mkdir -p /etc/test-file-to-dir && echo "new-default" > /etc/test-file-to-dir/config

# dir-to-file: /etc/test-dir-to-file/ was a directory in base, now becomes a file
RUN rm -rf /etc/test-dir-to-file && echo "new-default-file" > /etc/test-dir-to-file
'

def first_boot [] {
    tap begin "etc merge strategy test"

    bootc image copy-to-storage

    # Create the paths in the running pristine image so they exist in the base
    # file-to-dir: starts as a file
    echo "pristine-content" | save --force /etc/test-file-to-dir

    # dir-to-file: starts as a directory with a child
    mkdir /etc/test-dir-to-file
    echo "pristine-child" | save --force /etc/test-dir-to-file/child.conf

    # Now modify them (simulating user customization on the live system)
    echo "user-modified-content" | save --force /etc/test-file-to-dir
    echo "user-modified-child" | save --force /etc/test-dir-to-file/child.conf

    # Build the conflicting image
    (tap make_uki_containerfile $DOCKERFILE_CONFLICT) | save --force Dockerfile
    podman build -t localhost/bootc-etc-conflict .

    # Switch with skip strategy: new defaults should win
    bootc switch --transport containers-storage --merge-strategy skip localhost/bootc-etc-conflict
    tmt-reboot
}

def second_boot [] {
    # Verify skip: new defaults won
    # file-to-dir: should now be a directory (new default won)
    assert (/etc/test-file-to-dir | path type) == "dir" "skip: file-to-dir should be a directory"
    assert (open /etc/test-file-to-dir/config | str trim) == "new-default" "skip: file-to-dir/config should have new default content"

    # dir-to-file: should now be a file (new default won)
    assert (/etc/test-dir-to-file | path type) == "file" "skip: dir-to-file should be a file"
    assert (open /etc/test-dir-to-file | str trim) == "new-default-file" "skip: dir-to-file should have new default content"

    # Re-create the original paths as files/dirs so they exist in this image's pristine etc
    echo "pristine-content-2" | save --force /etc/test-file-to-dir-2

    mkdir /etc/test-dir-to-file-2
    echo "pristine-child-2" | save --force /etc/test-dir-to-file-2/child.conf

    # User modifications
    echo "user-keeps-this" | save --force /etc/test-file-to-dir-2
    echo "user-keeps-this-child" | save --force /etc/test-dir-to-file-2/child.conf

    # Build image with type conflicts on the -2 paths
    let dockerfile_replace = '
FROM localhost/bootc as base
RUN rm -f /etc/test-file-to-dir-2 && mkdir -p /etc/test-file-to-dir-2 && echo "should-be-replaced" > /etc/test-file-to-dir-2/config
RUN rm -rf /etc/test-dir-to-file-2 && echo "should-be-replaced" > /etc/test-dir-to-file-2
'
    (tap make_uki_containerfile $dockerfile_replace) | save --force Dockerfile
    podman build -t localhost/bootc-etc-replace .

    # Switch with replace strategy: user modifications should win
    bootc switch --transport containers-storage --merge-strategy replace localhost/bootc-etc-replace
    tmt-reboot
}

def third_boot [] {
    # Verify replace: user modifications won
    # file-to-dir: user had a file, should still be a file with user content
    assert (/etc/test-file-to-dir-2 | path type) == "file" "replace: file-to-dir-2 should be a file (user wins)"
    assert (open /etc/test-file-to-dir-2 | str trim) == "user-keeps-this" "replace: file-to-dir-2 should have user content"

    # dir-to-file: user had a directory, should still be a directory with user content
    assert (/etc/test-dir-to-file-2 | path type) == "dir" "replace: dir-to-file-2 should be a directory (user wins)"
    assert (open /etc/test-dir-to-file-2/child.conf | str trim) == "user-keeps-this-child" "replace: child.conf should have user content"

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
