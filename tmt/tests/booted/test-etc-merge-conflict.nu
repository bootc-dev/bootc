# number: 46
# tmt:
#   summary: Verify etc merge conflicts are caught during upgrade, not finalization
#   duration: 15m
#
# Verifies that file-to-directory and directory-to-file type changes between
# the current /etc and the new image's /etc are detected during `bootc switch`
# (the upgrade phase) and cause it to fail immediately, rather than silently
# staging and failing during finalization at reboot.
#
# No reboot needed: the upgrade is expected to fail before staging.
use std assert
use tap.nu

if not (tap is_composefs) {
    exit 0
}

tap begin "etc merge conflict detection during upgrade"

def main [] {
    bootc image copy-to-storage

    # Test case 1: File in current /etc conflicts with directory in new image's /etc.
    # Create a file on the live system; the new image will have a directory at
    # the same path.
    "local modification" | save /etc/test-etc-merge-conflict

    let td = mktemp -d
    cd $td

    let dockerfile = '
FROM localhost/bootc as base
RUN mkdir -p /etc/test-etc-merge-conflict && \
    echo "inner" > /etc/test-etc-merge-conflict/inner.conf
'
    (tap make_uki_containerfile $dockerfile) | save Dockerfile
    podman build -t localhost/bootc-etc-conflict .

    let result = do { bootc switch --transport containers-storage localhost/bootc-etc-conflict } | complete
    print $"exit_code: ($result.exit_code)"
    print $"stderr: ($result.stderr)"

    assert ($result.exit_code != 0) "bootc switch should fail: locally-added file conflicts with directory in new etc"
    assert ($result.stderr | str contains "Merge conflicts found in etc") $"Expected 'Merge conflicts found in etc' in stderr, got: ($result.stderr)"

    # Verify no deployment was staged - the failure must happen during upgrade,
    # not during finalization at reboot.
    assert ((bootc status --json | from json | get status.staged) == null) "No deployment should be staged after merge conflict failure"

    # Test case 2: Directory in current /etc conflicts with file in new image's /etc.
    # Create a directory with a file inside on the live system; the new image
    # will have a regular file at the same path.
    mkdir /etc/test-etc-merge-dir
    "local config" | save /etc/test-etc-merge-dir/local.conf

    let td2 = mktemp -d
    cd $td2

    let dockerfile2 = '
FROM localhost/bootc as base
RUN echo "now a file" > /etc/test-etc-merge-dir
'
    (tap make_uki_containerfile $dockerfile2) | save Dockerfile
    podman build -t localhost/bootc-etc-conflict-2 .

    let result2 = do { bootc switch --transport containers-storage localhost/bootc-etc-conflict-2 } | complete
    print $"exit_code: ($result2.exit_code)"
    print $"stderr: ($result2.stderr)"

    assert ($result2.exit_code != 0) "bootc switch should fail: locally-added directory conflicts with file in new etc"
    assert ($result2.stderr | str contains "Merge conflicts found in etc") $"Expected 'Merge conflicts found in etc' in stderr, got: ($result2.stderr)"

    # Again verify nothing was staged
    assert ((bootc status --json | from json | get status.staged) == null) "No deployment should be staged after directory-to-file conflict failure"

    tap ok
}
