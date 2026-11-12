# number: 46
# tmt:
#   summary: Verify etc merge conflicts are caught during upgrade, not finalization
#   duration: 15m
# extra:
#   skip_if_ostree: true
#
# Verifies that file-to-directory and directory-to-file type changes between
# the current /etc and the new image's /etc are detected during `bootc switch`
# (the upgrade phase) and cause it to fail immediately, rather than silently
# staging and failing during finalization at reboot.
#
# No reboot needed: the upgrade is expected to fail before staging.
use std assert
use tap.nu

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
    
    let missingVerityAllowed = bootc status --json | from json | get status.booted.composefs.missingVerityAllowed

    # Test that a change in fsverity on a file actually shows up as modified
    if not $missingVerityAllowed {
      mkdir /var/etc-test/current /var/etc-test/new /var/etc-test/pristine
      echo "hello" | save /var/etc-test/pristine/hello
      echo "hello-new" | save /var/etc-test/current/hello

      ^find /var/etc-test/ -type f -exec fsverity enable {} ';'

      let out = bootc internals dir-diff /var/etc-test/pristine/ /var/etc-test/current/ /var/etc-test/new/ --json | from json | get modified
      assert equal ($out | length) 1
      assert equal ($out | first) "hello"

      # Test one file with fs-verity enable and other without
      rm -rf /var/etc-test
      mkdir /var/etc-test/current /var/etc-test/new /var/etc-test/pristine
      echo "hello" | save /var/etc-test/pristine/hello
      echo "hello-new" | save /var/etc-test/current/hello

      fsverity enable /var/etc-test/pristine/hello

      let out = bootc internals dir-diff /var/etc-test/pristine/ /var/etc-test/current/ /var/etc-test/new/ --json | from json | get modified
      assert equal ($out | length) 1
      assert equal ($out | first) "hello"
    }

    tap ok
}
