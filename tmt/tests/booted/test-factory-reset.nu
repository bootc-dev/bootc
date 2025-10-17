use std assert
use tap.nu

def initial_build [] {
    tap begin "factory reset test"

    # Create test files that should be removed after factory reset
    print "Creating test files in /var and /etc"
    echo "test file in var" | save /var/test-file-factory-reset
    echo "test file in etc" | save /etc/test-file-factory-reset

    # Verify files were created
    assert ("/var/test-file-factory-reset" | path exists)
    assert ("/etc/test-file-factory-reset" | path exists)

    # Store the original stateroot
    let status = bootc status --json | from json
    let orig_stateroot = $status.status.booted.ostree.stateroot
    $orig_stateroot | save /var/tmp/tmt/orig_stateroot

    bootc install reset --experimental

    # sanity check that bootc status shows a new deployment with a non default stateroot
    let reset_status = bootc status --json | from json
    assert not equal $reset_status.status.otherDeployments.0.ostree.stateroot "default"

    # we need tmt in the new stateroot for second_boot
    print "Copying tmt into new stateroot"
    mount -o remount,rw /sysroot
    let stateroot = ls /sysroot/ostree/deploy
    cp -r /var/tmp/tmt $"($stateroot.1.name)/var/tmp"

    tmt-reboot
}

# The second boot; verify we're in the factory reset deployment
def second_boot [] {
    print "Verifying factory reset completed successfully"
    let status = bootc status --json | from json
    let new_stateroot = $status.status.booted.ostree.stateroot
    let orig_stateroot = open /var/tmp/tmt/orig_stateroot
    assert ($orig_stateroot != $new_stateroot) "Should be booted into a new deployment"

    print "Checking that test files do not exist in the reset deployment"
    assert (not ("/var/test-file-factory-reset" | path exists)) "Test file in /var should not exist after factory reset"
    assert (not ("/etc/test-file-factory-reset" | path exists)) "Test file in /etc should not exist after factory reset"
    print "Factory reset verification completed successfully"
    tap ok
}

def main [] {
    # See https://tmt.readthedocs.io/en/stable/stories/features.html#reboot-during-test
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => initial_build,
        "1" => second_boot,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
