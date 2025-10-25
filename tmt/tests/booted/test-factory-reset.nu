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

    bootc install reset --experimental

    # sanity check that bootc status shows a new deployment with a non default stateroot
    let reset_status = bootc status --json | from json
    assert not equal $reset_status.status.otherDeployments.0.ostree.stateroot "default"

    # we need tmt in the new stateroot for second_boot
    print "Copying tmt into new stateroot"

    # Get the new stateroot name from the staged deployment
    let new_stateroot = $reset_status.status.otherDeployments.0.ostree.stateroot
    print $"New stateroot: ($new_stateroot)"

    # Mount /sysroot as read-write and copy tmt directory to the new deployment
    mount -o remount,rw /sysroot

    # The new deployment is in /sysroot/ostree/deploy/<stateroot>/var/tmp
    let new_var_path = $"/sysroot/ostree/deploy/($new_stateroot)/var"

    let workdir_root = ($env.TMT_PLAN_DATA | path dirname | path dirname | path dirname | path dirname | path dirname | path dirname | path dirname)

    print $"Copying ($workdir_root) to ($new_var_path)"
    mkdir $new_var_path
    cp -r $workdir_root $new_var_path

    tmt-reboot
}

# The second boot; verify we're in the factory reset deployment
def second_boot [] {
    print "Verifying factory reset completed successfully"
    let status = bootc status --json | from json
    assert not equal $status.status.booted.ostree.stateroot "default"

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
