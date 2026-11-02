# number: 64
# tmt:
#   summary: Verify booted and staged deployment image mounts
#   duration: 10m

use std assert

def assert_mount_options [target] {
    let options = (
        findmnt --mountpoint $target --json
        | from json
        | get filesystems.0.options
        | split row ","
    )
    # findmnt's options field reports these VFS mount options, including nosymfollow.
    for option in [ro nosuid nodev nosymfollow] {
        assert (
            $options | any { |value| $value == $option }
        ) $"($target) should have the ($option) mount option"
    }
    assert (not ($options | any { |value| $value == "noexec" })) $"($target) should not have noexec"
}

def cleanup_targets [targets] {
    $targets | each { |target|
        let result = (do -i { bootc image unmount $target } | complete)
        if $result.exit_code != 0 {
            $"($target): unmount failed: ($result.stderr); mount target left in place"
        }
    } | where { |failure| $failure != null }
}

def mount_image [deployment source target] {
    let result = (do -i {
        bootc image mount --deployment $deployment --source $source --target $target
    } | complete)
    if $result.exit_code != 0 {
        error make {
            msg: $"Failed to mount ($deployment) image source ($source) at ($target): ($result.stderr)"
        }
    }
}

def verify_image_mounts [base] {
    let root_target = ($base | path join "root")
    let usr_target = ($base | path join "usr")
    let staged_target = ($base | path join "staged")
    mut mounted = []
    let result = try {
        mkdir $root_target $usr_target $staged_target

        mount_image booted / $root_target
        $mounted = ($mounted | append $root_target)
        mount_image booted /usr $usr_target
        $mounted = ($mounted | append $usr_target)

        let root_os_release = ($root_target | path join "usr/lib/os-release")
        let usr_os_release = ($usr_target | path join "lib/os-release")
        assert ($root_os_release | path exists) "booted root mount should contain usr/lib/os-release"
        assert ($usr_os_release | path exists) "/usr mount should contain lib/os-release"
        assert equal (open $root_os_release | into string) (open $usr_os_release | into string)

        assert_mount_options $root_target
        assert_mount_options $usr_target

        let write_path = ($usr_target | path join ".bootc-image-mount-write-test")
        let write_result = (do -i { touch $write_path } | complete)
        assert ($write_result.exit_code != 0) "writes to mounted image content should fail"
        assert (not ($write_path | path exists)) "failed write should not create a file"

        # The mount is intentionally not noexec; verify an image executable runs.
        let true_path = ($usr_target | path join "bin/true")
        let executable_result = (do -i { ^$true_path } | complete)
        assert equal $executable_result.exit_code 0 "mounted /usr/bin/true should be executable"

        let status = (bootc status --json | from json)
        if (($status.status.staged? | default null) != null) {
            mount_image staged /usr $staged_target
            $mounted = ($mounted | append $staged_target)
            let staged_os_release = ($staged_target | path join "lib/os-release")
            assert ($staged_os_release | path exists) "staged /usr mount should contain lib/os-release"
            assert_mount_options $staged_target
        } else {
            print "SKIP: staged image-mount coverage unavailable (active backend reports no staged deployment)"
        }
        true
    } catch { |error| $error }

    {
        result: $result
        mounted: $mounted
    }
}

let base = (^mktemp -d /run/bootc-image-mount.XXXXXX | str trim)
let test_outcome = (verify_image_mounts $base)
let mount_cleanup_errors = (cleanup_targets $test_outcome.mounted)
let cleanup_errors = if (($mount_cleanup_errors | length) > 0) {
    $mount_cleanup_errors | append $"($base): directory retained because a mount could not be unmounted"
} else {
    let remove_result = (do -i { ^rm --recursive $base } | complete)
    if $remove_result.exit_code == 0 {
        []
    } else {
        [$"($base): failed to remove test directory: ($remove_result.stderr)"]
    }
}

if (($cleanup_errors | length) > 0) {
    error make {
        msg: $"Failed to clean up image mounts: ($cleanup_errors); test result: ($test_outcome.result)"
    }
}
if $test_outcome.result != true {
    error make { msg: $"Image mount assertions failed: ($test_outcome.result)" }
}
