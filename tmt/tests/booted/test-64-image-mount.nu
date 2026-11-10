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

def verify_image_mounts [base deployment_etc_marker] {
    let sysroot_options = (
        findmnt --mountpoint /sysroot --json
        | from json
        | get filesystems.0.options
    )
    let root_target = ($base | path join "root")
    let usr_target = ($base | path join "usr")
    let staged_target = ($base | path join "staged")
    mut mounted = []
    let result = try {
        mkdir $root_target $usr_target $staged_target

        let marker_result = (do -i { ^touch $deployment_etc_marker } | complete)
        assert equal $marker_result.exit_code 0 $"failed to create deployment-local /etc marker: ($marker_result.stderr)"
        let root_result = (do -i {
            bootc image mount --deployment booted --source / --target $root_target
        } | complete)
        if $root_result.exit_code == 0 {
            $mounted = ($mounted | append $root_target)
            let root_os_release = ($root_target | path join "usr/lib/os-release")
            let mounted_deployment_marker = ($root_target | path join "etc" ($deployment_etc_marker | path basename))
            assert ($root_os_release | path exists) "booted root mount should contain usr/lib/os-release"
            assert (not ($mounted_deployment_marker | path exists)) "image root must not expose deployment-local /etc"
            assert_mount_options $root_target
        } else {
            assert ($root_result.stderr | str contains "OSTree checkout fallback does not support --source /") $"unexpected root mount failure: ($root_result.stderr)"
            print "SKIP: image-root mount is unsupported for OSTree checkout fallback"
        }
        mount_image booted /usr $usr_target
        $mounted = ($mounted | append $usr_target)

        let usr_os_release = ($usr_target | path join "lib/os-release")
        assert ($usr_os_release | path exists) "/usr mount should contain lib/os-release"

        assert_mount_options $usr_target
        if ($mounted | any { |target| $target == $root_target }) {
            let root_os_release = ($root_target | path join "usr/lib/os-release")
            assert equal (open $root_os_release | into string) (open $usr_os_release | into string)
        }

        let write_path = ($usr_target | path join ".bootc-image-mount-write-test")
        let write_result = (do -i { ^touch $write_path } | complete)
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
        let sysroot_options_after = (
            findmnt --mountpoint /sysroot --json
            | from json
            | get filesystems.0.options
        )
        assert equal $sysroot_options_after $sysroot_options "image mounts should not change /sysroot mount options"
        true
    } catch { |error| $error }

    {
        result: $result
        mounted: $mounted
    }
}

let base = (^mktemp -d /run/bootc-image-mount.XXXXXX | str trim)
let deployment_etc_marker = $"/etc/.bootc-image-mount-deployment-local-(($base | path basename))"
let test_outcome = (verify_image_mounts $base $deployment_etc_marker)
let mount_cleanup_errors = (cleanup_targets $test_outcome.mounted)
mut cleanup_errors = $mount_cleanup_errors
if ($deployment_etc_marker | path exists) {
    let marker_cleanup = (do -i { ^rm -- $deployment_etc_marker } | complete)
    if $marker_cleanup.exit_code != 0 {
        $cleanup_errors = ($cleanup_errors | append $"($deployment_etc_marker): failed to remove deployment-local /etc marker: ($marker_cleanup.stderr)")
    }
}
if (($cleanup_errors | length) == 0) {
    let remove_result = (do -i { ^rm --recursive $base } | complete)
    if $remove_result.exit_code == 0 {
        $cleanup_errors = []
    } else {
        $cleanup_errors = [$"($base): failed to remove test directory: ($remove_result.stderr)"]
    }
} else {
    $cleanup_errors = ($cleanup_errors | append $"($base): directory retained because a mount could not be unmounted")
}

if (($cleanup_errors | length) > 0) {
    error make {
        msg: $"Failed to clean up image mounts: ($cleanup_errors); test result: ($test_outcome.result)"
    }
}
if $test_outcome.result != true {
    error make { msg: $"Image mount assertions failed: ($test_outcome.result)" }
}
