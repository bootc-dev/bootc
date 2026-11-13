# number: 64
# tmt:
#   summary: Verify booted and staged deployment image mounts
#   duration: 30m

use std assert
use tap.nu

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

def secure_boot_enabled [] {
    let secure_boot_var = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
    let read_result = (do -i { ^od -An -t u1 $secure_boot_var } | complete)
    if $read_result.exit_code != 0 {
        error make {
            msg: $"Failed to read Secure Boot EFI variable ($secure_boot_var): ($read_result.stderr)"
        }
    }
    let bytes = try {
        $read_result.stdout | split words | each { into int }
    } catch {
        error make { msg: $"Failed to parse Secure Boot EFI variable ($secure_boot_var)" }
    }
    if ($bytes | length) != 5 {
        error make {
            msg: $"Unexpected Secure Boot EFI variable size at ($secure_boot_var): expected 5 bytes, got (($bytes | length))"
        }
    }
    let enabled = ($bytes | last)
    if not ($enabled in [0 1]) {
        error make { msg: $"Invalid Secure Boot EFI variable value at ($secure_boot_var): ($enabled)" }
    }
    $enabled == 1
}

def verify_image_mounts [base deployment_etc_marker staged_marker staged_fixture] {
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
        let booted_staged_marker = ($usr_target | path join "share" ($staged_marker | path basename))
        assert (not ($booted_staged_marker | path exists)) "booted /usr must not contain the staged image marker"

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

        if $staged_fixture {
            mount_image staged /usr $staged_target
            $mounted = ($mounted | append $staged_target)
            let staged_os_release = ($staged_target | path join "lib/os-release")
            assert ($staged_os_release | path exists) "staged /usr mount should contain lib/os-release"
            let staged_marker_path = ($staged_target | path join "share" ($staged_marker | path basename))
            assert ($staged_marker_path | path exists) "staged /usr mount should contain the staged image marker"
            assert equal (open $staged_marker_path | into string) "staged image mount marker\n" "staged image marker content should match exactly"
            assert_mount_options $staged_target
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
let staged_marker = $"/usr/share/bootc-image-mount-(($base | path basename))"
let staged_tag = $"localhost/bootc-image-mount:(($base | path basename))"
let staged_marker_content = "staged image mount marker"

let test_outcome = try {
    let booted_status = (bootc status --json | from json)
    let booted_digest = $booted_status.status.booted.image.imageDigest
    let booted_composefs = ($booted_status.status.booted.composefs? | default null)
    let is_composefs_uki = if $booted_composefs == null {
        false
    } else {
        (($booted_composefs.bootType? | default "" | str downcase) == "uki")
    }
    let skip_staged_fixture = if $is_composefs_uki {
        secure_boot_enabled
    } else {
        false
    }
    assert (not ($staged_marker | path exists)) "staged image marker must be absent from booted /usr before building the fixture"
    let staged_fixture = if $skip_staged_fixture {
        print "SKIP: Secure Boot composefs UKI; tap's staged fixture is unsealed and cannot be signed; booted checks still run"
        false
    } else {
        bootc image copy-to-storage
        let containerfile = (tap make_uki_containerfile $"FROM localhost/bootc as base\nRUN printf '%s\\n' '($staged_marker_content)' > ($staged_marker)")
        let build_result = (do -i { $containerfile | podman build --network=none -t $staged_tag $base -f - } | complete)
        assert equal $build_result.exit_code 0 $"failed to build staged image fixture: ($build_result.stderr)"

        let switch_result = (do -i { bootc switch --transport containers-storage $staged_tag } | complete)
        assert equal $switch_result.exit_code 0 $"failed to stage local image fixture: ($switch_result.stderr)"

        let staged_status = (bootc status --json | from json).status.staged
        assert ($staged_status != null) "bootc switch should create a staged deployment"
        assert equal $staged_status.image.image.transport containers-storage "staged image should use containers-storage transport"
        assert equal $staged_status.image.image.image $staged_tag "staged image should use the derived local image tag"
        assert (($staged_status.image.imageDigest? | default "") != "") "staged image digest should be reported"
        assert (($booted_digest | default "") != "") "booted image digest should be reported"
        assert ($staged_status.image.imageDigest != $booted_digest) "staged image digest should differ from the booted image digest"
        true
    }
    verify_image_mounts $base $deployment_etc_marker $staged_marker $staged_fixture
} catch { |error| { result: $error, mounted: [] } }
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
    $cleanup_errors = ($cleanup_errors | append $"($base): directory retained because cleanup failed")
}

if (($cleanup_errors | length) > 0) {
    error make {
        msg: $"Failed to clean up image mounts: ($cleanup_errors); test result: ($test_outcome.result)"
    }
}
if $test_outcome.result != true {
    error make { msg: $"Image mount assertions failed: ($test_outcome.result)" }
}
