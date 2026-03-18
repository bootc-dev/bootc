use std assert
use tap.nu

tap begin "verify SELinux is enforcing"

# Composefs upgrade source images boot with enforcing=0 because the
# base image's SELinux policy doesn't yet cover composefs file contexts.
# Skip this check in that case.
let upgrade_image = $env.BOOTC_test_upgrade_image? | default ""
let is_composefs = (tap is_composefs)
if $upgrade_image != "" and $is_composefs {
    print "# skip: composefs upgrade boots with enforcing=0 (base image SELinux policy gap)"
    tap ok
    exit 0
}

let enforce = (open /sys/fs/selinux/enforce | str trim)
assert equal $enforce "1" "SELinux should be in enforcing mode"
print "SELinux is enforcing"

tap ok
