use std assert
use tap.nu

tap begin "verify bootc upgrade --check succeeds after upgrade"

# After an upgrade (bootc switch), verify that the running system can
# still query for further upgrades. This catches regressions where
# on-disk state created by an older bootc is incompatible with the
# new bootc's upgrade machinery (e.g. #2074).
# Only meaningful when we actually performed an upgrade.
let upgrade_image = $env.BOOTC_test_upgrade_image? | default ""
if $upgrade_image == "" {
    print "# skip: not an upgrade test (BOOTC_test_upgrade_image not set)"
    tap ok
    exit 0
}

# Read the pre-upgrade bootc version saved during first boot.
let old_version_str = (open /var/bootc-pre-upgrade-version | str trim)
let old_ver = ($old_version_str | split row "." | each { into int })
print $"Pre-upgrade bootc version: ($old_version_str)"

let is_composefs = (tap is_composefs)

print "Running bootc upgrade --check to verify upgrade machinery works..."
let result = do -i { bootc upgrade --check } | complete
if $result.exit_code == 0 {
    print "bootc upgrade --check succeeded"
} else {
    print $"bootc upgrade --check failed: ($result.stderr)"
    # Known failure: composefs upgrades from bootc <= 1.13 have
    # incompatible on-disk state (see #2074).
    let old_bootc_le_1_13 = ($old_ver.0 < 1) or (($old_ver.0 == 1) and ($old_ver.1 <= 13))
    if $is_composefs and $old_bootc_le_1_13 {
        print $"# known failure: composefs upgrade --check from bootc ($old_version_str) \(see #2074\)"
    } else {
        error make { msg: $"bootc upgrade --check failed unexpectedly: ($result.stderr)" }
    }
}

tap ok
