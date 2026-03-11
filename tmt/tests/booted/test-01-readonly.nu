# number: 1
# extra:
#   try_bind_storage: true
# tmt:
#   summary: Execute booted readonly/nondestructive tests
#   duration: 30m
#
# Run all readonly tests in sequence
use tap.nu
use bootc_testlib.nu

tap begin "readonly tests"

# If an upgrade image is specified (via BOOTC_test_upgrade_image env var),
# perform the upgrade and reboot first. On the second boot after upgrade,
# this returns and we continue with the readonly tests below.
bootc_testlib maybe_upgrade

# Get all readonly test files and run them in order
let tests = (ls booted/readonly/*-test-*.nu | get name | sort)

for test_file in $tests {
    print $"Running ($test_file)..."
    nu $test_file
}

tap ok
