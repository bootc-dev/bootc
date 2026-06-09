# number: 45
# extra:
#   bootc_install_args: --experimental-unified-storage
#   fixme_skip_if_composefs: true
# tmt:
#   summary: Readonly tests after install with --experimental-unified-storage
#   duration: 30m

use std assert
use tap.nu
use bootc_testlib.nu

tap begin "readonly tests after install with --experimental-unified-storage"

let images = bootc image list --format json | from json
let already_unified = ($images | where image_type == "unified" | length) > 0

assert $already_unified "System must be in unified storage mode (installed with --experimental-unified-storage)"

bootc_testlib verify_unified_storage

# Run the readonly suite
let tests = (ls booted/readonly/*-test-*.nu | get name | sort)
for test_file in $tests {
    print $"Running ($test_file)..."
    nu $test_file
}

tap ok
