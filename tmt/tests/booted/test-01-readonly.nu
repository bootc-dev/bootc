# number: 1
# extra:
#   try_bind_storage: true
# tmt:
#   summary: Execute booted readonly/nondestructive tests
#   duration: 30m
#
# Run all readonly tests in sequence
use tap.nu

tap begin "readonly tests"

# Get all readonly test files and run them in order
let tests = (ls booted/readonly/*-test-*.nu | get name | sort)

for test_file in $tests {
    print $"Running ($test_file)..."
    nu $test_file
}

tap ok
