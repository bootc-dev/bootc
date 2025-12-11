use std assert
use tap.nu

tap begin "rhsm facts"

print "#####################################"
print "#####################################"
print "#####################################"
print "#####################################"

bootc status
hostname

# Verify we have this feature
if ("/etc/rhsm" | path exists) {
    bootc internals publish-rhsm-facts --help
    let status = systemctl show -P ActiveState bootc-publish-rhsm-facts.service
    assert equal $status "inactive"
}

tap ok
