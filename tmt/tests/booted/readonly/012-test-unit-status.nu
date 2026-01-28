# Verify our systemd units are enabled
use std assert
use tap.nu

tap begin "verify our systemd units"

# Detect composefs by checking if composefs field is present
let st = bootc status --json | from json
let is_composefs = (tap is_composefs)

if $is_composefs {
    print "# TODO composefs: skipping test - bootc-status-updated.path watches /ostree/bootc which doesn't exist with composefs"
} else {
    let units = [
        ["unit", "status"];
        # This one should be always enabled by our install logic
        ["bootc-status-updated.path", "active"]
    ]

    for elt in $units {
        let found_status = systemctl show -P ActiveState $elt.unit | str trim
        assert equal $elt.status $found_status
    }
}

tap ok
