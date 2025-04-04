# Verify our systemd units are enabled
use std assert
use tap.nu

tap begin "verify our systemd units"

let units = [
    ["unit", "status"]; 
    # This one should be always enabled by our install logic
    ["bootc-status-updated.path", "active"]
]

for elt in $units {
    let found_status = systemctl show -P ActiveState $elt.unit | str trim
    assert equal $elt.status $found_status
}

tap ok
