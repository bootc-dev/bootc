use std assert
use tap.nu

tap begin "verify /etc/hostname is not zero sized"

let hostname = try { ls /etc/hostname | first }
if $hostname != null {
    assert not equal $hostname.size 0B
}

tap ok
