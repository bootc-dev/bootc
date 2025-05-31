use std assert
use tap.nu

tap begin "verify bootc status output formats"

assert equal (bootc switch blah:// e>| find "\u{1B}") []

tap ok
