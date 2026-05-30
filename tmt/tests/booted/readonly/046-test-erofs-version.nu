use std assert
use tap.nu

tap begin "verify composefs UKI EROFS version boots correctly"

let is_composefs = (tap is_composefs)

if not $is_composefs {
    print "# Skipping: not a composefs system"
    tap ok
    exit 0
}

let st = bootc status --json | from json
let is_uki = ($st.status.booted.composefs.bootType | str downcase) == "uki"

if not $is_uki {
    print "# Skipping: not a UKI boot"
    tap ok
    exit 0
}

let erofs_version = ($env.BOOTC_erofs_version? | default "v2")
print $"# Testing EROFS version: ($erofs_version)"

# Verify composefs is active and status is healthy
assert (tap is_composefs) "composefs must be active"

# Verify verity digest is a 128-char hex string (SHA-512)
let verity = $st.status.booted.composefs.verity
assert equal ($verity | str length) 128 "verity digest must be 128 hex chars"
print $"# Verified verity digest length: 128"

# The composefs= karg is always in the v2 format (composefs=<hex>),
# regardless of --erofs-version; the difference is which EROFS image id
# is computed.  Verify the karg is present and well-formed.
let cmdline = open /proc/cmdline | str trim
assert (
    $cmdline | str contains "composefs="
) $"Expected composefs= karg in cmdline, got: ($cmdline)"

# Verify the composefs karg value matches the booted verity digest
let cfs_param = ($cmdline | split row " " | where { |p| $p | str starts-with "composefs=" } | first)
let cfs_value = ($cfs_param | str replace "composefs=" "")
# Strip optional leading '?' for insecure mode
let cfs_digest = (if ($cfs_value | str starts-with "?") { $cfs_value | str substring 1.. } else { $cfs_value })
assert equal $cfs_digest $verity "composefs= karg must match booted verity digest"
print $"# Verified composefs karg matches verity"

tap ok
