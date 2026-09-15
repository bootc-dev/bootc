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

let erofs_version = tap selected_erofs_version
print $"# Testing EROFS version: ($erofs_version)"

# Verify composefs is active and status is healthy
assert (tap is_composefs) "composefs must be active"

# Verify verity digest is a 128-char hex string (SHA-512)
let verity = $st.status.booted.composefs.verity
assert equal ($verity | str length) 128 "verity digest must be 128 hex chars"
print $"# Verified verity digest length: 128"

# The karg format depends on which EROFS version was sealed into the UKI:
#   v1 -> composefs.digest=v1-<hash>-<lg>:<hex>  (self-describing form)
#   v2 -> composefs=<hex>                        (legacy shorthand)
let cmdline = open /proc/cmdline | str trim
let params = ($cmdline | split row " ")

let cfs_digest = if $erofs_version == "v1" {
    assert (
        $cmdline | str contains "composefs.digest="
    ) $"Expected composefs.digest= karg in cmdline, got: ($cmdline)"

    let param = ($params | where { |p| $p | str starts-with "composefs.digest=" } | first)
    let value = ($param | str replace "composefs.digest=" "")
    # Strip optional leading '?' for insecure mode, then the "v1-<hash>-<lg>:" descriptor
    let value = (if ($value | str starts-with "?") { $value | str substring 1.. } else { $value })
    # The default V1 UKI must retain a V2 fallback.  V2-only initramfs
    # releases ignore the self-describing V1 argument and consume this one.
    assert (
        $params | any { |p| $p | str starts-with "composefs=" }
    ) $"Expected V2 fallback karg in cmdline, got: ($cmdline)"
    ($value | split row ":" | last)
} else {
    assert (
        not ($params | any { |p| $p | str starts-with "composefs.digest=" })
    ) $"Explicit V2 UKI must not contain a V1 karg, got: ($cmdline)"
    assert (
        $cmdline | str contains "composefs="
    ) $"Expected composefs= karg in cmdline, got: ($cmdline)"

    let param = ($params | where { |p| $p | str starts-with "composefs=" } | first)
    let value = ($param | str replace "composefs=" "")
    # Strip optional leading '?' for insecure mode
    (if ($value | str starts-with "?") { $value | str substring 1.. } else { $value })
}

assert equal $cfs_digest $verity "composefs karg digest must match booted verity digest"
print $"# Verified composefs karg matches verity ($erofs_version)"

tap ok
