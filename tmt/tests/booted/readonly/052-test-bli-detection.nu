use std assert
use tap.nu

tap begin "DPS root discovery when partition-uuids is false"

# In upgrade scenarios, the system was installed by an older bootc that may not
# have had DPS enabled, so root= would still be in the cmdline.
let is_upgrade = ($env.BOOTC_test_upgrade_image? | default "" | is-not-empty)
if $is_upgrade {
    print "# skip: DPS check not applicable for upgrades (installed by older bootc)"
    tap ok
    exit 0
}

# Parse os-release
let os = open /usr/lib/os-release
    | lines
    | filter {|l| $l != "" and not ($l | str starts-with "#") }
    | parse "{key}={value}"
    | reduce -f {} {|it, acc| $acc | upsert $it.key ($it.value | str trim -c '"') }

let os_id = ($os.ID? | default "unknown")
let version_id = ($os.VERSION_ID? | default "0" | into int)

# We inject this in our builds, but hopefully C10S gets this too at some point
if not ($os_id == "fedora" and $version_id >= 43) {
    print $"# skip: only applies to Fedora 43+ \(found ($os_id) ($version_id)\)"
    tap ok
    exit 0
}

# DPS root discovery only works when bootc install to-disk created the
# partitions with DPS type GUIDs.  In Packit/gating CI the system was
# installed via to-existing-root on pre-existing partitions, so skip.
# BCVK_EXPORT=1 is set by xtask when running via bcvk (image-mode).
if ($env.BCVK_EXPORT? | default "" | is-empty) {
    print "# skip: not running in image-mode (BCVK_EXPORT not set)"
    tap ok
    exit 0
}

print $"Running on ($os_id) ($version_id), checking DPS root discovery"

let cmdline = (open /proc/cmdline)
let has_root_karg = ($cmdline | str contains "root=")

assert (not $has_root_karg) "Fedora 43+ should use DPS auto-discovery (no root= in cmdline)"

tap ok
