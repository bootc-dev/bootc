use std assert
use tap.nu

tap begin "blockdev ls-filesystem works without udev"

# Normal invocation should populate parttype via udev
let normal = (bootc internals blockdev ls-filesystem /sysroot | from json)
assert ($normal.parttype != null) "expected parttype set (with udev)"

# Run with udev hidden via InaccessiblePaths to force the blkid -p fallback
let no_udev = (systemd-run -qPG -p InaccessiblePaths=/run/udev -- bootc internals blockdev ls-filesystem /sysroot | from json)
assert ($no_udev.parttype != null) "expected parttype set (without udev, via blkid fallback)"

# The values should match
assert equal $no_udev.parttype $normal.parttype "parttype mismatch between udev and blkid fallback"

tap ok
