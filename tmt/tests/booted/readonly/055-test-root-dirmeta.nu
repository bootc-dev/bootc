# Verify that the root dir's uid, gid, and permissions match /usr.
#
# See: https://github.com/coreos/fedora-coreos-tracker/issues/2238
use std assert
use tap.nu

tap begin "verify root dir metadata matches /usr"

let root_meta = (stat -c "mode: %a, gid: %g, uid: %u" / | str trim)
let usr_meta = (stat -c "mode: %a, gid: %g, uid: %u" /usr | str trim)

print $"# root: ($root_meta)"
print $"# /usr: ($usr_meta)"

assert equal $root_meta $usr_meta $"root dir metadata \(($root_meta)\) should match /usr \(($usr_meta)\)"
assert equal $root_meta "mode: 555, gid: 0, uid: 0" $"root dir metadata \(($root_meta)\) should match expected \(mode: 555, gid: 0, uid: 0\)"

tap ok
