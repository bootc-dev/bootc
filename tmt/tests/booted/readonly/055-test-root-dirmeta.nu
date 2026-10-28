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

# When this system was upgraded from a published base image (test-upgrade flow),
# the import ran with the older bootc from that image, which predates the
# directory metadata preservation. Both / and /usr end up 0755 there.
# Only assert the strict mode on systems imported by a bootc that has the fix.
# TODO: once published base images ship the metadata fix, compare
# /var/bootc-pre-upgrade-version against the fixed version instead (like 031 does).
if not ("/var/bootc-pre-upgrade-version" | path exists) {
    assert equal $root_meta "mode: 555, gid: 0, uid: 0" $"root dir metadata \(($root_meta)\) should match expected \(mode: 555, gid: 0, uid: 0\)"
} else {
    print "# skipping strict 0555 check: imported by pre-fix bootc during upgrade"
}

tap ok
