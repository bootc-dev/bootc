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

# When this system was upgraded from a published base image (test-upgrade flow),
# the import ran with the older bootc from that image, which predates
# normalize_root_dirmeta. The root keeps the 0755 of the importer's checkout
# temp dir, while /usr keeps the 0555 from the image layers. The two only
# match on systems imported by a bootc that has the fix, so check /usr alone
# here.
# TODO: once published base images ship the metadata fix, compare
# /var/bootc-pre-upgrade-version against the fixed version instead (like 031 does).
if not ("/var/bootc-pre-upgrade-version" | path exists) {
    assert equal $root_meta $usr_meta $"root dir metadata \(($root_meta)\) should match /usr \(($usr_meta)\)"
    assert equal $root_meta "mode: 555, gid: 0, uid: 0" $"root dir metadata \(($root_meta)\) should match expected \(mode: 555, gid: 0, uid: 0\)"
} else {
    print "# skipping root == /usr check: imported by pre-fix bootc during upgrade"
    assert equal $usr_meta "mode: 555, gid: 0, uid: 0" $"/usr metadata \(($usr_meta)\) should match expected \(mode: 555, gid: 0, uid: 0\)"
}

tap ok
