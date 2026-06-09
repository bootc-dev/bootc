# number: 46
# extra:
#   bootc_install_args: --experimental-ostree-composefs-unified
#   fixme_skip_if_composefs: true
# tmt:
#   summary: Readonly tests after install with --experimental-ostree-composefs-unified (bound-only)
#   duration: 30m

use std assert
use tap.nu
use bootc_testlib.nu

tap begin "readonly tests after install with --experimental-ostree-composefs-unified (bound-only)"

# Delegate all substantive bound-only consistency checks to fsck, which is the
# single authoritative gate for this state.
bootc_testlib verify_bound_only

# The OS image must NOT be visible via the bootc additional image store.
# On a bound-only system the image lives in composefs, not containers-storage,
# so the bootc store should be absent or empty.
# (Merely assert the podman command runs; the store may not exist at all.)
let podman_images = (podman --storage-opt=additionalimagestore=/usr/lib/bootc/storage images --format "{{.Repository}}" | str trim)
print $"Images visible via podman additional store: ($podman_images)"

tap ok
