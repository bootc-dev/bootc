# number: 49
# tmt:
#   summary: switch --target-imgref records a decoupled origin (composefs)
#   duration: 30m
# extra:
#   skip_if_ostree: true
#   fixme_skip_if_uki: true
#
# Verify that `bootc switch --target-imgref` fetches the image from the given
# source (here a local containers-storage copy) but persists the *decoupled*
# reference as the origin for subsequent upgrades (issue #2464), on the
# composefs backend.
#
# Skipped on UKI: the test switches to a freshly derived image, whose composefs
# digest won't match the one sealed into the booted UKI, so the switch is
# rejected before the origin is ever recorded (same limitation as
# test-composefs-gc). The decoupling logic is boot-type agnostic and is covered
# on the BLS composefs matrix.
use std assert
use tap.nu

tap begin "bootc switch --target-imgref decouples pull source from origin"

# Make the booted image available in podman storage as our pull-source base.
bootc image copy-to-storage

# Derive a new image so its content — and therefore its composefs fs-verity
# digest — differs from the booted deployment; otherwise the same-digest guard
# (see test-43) would refuse the switch. This derived image is our pull source.
("FROM localhost/bootc\n"
 + "RUN touch /usr/share/testing-target-imgref\n") | podman build -t localhost/bootc-source -f - .

# The reference we want recorded as the origin for future upgrades. It is never
# pulled (so it needs no network / need not exist): switch fetches from the
# local source above and only *records* this as the origin.
let origin = "quay.io/example/os:latest"

# Fetch from the local containers-storage copy, but decouple the persisted origin.
bootc switch --transport containers-storage --target-imgref $origin localhost/bootc-source

# The staged deployment's origin must be the --target-imgref value, not the
# containers-storage source we actually pulled from.
let st = bootc status --json | from json
assert ($st.status.staged != null) "Expected a staged deployment after switch"
let staged = $st.status.staged.image
assert equal $staged.image.transport "registry"
assert equal $staged.image.image $origin

tap ok
