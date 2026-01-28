# number: 31
# tmt:
#   summary: switch --mutate-in-place
#   duration: 30m
#
use std assert
use tap.nu
use bootc_testlib.nu

# See https://github.com/bootc-dev/bootc/issues/1854

if not (tap is_composefs) {
    # This is aiming to reproduce an environment closer to the Anaconda case
    # where we're chrooted into a non-booted system. TODO: What we really want
    # is to add `bootc switch --sysroot` too.
    mv /run/ostree-booted /run/ostree-booted.orig
    unshare -m /bin/sh -c 'mount -o remount,rw /sysroot && bootc switch --mutate-in-place quay.io/nosuchimage/image-to-test-switch'
    tap ok
}
