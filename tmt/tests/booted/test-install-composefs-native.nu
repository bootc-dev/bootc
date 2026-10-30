# number: 60
# tmt:
#   summary: Test that composefs-native images default to the composefs backend
#   duration: 45m
# extra:
#   # A UKI selects the composefs backend by itself, and a derived layer
#   # wouldn't match the composefs digest embedded in it.
#   fixme_skip_if_uki: true
#
# An image that ships /usr/lib/composefs/setup-root-conf.toml and no ostree
# prepare-root.conf must be installed with the composefs backend by
# `bootc install` run from that image without `--composefs-backend`, both
# as a self-install and with --source-imgref (as bootc-image-builder does).
# An image with both files is still installed with ostree. This runs on the
# ostree variant too, where nothing else selects composefs; on the composefs
# variant, every test's install already relies on this default.
#
# TODO: This doesn't depend on the booted host; move it into a dedicated
# install test suite, sharing the install-in-test code with the other install
# tests: https://github.com/cgwalters-forge/tracker/issues/249

use std assert
use tap.nu

const NATIVE = "localhost/bootc-composefs-native"
const BOTH = "localhost/bootc-composefs-both"
const DISK = "/var/tmp/composefs-native.img"
const MNT = "/var/mnt/composefs-native"
const KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITEST test@example.com"
const KEYS = "/var/tmp/composefs-native-keys"

def build [image: string, extra: string] {
    let td = mktemp -d
    $"FROM localhost/bootc
RUN rm -rf /usr/lib/bootc/bound-images.d/*
RUN mkdir -p /usr/lib/composefs && touch /usr/lib/composefs/setup-root-conf.toml
($extra)
" | save $"($td)/Containerfile"
    # Keep an OCI manifest, see https://github.com/bootc-dev/bootc/issues/1703
    podman build --format oci -t $image $td
    rm -rf $td
}

# Install `image` from itself and return the backend found on the disk
def install [image: string, ...args: string] {
    truncate -s 15G $DISK
    (podman run --rm --privileged --pid=host
        --security-opt label=type:unconfined_t
        -v /dev:/dev -v /var/lib/containers:/var/lib/containers -v /var/tmp:/var/tmp
        $image
        bootc install to-disk --disable-selinux --via-loopback
        --root-ssh-authorized-keys $KEYS ...$args $DISK)

    # Inspect the root partition of the installed disk
    let parts = sfdisk --json $DISK | from json | get partitiontable
    let root = $parts.partitions | where name == "root" | first
    let offset = $root.start * ($parts.sectorsize? | default 512)
    mkdir $MNT
    mount -o $"ro,loop,offset=($offset)" $DISK $MNT
    let composefs = ($"($MNT)/composefs" | path exists) and ((ls $"($MNT)/state/deploy" | length) == 1)
    let ostree = ($"($MNT)/ostree/deploy" | path exists)
    let dropin = glob $"($MNT)/state/deploy/*/etc/tmpfiles.d/bootc-root-ssh.conf"
        | append (glob $"($MNT)/ostree/deploy/*/deploy/*/etc/tmpfiles.d/bootc-root-ssh.conf")
        | each {|p| {content: (open --raw $p | decode utf-8), mode: (stat -c %a $p | str trim)}}
    umount $MNT
    rm -f $DISK
    assert equal $dropin [{content: $"f~ /var/roothome/.ssh/authorized_keys 600 root root - ($KEY | encode base64)\n", mode: "644"}] "root ssh drop-in"
    match [$composefs $ostree] {
        [true false] => "composefs",
        [false true] => "ostree",
        _ => $"unexpected: composefs=($composefs) ostree=($ostree)",
    }
}

def main [] {
    tap begin "composefs-native images default to the composefs backend"

    bootc image copy-to-storage
    $KEY | save -f $KEYS
    build $NATIVE "RUN rm -f /usr/lib/ostree/prepare-root.conf /etc/ostree/prepare-root.conf"
    # On the composefs variant, localhost/bootc is itself composefs-native: it
    # has no prepare-root.conf, and configures its composefs bootloader.
    build $BOTH "RUN printf '[composefs]\\nenabled = yes\\n' > /usr/lib/ostree/prepare-root.conf && rm -f /usr/lib/bootc/install/80-composefs-bootloader.toml"

    assert equal (install $NATIVE) "composefs" "composefs-native self-install"
    let src = $"--source-imgref=containers-storage:($NATIVE)"
    assert equal (install $NATIVE $src) "composefs" "composefs-native with --source-imgref"
    # The ostree backend needs bootupd, which images built for systemd-boot drop
    if (which bootupctl | is-not-empty) {
        assert equal (install $BOTH) "ostree" "image with both configurations"
    }

    podman rmi $NATIVE $BOTH
    rm -f $KEYS
    tap ok
}
