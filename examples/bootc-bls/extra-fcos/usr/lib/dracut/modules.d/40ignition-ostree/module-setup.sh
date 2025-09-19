#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh

check() {
    if [[ $IN_KDUMP == 1 ]]; then
        return 1
    fi
}

depends() {
    echo ignition rdcore
}

install_ignition_unit() {
    local unit=$1; shift
    local target=${1:-complete}
    inst_simple "$moddir/$unit" "$systemdsystemunitdir/$unit"
    # note we `|| exit 1` here so we error out if e.g. the units are missing
    # see https://github.com/coreos/fedora-coreos-config/issues/799
    systemctl -q --root="$initdir" add-requires "ignition-${target}.target" "$unit" || exit 1
}

installkernel() {
    # Used by ignition-ostree-transposefs
    instmods -c zram
}

install() {
    inst_multiple \
        realpath \
        setfiles \
        chcon \
        systemd-sysusers \
        systemd-tmpfiles \
        sort \
        xfs_info \
        xfs_spaceman \
        uniq

    if [[ $(uname -m) = s390x ]]; then
        # for Secure Execution
        inst_multiple \
            veritysetup
    fi

    # ignition-ostree-growfs deps
    inst_multiple  \
        basename   \
        blkid      \
        blockdev   \
        cat        \
        dirname    \
        findmnt    \
        growpart   \
        realpath   \
        resize2fs  \
        tail       \
        tune2fs    \
        touch      \
        xfs_admin  \
        xfs_growfs \
        wc         \
        wipefs

    # growpart deps
    # Mostly generated from the following command:
    #   $ bash --rpm-requires /usr/bin/growpart | sort | uniq | grep executable
    # with a few false positives (rq, rqe, -v) and one missed (mktemp)
    inst_multiple \
        awk       \
        cat       \
        dd        \
        grep      \
        mktemp    \
        partx     \
        rm        \
        sed       \
        sfdisk    \
        find      \
        fsverity

    # In some cases we had to vendor gdisk in Ignition.
    # If this is the case here use that one.
    # See https://issues.redhat.com/browse/RHEL-56080
    if [ -f /usr/libexec/ignition-sgdisk ]; then
        inst /usr/libexec/ignition-sgdisk /usr/sbin/sgdisk
    else
        inst sgdisk
    fi

    for x in mount populate; do
        install_ignition_unit ignition-ostree-${x}-var.service
        inst_script "$moddir/ignition-ostree-${x}-var.sh" "/usr/sbin/ignition-ostree-${x}-var"
    done

    inst_simple \
        /usr/lib/udev/rules.d/90-coreos-device-mapper.rules

    inst_multiple jq chattr
    inst_script "$moddir/ignition-ostree-transposefs.sh" "/usr/libexec/ignition-ostree-transposefs"
    for x in detect save autosave-xfs restore; do
        install_ignition_unit ignition-ostree-transposefs-${x}.service
    done

    # Disk support
    for p in boot root; do
        install_ignition_unit ignition-ostree-uuid-${p}.service diskful
    done
    inst_script "$moddir/ignition-ostree-firstboot-uuid" \
        "/usr/sbin/ignition-ostree-firstboot-uuid"

    install_ignition_unit ignition-ostree-growfs.service
    inst_script "$moddir/ignition-ostree-growfs.sh" \
        /usr/sbin/ignition-ostree-growfs

    install_ignition_unit ignition-ostree-check-rootfs-size.service
    inst_script "$moddir/coreos-check-rootfs-size" \
        /usr/libexec/coreos-check-rootfs-size

    install_ignition_unit ignition-ostree-mount-state-overlays.service
    inst_script "$moddir/ignition-ostree-mount-state-overlays.sh" \
        /usr/libexec/ignition-ostree-mount-state-overlays

    inst_script "$moddir/coreos-relabel" /usr/bin/coreos-relabel
}
