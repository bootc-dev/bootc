#!/bin/bash
set -euo pipefail

fatal() {
    echo "$@" >&2
    exit 1
}

if [ $# -ne 1 ] || { [[ $1 != mount ]] && [[ $1 != umount ]]; }; then
    fatal "Usage: $0 <mount|umount>"
fi

# if state overlays are not enabled, there's nothing to do
if ! ls /sysroot/usr/lib/systemd/system/local-fs.target.requires/ostree-state-overlay@*.service 2>/dev/null; then
    exit 0
fi

do_mount() {
    # be nice to persistent /var; if the top-level state overlay dir exists,
    # then assume it's properly labeled
    relabel=1
    state_overlays_dir=/sysroot/var/ostree/state-overlays
    if [ -d ${state_overlays_dir} ]; then
        relabel=0
    fi
    for overlay in /usr/lib/opt /usr/local; do
        escaped=$(systemd-escape --path "${overlay}")
        overlay_dirs=${state_overlays_dir}/${escaped}
        mkdir -p "${overlay_dirs}"/{upper,work}
        # ideally we'd use `ostree admin state-overlay`, but that'd require
        # pulling in bwrap and chroot which isn't yet in the FCOS initrd
        mount -t overlay overlay /sysroot/${overlay} -o "lowerdir=/sysroot/${overlay},upperdir=${overlay_dirs}/upper,workdir=${overlay_dirs}/work"
    done
    if [ $relabel = 1 ]; then
        coreos-relabel /var/ostree
        # the above relabel will have relabeled the upperdir too; relabel that
        # from the perspective of the mount point so it's not var_t
        for overlay in /usr/lib/opt /usr/local; do
            coreos-relabel ${overlay}
        done
    fi
}

do_umount() {
    for overlay in /usr/lib/opt /usr/local; do
        umount /sysroot/${overlay}
    done
}

"do_$1"
