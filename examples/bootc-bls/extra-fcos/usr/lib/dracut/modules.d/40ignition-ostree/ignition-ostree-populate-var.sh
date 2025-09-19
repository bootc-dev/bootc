#!/bin/bash
set -euo pipefail

fatal() {
    echo "$@" >&2
    exit 1
}

if [ $# -ne 0 ]; then
    fatal "Usage: $0"
fi

# See the similar code block in Anaconda, which handles this today for Atomic
# Host and Silverblue:
# https://github.com/rhinstaller/anaconda/blob/b9ea8ce4e68196b30a524c1cc5680dcdc4b89371/pyanaconda/payload/rpmostreepayload.py#L332

for varsubdir in lib log home roothome opt srv usrlocal mnt media; do

    # If the directory already existed, just ignore. This addresses the live
    # image case with persistent `/var`; we don't want to relabel all the files
    # there on each boot.
    if [ -d "/sysroot/var/${varsubdir}" ]; then
        continue
    fi

    if [[ $varsubdir == lib ]] || [[ $varsubdir == log ]]; then
        # Simply manually mkdir /var/{lib,log}; the tmpfiles.d entries otherwise
        # reference users/groups which we don't have access to from here
        # (though... we *could* import them from the sysroot, and have
        # nss-altfiles in the initrd, but meh...  let's just wait for
        # systemd-sysusers which will make this way easier:
        # https://github.com/coreos/fedora-coreos-config/pull/56/files#r262592361).
        mkdir -p /sysroot/var/${varsubdir}
    else
        systemd-tmpfiles --create --boot --root=/sysroot --prefix="/var/${varsubdir}"
    fi

    coreos-relabel "/var/${varsubdir}"
done
