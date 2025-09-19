#!/bin/bash
set -euo pipefail

fatal() {
    echo "$@" >&2
    exit 1
}

if [ $# -ne 1 ] || { [[ $1 != mount ]] && [[ $1 != umount ]]; }; then
    fatal "Usage: $0 <mount|umount>"
fi

get_ostree_arg() {
    # yes, this doesn't account for spaces within args, e.g. myarg="my val", but
    # it still works for our purposes
    (
    IFS=$' '
    # shellcheck disable=SC2013
    for arg in $(cat /proc/cmdline); do
        if [[ $arg == ostree=* ]]; then
            echo "${arg#ostree=}"
        fi
    done
    )
}

do_mount() {
    ostree=$(get_ostree_arg)
    if [ -z "${ostree}" ]; then
        fatal "No ostree= kernel argument in /proc/cmdline"
    fi

    deployment_path=/sysroot/${ostree}
    if [ ! -L "${deployment_path}" ]; then
        fatal "${deployment_path} is not a symlink"
    fi

    stateroot_var_path=$(realpath "${deployment_path}/../../var")
    if [ ! -d "${stateroot_var_path}" ]; then
        fatal "${stateroot_var_path} is not a directory"
    fi

    echo "Mounting $stateroot_var_path"
    mount --bind "$stateroot_var_path" /sysroot/var
}

do_umount() {
    echo "Unmounting /sysroot/var"
    umount /sysroot/var
}

"do_$1"
