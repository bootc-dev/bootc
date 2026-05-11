#!/bin/bash
installkernel() {
    instmods erofs overlay
}
check() {
    # We are never installed by default; see 10-bootc-base.conf
    # for how base images can opt in.
    return 255
}
depends() {
    return 0
}
install() {
    local service=bootc-root-setup.service
    dracut_install /usr/lib/bootc/initramfs-setup
    inst_simple "${systemdsystemunitdir}/${service}"
    mkdir -p "${initdir}${systemdsystemunitdir}/initrd-root-fs.target.wants"
    ln_r "${systemdsystemunitdir}/${service}" \
        "${systemdsystemunitdir}/initrd-root-fs.target.wants/${service}"
}
