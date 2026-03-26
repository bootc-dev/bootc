#!/bin/bash
installkernel() {
    instmods erofs overlay dm_crypt
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
    mkdir -p "${initdir}${systemdsystemconfdir}/initrd-root-fs.target.wants"
    ln_r "${systemdsystemunitdir}/${service}" \
        "${systemdsystemconfdir}/initrd-root-fs.target.wants/${service}"

    # First-boot LUKS encryption support
    local luks_service=bootc-luks-firstboot.service
    if [ -x /usr/lib/bootc/bootc-luks-firstboot.sh ]; then
        dracut_install /usr/lib/bootc/bootc-luks-firstboot.sh
        dracut_install cryptsetup systemd-cryptenroll blkid sed awk grep
        inst_simple "${systemdsystemunitdir}/${luks_service}"
        mkdir -p "${initdir}${systemdsystemconfdir}/sysroot.mount.requires"
        ln_r "${systemdsystemunitdir}/${luks_service}" \
            "${systemdsystemconfdir}/sysroot.mount.requires/${luks_service}"
    fi
}
