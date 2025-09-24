#!/usr/bin/bash

check() {
    return 0
}

depends() {
    return 0
}

install() {
    inst \
        "${moddir}/bootc-initramfs-setup" /usr/bin/bootc-initramfs-setup
    inst \
        "${moddir}/bootc-initramfs-setup.service" \
        "${systemdsystemunitdir}/bootc-initramfs-setup.service"

    $SYSTEMCTL -q --root "${initdir}" add-wants \
        'initrd-root-fs.target' 'bootc-initramfs-setup.service'
}
