#!/usr/bin/bash

check() {
    return 0
}

depends() {
    return 0
}

install() {
    inst \
        "${moddir}/composefs-setup-root" /usr/bin/composefs-setup-root
    inst \
        "${moddir}/composefs-setup-root.service" \
        "${systemdsystemunitdir}/composefs-setup-root.service"

    $SYSTEMCTL -q --root "${initdir}" add-wants \
        'initrd-root-fs.target' 'composefs-setup-root.service'
}
