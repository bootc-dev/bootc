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

    # Install the host's setup-root-conf.toml if present so that
    # per-image composefs mount configuration (e.g. etc.transient) is
    # embedded in the initramfs without requiring manual --include flags.
    # Use '[[ -e ]] && inst_simple' rather than inst_if_exists, which is
    # not available in all dracut invocation contexts (e.g. explicit
    # dracut --force in a Containerfile RUN layer).
    [[ -e /usr/lib/composefs/setup-root-conf.toml ]] && \
        inst_simple /usr/lib/composefs/setup-root-conf.toml
}
