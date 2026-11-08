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
    # Required, not wanted: initrd-parse-etc.service, the only way on to
    # switch-root, requires initrd-root-fs.target. If the root setup fails,
    # the target must fail with it, so the boot cannot continue into the
    # unverified /sysroot once the emergency shell returns (dracut's
    # emergency.service starts the default target again when it exits,
    # and sulogin returns at once when root is locked).
    mkdir -p "${initdir}${systemdsystemunitdir}/initrd-root-fs.target.requires"
    ln_r "${systemdsystemunitdir}/${service}" \
        "${systemdsystemunitdir}/initrd-root-fs.target.requires/${service}"

    # Install the host's setup-root-conf.toml if present so that
    # per-image composefs mount configuration (e.g. etc.transient) is
    # embedded in the initramfs without requiring manual --include flags.
    # Use '[[ -e ]] && inst_simple' rather than inst_if_exists, which is
    # not available in all dracut invocation contexts (e.g. explicit
    # dracut --force in a Containerfile RUN layer).
    [[ -e /usr/lib/composefs/setup-root-conf.toml ]] && \
        inst_simple /usr/lib/composefs/setup-root-conf.toml

    return 0
}
