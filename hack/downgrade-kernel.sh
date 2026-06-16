set -eux

rootfs=${1:-/}

# Temporary: downgrade kernel to last 6.x when 7.0 or 7.1 is present.
# Kernel 7.x broke composefs ("has no fs-verity digest"), fixed in 7.2.
# xref https://github.com/bootc-dev/bootc/issues/2174
# TODO: Remove once all base images ship kernel >= 7.2
kernel_ver=$(rpm --root "$rootfs" -q --qf '%{VERSION}' kernel 2>/dev/null || true)
case "${kernel_ver}" in
    7.0.*|7.1.*)
        arch=$(uname -m)
        koji_kver="6.19.10"
        koji_krel="300.fc44"
        koji_base="https://kojipkgs.fedoraproject.org/packages/kernel/${koji_kver}/${koji_krel}/${arch}"
        kernel_td=$(mktemp -d)
        trap 'rm -rf "${kernel_td}"' EXIT
        for pkg in kernel kernel-core kernel-modules kernel-modules-core; do
            curl --retry 5 --retry-delay 5 --retry-all-errors -fL \
                "${koji_base}/${pkg}-${koji_kver}-${koji_krel}.${arch}.rpm" \
                -o "${kernel_td}/${pkg}.rpm"
        done
        # TMPDIR=/var/tmp: works around an rpm-ostree bug
        TMPDIR=/var/tmp dnf --installroot="$rootfs" -y downgrade "${kernel_td}"/*.rpm
        # Note: we should also fix the Fedora kernel packaging to not copy symvers into /boot
        rm -rf "${rootfs}"/boot/*
        rm -rf "${kernel_td}"
        trap - EXIT
        ;;
esac

dnf clean all
# Clean logs and caches
rm "$rootfs"/var/log/* "$rootfs"/var/cache "$rootfs"/var/lib/{dnf,rpm-state,rhsm} -rf
