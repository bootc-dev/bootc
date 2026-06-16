#!/bin/bash
# All network-fetching operations needed to provision a derived test image.
# Separated from provision-configure.sh so this phase can be retried
# independently on transient network failures (Koji 503s, Copr outages, etc.)
#
# This script is idempotent: re-running it after a partial failure is safe.
set -xeu

cloudinit=0
case ${1:-} in
  cloudinit) cloudinit=1 ;;
  "") ;;
  *) echo "Unhandled flag: ${1:-}" 1>&2; exit 1 ;;
esac

# We don't want openh264
rm -f "/etc/yum.repos.d/fedora-cisco-openh264.repo"

. /usr/lib/os-release

# Install nushell (used in our test suite).
# It's available in most distro repos except CentOS/RHEL 10 where we
# fetch a binary from GitHub releases.
case "${ID}-${VERSION_ID}" in
    "centos-9")
        dnf config-manager --set-enabled crb
        dnf -y install epel-release epel-next-release
        dnf -y install nu
        ;;
    "rhel-9."*)
        dnf -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm
        dnf -y install nu
        ;;
    "centos-10"|"rhel-10."*)
        # nu is not available in CS10
        td=$(mktemp -d)
        cd $td
        curl -fL --retry 5 --retry-delay 5 --retry-all-errors "https://github.com/nushell/nushell/releases/download/0.103.0/nu-0.103.0-$(uname -m)-unknown-linux-gnu.tar.gz" --output nu.tar.gz
        mkdir -p nu && tar zvxf nu.tar.gz --strip-components=1 -C nu
        mv nu/nu /usr/bin/nu
        rm -rf nu nu.tar.gz
        cd -
        rm -rf "${td}"
        ;;
    "fedora-"*)
        dnf -y install nu
        ;;
esac

# Extra packages needed by tmt and integration tests
grep -Ev -e '^#' packages.txt | xargs dnf install --allowerasing -y

if test $cloudinit = 1; then
  dnf -y install cloud-init
fi

# Temporary: upgrade ostree to 2026.1 for bootconfig-extra support
# (required by loader-entries source tracking)
# xref https://github.com/ostreedev/ostree/pull/3570
# TODO: Remove this block once all base images ship ostree >= 2026.1
if ! rpm -q ostree 2>/dev/null | grep -q "2026\." ; then
    arch=$(uname -m)
    case "${ID}-${VERSION_ID}" in
        "centos-9")
            koji_base="https://kojihub.stream.centos.org/kojifiles/packages/ostree/2026.1/1.el9/${arch}"
            dnf -y install \
                "${koji_base}/ostree-2026.1-1.el9.${arch}.rpm" \
                "${koji_base}/ostree-libs-2026.1-1.el9.${arch}.rpm"
            if rpm -q ostree-grub2 &>/dev/null; then
                dnf -y install "${koji_base}/ostree-grub2-2026.1-1.el9.${arch}.rpm"
            fi
            ;;
        "centos-10")
            koji_base="https://kojihub.stream.centos.org/kojifiles/vol/koji02/packages/ostree/2026.1/1.el10/${arch}"
            dnf -y install \
                "${koji_base}/ostree-2026.1-1.el10.${arch}.rpm" \
                "${koji_base}/ostree-libs-2026.1-1.el10.${arch}.rpm"
            if rpm -q ostree-grub2 &>/dev/null; then
                dnf -y install "${koji_base}/ostree-grub2-2026.1-1.el10.${arch}.rpm"
            fi
            ;;
        "fedora-"*)
            dnf -y --enablerepo=updates-testing install \
                ostree-2026.1 ostree-libs-2026.1
            ;;
    esac
fi

dnf clean all
# Clean logs and caches
rm /var/log/* /var/cache /var/lib/{dnf,rpm-state,rhsm} -rf
