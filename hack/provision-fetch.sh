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

# Temporary: update bootupd from @CoreOS/continuous copr until
# base images include a version supporting --filesystem
case $ID in
    fedora) copr_distro="fedora" ;;
    *) copr_distro="centos-stream" ;;
esac
# Update bootc from rhcontainerbot copr; the new bootupd
# requires a newer bootc than what ships in some base images.
cat >/etc/yum.repos.d/rhcontainerbot-bootc.repo <<REPOEOF
[copr:copr.fedorainfracloud.org:rhcontainerbot:bootc]
name=Copr repo for bootc owned by rhcontainerbot
baseurl=https://download.copr.fedorainfracloud.org/results/rhcontainerbot/bootc/${copr_distro}-\$releasever-\$basearch/
type=rpm-md
gpgcheck=1
gpgkey=https://download.copr.fedorainfracloud.org/results/rhcontainerbot/bootc/pubkey.gpg
repo_gpgcheck=0
enabled=1
enabled_metadata=1
REPOEOF
dnf -y update bootc
rm -f /etc/yum.repos.d/rhcontainerbot-bootc.repo
cat >/etc/yum.repos.d/coreos-continuous.repo <<REPOEOF
[copr:copr.fedorainfracloud.org:group_CoreOS:continuous]
name=Copr repo for continuous owned by @CoreOS
baseurl=https://download.copr.fedorainfracloud.org/results/@CoreOS/continuous/${copr_distro}-\$releasever-\$basearch/
type=rpm-md
gpgcheck=1
gpgkey=https://download.copr.fedorainfracloud.org/results/@CoreOS/continuous/pubkey.gpg
repo_gpgcheck=0
enabled=1
enabled_metadata=1
REPOEOF

# This unfortunately has "older" versions with higher NEVRA:
#
# # dnf --disablerepo=* --enablerepo=copr:copr.fedorainfracloud.org:group_CoreOS:continuous repoquery bootupd 2> /dev/null
# bootupd-0:0.2.32.45.gb483a63-1.fc45.x86_64
# bootupd-0:202501200321.0.2.25.65.ge296f82-1.fc42.src
# bootupd-0:202501200321.0.2.25.65.ge296f82-1.fc42.x86_64
# bootupd-0:202501210627.0.2.25.67.gefe41b6-1.fc42.src
#
# So we need to be more selective, but also be dynamic to grab newer
# versions
#
# The subscription-manager plugin needs to be disabled because it
# likes to write warnings to stdout which corrupts the NEVRA output
# we're going for here...
bootupd_nevra=$(dnf --disableplugin=subscription-manager --disablerepo=* --enablerepo=copr:copr.fedorainfracloud.org:group_CoreOS:continuous repoquery --latest-limit 1 --arch "$(uname -m)" "bootupd-0.2.*")
dnf -y install ${bootupd_nevra}
rm -f /etc/yum.repos.d/coreos-continuous.repo

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

# Temporary: downgrade kernel to last 6.x when 7.0 or 7.1 is present.
# Kernel 7.x broke composefs ("has no fs-verity digest"), fixed in 7.2.
# xref https://github.com/bootc-dev/bootc/issues/2174
# TODO: Remove once all base images ship kernel >= 7.2
kernel_ver=$(rpm -q --qf '%{VERSION}' kernel 2>/dev/null || true)
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
        # Skip scriptlets: kernel-core's posttrans runs `kernel-install add`
        # which calls rpm-ostree, and that fails inside a container build.
        # We manually run depmod afterward since it's the only useful
        # scriptlet the kernel packages would otherwise execute.
        dnf -y install --allowerasing --setopt=tsflags=noscripts "${kernel_td}"/*.rpm
        /sbin/depmod -a "${koji_kver}-${koji_krel}.$(uname -m)"
        # Remove any leftover module directories for the old kernel (e.g.
        # initramfs.img generated by the base image build is not RPM-owned
        # so dnf does not clean it up).
        for old_kmod_dir in /usr/lib/modules/*; do
            kd_ver=$(basename "${old_kmod_dir}")
            if [[ "${kd_ver}" != "${koji_kver}-"* ]]; then
                rm -rf "${old_kmod_dir}"
            fi
        done
        rm -rf "${kernel_td}"
        trap - EXIT
        ;;
esac

dnf clean all
# Clean logs and caches
rm /var/log/* /var/cache /var/lib/{dnf,rpm-state,rhsm} -rf
