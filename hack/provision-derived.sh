#!/bin/bash
set -xeu
# I'm a big fan of nushell for interactive use, and I want to support
# using it in our test suite because it's better than bash. First,
# enable EPEL to get it.

# Ensure this is pre-created
mkdir -p -m 0700 /var/roothome
mkdir -p ~/.config/nushell
echo '$env.config = { show_banner: false, }' > ~/.config/nushell/config.nu
touch ~/.config/nushell/env.nu

. /usr/lib/os-release
case "${ID}-${VERSION_ID}" in
    "centos-9")
        dnf config-manager --set-enabled crb
        dnf -y install epel-release epel-next-release
        dnf -y install nu
        dnf clean all
        ;;
    "centos-10")
        # nu is not available in CS10
        curl -kL "https://github.com/nushell/nushell/releases/download/0.103.0/nu-0.103.0-$(uname -m)-unknown-linux-gnu.tar.gz" --output nu.tar.gz
        mkdir -p nu && tar zvxf nu.tar.gz --strip-components=1 -C nu
        mv nu/nu /usr/bin/nu
        rm -rf nu nu.tar.gz
        ;;
    "fedora-"*)
        dnf -y install nu
        dnf clean all
        ;;
esac

# Stock extra cleaning of logs and caches in general (mostly dnf)
rm /var/log/* /var/cache /var/lib/{dnf,rpm-state,rhsm} -rf
# And clean root's homedir
rm /var/roothome/.config -rf

# Fast track tmpfiles.d content from the base image, xref
# https://gitlab.com/fedora/bootc/base-images/-/merge_requests/92
if test '!' -f /usr/lib/tmpfiles.d/bootc-base-rpmstate.conf; then
  cat >/usr/lib/tmpfiles.d/bootc-base-rpmstate.conf <<'EOF'
# Workaround for https://bugzilla.redhat.com/show_bug.cgi?id=771713
d /var/lib/rpm-state 0755 - - -
EOF
fi
if ! grep -q -r var/roothome/buildinfo /usr/lib/tmpfiles.d; then
  cat > /usr/lib/tmpfiles.d/bootc-contentsets.conf <<'EOF'
# Workaround for https://github.com/konflux-ci/build-tasks-dockerfiles/pull/243
d /var/roothome/buildinfo 0755 - - -
d /var/roothome/buildinfo/content_manifests 0755 - - -
# Note we don't actually try to recreate the content; this just makes the linter ignore it
f /var/roothome/buildinfo/content_manifests/content-sets.json 0644 - - -
EOF
fi

# And add missing sysusers.d entries
if ! grep -q -r sudo /usr/lib/sysusers.d; then
  cat >/usr/lib/sysusers.d/bootc-sudo-workaround.conf <<'EOF'
g sudo 16
EOF
fi
