#!/bin/bash
# All local filesystem configuration for a derived test image.
# No network access required; this runs after provision-fetch.sh has
# installed all packages. See also: Dockerfile fetch/base stage split.
set -xeu

cloudinit=0
case ${1:-} in
  cloudinit) cloudinit=1 ;;
  "") ;;
  *) echo "Unhandled flag: ${1:-}" 1>&2; exit 1 ;;
esac

# Clean root's homedir (provision-fetch.sh may have left cargo/dnf state).
rm -rf /var/roothome/.config
mkdir -p -m 0700 /var/roothome

# Nushell config for root: store the files under /usr so they are covered by
# the OS image, then use tmpfiles.d 'C' to copy them into /var/roothome at
# first boot.  Writing directly to /var would require tmpfiles entries anyway
# and would fail `bootc container lint --fatal-warnings`.
mkdir -p /usr/share/bootc-test/nushell-skel
echo '$env.config = { show_banner: false, }' > /usr/share/bootc-test/nushell-skel/config.nu
touch /usr/share/bootc-test/nushell-skel/env.nu
cat >/usr/lib/tmpfiles.d/bootc-test-nushell.conf <<'EOF'
d  /var/roothome/.config          0700 root root - -
d  /var/roothome/.config/nushell  0700 root root - -
C+ /var/roothome/.config/nushell/config.nu 0600 root root - /usr/share/bootc-test/nushell-skel/config.nu
C+ /var/roothome/.config/nushell/env.nu    0600 root root - /usr/share/bootc-test/nushell-skel/env.nu
EOF

# kargs for serial console
cat <<KARGEOF >> /usr/lib/bootc/kargs.d/20-console.toml
kargs = ["console=ttyS0,115200n8"]
KARGEOF

if test $cloudinit = 1; then
  ln -s ../cloud-init.target /usr/lib/systemd/system/default.target.wants
  # Allow root SSH login for testing with bcvk/tmt
  mkdir -p /etc/cloud/cloud.cfg.d
  cat > /etc/cloud/cloud.cfg.d/80-enable-root.cfg <<'CLOUDEOF'
# Enable root login for testing
disable_root: false

# In image mode, the host root filesystem is mounted at /sysroot, not /
# That is the one we should attempt to resize, not what is mounted at /
growpart:
  mode: auto
  devices: ["/sysroot"]
resize_rootfs: false
CLOUDEOF
fi

cat >/usr/lib/tmpfiles.d/bootc-cloud-init.conf <<'EOF'
d /var/lib/cloud 0755 root root - -
EOF

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

# dhcpcd
if rpm -q dhcpcd &>/dev/null; then
if ! grep -q -r dhcpcd /usr/lib/sysusers.d; then
  cat >/usr/lib/sysusers.d/bootc-dhcpcd-workaround.conf <<'EOF'
u dhcpcd - 'Minimalistic DHCP client' /var/lib/dhcpcd
EOF
fi
cat >/usr/lib/tmpfiles.d/bootc-dhcpd.conf <<'EOF'
d /var/lib/dhcpcd 0755 root dhcpcd - -
EOF
  rm -rf /var/lib/dhcpcd
fi
# dhclient
if test -d /var/lib/dhclient; then
  cat >/usr/lib/tmpfiles.d/bootc-dhclient.conf <<'EOF'
d /var/lib/dhclient 0755 root root - -
EOF
  rm -rf /var/lib/dhclient
fi

# The following configs are skipped when SKIP_CONFIGS=1, which is used
# for testing bootc install on Fedora CoreOS where these would conflict.
if test -z "${SKIP_CONFIGS:-}"; then
  # For test-22-logically-bound-install
  install -D -m 0644 -t /usr/share/containers/systemd/ lbi/*
  for x in curl.container curl-base.image podman.image; do
      ln -s /usr/share/containers/systemd/$x /usr/lib/bootc/bound-images.d/$x
  done

  # Add some testing kargs into our dev builds
  install -D -t /usr/lib/bootc/kargs.d test-kargs/*
  # Also copy in some default install configs we use for testing
  install -D -t /usr/lib/bootc/install/ install-test-configs/*

  # Install os-image-map.json for tests that need to select OS-matched images
  install -D -m 0644 os-image-map.json /usr/share/bootc/os-image-map.json
else
  echo "SKIP_CONFIGS is set, skipping LBIs, test kargs, and install configs"
fi
