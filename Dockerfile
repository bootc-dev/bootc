# Build this project from source and write the updated content
# (i.e. /usr/bin/bootc and systemd units) to a new derived container
# image. See the `Justfile` for an example

# Note this is usually overridden via Justfile
ARG base=quay.io/centos-bootc/centos-bootc:stream10

# This first image captures a snapshot of the source code,
# note all the exclusions in .dockerignore.
FROM scratch as src
COPY . /src

FROM $base as base
# We could inject other content here

# This image installs build deps, pulls in our source code, and installs updated
# bootc binaries in /out. The intention is that the target rootfs is extracted from /out
# back into a final stage (without the build deps etc) below.
FROM base as build
# Flip this off to disable initramfs code
ARG initramfs=1
# This installs our package dependencies, and we want to cache it independently of the rest.
# Basically we don't want changing a .rs file to blow out the cache of packages. So we only
# copy files necessary
COPY contrib/packaging /tmp/packaging
RUN <<EORUN
set -xeuo pipefail
. /usr/lib/os-release
case $ID in
  centos|rhel) dnf config-manager --set-enabled crb;;
  fedora) dnf -y install dnf-utils 'dnf5-command(builddep)';;
esac
# Handle version skew, xref https://gitlab.com/redhat/centos-stream/containers/bootc/-/issues/1174
dnf -y distro-sync ostree{,-libs} systemd
# Install base build requirements
dnf -y builddep /tmp/packaging/bootc.spec
# And extra packages
grep -Ev -e '^#' /tmp/packaging/fedora-extra.txt | xargs dnf -y install
rm /tmp/packaging -rf
EORUN
# Now copy the rest of the source
COPY --from=src /src /src
WORKDIR /src
# See https://www.reddit.com/r/rust/comments/126xeyx/exploring_the_problem_of_faster_cargo_docker/
# We aren't using the full recommendations there, just the simple bits.
# First we download all of our Rust dependencies
RUN --mount=type=cache,target=/src/target --mount=type=cache,target=/var/roothome cargo fetch
# Then on general principle all the stuff from the Makefile runs with no network
RUN --mount=type=cache,target=/src/target --mount=type=cache,target=/var/roothome --network=none <<EORUN
set -xeuo pipefail
make
make install-all DESTDIR=/out
if test "${initramfs:-}" = 1; then
  make install-initramfs-dracut DESTDIR=/out
fi
EORUN

# This "build" includes our unit tests
FROM build as units
# A place that we're more likely to be able to set xattrs
VOLUME /var/tmp
ENV TMPDIR=/var/tmp
RUN --mount=type=cache,target=/src/target --mount=type=cache,target=/var/roothome --network=none make install-unit-tests

# This just does syntax checking
FROM build as validate
RUN --mount=type=cache,target=/src/target --mount=type=cache,target=/var/roothome --network=none make validate

# The final image that derives from the original base and adds the release binaries
FROM base
# See the Justfile for possible variants
ARG variant
RUN <<EORUN
set -xeuo pipefail
# Ensure we've flushed out prior state (i.e. files no longer shipped from the old version);
# and yes, we may need to go to building an RPM in this Dockerfile by default.
rm -vf /usr/lib/systemd/system/multi-user.target.wants/bootc-*
case "${variant}" in
  *-sdboot)
    dnf -y install systemd-boot-unsigned
    # And uninstall bootupd
    rpm -e bootupd
    rm /usr/lib/bootupd/updates -rf
    dnf clean all
    rm -rf /var/cache /var/lib/{dnf,rhsm} /var/log/*
  ;;
esac
EORUN
# Support overriding the rootfs at build time conveniently
ARG rootfs=
RUN <<EORUN
set -xeuo pipefail
# Do we have an explicit build-time override? Then write it.
if test -n "$rootfs"; then
  cat > /usr/lib/bootc/install/80-rootfs-override.toml <<EOF
[install.filesystem.root]
type = "$rootfs"
EOF
else
  # Query the default rootfs
  base_rootfs=$(bootc install print-configuration | jq -r '.filesystem.root.type // ""')
  # No filesystem override set. If we're doing composefs, we need a FS that
  # supports fsverity. If btrfs is available we'll pick that, otherwise ext4.
  fs=
  case "${variant}" in
    composefs*)
      btrfs=$(grep -qEe '^CONFIG_BTRFS_FS' /usr/lib/modules/*/config && echo btrfs || true)
      fs=${btrfs:-ext4}
      ;;
    *)
      # No explicit filesystem set and we're not using composefs. Default to xfs
      # with the rationale that we're trying to get filesystem coverage across
      # all the cases in general.
      if test -z "${base_rootfs}"; then
        fs=xfs
      fi 
      ;;
  esac
  if test -n "$fs"; then
    cat > /usr/lib/bootc/install/80-ext4-composefs.toml <<EOF
[install.filesystem.root]
type = "${fs}"
EOF
  fi
fi
EORUN
# Create a layer that is our new binaries
COPY --from=build /out/ /
# We have code in the initramfs so we always need to regenerate it
RUN --network=none <<EORUN
set -xeuo pipefail
if test -x /usr/lib/bootc/initramfs-setup; then
   kver=$(cd /usr/lib/modules && echo *);
   env DRACUT_NO_XATTR=1 dracut -vf /usr/lib/modules/$kver/initramfs.img $kver
fi
# Only in this containerfile, inject a file which signifies
# this comes from this development image. This can be used in
# tests to know we're doing upstream CI.
touch /usr/lib/.bootc-dev-stamp
# And test our own linting
## Workaround for https://github.com/bootc-dev/bootc/issues/1546
rm -rf /root/buildinfo
bootc container lint --fatal-warnings
EORUN
