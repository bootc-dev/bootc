# Build this project from source and write the updated content
# (i.e. /usr/bin/bootc and systemd units) to a new derived container
# image. See the `Justfile` for an example
#
# Use e.g. --build-arg=base=quay.io/fedora/fedora-bootc:42 to target
# Fedora instead.

ARG base=quay.io/centos-bootc/centos-bootc:stream10

# This first image captures a snapshot of the source code,
# note all the exclusions in .dockerignore.
FROM scratch as src
COPY . /src

FROM $base as base
# Set this to anything non-0 to enable https://copr.fedorainfracloud.org/coprs/g/CoreOS/continuous/
ARG continuous_repo=0
RUN <<EORUN
set -xeuo pipefail
if [ "${continuous_repo}" == 0 ]; then
  exit 0
fi
# Sadly dnf copr enable looks for epel, not centos-stream....
. /usr/lib/os-release
case $ID in
  centos) 
    curl -L -o /etc/yum.repos.d/continuous.repo https://copr.fedorainfracloud.org/coprs/g/CoreOS/continuous/repo/centos-stream-$VERSION_ID/group_CoreOS-continuous-centos-stream-$VERSION_ID.repo
  ;;
  fedora)
    if rpm -q dnf5 &>/dev/null; then
      dnf -y install dnf5-plugins
    fi
    dnf copr enable -y @CoreOS/continuous
  ;;
  *) echo "error: Unsupported OS '$ID'" >&2; exit 1
  ;;
esac
dnf -y upgrade ostree bootupd
rm -rf /var/cache/* /var/lib/dnf /var/lib/rhsm /var/log/*
EORUN

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
RUN --mount=type=cache,target=/src/target --mount=type=cache,target=/var/roothome <<EORUN
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
RUN --mount=type=cache,target=/build/target --mount=type=cache,target=/var/roothome make install-unit-tests

# This just does syntax checking
FROM build as validate
RUN --mount=type=cache,target=/build/target --mount=type=cache,target=/var/roothome make validate

# The final image that derives from the original base and adds the release binaries
FROM base
RUN <<EORUN
set -xeuo pipefail
# Ensure we've flushed out prior state (i.e. files no longer shipped from the old version);
# and yes, we may need to go to building an RPM in this Dockerfile by default.
rm -vf /usr/lib/systemd/system/multi-user.target.wants/bootc-*
EORUN
# Create a layer that is our new binaries
COPY --from=build /out/ /
# We have code in the initramfs so we always need to regenerate it
RUN <<EORUN
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
