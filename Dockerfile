# Build this project from source and drop the updated content on to
# a bootc container image. By default we use CentOS Stream 9 as a base;
# use e.g. --build-arg=base=quay.io/fedora/fedora-bootc:41 to target
# Fedora instead.

ARG base=quay.io/centos-bootc/centos-bootc:stream9

FROM scratch as src
COPY . /src

# This image installs build deps, pulls in our source code, and installs updated
# bootc binaries in /out. The intention is that the target rootfs is extracted from /out
# back into a final stae (without the build deps etc) below.
FROM $base as build
# This installs our package dependencies, and we want to cache it independently of the rest.
# Basically we don't want changing a .rs file to blow out the cache of packages. So we only
# copy files necessary
COPY contrib/packaging/bootc.spec /tmp/bootc.spec
RUN <<EORUN
set -xeuo pipefail
. /usr/lib/os-release
case $ID in
  centos|rhel) dnf config-manager --set-enabled crb;;
  fedora) dnf -y install dnf-utils 'dnf5-command(builddep)';;
esac
dnf -y builddep /tmp/bootc.spec
# Extra dependencies
dnf -y install git-core
EORUN
# Now copy the rest of the source
COPY --from=src /src /src
WORKDIR /src
# See https://www.reddit.com/r/rust/comments/126xeyx/exploring_the_problem_of_faster_cargo_docker/
# We aren't using the full recommendations there, just the simple bits.
RUN --mount=type=cache,target=/build/target --mount=type=cache,target=/var/roothome \
    make && make install-all DESTDIR=/out

# This "build" just runs our unit tests
FROM build as units
ARG unitargs
RUN --mount=type=cache,target=/build/target --mount=type=cache,target=/var/roothome \
    cargo test --locked $unitargs

# The final image that derives from the original base and adds the release binaries
FROM $base
# First, create a layer that is our new binaries.
COPY --from=build /out/ /
RUN <<EORUN
set -xeuo pipefail
# Only in this containerfile, inject a file which signifies
# this comes from this development image. This can be used in
# tests to know we're doing upstream CI.
touch /usr/lib/.bootc-dev-stamp
# And test our own linting
bootc container lint --fatal-warnings
EORUN
