# Build this project from source and write the updated content
# (i.e. /usr/bin/bootc and systemd units) to a new derived container
# image. See the `Justfile` for an example

# Note this is usually overridden via Justfile
ARG base=quay.io/centos-bootc/centos-bootc:stream10

# This first image captures a snapshot of the source code,
# note all the exclusions in .dockerignore.
FROM scratch as src
COPY . /src

# And this image only captures contrib/packaging separately
# to ensure we have more precise cache hits.
FROM scratch as packaging
COPY contrib/packaging /

# This image captures pre-built packages from the context.
# By COPYing into a stage, we avoid SELinux issues with context bind mounts.
FROM scratch as packages
COPY target/packages/*.rpm /

FROM $base as base
# Mark this as a test image (moved from --label build flag to fix layer caching)
LABEL bootc.testimage="1"

# This image installs build deps, pulls in our source code, and installs updated
# bootc binaries in /out. The intention is that the target rootfs is extracted from /out
# back into a final stage (without the build deps etc) below.
FROM base as buildroot
# Flip this off to disable initramfs code
ARG initramfs=1
# This installs our buildroot, and we want to cache it independently of the rest.
# Basically we don't want changing a .rs file to blow out the cache of packages.
RUN --mount=type=bind,from=packaging,target=/run/packaging /run/packaging/install-buildroot
# Now copy the rest of the source
COPY --from=src /src /src
WORKDIR /src
# See https://www.reddit.com/r/rust/comments/126xeyx/exploring_the_problem_of_faster_cargo_docker/
# We aren't using the full recommendations there, just the simple bits.
# First we download all of our Rust dependencies
RUN --mount=type=cache,target=/src/target --mount=type=cache,target=/var/roothome cargo fetch

FROM buildroot as sdboot-content
# Writes to /out
RUN /src/contrib/packaging/configure-systemdboot download

# NOTE: Every RUN instruction past this point should use `--network=none`; we want to ensure
# all external dependencies are clearly delineated.

FROM buildroot as build
# Version for RPM build (optional, computed from git in Justfile)
ARG pkgversion
# Build RPM directly from source, using cached target directory
RUN --mount=type=cache,target=/src/target --mount=type=cache,target=/var/roothome --network=none RPM_VERSION="${pkgversion}" /src/contrib/packaging/build-rpm

FROM buildroot as sdboot-signed
# The secureboot key and cert are passed via Justfile
# We write the signed binary into /out
RUN --network=none \
    --mount=type=bind,from=sdboot-content,target=/run/sdboot-package \
    --mount=type=secret,id=secureboot_key \
    --mount=type=secret,id=secureboot_cert \
    /src/contrib/packaging/configure-systemdboot sign

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
RUN --network=none --mount=type=bind,from=packaging,target=/run/packaging \
    --mount=type=bind,from=sdboot-content,target=/run/sdboot-content \
    --mount=type=bind,from=sdboot-signed,target=/run/sdboot-signed \
    /run/packaging/configure-variant "${variant}"
# Support overriding the rootfs at build time conveniently
ARG rootfs
RUN --mount=type=bind,from=packaging,target=/run/packaging /run/packaging/configure-rootfs "${variant}" "${rootfs}"
# Inject additional content
COPY --from=packaging /usr-extras/ /usr/
# Install packages from the packages stage
# Using bind from a stage avoids SELinux issues with context bind mounts
RUN --mount=type=bind,from=packaging,target=/run/packaging \
    --mount=type=bind,from=packages,target=/build-packages \
    --network=none \
    /run/packaging/install-rpm-and-setup /build-packages
# Finally, testour own linting
RUN bootc container lint --fatal-warnings
