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

# This image installs build deps, pulls in our source code, and installs updated
# bootc binaries in /out. The intention is that the target rootfs is extracted from /out
# back into a final stage (without the build deps etc) below.
FROM $base as buildroot
# Flip this off to disable initramfs code
ARG initramfs=1
# This installs our buildroot, and we want to cache it independently of the rest.
# Basically we don't want changing a .rs file to blow out the cache of packages.
RUN --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp \
    --mount=type=bind,from=packaging,src=/,target=/run/packaging \
    /run/packaging/install-buildroot
# Now copy the rest of the source
COPY --from=src /src /src
WORKDIR /src
# See https://www.reddit.com/r/rust/comments/126xeyx/exploring_the_problem_of_faster_cargo_docker/
# We aren't using the full recommendations there, just the simple bits.
# First we download all of our Rust dependencies
RUN --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/src/target --mount=type=cache,target=/var/roothome cargo fetch

FROM buildroot as sdboot-content
# Writes to /out
RUN --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp /src/contrib/packaging/configure-systemdboot download

# We always do a "from scratch" build
# https://docs.fedoraproject.org/en-US/bootc/building-from-scratch/
# because this fixes https://github.com/containers/composefs-rs/issues/132
# NOTE: Until we have https://gitlab.com/fedora/bootc/base-images/-/merge_requests/317
#       this stage will end up capturing whatever RPMs we find at this time.
# NOTE: This is using the *stock* bootc binary, not the one we want to build from
#       local sources. We'll override it later.
# NOTE: All your base belong to me.
FROM $base as target-base
# Handle version skew between base image and mirrors for CentOS Stream
# xref https://gitlab.com/redhat/centos-stream/containers/bootc/-/issues/1174
RUN --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp \
    --mount=type=bind,from=packaging,src=/,target=/run/packaging \
    /run/packaging/enable-compose-repos
RUN --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp /usr/libexec/bootc-base-imagectl build-rootfs --manifest=standard /target-rootfs

FROM scratch as base
COPY --from=target-base /target-rootfs/ /
# SKIP_CONFIGS=1 skips LBIs, test kargs, and install configs (for FCOS testing)
ARG SKIP_CONFIGS
# Use tmpfs for /run and /tmp with bind mounts inside to avoid leaking mount stubs into the image
RUN --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp \
    --mount=type=bind,from=src,src=/src/hack,target=/run/hack \
    cd /run/hack/ && SKIP_CONFIGS="${SKIP_CONFIGS}" ./provision-derived.sh
# Note we don't do any customization here yet
# Mark this as a test image
LABEL bootc.testimage="1"
# Otherwise standard metadata
LABEL containers.bootc 1
LABEL ostree.bootable 1
# https://pagure.io/fedora-kiwi-descriptions/pull-request/52
ENV container=oci
# Optional labels that only apply when running this image as a container. These keep the default entry point running under systemd.
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]

# -------------
# external dependency cutoff point:
# NOTE: Every RUN instruction past this point should use `--network=none`; we want to ensure
# all external dependencies are clearly delineated.
# This is verified in `cargo xtask check-buildsys`.
# -------------

FROM buildroot as build
# Version for RPM build (optional, computed from git in Justfile)
ARG pkgversion
# For reproducible builds, SOURCE_DATE_EPOCH must be exported as ENV for rpmbuild to see it
ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
# Build RPM directly from source, using cached target directory
RUN --network=none --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/src/target --mount=type=cache,target=/var/roothome RPM_VERSION="${pkgversion}" /src/contrib/packaging/build-rpm

FROM buildroot as sdboot-signed
# The secureboot key and cert are passed via Justfile
# We write the signed binary into /out
RUN --network=none --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp \
    --mount=type=bind,from=sdboot-content,src=/,target=/run/sdboot-package \
    --mount=type=secret,id=secureboot_key \
    --mount=type=secret,id=secureboot_cert \
    /src/contrib/packaging/configure-systemdboot sign

# This "build" includes our unit tests
FROM build as units
# A place that we're more likely to be able to set xattrs
VOLUME /var/tmp
ENV TMPDIR=/var/tmp
RUN --network=none --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/src/target --mount=type=cache,target=/var/roothome make install-unit-tests

# This just does syntax checking
FROM buildroot as validate
RUN --network=none --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/src/target --mount=type=cache,target=/var/roothome make validate

# Common base for final images: configures variant, rootfs, and injects extra content
FROM base as final-common
ARG variant
RUN --network=none --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp \
    --mount=type=bind,from=packaging,src=/,target=/run/packaging \
    --mount=type=bind,from=sdboot-content,src=/,target=/run/sdboot-content \
    --mount=type=bind,from=sdboot-signed,src=/,target=/run/sdboot-signed \
    /run/packaging/configure-variant "${variant}"
ARG rootfs=""
RUN --network=none --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp \
    --mount=type=bind,from=packaging,src=/,target=/run/packaging \
    /run/packaging/configure-rootfs "${variant}" "${rootfs}"
COPY --from=packaging /usr-extras/ /usr/

# Final target: installs pre-built packages from the 'packages' build context.
# Use with: podman build --target=final --build-context packages=path/to/packages
# We use --build-context instead of -v to avoid volume mount stubs leaking into /run.
FROM final-common as final
RUN --network=none --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp \
    --mount=type=bind,from=packaging,src=/,target=/run/packaging \
    --mount=type=bind,from=packages,src=/,target=/run/packages \
    /run/packaging/install-rpm-and-setup /run/packages
# lint: allow non-tmpfs
RUN --network=none <<EORUN
set -xeuo pipefail
# workaround for https://github.com/containers/buildah/pull/6233
rm -vrf /run/systemd
bootc container lint --fatal-warnings
EORUN
