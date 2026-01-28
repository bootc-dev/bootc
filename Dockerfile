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
# Use tmpfs for /run and /tmp with bind mounts inside to avoid leaking mount stubs into the image
RUN --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp \
    --mount=type=bind,from=packaging,src=/,target=/run/packaging \
    /run/packaging/install-buildroot
# Now copy the rest of the source
COPY --from=src /src /src
WORKDIR /src
# See https://www.reddit.com/r/rust/comments/126xeyx/exploring_the_problem_of_faster_cargo_docker/
# We aren't using the full recommendations there, just the simple bits.
# First we download all of our Rust dependencies
# Note: Local path dependencies (from [patch] sections) are auto-detected and bind-mounted by the Justfile
RUN --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/src/target --mount=type=cache,target=/var/roothome \
    rm -rf /var/roothome/.cargo/registry; cargo fetch

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

# This layer contains things which aren't in the default image and may
# be used for sealing images in particular.
FROM base as tools
RUN --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp \
    --mount=type=bind,from=packaging,src=/,target=/run/packaging \
    /run/packaging/initialize-sealing-tools

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

# This image signs systemd-boot using our key, and writes the resulting binary into /out
FROM tools as sdboot-signed
# The secureboot key and cert are passed via Justfile
# We write the signed binary into /out
# Note: /out already contains systemd-boot-unsigned RPM from initialize-sealing-tools
RUN --network=none --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp \
    --mount=type=secret,id=secureboot_key \
    --mount=type=secret,id=secureboot_cert <<EORUN
set -xeuo pipefail

# Extract the unsigned systemd-boot binary from the downloaded RPM
cd /tmp
rpm2cpio /out/*.rpm | cpio -idmv
# Find the extracted unsigned binary
sdboot_unsigned=$(ls ./usr/lib/systemd/boot/efi/systemd-boot*.efi)
sdboot_bn=$(basename ${sdboot_unsigned})
# Sign with sbsign using db certificate and key
sbsign --key /run/secrets/secureboot_key \
   --cert /run/secrets/secureboot_cert \
   --output /out/${sdboot_bn} \
   ${sdboot_unsigned}
ls -al /out/${sdboot_bn}
EORUN

# ----
# Unit and integration tests
# The section here (up until the last `FROM` line which acts as the default target)
# is non-default images for unit and source code validation.
# ----

# This "build" includes our unit tests
FROM build as units
# A place that we're more likely to be able to set xattrs
VOLUME /var/tmp
ENV TMPDIR=/var/tmp
RUN --network=none --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/src/target --mount=type=cache,target=/var/roothome make install-unit-tests

# This just does syntax checking
FROM buildroot as validate
RUN --network=none --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp --mount=type=cache,target=/src/target --mount=type=cache,target=/var/roothome make validate

# ----
# Stages for the final image
# ----

# Perform all filesystem transformations except generating the sealed UKI (if configured)
FROM base as base-penultimate
ARG variant
# Switch to a signed systemd-boot, if configured
RUN --network=none --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp \
    --mount=type=bind,from=packaging,src=/,target=/run/packaging \
    --mount=type=bind,from=sdboot-signed,src=/,target=/run/sdboot-signed <<EORUN
set -xeuo pipefail
if test "${variant}" = "composefs-sealeduki-sdboot"; then
  /run/packaging/switch-to-sdboot /run/sdboot-signed
fi
EORUN
# Configure the rootfs
ARG rootfs=""
RUN --network=none --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp \
    --mount=type=bind,from=packaging,src=/,target=/run/packaging \
    /run/packaging/configure-rootfs "${variant}" "${rootfs}"
# Override with our built package
RUN --network=none --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp \
    --mount=type=bind,from=packaging,src=/,target=/run/packaging \
    --mount=type=bind,from=packages,src=/,target=/run/packages \
    /run/packaging/install-rpm-and-setup /run/packages
# Inject some other configuration
COPY --from=packaging /usr-extras/ /usr/
# Clean up package manager caches
RUN --network=none --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp \
    --mount=type=bind,from=packaging,src=/,target=/run/packaging \
    /run/packaging/cleanup

# Generate the sealed UKI in a separate stage
# This computes the composefs digest from base-penultimate and creates a signed UKI
# We need our newly-built bootc for the compute-composefs-digest command
FROM tools as sealed-uki
ARG variant
# Install our bootc package (only needed for the compute-composefs-digest command)
RUN --network=none --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp \
    --mount=type=bind,from=packages,src=/,target=/run/packages \
    rpm -Uvh --oldpackage /run/packages/bootc-*.rpm
RUN --network=none --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp \
    --mount=type=secret,id=secureboot_key \
    --mount=type=secret,id=secureboot_cert \
    --mount=type=bind,from=packaging,src=/,target=/run/packaging \
    --mount=type=bind,from=base-penultimate,src=/,target=/run/target <<EORUN
set -xeuo pipefail
if test "${variant}" = "composefs-sealeduki-sdboot"; then
  /run/packaging/seal-uki /run/target /out /run/secrets
fi
EORUN

# And now the final image
FROM base-penultimate
ARG variant
# Copy the sealed UKI and finalize the image (remove raw kernel, create symlinks)
RUN --network=none --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp \
    --mount=type=bind,from=packaging,src=/,target=/run/packaging \
    --mount=type=bind,from=sealed-uki,src=/,target=/run/sealed-uki <<EORUN
set -xeuo pipefail
if test "${variant}" = "composefs-sealeduki-sdboot"; then
  /run/packaging/finalize-uki /run/sealed-uki/out
fi
EORUN
# And finally, test our linting
# lint: allow non-tmpfs - we want to detect leaked files in /run and /tmp
RUN --network=none <<EORUN
set -xeuo pipefail
# workaround for https://github.com/containers/buildah/pull/6233
rm -vrf /run/systemd
bootc container lint --fatal-warnings
EORUN
