#!/bin/bash
set -exuo pipefail

# This script basically builds bootc from source using the provided base image,
# then runs the target tests.

mkdir -p /tmp/tmp-bootc-build
BOOTC_TEMPDIR="/tmp/tmp-bootc-build"

# Get OS info from TEST_OS env
OS_ID=$(echo "$TEST_OS" | cut -d '-' -f 1)
OS_VERSION_ID=$(echo "$TEST_OS" | cut -d '-' -f 2)

# Base image
case "$OS_ID" in
    "centos")
        TIER1_IMAGE_URL="quay.io/centos-bootc/centos-bootc:stream${OS_VERSION_ID}"
        ;;
    "fedora")
        TIER1_IMAGE_URL="quay.io/fedora/fedora-bootc:${OS_VERSION_ID}"
        ;;
esac

CONTAINERFILE="${BOOTC_TEMPDIR}/Containerfile"
tee "$CONTAINERFILE" > /dev/null << CONTAINERFILEOF
FROM $TIER1_IMAGE_URL as build

WORKDIR /code

RUN <<EORUN
set -xeuo pipefail
. /usr/lib/os-release
case \$ID in
    centos|rhel) dnf config-manager --set-enabled crb;;
    fedora) dnf -y install dnf-utils 'dnf5-command(builddep)';;
esac
dnf -y builddep contrib/packaging/bootc.spec
dnf -y install git-core
EORUN

RUN mkdir -p /build/target/dev-rootfs
# git config --global --add safe.directory /code to fix "fatal: detected dubious ownership in repository at '/code'" error
RUN --mount=type=cache,target=/build/target --mount=type=cache,target=/var/roothome git config --global --add safe.directory /code && make test-bin-archive && mkdir -p /out && cp target/bootc.tar.zst /out

FROM $TIER1_IMAGE_URL

# Inject our built code
COPY --from=build /out/bootc.tar.zst /tmp
RUN tar -C / --zstd -xvf /tmp/bootc.tar.zst && rm -vrf /tmp/*

RUN <<EORUN
set -xeuo pipefail

# Provision test requirement
/code/hack/provision-derived.sh
# Also copy in some default install configs we use for testing
cp -a /code/hack/install-test-configs/* /usr/lib/bootc/install/
# And some test kargs
cp -a /code/hack/test-kargs/* /usr/lib/bootc/kargs.d/

# For testing farm
mkdir -p -m 0700 /var/roothome

# Enable ttyS0 console
mkdir -p /usr/lib/bootc/kargs.d/
cat <<KARGEOF >> /usr/lib/bootc/kargs.d/20-console.toml
kargs = ["console=ttyS0,115200n8"]
KARGEOF

# For test-22-logically-bound-install
cp -a /code/tmt/tests/lbi/usr/. /usr
ln -s /usr/share/containers/systemd/curl.container /usr/lib/bootc/bound-images.d/curl.container
ln -s /usr/share/containers/systemd/curl-base.image /usr/lib/bootc/bound-images.d/curl-base.image
ln -s /usr/share/containers/systemd/podman.image /usr/lib/bootc/bound-images.d/podman.image

# Install rsync which is required by tmt
dnf -y install cloud-init rsync
dnf -y clean all

rm -rf /var/cache /var/lib/dnf
EORUN
CONTAINERFILEOF

LOCAL_IMAGE="localhost/bootc:test"
sudo podman build \
    --retry 5 \
    --retry-delay 5s \
    -v "$(pwd)":/code:z \
    -t "$LOCAL_IMAGE" \
    -f "$CONTAINERFILE" \
    "$BOOTC_TEMPDIR"

SSH_KEY=${BOOTC_TEMPDIR}/id_rsa
ssh-keygen -f "${SSH_KEY}" -N "" -q -t rsa-sha2-256 -b 2048

sudo truncate -s 10G "${BOOTC_TEMPDIR}/disk.raw"

# For test-22-logically-bound-install
sudo podman pull --retry 5 --retry-delay 5s quay.io/curl/curl:latest
sudo podman pull --retry 5 --retry-delay 5s quay.io/curl/curl-base:latest
sudo podman pull --retry 5 --retry-delay 5s registry.access.redhat.com/ubi9/podman:latest

sudo podman run \
  --rm \
  --privileged \
  --pid=host \
  --security-opt label=type:unconfined_t \
  -v /var/lib/containers:/var/lib/containers \
  -v /dev:/dev \
  -v "$BOOTC_TEMPDIR":/output \
  "$LOCAL_IMAGE" \
  bootc install to-disk \
  --filesystem "xfs" \
  --root-ssh-authorized-keys "/output/id_rsa.pub" \
  --karg=console=ttyS0,115200n8 \
  --generic-image \
  --via-loopback \
  /output/disk.raw
