#!/bin/bash
set -exuo pipefail

# This script basically builds bootc from source using the provided base image,
# then runs the target tests.

# If provided should be of the form fedora-42 or centos-10
target=${1:-}

build_args=()
if test -n "${target:-}"; then
    shift
    # Get OS info from TEST_OS env
    OS_ID=$(echo "$target" | cut -d '-' -f 1)
    OS_VERSION_ID=$(echo "$target" | cut -d '-' -f 2)

    # Base image
    case "$OS_ID" in
        "centos")
            BASE="quay.io/centos-bootc/centos-bootc:stream${OS_VERSION_ID}"
        ;;
        "fedora")
            BASE="quay.io/fedora/fedora-bootc:${OS_VERSION_ID}"
        ;;
        *) echo "Unknown OS: ${OS_ID}" 1>&2; exit 1
        ;;
    esac
    build_args+=("--build-arg=base=$BASE")
fi

just build ${build_args[@]}
just build-integration-test-image

# Host builds will have this already, but we use it as a general dumping space
# for output artifacts
mkdir -p target

SSH_KEY=$(pwd)/target/id_rsa
rm -vf "${SSH_KEY}"*
ssh-keygen -f "${SSH_KEY}" -N "" -q -t rsa-sha2-256 -b 2048
chmod 600 "${SSH_KEY}"

rm -vf target/disk.raw
truncate -s 10G "target/disk.raw"

# For test-22-logically-bound-install
podman pull --retry 5 --retry-delay 5s quay.io/curl/curl:latest
podman pull --retry 5 --retry-delay 5s quay.io/curl/curl-base:latest
podman pull --retry 5 --retry-delay 5s registry.access.redhat.com/ubi9/podman:latest

mkdir -p target/disks

podman run \
  --rm \
  --privileged \
  --pid=host \
  --security-opt label=type:unconfined_t \
  -v /var/lib/containers:/var/lib/containers \
  -v /dev:/dev \
  -v $(pwd)/target:/target \
  localhost/bootc-integration \
  bootc install to-disk \
  --filesystem "xfs" \
  --root-ssh-authorized-keys "/target/id_rsa.pub" \
  --karg=console=ttyS0,115200n8 \
  --generic-image \
  --via-loopback \
  /target/disk.raw
