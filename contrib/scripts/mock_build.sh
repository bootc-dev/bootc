#!/bin/bash
set -exuo pipefail

ARCH=$(uname -m)
MOCK_CONFIG="${DISTRO}-${ARCH}"

sudo dnf install -y cargo zstd git openssl-devel ostree-devel rpm-build mock

sudo dnf -y builddep contrib/packaging/bootc.spec
cargo install cargo-vendor-filterer

cargo xtask spec

# Adding user to mock group
sudo usermod -a -G mock "$(whoami)"

# Building SRPM
mock -r "$MOCK_CONFIG" --buildsrpm \
  --spec "target/bootc.spec" \
  --config-opts=cleanup_on_failure=False \
  --config-opts=cleanup_on_success=True \
  --sources target \
  --resultdir target/build

# Building RPMs
mock -r "$MOCK_CONFIG" \
    --config-opts=cleanup_on_failure=False \
    --config-opts=cleanup_on_success=True \
    --resultdir "target/build" \
    target/build/*.src.rpm
