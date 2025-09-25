#!/bin/bash

set -euxo pipefail

export IMAGE="quay.io/fedora/fedora-coreos-bls:stable"
export DISKIMAGE="${DISKIMAGE:-test-filesystem-fcos-bls.img}"
exec ./to-filesystem.sh
