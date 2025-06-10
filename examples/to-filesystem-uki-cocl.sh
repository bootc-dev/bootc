#!/bin/bash

set -euxo pipefail

export IMAGE="quay.io/fedora/fedora-coreos-uki-cocl:42.20250901.3.0"
export TARGET="quay.io/travier/fedora-coreos-uki-cocl:42.20250901.3.0"
export DISKIMAGE="${DISKIMAGE:-test-filesystem-fcos-uki-cocl.img}"
export ADDONS="--uki-addon ignition"
exec ./to-filesystem-uki.sh
