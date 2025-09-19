#!/bin/bash

set -euxo pipefail

export IMAGE="quay.io/fedora/fedora-coreos-bls:stable"
exec ./to-filesystem.sh
