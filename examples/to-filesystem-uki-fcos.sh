#!/bin/bash

set -euxo pipefail

export IMAGE="quay.io/fedora/fedora-coreos-uki:stable"
exec ./to-filesystem-uki.sh
