#!/bin/bash
set -exuo pipefail

# You must have invoked test/build.sh before running this.
# This is basically a wrapper for tmt which sets up context
# (to point to our disk image) and works around bugs in
# tmt and testcloud.
# Use e.g. `./tests/run-tmt.sh plan --name test-21-logically-bound-switch`
# to run an individual test.

# Ensure we're in the topdir canonically
cd $(git rev-parse --show-toplevel)

DISK=$(pwd)/target/bootc-integration-test.qcow2
test -f "${DISK}"

# Move the tmt bits to a subdirectory to work around https://github.com/teemtee/tmt/issues/4062
mkdir -p target/tmt-workdir
rsync -a --delete --force .fmf tmt target/tmt-workdir/

# Hack around https://github.com/teemtee/testcloud/issues/17
rm -vrf /var/tmp/tmt/testcloud/images/bootc-integration-test.qcow2

cd target/tmt-workdir
# TMT will rsync tmt-* scripts to TMT_SCRIPTS_DIR=/var/lib/tmt/scripts
# running_env=image_mode means running tmt on image mode system on Github CI or locally
exec tmt --context "test_disk_image=${DISK}" --context "running_env=image_mode" run --all -e TMT_SCRIPTS_DIR=/var/lib/tmt/scripts "$@"
