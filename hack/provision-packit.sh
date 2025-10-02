#!/bin/bash
set -exuo pipefail

# Check environment
printenv

# This script only runs on Packit and gating environment
# Do not run this script for image mode system
if command -v bootc >/dev/null && bootc status --json | grep '"type":"bootcHost"'; then
    echo "This system is Image Mode."
    exit 0
fi

# Install required packages
dnf install -y podman skopeo jq bootc system-reinstall-bootc expect ansible-core

# temp folder to save building files and folders
BOOTC_TEMPDIR=$(mktemp -d)
trap 'rm -rf -- "$BOOTC_TEMPDIR"' EXIT

# Copy files and folders in hack to TEMPDIR
cp -a . "$BOOTC_TEMPDIR"

# Keep testing farm run folder
cp -r /var/ARTIFACTS "$BOOTC_TEMPDIR"

# Copy bootc repo
cp -r /var/share/test-artifacts "$BOOTC_TEMPDIR"

ARCH=$(uname -m)
# Get OS info
source /etc/os-release

# Some rhts-*, rstrnt-* and tmt-* commands are in /usr/local/bin
if [[ -d /var/lib/tmt/scripts ]]; then
    cp -r /var/lib/tmt/scripts "$BOOTC_TEMPDIR"
else
    cp -r /usr/local/bin "$BOOTC_TEMPDIR"
fi

# Get base image URL
TEST_OS="${ID}-${VERSION_ID}"
BASE=$(cat os-image-map.json | jq --arg v "$TEST_OS" '.[$v]')

if [[ "$ID" == "rhel" ]]; then
    # OSCI gating only
    CURRENT_COMPOSE_ID=$(skopeo inspect --no-tags --retry-times=5 --tls-verify=false "docker://${BASE}" | jq -r '.Labels."redhat.compose-id"')

    if [[ -n ${CURRENT_COMPOSE_ID} ]]; then
        if [[ ${CURRENT_COMPOSE_ID} == *-updates-* ]]; then
            BATCH_COMPOSE="updates/"
        else
            BATCH_COMPOSE=""
        fi
    else
        BATCH_COMPOSE="updates/"
        CURRENT_COMPOSE_ID=latest-RHEL-$VERSION_ID
    fi

    # use latest compose if specific compose is not accessible
    RC=$(curl -skIw '%{http_code}' -o /dev/null "http://${NIGHTLY_COMPOSE_SITE}/rhel-${VERSION_ID%%.*}/nightly/${BATCH_COMPOSE}RHEL-${VERSION_ID%%.*}/${CURRENT_COMPOSE_ID}/STATUS")
    if [[ $RC != "200" ]]; then
        CURRENT_COMPOSE_ID=latest-RHEL-${VERSION_ID%%}
    fi

    # generate rhel repo
    tee "${BOOTC_TEMPDIR}/rhel.repo" >/dev/null <<REPOEOF
[rhel-baseos]
name=baseos
baseurl=http://${NIGHTLY_COMPOSE_SITE}/rhel-${VERSION_ID%%.*}/nightly/${BATCH_COMPOSE}RHEL-${VERSION_ID%%.*}/${CURRENT_COMPOSE_ID}/compose/BaseOS/${ARCH}/os/
enabled=1
gpgcheck=0

[rhel-appstream]
name=appstream
baseurl=http://${NIGHTLY_COMPOSE_SITE}/rhel-${VERSION_ID%%.*}/nightly/${BATCH_COMPOSE}RHEL-${VERSION_ID%%.*}/${CURRENT_COMPOSE_ID}/compose/AppStream/${ARCH}/os/
enabled=1
gpgcheck=0
REPOEOF
    cp "${BOOTC_TEMPDIR}/rhel.repo" /etc/yum.repos.d
fi

# Fedora CI: https://github.com/fedora-ci/dist-git-pipeline/blob/master/Jenkinsfile#L145
# OSCI: https://gitlab.cee.redhat.com/osci-pipelines/dist-git-pipeline/-/blob/master/Jenkinsfile?ref_type=heads#L93
if [[ -v KOJI_TASK_ID ]] || [[ -v CI_KOJI_TASK_ID ]]; then
    # Just left those ls commands here to ring the bell for me when something changed
    echo "$TMT_SOURCE_DIR"
    ls -al "$TMT_SOURCE_DIR"
    ls -al "$TMT_SOURCE_DIR/SRPMS"
fi

ls -al /etc/yum.repos.d
cat /etc/yum.repos.d/test-artifacts.repo
ls -al /var/share/test-artifacts

# copy bootc rpm repo into image building root
cp /etc/yum.repos.d/test-artifacts.repo "$BOOTC_TEMPDIR"

# Let's check things in hack folder
ls -al "$BOOTC_TEMPDIR" "${BOOTC_TEMPDIR}/bin"

# Do not use just because it's only available on Fedora, not on CS and RHEL
podman build --jobs=4 --from "$BASE" -v "$BOOTC_TEMPDIR":/bootc-test:z -t localhost/bootc-integration -f "${BOOTC_TEMPDIR}/Containerfile.packit" "$BOOTC_TEMPDIR"

# Keep these in sync with what's used in hack/lbi
podman pull -q --retry 5 --retry-delay 5s quay.io/curl/curl:latest quay.io/curl/curl-base:latest registry.access.redhat.com/ubi9/podman:latest

# Run system-reinstall-bootc
# TODO make it more scriptable instead of expect + send
./system-reinstall-bootc.exp
