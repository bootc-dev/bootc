#!/bin/bash
set -exuo pipefail

# This script basically builds bootc from source using the provided base image,
# then runs the target tests. We need to do this because at the moment
# packit/tmt/testing-farm effectively only support RPMs, not container images.
# https://issues.redhat.com/browse/TFT-2751

BOOTC_TEMPDIR=$(mktemp -d)
trap 'rm -rf -- "$BOOTC_TEMPDIR"' EXIT

# LBI only enabled for test-22-logically-bound-install
LBI="${LBI:-disabled}"

# Get OS info
source /etc/os-release
case "$ID" in
    "centos")
        TIER1_IMAGE_URL="${TIER1_IMAGE_URL:-quay.io/centos-bootc/centos-bootc:stream${VERSION_ID}}"
        ;;
    "fedora")
        TIER1_IMAGE_URL="${TIER1_IMAGE_URL:-quay.io/fedora/fedora-bootc:${VERSION_ID}}"
        ;;
esac

if [ "$TMT_REBOOT_COUNT" -eq 0 ]; then
    # Let's move to bootc root folder
    cd ../..
    # Fedora CI: https://github.com/fedora-ci/dist-git-pipeline/blob/master/Jenkinsfile#L145
    # OSCI: https://gitlab.cee.redhat.com/osci-pipelines/dist-git-pipeline/-/blob/master/Jenkinsfile?ref_type=heads#L93
    if [[ -v KOJI_TASK_ID ]] || [[ -v CI_KOJI_TASK_ID ]]; then
        # Just left those ls commands here to ring the bell for me when something changed
        echo "$TMT_SOURCE_DIR"
        ls -al "$TMT_SOURCE_DIR"
        ls -al "$TMT_SOURCE_DIR/SRPMS"
        ls -al /etc/yum.repos.d
        cat /etc/yum.repos.d/test-artifacts.repo
        ls -al /var/share/test-artifacts
    fi

    # TMT needs this key
    cp -r /root/.ssh "$BOOTC_TEMPDIR"

    # Running on Testing Farm
    if [[ -d "/var/ARTIFACTS" ]]; then
        cp -r /var/ARTIFACTS "$BOOTC_TEMPDIR"
    # Running on local machine with tmt run
    else
        cp -r /var/tmp/tmt "$BOOTC_TEMPDIR"
    fi

    # Some rhts-*, rstrnt-* and tmt-* commands are in /usr/local/bin
    cp -r /usr/local/bin "$BOOTC_TEMPDIR"

    # Check image building folder content
    ls -al "$BOOTC_TEMPDIR"

    CONTAINERFILE=${BOOTC_TEMPDIR}/Containerfile

    COMMON_CONTAINERFILE="${BOOTC_TEMPDIR}/common_containerfile"
    tee "$COMMON_CONTAINERFILE" > /dev/null << COMMONEOF
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

# cloud-init and rsync are required by TMT
dnf -y install cloud-init rsync
ln -s ../cloud-init.target /usr/lib/systemd/system/default.target.wants
dnf -y clean all

rm -rf /var/cache /var/lib/dnf
EORUN

# Some rhts-*, rstrnt-* and tmt-* commands are in /usr/local/bin
COPY bin /usr/local/bin

# In Testing Farm, all ssh things should be reserved for ssh command run after reboot
COPY .ssh /var/roothome/.ssh
COMMONEOF

    if [[ -v KOJI_TASK_ID ]] || [[ -v CI_KOJI_TASK_ID ]]; then
        FEDORA_CI_CONTAINERFILE="${BOOTC_TEMPDIR}/fedora_ci_containerfile"
        tee "$FEDORA_CI_CONTAINERFILE" > /dev/null << FEDORACIEOF
FROM $TIER1_IMAGE_URL

RUN dnf -y upgrade /rpms/*.rpm
FEDORACIEOF
        cat >"$CONTAINERFILE" <<REALEOF
$(cat "$FEDORA_CI_CONTAINERFILE")
$(cat "$COMMON_CONTAINERFILE")

REALEOF
    else
        BOOTC_CI_CONTAINERFILE="${BOOTC_TEMPDIR}/bootc_ci_containerfile"
        # TODO use the default Dockerfile here instead of a copy of it
        tee "$BOOTC_CI_CONTAINERFILE" > /dev/null <<'BOOTCCIEOF'
FROM $TIER1_IMAGE_URL as build

WORKDIR /code
RUN <<EORUN
set -xeuo pipefail
. /usr/lib/os-release
case $ID in
  centos|rhel) dnf config-manager --set-enabled crb;;
  fedora) dnf -y install dnf-utils 'dnf5-command(builddep)';;
esac
dnf -y builddep /tmp/bootc.spec
# Extra dependencies
dnf -y install git-core
EORUN

RUN mkdir -p /build/target/dev-rootfs
RUN --mount=type=cache,target=/build/target --mount=type=cache,target=/var/roothome make test-bin-archive && mkdir -p /out && cp target/bootc.tar.zst /out

FROM $TIER1_IMAGE_URL

# Inject our built code
COPY --from=build /out/bootc.tar.zst /tmp
RUN tar -C / --zstd -xvf /tmp/bootc.tar.zst && rm -vrf /tmp/*
BOOTCCIEOF
        cat >"$CONTAINERFILE" <<REALEOF
$(cat "$BOOTC_CI_CONTAINERFILE")
$(cat "$COMMON_CONTAINERFILE")
REALEOF
    fi

    if [[ -d "/var/ARTIFACTS" ]]; then
        # In Testing Farm, TMT work dir /var/ARTIFACTS should be reserved
        echo "COPY ARTIFACTS /var/ARTIFACTS" >> "$CONTAINERFILE"
    else
        # In local machine, TMT work dir /var/tmp/tmt should be reserved
        echo "COPY tmt /var/tmp/tmt" >> "$CONTAINERFILE"
    fi

    # For test-22-logically-bound-install
    if [[ "$LBI" == "enabled" ]]; then
        echo "RUN cp -a /code/tmt/tests/lbi/usr/. /usr && ln -s /usr/share/containers/systemd/curl.container /usr/lib/bootc/bound-images.d/curl.container && ln -s /usr/share/containers/systemd/curl-base.image /usr/lib/bootc/bound-images.d/curl-base.image && ln -s /usr/share/containers/systemd/podman.image /usr/lib/bootc/bound-images.d/podman.image" >> "$CONTAINERFILE"
        podman pull --retry 5 --retry-delay 5s quay.io/curl/curl:latest
        podman pull --retry 5 --retry-delay 5s quay.io/curl/curl-base:latest
        podman pull --retry 5 --retry-delay 5s registry.access.redhat.com/ubi9/podman:latest
    fi

    cat "$CONTAINERFILE"
    # Retry here to avoid quay.io "502 Bad Gateway"
    # bind mount bootc source code folder for bootc binary building and run test provision
    # bind mount /var/share/test-artifacts for bootc RPM package installation in Fedora CI and OSCI
    if [[ -v KOJI_TASK_ID ]] || [[ -v CI_KOJI_TASK_ID ]]; then
        podman build \
            --retry 5 \
            --retry-delay 5s \
            --tls-verify=false \
            -v /var/share/test-artifacts:/rpms:z \
            -v "$(pwd)":/code:z \
            -t localhost/bootc:tmt \
            -f "$CONTAINERFILE" \
            "$BOOTC_TEMPDIR"
    else
        podman build \
            --retry 5 \
            --retry-delay 5s \
            --tls-verify=false \
            -v "$(pwd)":/code:z \
            -t localhost/bootc:tmt \
            -f "$CONTAINERFILE" \
            "$BOOTC_TEMPDIR"
    fi

    podman images
    podman run \
        --rm \
        --tls-verify=false \
        --privileged \
        --pid=host \
        -v /:/target \
        -v /dev:/dev \
        -v /var/lib/containers:/var/lib/containers \
        -v /root/.ssh:/output \
        --security-opt label=type:unconfined_t \
        "localhost/bootc:tmt" \
        bootc install to-existing-root --target-transport containers-storage --acknowledge-destructive

    # Reboot
    tmt-reboot
elif [ "$TMT_REBOOT_COUNT" -eq 1 ]; then
    # Some simple and fast checkings
    bootc status
    echo "$PATH"
    printenv
    if [[ -d "/var/ARTIFACTS" ]]; then
        ls -al /var/ARTIFACTS
    else
        ls -al /var/tmp/tmt
    fi
    ls -al /usr/local/bin
    echo "Bootc system on TMT/TF runner"

    exit 0
fi
