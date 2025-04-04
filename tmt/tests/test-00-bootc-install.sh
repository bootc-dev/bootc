#!/bin/bash
set -exuo pipefail

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
    # Copy bootc root folder to image build root folder
    cp -a ../../. "$BOOTC_TEMPDIR"

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
    tee "$CONTAINERFILE" > /dev/null << REALEOF
FROM $TIER1_IMAGE_URL as build

COPY contrib /contrib
COPY hack/build.sh /build.sh
RUN /build.sh && rm -v /build.sh
COPY . /build
WORKDIR /build

RUN mkdir -p /build/target/dev-rootfs
RUN --mount=type=cache,target=/build/target --mount=type=cache,target=/var/roothome make test-bin-archive && mkdir -p /out && cp target/bootc.tar.zst /out

FROM $TIER1_IMAGE_URL

COPY hack/provision-derived.sh /tmp
RUN /tmp/provision-derived.sh && rm -f /tmp/*.sh
# Also copy in some default install configs we use for testing
COPY hack/install-test-configs/* /usr/lib/bootc/install/
# And some test kargs
COPY hack/test-kargs /usr/lib/bootc/kargs.d/
# Inject our built code
COPY --from=build /out/bootc.tar.zst /tmp
RUN tar -C / --zstd -xvf /tmp/bootc.tar.zst && rm -vrf /tmp/*
# Also copy over arbitrary bits from the target root
COPY --from=build /build/target/dev-rootfs/ /

RUN <<EORUN
set -xeuo pipefail

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
REALEOF

    if [[ -d "/var/ARTIFACTS" ]]; then
        # In Testing Farm, TMT work dir /var/ARTIFACTS should be reserved
        echo "COPY ARTIFACTS /var/ARTIFACTS" >> "$CONTAINERFILE"
    else
        # In local machine, TMT work dir /var/tmp/tmt should be reserved
        echo "COPY tmt /var/tmp/tmt" >> "$CONTAINERFILE"
    fi

    # For test-22-logically-bound-install
    if [[ "$LBI" == "enabled" ]]; then
        echo "COPY tmt/tests/lbi/usr/. /usr" >> "$CONTAINERFILE"
        echo "RUN ln -s /usr/share/containers/systemd/curl.container /usr/lib/bootc/bound-images.d/curl.container && ln -s /usr/share/containers/systemd/curl-base.image /usr/lib/bootc/bound-images.d/curl-base.image && ln -s /usr/share/containers/systemd/podman.image /usr/lib/bootc/bound-images.d/podman.image" >> "$CONTAINERFILE"
        podman pull --retry 5 --retry-delay 5s quay.io/curl/curl:latest
        podman pull --retry 5 --retry-delay 5s quay.io/curl/curl-base:latest
        podman pull --retry 5 --retry-delay 5s registry.access.redhat.com/ubi9/podman:latest
    fi

    cat "$CONTAINERFILE"
    # Retry here to avoid quay.io "502 Bad Gateway"
    podman build --retry 5 --retry-delay 5s --tls-verify=false -t localhost/bootc:tmt -f "$CONTAINERFILE" "$BOOTC_TEMPDIR"

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
        bootc install to-existing-root --target-transport containers-storage

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
