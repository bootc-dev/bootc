#!/bin/bash

set -euxo pipefail

IMAGE="${IMAGE:-quay.io/fedora/fedora-bootc-bls:42}"
DISKIMAGE="${DISKIMAGE:-test-disk.img}"

if [[ ! -f systemd-bootx64.efi ]]; then
    echo "Needs /srv/bootc/examples/systemd-bootx64.efi to exists for now"
    exit 1
fi

umount -R efi || true
losetup --detach-all || true

rm -rf "${DISKIMAGE}"
truncate -s 15G "${DISKIMAGE}"

# -v /srv/bootc/target/release/bootc:/usr/bin/bootc:ro,Z \
podman run \
    --rm --privileged \
    --pid=host \
    -v /dev:/dev \
    -v /var/lib/containers:/var/lib/containers \
    -v /var/tmp:/var/tmp \
    -v $PWD:/output \
    --env RUST_BACKTRACE=1 \
    --env RUST_LOG=debug \
    --security-opt label=type:unconfined_t \
    "${IMAGE}" \
    bootc install to-disk \
        --composefs-native \
        --bootloader=systemd \
        --source-imgref "containers-storage:$IMAGE" \
        --target-imgref="$IMAGE" \
        --target-transport="docker" \
        --filesystem=ext4 \
        --wipe \
        --generic-image \
        --via-loopback \
        --karg "selinux=1" \
        --karg "enforcing=0" \
        --karg "audit=0" \
        --karg "ignition.firstboot" \
        --karg "ignition.platform.id=qemu" \
        /output/"${DISKIMAGE}"

# Manual systemd-boot installation
losetup /dev/loop0 "${DISKIMAGE}"
partx --update /dev/loop0
mkdir -p efi
mount /dev/loop0p2 efi

# cp systemd-bootx64.efi efi/EFI/fedora/grubx64.efi
mkdir -p efi/loader
echo "timeout 5" > efi/loader/loader.conf
rm -rf efi/EFI/fedora/grub.cfg

umount efi
losetup -d /dev/loop0
