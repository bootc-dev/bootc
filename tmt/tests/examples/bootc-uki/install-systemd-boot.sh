#!/bin/bash

set -eux

curl http://192.168.122.1:8000/bootc -o bootc
chmod +x bootc

IMAGE=quay.io/fedora/fedora-bootc-uki:42

if [[ ! -f /srv/systemd-bootx64.efi ]]; then
    echo "Needs /srv/systemd-bootx64.efi to exists for now"
    exit 1
fi

#    --env RUST_LOG=debug \
#    --env RUST_BACKTRACE=1 \
podman run \
    --rm --privileged \
    --pid=host \
    -v /dev:/dev \
    -v /var/lib/containers:/var/lib/containers \
    -v /srv/bootc:/usr/bin/bootc:ro,Z \
    -v /var/tmp:/var/tmp \
    --security-opt label=type:unconfined_t \
    "${IMAGE}" \
    bootc install to-disk \
        --composefs-backend \
        --boot=uki \
        --source-imgref="containers-storage:${IMAGE}" \
        --target-imgref="${IMAGE}" \
        --target-transport="docker" \
        /dev/vdb \
        --filesystem=ext4 \
        --wipe

mkdir -p efi
mount /dev/vdb2 /srv/efi

# Manual systemd-boot installation
cp /srv/systemd-bootx64.efi /srv/efi/EFI/fedora/grubx64.efi
mkdir -p /srv/efi/loader
echo "timeout 5" > /srv/efi/loader/loader.conf
rm -rf /srv/efi/EFI/fedora/grub.cfg

umount efi
