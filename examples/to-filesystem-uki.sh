#!/bin/bash

set -euxo pipefail

IMAGE="${IMAGE:-quay.io/fedora/fedora-bootc-uki:42}"
TARGET="${TARGET:-quay.io/fedora/fedora-bootc-uki:42}"
DISKIMAGE="${DISKIMAGE:-test-filesystem-uki.img}"
ADDONS="${ADDONS:-}"

umount -R ./mnt || true
losetup --detach-all || true

rm -rf "${DISKIMAGE}"
truncate -s 15G "${DISKIMAGE}"

BOOTFS_UUID="96d15588-3596-4b3c-adca-a2ff7279ea63"
ROOTFS_UUID="910678ff-f77e-4a7d-8d53-86f2ac47a823"

cat > buf <<EOF
    label: gpt
    label-id: $(uuidgen)
    size=1024MiB, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name="EFI-SYSTEM"
    size=1024MiB, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="boot"
    type=4f68bce3-e8cd-4db1-96e7-fbcaf984b709, name="root"
EOF

losetup /dev/loop0 "${DISKIMAGE}"
sfdisk --wipe=always /dev/loop0 < buf
rm ./buf

# To make sure kernel updates
partx --update /dev/loop0

mkfs.fat /dev/loop0p1
mkfs.ext4 /dev/loop0p2 -L boot -U $BOOTFS_UUID
mkfs.ext4 /dev/loop0p3 -O verity -L root -U $ROOTFS_UUID

mkdir -p ./mnt

mount /dev/loop0p3 ./mnt
mkdir ./mnt/boot

# --generic-image \
podman run --rm --net=host --privileged --pid=host \
    --security-opt label=type:unconfined_t \
    --env RUST_LOG=debug \
    -v /dev:/dev \
    -v $PWD/../target/release/bootc:/usr/bin/bootc:ro,Z \
    -v /var/lib/containers:/var/lib/containers \
    -v $PWD/mnt:/var/mnt \
    "$IMAGE" \
        /usr/bin/bootc install to-filesystem \
            --composefs-native \
            --bootloader=systemd \
            --source-imgref "containers-storage:$IMAGE" \
            --target-imgref "${TARGET}" \
            ${ADDONS} \
            /var/mnt

#             --uki-addon-permanent=btrfs \
#             --uki-addon=ignition \
# bootc uki addon remove ignition
# bootc uki addon enable luks
# bootc uki addon enable keyboard-layout-fr
# bootc uki addon install console-ttyS0

# Manual systemd-boot installation
mount /dev/loop0p1 ./mnt
# cp systemd-bootx64.efi ./mnt/EFI/fedora/grubx64.efi
mkdir -p ./mnt/loader
echo "timeout 5" > ./mnt//loader/loader.conf

umount -R ./mnt
losetup -d /dev/loop0
