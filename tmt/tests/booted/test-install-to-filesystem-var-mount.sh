# number: 32
# tmt:
#   summary: Test bootc install to-filesystem with separate /var mount
#   duration: 30m
#   require:
#     - parted
#     - lvm2
#     - dosfstools
#     - e2fsprogs
#
#!/bin/bash
# Test bootc install to-filesystem with a pre-existing /var mount point.
# This verifies that bootc correctly handles scenarios where /var is on a
# separate filesystem, which is a common production setup for managing
# persistent data separately from the OS.

set -xeuo pipefail

# Build a derived image with LBIs removed for installation
TARGET_IMAGE="localhost/bootc-install"

echo "Testing bootc install to-filesystem with separate /var mount"

# Copy the currently booted image to container storage for podman to use
bootc image copy-to-storage

# Build a derived image that removes LBIs
cat > /tmp/Containerfile.drop-lbis <<'EOF'
FROM localhost/bootc as base
RUN rm -rf /usr/lib/bootc/bound-images.d/*
RUN mkdir -p /var/lib/bootc-var-test/child && \
    printf 'parent seed\n' > /var/lib/bootc-var-test/parent && \
    printf 'child seed\n' > /var/lib/bootc-var-test/child/seed && \
    chmod 0640 /var/lib/bootc-var-test/child/seed && \
    chown 1001:1002 /var/lib/bootc-var-test/child/seed && \
    ln /var/lib/bootc-var-test/child/seed /var/lib/bootc-var-test/crosslink && \
    ln /var/lib/bootc-var-test/child/seed /var/lib/bootc-var-test/child/hardlink && \
    ln -s seed /var/lib/bootc-var-test/child/symlink
EOF

is_composefs=$(bootc status --json | jq '.status.booted.composefs')
boot_type=$(bootc status --json | jq -r '.status.booted.composefs.bootType' | tr '[:upper:]' '[:lower:]')

if [[ $is_composefs != "null" && $boot_type == "uki" ]]; then
    allow_missing_verity=()

    if [[ "$(bootc status --json | jq -r '.status.booted.composefs.missingVerityAllowed')" == "true" ]]; then
        allow_missing_verity=("--allow-missing-verity")
    fi

    seal_state="unsealed"

    cat >> /tmp/Containerfile.drop-lbis <<-EOF
FROM base as kernel
RUN <<-RUNEOF
    kver=\$(bootc container inspect --rootfs / --json | jq -r '.kernel.version')
    bootc internals uki extract /boot/EFI/Linux/\$kver.efi /boot
RUNEOF

FROM base as base-final
RUN rm -rf /boot/EFI/Linux/*.efi

FROM base as sealed-uki
RUN --network=none --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp \
    --mount=type=bind,from=kernel,src=/,target=/run/kernel \
    --mount=type=bind,from=base-final,src=/,target=/run/target <<RUNEOF

    kver=\$(bootc container inspect --rootfs /run/kernel --json | jq -r '.kernel.version')

    /usr/bin/seal-uki \
      --target /run/target \
      --output /out \
      --secrets /run/secrets \
      --kernel-dir /run/kernel/boot/\$kver \
      --seal-state $seal_state \
      --erofs-version "${BOOTC_erofs_version:-v1}" \
      "${allow_missing_verity[@]}"

RUNEOF

FROM base-final

RUN --network=none --mount=type=tmpfs,target=/run --mount=type=tmpfs,target=/tmp \
    --mount=type=bind,from=sealed-uki,src=/,target=/run/sealed-uki \
    --mount=type=bind,from=kernel,src=/,target=/run/kernel \
    /usr/bin/finalize-uki /run/sealed-uki/out \$(bootc container inspect --rootfs /run/kernel --json | jq -r '.kernel.version')
EOF
fi

podman build -t "$TARGET_IMAGE" -f /tmp/Containerfile.drop-lbis

# Create a 15GB sparse disk image in /var/tmp (not /tmp which may be tmpfs)
# Increased this as we want a larger ESP for composefs
DISK_IMG=/var/tmp/disk-var-mount-test.img
truncate -s 15G "$DISK_IMG"

# Setup loop device
LOOP_DEV=$(losetup -f --show "$DISK_IMG")
echo "Using loop device: $LOOP_DEV"

# Cleanup function
cleanup() {
    set +e
    echo "Cleaning up..."
    umount -R /var/mnt/target 2>/dev/null
    vgchange -an BL 2>/dev/null
    vgremove -f BL 2>/dev/null
    losetup -d "$LOOP_DEV" 2>/dev/null
    rm -f "$DISK_IMG" 2>/dev/null
}
trap cleanup EXIT

# Create partition table
parted -s "$LOOP_DEV" mklabel gpt
# BIOS boot partition (for GRUB on GPT)
parted -s "$LOOP_DEV" mkpart primary 1MiB 2MiB
parted -s "$LOOP_DEV" set 1 bios_grub on
# EFI partition (1 GiB)
parted -s "$LOOP_DEV" mkpart primary fat32 2MiB 1026MiB
parted -s "$LOOP_DEV" set 2 esp on
# Boot partition (1 GiB)
parted -s "$LOOP_DEV" mkpart primary ext4 1026MiB 2052MiB
# LVM partition (rest of disk)
parted -s "$LOOP_DEV" mkpart primary 2052MiB 100%

# Reload partition table
partprobe "$LOOP_DEV"
sleep 2

# Partition device names
EFI_PART="${LOOP_DEV}p2"
BOOT_PART="${LOOP_DEV}p3"
LVM_PART="${LOOP_DEV}p4"

# Create filesystems on boot partitions
mkfs.vfat -F32 "$EFI_PART"
mkfs.ext4 -F "$BOOT_PART"

# Setup LVM
pvcreate "$LVM_PART"
vgcreate BL "$LVM_PART"

# Create logical volumes
lvcreate -L 4G -n var02 BL
lvcreate -L 256M -n child02 BL
lvcreate -l 100%FREE -n root02 BL

# Create filesystems on logical volumes
mkfs.ext4 -F /dev/BL/var02
mkfs.ext4 -F /dev/BL/child02
mkfs.ext4 -F /dev/BL/root02

# Get UUIDs for bootc install
ROOT_UUID=$(blkid -s UUID -o value /dev/BL/root02)
BOOT_UUID=$(blkid -s UUID -o value "$BOOT_PART")

# Mount the partitions, with /var as a separate partition and a nested
# filesystem below it
mount_target() {
    mkdir -p /var/mnt/target
    mount /dev/BL/root02 /var/mnt/target
    mkdir -p /var/mnt/target/boot
    mount "$BOOT_PART" /var/mnt/target/boot
    mkdir -p /var/mnt/target/boot/efi
    mount "$EFI_PART" /var/mnt/target/boot/efi

    # Create EFI directory structure with some files (simulating existing EFI content)
    mkdir -p /var/mnt/target/boot/efi/EFI/fedora
    touch /var/mnt/target/boot/efi/EFI/fedora/shimx64.efi
    touch /var/mnt/target/boot/efi/EFI/fedora/grubx64.efi

    mkdir -p /var/mnt/target/var
    mount /dev/BL/var02 /var/mnt/target/var
    mkdir -p /var/mnt/target/var/lib/bootc-var-test/child
    mount /dev/BL/child02 /var/mnt/target/var/lib/bootc-var-test/child
}

mount_target

echo "Filesystem layout:"
mount | grep /var/mnt/target || true
df -h /var/mnt/target /var/mnt/target/boot /var/mnt/target/boot/efi /var/mnt/target/var

bootloader=$(bootc status --json | jq -r '.status.booted.composefs.bootloader' | tr '[:upper:]' '[:lower:]')

COMPOSEFS_BACKEND_PARAMS=()
KARGS=("--karg=root=UUID=$ROOT_UUID")

if [[ $is_composefs != "null" ]]; then
    COMPOSEFS_BACKEND_PARAMS+=("--bootloader" "${bootloader}")

    tune2fs -O verity /dev/BL/var02
    tune2fs -O verity /dev/BL/root02

    if [[ $boot_type == "uki" ]]; then
        KARGS=()
    fi
fi

run_install() {
    # Run bootc install to-filesystem from within the container image under test
    podman run \
        --rm --privileged \
        -v /var/mnt/target:/target \
        -v /dev:/dev \
        --pid=host \
        --security-opt label=type:unconfined_t \
        "$TARGET_IMAGE" \
        bootc install to-filesystem \
            "${COMPOSEFS_BACKEND_PARAMS[@]}" \
            "${KARGS[@]}" \
            --root-mount-spec=UUID="$ROOT_UUID" \
            --boot-mount-spec=UUID="$BOOT_UUID" \
            "$@" \
            /target
}

run_install --initialize-var-mounts

# Verify the installation succeeded
echo "Verifying installation..."

if [[ $is_composefs == "null" ]]; then
    test -d /var/mnt/target/ostree
    test -d /var/mnt/target/ostree/repo

    # Verify bootloader was installed (grub2 or loader for different configurations)
    test -d /var/mnt/target/boot/grub2 || test -d /var/mnt/target/boot/loader
else
    test -d /var/mnt/target/composefs

    # TODO(Johan-Liebert1): This is getting bootloader from the VM, which is not quite correct
    # It works for now as the CI runs separately for each bootloader, but we need to get the 
    # bootloader from the installed systemd if we wish to run the tests locally without rebuilding the images
    # This probably also happens in other tests, one instance is install-outside-container
    if [[ $bootloader == "grub" ]]; then
        test -d /var/mnt/target/boot/grub2 || test -d /var/mnt/target/boot/loader
    else
        test -d /var/mnt/target/boot/efi/EFI
        test -d /var/mnt/target/boot/efi/loader/entries
    fi
fi

# Check the volume contents, not just successful deployment. The nested LV
# must contain its own seed files rather than hide them on the parent LV.
test "$(cat /var/mnt/target/var/lib/bootc-var-test/parent)" = 'parent seed'
child=/var/mnt/target/var/lib/bootc-var-test/child
test "$(cat "$child/seed")" = 'child seed'
test "$(stat -c '%u:%g:%a' "$child/seed")" = '1001:1002:640'
test "$(readlink "$child/symlink")" = seed
test "$(cat "$child/hardlink")" = 'child seed'
test "$(cat /var/mnt/target/var/lib/bootc-var-test/crosslink)" = 'child seed'
if selinuxenabled; then
    for path in /var /var/lib/bootc-var-test/child /var/lib/bootc-var-test/child/seed; do
        test "$(stat -c '%C' "/var/mnt/target$path")" = "$(matchpathcon -n "$path")"
    done
fi
umount "$child"
test ! -e "$child/seed"
mount /dev/BL/child02 "$child"
test "$(cat "$child/seed")" = 'child seed'

echo "Caller-mounted /var is left alone without --initialize-var-mounts"
# Start over on fresh filesystems, keeping their UUIDs for KARGS
umount -R /var/mnt/target
mkfs.vfat -F32 "$EFI_PART"
mkfs.ext4 -F -U "$BOOT_UUID" "$BOOT_PART"
mkfs.ext4 -F -U "$ROOT_UUID" /dev/BL/root02
mkfs.ext4 -F /dev/BL/var02
mkfs.ext4 -F /dev/BL/child02
if [[ $is_composefs != "null" ]]; then
    tune2fs -O verity /dev/BL/var02
    tune2fs -O verity /dev/BL/root02
fi
mount_target
run_install
test ! -e /var/mnt/target/var/lib/bootc-var-test/parent
test ! -e "$child/seed"
# The image's /var stays in the backend's state directory instead
if [[ $is_composefs == "null" ]]; then
    seeded_var=/var/mnt/target/ostree/deploy/default/var
else
    seeded_var=/var/mnt/target/state/os/default/var
fi
test "$(cat "$seeded_var/lib/bootc-var-test/parent")" = 'parent seed'

echo "Installation to-filesystem with separate /var mount succeeded!"
