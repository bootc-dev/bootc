#!/bin/bash
# bootc-luks-firstboot -- encrypt root partition on first boot
#
# This script runs in the initrd before sysroot.mount. It checks for the
# rd.bootc.luks.encrypt kernel argument and, if present, encrypts the root
# partition in-place using cryptsetup reencrypt --encrypt.
#
# The root partition must have been created with 32MB of trailing free space
# (filesystem smaller than partition) by bootc install to-disk.
#
# After encryption:
# - The root device is available as /dev/mapper/cr_root
# - TPM2 is enrolled via systemd-cryptenroll
# - A recovery key is generated and printed to the console
# - /etc/crypttab is written inside the encrypted root
# - BLS entries are updated with rd.luks.uuid kargs
# - The rd.bootc.luks.encrypt trigger karg is removed
#
# The root=UUID=<ext4-uuid> karg does NOT need to change. Once the initrd
# unlocks LUKS via rd.luks.uuid on subsequent boots, the ext4 UUID becomes
# visible on /dev/mapper/cr_root and systemd resolves root= normally.
#
# SPDX-License-Identifier: Apache-2.0 OR MIT

set -euo pipefail

ENCRYPT_KARG=""
ROOT_DEV=""
LUKS_NAME="cr_root"

log() {
    echo "bootc-luks-firstboot: $*" >&2
}

die() {
    log "FATAL: $*"
    exit 1
}

parse_cmdline() {
    local arg
    local -a cmdline_args
    read -r -a cmdline_args < /proc/cmdline

    for arg in "${cmdline_args[@]}"; do
        case "$arg" in
            rd.bootc.luks.encrypt=*)
                ENCRYPT_KARG="${arg#rd.bootc.luks.encrypt=}"
                ;;
            root=UUID=*)
                local uuid="${arg#root=UUID=}"
                ROOT_DEV=$(blkid -U "$uuid" 2>/dev/null) || true
                ;;
            root=/dev/*)
                ROOT_DEV="${arg#root=}"
                ;;
        esac
    done
}


encrypt_root() {
    log "Encrypting root device $ROOT_DEV (method: $ENCRYPT_KARG)"

    # Generate a temporary passphrase for initial encryption. This will be
    # replaced by TPM2 enrollment below.
    local tmp_passphrase
    tmp_passphrase=$(cat /proc/sys/kernel/random/uuid)

    # Encrypt in-place. The filesystem was created 32MB smaller than the
    # partition by bootc, so cryptsetup uses the trailing space for the
    # LUKS2 header. The device is auto-opened as /dev/mapper/$LUKS_NAME.
    log "Running cryptsetup reencrypt --encrypt --reduce-device-size 32M ..."
    echo -n "$tmp_passphrase" | cryptsetup reencrypt \
        --encrypt \
        --reduce-device-size 32M \
        --batch-mode \
        "$ROOT_DEV" "$LUKS_NAME" \
        --key-file=-

    log "Encryption complete. Device: /dev/mapper/$LUKS_NAME"

    # Enroll TPM2. --wipe-slot=all removes the temporary passphrase and
    # binds unlock to the local TPM2 device with default PCR policy.
    if [ "$ENCRYPT_KARG" = "tpm2" ]; then
        log "Enrolling TPM2..."
        echo -n "$tmp_passphrase" | systemd-cryptenroll \
            --unlock-key-file=/dev/stdin \
            --tpm2-device=auto \
            --wipe-slot=all \
            "$ROOT_DEV"
        log "TPM2 enrolled, temporary passphrase removed"

        # Add a recovery key. systemd-cryptenroll --recovery-key generates
        # a high-entropy key and prints it to stdout. We capture and display
        # it on the console for the user to record.
        log "Generating recovery key..."
        local recovery_output
        recovery_output=$(systemd-cryptenroll \
            --tpm2-device=auto \
            --recovery-key \
            "$ROOT_DEV" 2>&1) || {
            log "WARNING: Could not add recovery key: $recovery_output"
        }
        # Print the recovery key prominently so the user can record it
        echo ""
        echo "========================================================"
        echo "  LUKS RECOVERY KEY -- RECORD THIS NOW"
        echo "  $recovery_output"
        echo "========================================================"
        echo ""
    fi
}

configure_system() {
    local luks_uuid
    luks_uuid=$(cryptsetup luksDump "$ROOT_DEV" | awk '/^UUID:/{print $2; exit}')
    log "LUKS UUID: $luks_uuid"

    # Mount the encrypted root to update its configuration
    local mnt="/run/bootc-luks-mnt"
    mkdir -p "$mnt"
    mount /dev/mapper/"$LUKS_NAME" "$mnt"

    # Write crypttab inside the ostree deploy directory
    local deploy_etc
    deploy_etc=$(find "$mnt/ostree/deploy" -maxdepth 4 -name "etc" -type d | head -1)
    if [ -n "$deploy_etc" ]; then
        echo "$LUKS_NAME UUID=$luks_uuid - tpm2-device=auto" > "$deploy_etc/crypttab"
        log "Written crypttab: $deploy_etc/crypttab"
    else
        log "WARNING: Could not find ostree deploy etc directory"
    fi

    # Update BLS entries. These may be on /boot (separate partition, already
    # mounted by the initrd) or inside the encrypted root at /boot/loader/.
    # Check both locations.
    local updated=0
    local entry
    for entry in /boot/loader/entries/*.conf "$mnt"/boot/loader/entries/*.conf; do
        [ -f "$entry" ] || continue
        if grep -q "rd.bootc.luks.encrypt" "$entry"; then
            # Remove the first-boot trigger karg
            sed -i 's/ rd.bootc.luks.encrypt=[^ ]*//' "$entry"
            # Add LUKS unlock kargs. The root=UUID= karg stays unchanged --
            # once systemd-cryptsetup unlocks LUKS via rd.luks.uuid, the
            # ext4 UUID inside becomes visible and root= resolves normally.
            sed -i "s|^options |options rd.luks.uuid=$luks_uuid rd.luks.name=$luks_uuid=$LUKS_NAME rd.luks.options=$luks_uuid=tpm2-device=auto,headless=true |" "$entry"
            updated=$((updated + 1))
            log "Updated BLS entry: $entry"
        fi
    done

    if [ "$updated" -eq 0 ]; then
        log "WARNING: No BLS entries found to update"
    fi

    umount "$mnt"
}

# Main
parse_cmdline

if [ -z "$ENCRYPT_KARG" ]; then
    log "No encryption requested. Exiting."
    exit 0
fi

if [ -z "$ROOT_DEV" ]; then
    die "rd.bootc.luks.encrypt set but no root= device found"
fi

if ! cryptsetup isLuks "$ROOT_DEV" 2>/dev/null; then
    encrypt_root
else
    log "Root device $ROOT_DEV is already LUKS. Skipping encryption."
fi

# Always run configure_system when the karg is present. This handles
# the case where a previous boot encrypted the device but was
# interrupted before BLS entries were updated.
configure_system

log "First-boot encryption complete."
