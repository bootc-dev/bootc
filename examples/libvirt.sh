#!/bin/bash

set -euo pipefail
# set -x

main() {
    local -r name="fedora-bootc-ignition"
    local -r config="config.ign"
    local -r image="test.img"

    IGNITION_CONFIG="$(realpath "${config}")"
    IMAGE="$(realpath "${image}")"

    # Default to the stable stream as this is only used for os-variant
    local -r STREAM="stable"

    VCPUS="2"
    RAM_MB="4096"
    DISK_GB="20"

    IGNITION_DEVICE_ARG=(--qemu-commandline="-fw_cfg name=opt/com.coreos/config,file=${IGNITION_CONFIG}")

    chcon --verbose --type svirt_home_t "${IGNITION_CONFIG}"

    virsh --connect="qemu:///system" \
        destroy "${name}" || true
    virsh --connect="qemu:///system" \
        undefine "${name}" --nvram --managed-save || true

    virt-install --connect="qemu:///system" \
        --name="${name}" \
        --vcpus="${VCPUS}" \
        --memory="${RAM_MB}" \
        --os-variant="fedora-coreos-${STREAM}" \
        --import \
        --disk="size=${DISK_GB},backing_store=${IMAGE}" \
        --network bridge=virbr0 \
        "${IGNITION_DEVICE_ARG[@]}" \
        --machine q35 \
        --boot uefi,firmware.feature0.name=secure-boot,firmware.feature0.enabled=no
}

main "${@}"
