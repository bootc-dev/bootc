#!/bin/bash

set -euo pipefail
# set -x

main() {
    local image="test.img"
    if [[ "${#}" -eq 1 ]]; then
        image="${1}"
    fi

    local -r name="fedora-bootc-ignition"
    local -r config="config.ign"

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

    cp "$PWD/bootc-bls/OVMF_VARS_CUSTOM.qcow2" .

    OVMF_CODE="/usr/share/edk2/ovmf/OVMF_CODE_4M.secboot.qcow2"
    OVMF_VARS_TEMPLATE="/usr/share/edk2/ovmf/OVMF_VARS_4M.secboot.qcow2"
    OVMF_VARS="$PWD/OVMF_VARS_CUSTOM.qcow2"

    local args=()
    secureboot=true
    if [[ "${secureboot}" == "true" ]]; then
        loader="loader=${OVMF_CODE},loader.readonly=yes,loader.type=pflash"
        nvram="nvram=${OVMF_VARS},nvram.template=${OVMF_VARS_TEMPLATE},loader_secure=yes"
        features="firmware.feature0.name=secure-boot,firmware.feature0.enabled=yes,firmware.feature1.name=enrolled-keys,firmware.feature1.enabled=yes"
        args+=("--boot")
        args+=("uefi,${loader},${nvram},${features}")
        args+=("--tpm")
        args+=("backend.type=emulator,backend.version=2.0,model=tpm-tis")
    else
        args+=("--boot")
        args+=("uefi,firmware.feature0.name=secure-boot,firmware.feature0.enabled=no")
    fi

    connect_to_console="true"
    if [[ "${connect_to_console}" == "true" ]]; then
        args+=('--autoconsole')
        args+=('text')
    else
        args+=('--noautoconsole')
    fi

    set -x
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
        "${args[@]}"
}

main "${@}"
