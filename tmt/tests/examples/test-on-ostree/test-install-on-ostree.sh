# number: 50
# extra:
#   try_bind_storage: true
# tmt:
#   summary: Test bootc install on ostree OS
#   duration: 30m
#   adjust:
#     - when: VARIANT_ID != coreos
#       enabled: false
#       because: this needs to start an ostree OS firstly
#
#!/bin/bash
set -eux

echo "Testing bootc install on ostree"

# BOOTC_target is integration image
[ -n "$BOOTC_target" ]

if [ "$TMT_REBOOT_COUNT" -eq 0 ]; then
    echo "Running before first reboot"
    pwd
    ls -l
    # Verify testing on ostree OS
    if [ ! -f "/run/ostree-booted" ]; then
        echo "Should be ostree OS"
        exit 1
    fi
    podman image exists ${BOOTC_target}
    # Run bootc install using the same stateroot for shared /var
    stateroot=$(bootc status --json | jq -r .status.booted.ostree.stateroot)

    # Need bind mount for /run/host-container-storage
    podman run --rm --privileged \
        -v /dev:/dev \
        -v /run/host-container-storage:/run/host-container-storage \
        -v /:/target \
        --pid=host \
        --security-opt label=type:unconfined_t \
        ${BOOTC_target} \
            env BOOTC_BOOTLOADER_DEBUG=1 STORAGE_OPTS=additionalimagestore=/run/host-container-storage \
            bootc install to-existing-root \
            --stateroot=${stateroot} \
            --skip-fetch-check \
            --acknowledge-destructive \
            --karg=console=ttyS0,115200n8

    bootc status
    tmt-reboot
elif [ "$TMT_REBOOT_COUNT" -eq 1 ]; then
    echo 'After the reboot'
    booted=$(bootc status --json | jq -r .status.booted.image.image.image)
    [ ${booted} == ${BOOTC_target} ]
fi

echo "Run bootc install on ostree OS successfully"
