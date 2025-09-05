#!/bin/bash
set -exuo pipefail

# This script runs disk image with qemu-system and run tmt against this vm.

BOOTC_TEMPDIR="/tmp/tmp-bootc-build"
SSH_OPTIONS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5)
SSH_KEY=${BOOTC_TEMPDIR}/id_rsa

ARCH=$(uname -m)
case "$ARCH" in
"aarch64")
  qemu-system-aarch64 \
    -name bootc-vm \
    -enable-kvm \
    -machine virt \
    -cpu host \
    -m 2G \
    -bios /usr/share/AAVMF/AAVMF_CODE.fd \
    -drive file="${BOOTC_TEMPDIR}/disk.raw",if=virtio,format=raw \
    -net nic,model=virtio \
    -net user,hostfwd=tcp::2222-:22 \
    -display none \
    -daemonize
  ;;
"x86_64")
  qemu-system-x86_64 \
    -name bootc-vm \
    -enable-kvm \
    -cpu host \
    -m 2G \
    -drive file="${BOOTC_TEMPDIR}/disk.raw",if=virtio,format=raw \
    -net nic,model=virtio \
    -net user,hostfwd=tcp::2222-:22 \
    -display none \
    -daemonize
  ;;
*)
  echo "Only support x86_64 and aarch64" >&2
  exit 1
  ;;
esac

wait_for_ssh_up() {
  SSH_STATUS=$(ssh "${SSH_OPTIONS[@]}" -i "$SSH_KEY" -p 2222 root@"${1}" '/bin/bash -c "echo -n READY"')
  if [[ $SSH_STATUS == READY ]]; then
    echo 1
  else
    echo 0
  fi
}

for _ in $(seq 0 30); do
  RESULT=$(wait_for_ssh_up "localhost")
  if [[ $RESULT == 1 ]]; then
    echo "SSH is ready now! 🥳"
    break
  fi
  sleep 10
done

# Make sure VM is ready for testing
ssh "${SSH_OPTIONS[@]}" \
  -i "$SSH_KEY" \
  -p 2222 \
  root@localhost \
  "bootc status"

# TMT will rsync tmt-* scripts to TMT_SCRIPTS_DIR=/var/lib/tmt/scripts
tmt run --all --verbose -e TMT_SCRIPTS_DIR=/var/lib/tmt/scripts provision --how connect --guest localhost --port 2222 --user root --key "$SSH_KEY" plan --name "/tmt/plans/bootc-integration/${TMT_PLAN_NAME}"
