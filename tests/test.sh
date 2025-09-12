#!/bin/bash
set -exuo pipefail

# You must have invoked test/build.sh before running this.

# Put ourself in a user+mount+pid namespace to close leaks
if test -z "${test_unshared:-}"; then
  exec unshare -m -- env test_unshared=1 "$0" "$@"
fi

TMT_PLAN_NAME=$1
shift

SSH_OPTIONS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5)
SSH_KEY=$(pwd)/target/id_rsa
test -f $SSH_KEY

# TODO replace with tmt's virt provisioner
ARCH=$(uname -m)
qemu_args=()
case "$ARCH" in
"aarch64")
  qemu_args+=(qemu-system-aarch64
    -machine virt
    -bios /usr/share/AAVMF/AAVMF_CODE.fd)
  ;;
"x86_64")
  qemu_args+=(qemu-system-x86_64)
  ;;
*)
  echo "Only support x86_64 and aarch64" >&2
  exit 1
  ;;
esac
qemu_args+=(
    -name bootc-vm \
    -enable-kvm \
    -cpu host \
    -m 2G \
    -drive file="target/disk.raw",if=virtio,format=raw 
    -net nic,model=virtio
    -net user,hostfwd=tcp::2222-:22
    -display none
)

# Kill qemu when the test exits by default
setpriv --pdeathsig SIGTERM -- ${qemu_args[@]} &>/dev/null &

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

# First a tremendous hackaround for tmt blindly rsync'ing all of .
# including the target/ directory
rm target/stub -rf
mkdir -p target/stub
ls -al $SSH_KEY
touch -m 0600 target/stub/$(basename $SSH_KEY)
mount --bind $SSH_KEY target/stub/$(basename $SSH_KEY)
mount --rbind target/stub target
ls -al "$SSH_KEY"

# TMT will rsync tmt-* scripts to TMT_SCRIPTS_DIR=/var/lib/tmt/scripts
tmt run --all --verbose -e TMT_SCRIPTS_DIR=/var/lib/tmt/scripts provision --how connect --guest localhost --port 2222 --user root --key "$SSH_KEY" plan --name "/tmt/plans/bootc-integration/${TMT_PLAN_NAME}"
