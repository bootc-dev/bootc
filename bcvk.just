# bcvk development VM management
#
# The dev binary is overlaid onto /usr via systemd-sysext. After
# rebuilding with `just sysext`, run `just bcvk sync` to
# refresh the overlay (~30s total cycle).
#
# Usage:
#   just bcvk up            # Build sysext + launch persistent VM
#   just bcvk sync          # Rebuild sysext + refresh overlay (~30s)
#   just bcvk ssh           # SSH into the VM
#   just bcvk ephemeral     # Ephemeral VM (full image, destroyed on exit)

base_img := env("BOOTC_base_img", "localhost/bootc")

# List available recipes
[private]
default:
    @just --list bcvk

# Run an ephemeral VM from the latest build and SSH in (destroyed on exit)
[group('ephemeral')]
ephemeral:
    just build
    bcvk ephemeral run-ssh {{base_img}}

# Launch persistent development VM with sysext
[group('vm')]
up:
    just sysext
    cargo xtask bcvk vm

# Rebuild sysext and verify the new binary in the running VM
[group('vm')]
sync:
    just sysext
    cargo xtask bcvk sync

# SSH into development VM (interactive shell if no args given)
[group('vm')]
ssh *ARGS:
    cargo xtask bcvk ssh {{ARGS}}

# Stop and remove development VM
[group('vm')]
down:
    cargo xtask bcvk down

# Show development VM status
[group('vm')]
status:
    cargo xtask bcvk status

# Watch development VM logs
[group('vm')]
logs:
    cargo xtask bcvk logs

# Show sysext status in development VM
[group('vm')]
sysext-status:
    cargo xtask bcvk ssh systemd-sysext status

# Restart development VM
[group('vm')]
restart:
    #!/bin/bash
    set -euo pipefail
    echo "Restarting development VM..."
    cargo xtask bcvk ssh -- sudo systemctl reboot || true
    sleep 5
    echo "Waiting for VM to come back up..."
    for i in {1..30}; do
        if cargo xtask bcvk ssh -- echo "VM is up" 2>/dev/null; then
            echo "VM is back online!"
            break
        fi
        echo "Waiting... (attempt $i/30)"
        sleep 2
    done

# Clean up all development resources (VM + sysext)
[group('vm')]
clean:
    cargo xtask bcvk clean
