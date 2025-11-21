# number: 26
# tmt:
#   summary: Test bootc examples build scripts
#   duration: 45m
#   adjust:
#     - when: running_env != image_mode
#       enabled: false
#       because: packit tests use RPM bootc and does not install /usr/lib/bootc/initramfs-setup
#
#!/bin/bash
set -eux

# Test bootc-bls example
echo "Testing bootc-bls example..."
cd examples/bootc-bls
./build

# Test bootc-uki example
echo "Testing bootc-uki example..."
cd ../bootc-uki
./build.base
./build.final

echo "All example builds completed successfully"
