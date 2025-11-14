# Verify that soft reboot is blocked when SELinux policies differ
use std assert
use tap.nu

let soft_reboot_capable = "/usr/lib/systemd/system/soft-reboot.target" | path exists
if not $soft_reboot_capable {
    echo "Skipping, system is not soft reboot capable"
    return
}

# Check if SELinux is enabled
let selinux_enabled = "/sys/fs/selinux/enforce" | path exists
if not $selinux_enabled {
    echo "Skipping, SELinux is not enabled"
    return
}

# This code runs on *each* boot.
bootc status

# Run on the first boot
def initial_build [] {
    tap begin "Build base image and test soft reboot with SELinux policy change"

    let td = mktemp -d
    cd $td

    bootc image copy-to-storage

    # Create a derived container that installs a custom SELinux policy module
    # Installing a policy module will change the compiled policy checksum
    # Following Colin's suggestion and the composefs-rs example
    # We create a minimal policy module and install it
    "FROM localhost/bootc
# Install tools needed to build and install SELinux policy modules
RUN dnf install -y selinux-policy-devel checkpolicy policycoreutils

# Create a minimal SELinux policy module that will change the policy checksum
# We install it to ensure it's part of the deployment filesystem
RUN <<EORUN
    set -eux
    mkdir -p /tmp/bootc-test-policy
    cd /tmp/bootc-test-policy
    echo 'module bootc_test_policy 1.0;' > bootc_test_policy.te
    echo 'require {' >> bootc_test_policy.te
    echo '    type unconfined_t;' >> bootc_test_policy.te
    echo '    class file { read write };' >> bootc_test_policy.te
    echo '}' >> bootc_test_policy.te
    echo 'type bootc_test_t;' >> bootc_test_policy.te
    checkmodule -M -m -o bootc_test_policy.mod bootc_test_policy.te
    semodule_package -o bootc_test_policy.pp -m bootc_test_policy.mod
    semodule -i bootc_test_policy.pp
    rm -rf /tmp/bootc-test-policy
    # Clean up dnf cache and logs, and SELinux policy generation artifacts to satisfy lint checks
    dnf clean all
    rm -rf /var/log/dnf* /var/log/hawkey.log /var/log/rhsm
    rm -rf /var/cache/dnf /var/lib/dnf
    rm -rf /var/lib/sepolgen /var/lib/rhsm /var/cache/ldconfig
EORUN
" | save Dockerfile
    
    # Build the derived image
    podman build --quiet -t localhost/bootc-derived-policy .
    
    # Verify soft reboot preparation hasn't happened yet
    assert (not ("/run/nextroot" | path exists))
    
    # Try to soft reboot - this should fail because policies differ
    bootc switch --soft-reboot=auto --transport containers-storage localhost/bootc-derived-policy
    let st = bootc status --json | from json
    
    # Verify staged deployment exists
    assert ($st.status.staged != null) "Expected staged deployment to exist"
    
    # The staged deployment should NOT be soft-reboot capable because policies differ
    assert (not $st.status.staged.softRebootCapable) "Expected soft reboot to be blocked due to SELinux policy difference, but softRebootCapable is true"
    
    # Verify soft reboot preparation didn't happen
    assert (not ("/run/nextroot" | path exists)) "Soft reboot should not be prepared when policies differ"
    
    # Do a full reboot
    tmt-reboot
}

# The second boot; verify we're in the derived image
def second_boot [] {
    tap begin "Verify deployment with different SELinux policy"
    
    # Verify we're in the new deployment
    let st = bootc status --json | from json
    let booted = $st.status.booted.image
    assert ($booted.image.image | str contains "bootc-derived-policy") $"Expected booted image to contain 'bootc-derived-policy', got: ($booted.image.image)"
    
    tap ok
}

def main [] {
    # See https://tmt.readthedocs.io/en/stable/stories/features.html#reboot-during-test
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => initial_build,
        "1" => second_boot,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
