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

    # Create a derived container that injects a local SELinux policy module
    # This modifies the policy in a way that changes the policy checksum
    # Following Colin's suggestion: inject a local selinux policy module
    "FROM localhost/bootc
# Inject a local SELinux policy change by modifying file_contexts
# This will change the policy checksum between deployments
RUN mkdir -p /opt/bootc-test-selinux-policy && \
    echo '/opt/bootc-test-selinux-policy /opt/bootc-test-selinux-policy' >> /etc/selinux/targeted/contexts/files/file_contexts.subs_dist || true
" | save Dockerfile
    
    # Build the derived image
    podman build -t localhost/bootc-derived-policy .
    
    # Try to soft reboot - this should fail because policies differ
    bootc switch --soft-reboot=auto --transport containers-storage localhost/bootc-derived-policy
    let st = bootc status --json | from json
    
    # The staged deployment should NOT be soft-reboot capable because policies differ
    assert (not $st.status.staged.softRebootCapable) "Expected soft reboot to be blocked due to SELinux policy difference"
    
    print "Soft reboot correctly blocked when SELinux policies differ"
    
    # Reset and do a full reboot instead
    ostree admin prepare-soft-reboot --reset
    tmt-reboot
}

# The second boot; verify we're in the derived image
def second_boot [] {
    tap begin "Verify deployment and test soft reboot with same policy"
    
    # Verify we're in the new deployment
    let st = bootc status --json | from json
    assert ($st.status.booted.image.name | str contains "bootc-derived-policy")
    
    # Now create another derived image with the SAME policy (no changes)
    let td = mktemp -d
    cd $td
    
    bootc image copy-to-storage
    
    # Create a derived container that doesn't change the policy
    "FROM localhost/bootc-derived-policy
RUN echo 'same policy test' > /usr/share/testfile-same-policy.txt
" | save Dockerfile
    
    podman build -t localhost/bootc-same-policy .
    
    # Try to soft reboot - this should succeed because policies match
    bootc switch --soft-reboot=auto --transport containers-storage localhost/bootc-same-policy
    let st = bootc status --json | from json
    
    # The staged deployment SHOULD be soft-reboot capable because policies match
    assert $st.status.staged.softRebootCapable "Expected soft reboot to be allowed when SELinux policies match"
    
    print "Soft reboot correctly allowed when SELinux policies match"
    
    # See ../bug-soft-reboot.md - TMT cannot handle systemd soft-reboots
    ostree admin prepare-soft-reboot --reset
    tmt-reboot
}

# The third boot; verify we're in the same-policy deployment
def third_boot [] {
    tap begin "Verify same-policy deployment"
    
    assert ("/usr/share/testfile-same-policy.txt" | path exists)
    
    let st = bootc status --json | from json
    assert ($st.status.booted.image.name | str contains "bootc-same-policy")
    
    print "Successfully verified soft reboot with SELinux policy checks"
    
    tap ok
}

def main [] {
    # See https://tmt.readthedocs.io/en/stable/stories/features.html#reboot-during-test
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => initial_build,
        "1" => second_boot,
        "2" => third_boot,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}

