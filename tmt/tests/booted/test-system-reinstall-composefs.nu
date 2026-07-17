# number: 47
# tmt:
#   summary: Test system-reinstall with composefs backend and bootloader compatibility
#   duration: 60m
#
# Tests that system-reinstall-bootc works with composefs backend by running
# `bootc install to-existing-root --composefs-backend` on the live root,
# matching the invocation pattern of system-reinstall-bootc.
#
# Three scenarios across three reboot cycles:
#
# Reboot 0:
#   Same bootloader: image supports the host's bootloader
#   → that bootloader should be installed
#
# Reboot 1:
#   Verify same-bootloader result, then:
#   Bootloader mismatch: image lacks support for the host's bootloader
#   → fallback bootloader should be installed
#   (skipped for UKI boot type where switching bootloaders is unsafe)
#
# Reboot 2:
#   Verify mismatch fallback result
#
use std assert
use tap.nu

if not (tap is_composefs) {
    exit 0
}

let st = bootc status --json | from json

# Run bootc install to-existing-root --composefs-backend via podman,
# matching the system-reinstall-bootc invocation from podman.rs.
# Key details tested by these flags:
#   /:/target:rslave  — propagates boot automount (commit 3bf1acba)
#   --composefs-backend — exercises composefs repo init fix (commit fa18de18)
#   efivars read      — bootloader detection (commits fa18de18, 4cb1e63b)
def run_reinstall [image: string] {
    (podman run
        --rm
        --privileged
        --pid=host
        --user=root:root
        -v /var/lib/containers:/var/lib/containers
        -v /dev:/dev
        --security-opt label=type:unconfined_t
        -v /:/target:rslave
        $image
        bootc install to-existing-root
            --acknowledge-destructive
            --skip-fetch-check
            --composefs-backend
            --disable-selinux)
}

def first_boot [] {
    tap begin "system-reinstall composefs + bootloader compatibility"

    let bootloader = ($st.status.booted.composefs.bootloader | str downcase)
    let boot_type = ($st.status.booted.composefs.bootType | str downcase)

    # Persist host state for verification across reboots
    $bootloader | save /var/host-bootloader
    $boot_type | save /var/host-boot-type

    print $"Host bootloader: ($bootloader), boot type: ($boot_type)"

    bootc image copy-to-storage

    # Build derived image preserving the same bootloader support as the host.
    # make_uki_containerfile appends UKI sealing stages when running on UKI.
    let containerfile = (tap make_uki_containerfile "
        FROM localhost/bootc as base
        RUN rm -rf /usr/lib/bootc/bound-images.d
        RUN touch /usr/share/testing-reinstall-same-bl
    ")

    let td = mktemp -d
    cd $td
    $containerfile | save Dockerfile
    podman build -t localhost/bootc-reinstall-same .

    print "Running to-existing-root --composefs-backend (same bootloader)"
    run_reinstall localhost/bootc-reinstall-same

    tmt-reboot
}

def second_boot [] {
    print "Verifying reinstall with same bootloader"

    assert (tap is_composefs) "composefs should be active after reinstall"
    assert ("/usr/share/testing-reinstall-same-bl" | path exists) "same-bootloader marker should exist"

    let orig_bootloader = (open /var/host-bootloader | str trim)
    let current_bootloader = ($st.status.booted.composefs.bootloader | str downcase)

    print $"Original bootloader: ($orig_bootloader), Current: ($current_bootloader)"
    assert equal $current_bootloader $orig_bootloader "bootloader should match host after same-bootloader reinstall"

    # Build image that lacks the host's bootloader, forcing a fallback:
    #   host=systemd-boot -> remove bootctl -> falls back to grub
    #   host=grub/grub-cc -> remove bootupd -> falls back to systemd-boot
    bootc image copy-to-storage

    let containerfile = if $orig_bootloader == "systemd" {
        print "Building image without systemd-boot support (removing bootctl)"
        "
            FROM localhost/bootc as base
            RUN rpm -e systemd-boot-unsigned
            RUN rm -f /usr/bin/bootctl
            RUN rm -rf /usr/lib/bootc/bound-images.d
            RUN dnf install -y bootupd
            RUN touch /usr/share/testing-reinstall-mismatch
        "
    } else {
        print "Building image without grub/bootupd support"
        "
            FROM localhost/bootc as base
            RUN rpm -e bootupd
            RUN rm -rf /usr/lib/bootc/bound-images.d
            RUN dnf install -y systemd-boot-unsigned
            RUN touch /usr/share/testing-reinstall-mismatch
        "
    }

    let td = mktemp -d
    cd $td
    $containerfile | save Dockerfile
    podman build -t localhost/bootc-reinstall-mismatch .

    print "Running to-existing-root --composefs-backend (mismatched bootloader)"
    run_reinstall localhost/bootc-reinstall-mismatch

    tmt-reboot
}

def third_boot [] {
    print "Verifying reinstall with mismatched bootloader"

    assert (tap is_composefs) "composefs should be active after mismatch reinstall"
    assert ("/usr/share/testing-reinstall-mismatch" | path exists) "mismatch marker should exist"

    let orig_bootloader = (open /var/host-bootloader | str trim)
    let current_bootloader = ($st.status.booted.composefs.bootloader | str downcase)

    print $"Original host bootloader: ($orig_bootloader), Installed: ($current_bootloader)"

    if $orig_bootloader == "systemd" {
        assert equal $current_bootloader "grub" "should fall back to grub when image lacks systemd-boot"
    } else {
        assert equal $current_bootloader "systemd" "should fall back to systemd-boot when image lacks grub"
    }

    tap ok
}

def main [] {
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => first_boot,
        "1" => second_boot,
        "2" => third_boot,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
