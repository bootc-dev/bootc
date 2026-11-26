# number: 68
# tmt:
#   summary: Make sure SeLinux policy is updated on switch/update
#   duration: 15m
#   adjust:
#     - when: running_env != image_mode
#       enabled: false
#       because: these tests require features only available in image mode

use std assert
use tap.nu

def selinux_boolean_exists [name: string] {
    $"/sys/fs/selinux/booleans/($name)" | path exists
}

bootc status

def first_boot [] {
    # Install a local module
    echo '(boolean cfs_local_change false)' | save /tmp/cfs_local_change.cil
    sudo semodule -i /tmp/cfs_local_change.cil

    assert (selinux_boolean_exists "cfs_local_change")

    # A derived image whose policy differs from the booted one
    bootc image copy-to-storage

    (
      tap make_uki_containerfile "
      FROM localhost/bootc as base

      RUN echo '(boolean cfs_incoming_change false)' > /var/cfs_incoming_change.cil
      RUN semodule -i /var/cfs_incoming_change.cil

      RUN rm -rf /var/cfs_incoming_change.cil
      "
    ) | save Dockerfile

    podman build -t localhost/bootc-selinux .

    bootc switch --transport containers-storage localhost/bootc-selinux

    tmt-reboot
}

def second_boot [] {
    let st = bootc status --json | from json
    assert ($st.status.booted.image.image.image | str contains "bootc-selinux")

    let modules = semodule -l | lines
    assert ("cfs_local_change" in $modules) "local module missing from the module store"
    assert ("cfs_incoming_change" in $modules) "image module missing from the module store"

    assert (selinux_boolean_exists "cfs_local_change") "local module missing from the loaded policy"
    assert (selinux_boolean_exists "cfs_incoming_change") "new image's policy was not loaded"

    tap ok
}

def main [] {
    if not ("/sys/fs/selinux/enforce" | path exists) {
        print "SeLinux is not enabled. Skipping"
        tap ok
        exit 0
    }

    match $env.TMT_REBOOT_COUNT? {
        null | "0" => first_boot,
        "1" => second_boot,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
