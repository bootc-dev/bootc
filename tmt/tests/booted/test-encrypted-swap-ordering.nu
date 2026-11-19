# number: 66
# tmt:
#   summary: Verify a random-key encrypted swap boots without an ordering cycle
#   duration: 30m
#
# Regression test for https://github.com/bootc-dev/bootc/issues/2624.
# A crypttab entry keyed from /dev/urandom orders its systemd-cryptsetup@
# unit after systemd-random-seed.service, and tmp.mount is
# After=swap.target, so local-fs.target ends up after random-seed.
# Anything bootc orders before random-seed must therefore not wait for
# local-fs.target itself: bootc 1.17 ordered systemd-tmpfiles-setup.service
# (After=local-fs.target) before it on native composefs boots, and systemd
# broke the resulting cycle by dropping a job, which could leave /tmp
# mounted over what tmpfiles had just created.
#
# Boot 0 sets up such a swap on a file in /var and reboots; boot 1 checks
# that there was no ordering cycle and that the swap and /tmp came up in
# order.
use std assert
use tap.nu
use bootc_testlib.nu

const SWAP_NAME = "bootc-test-swap"
const SWAP_FILE = "/var/bootc-test-swap.img"

def initial_setup [] {
    tap begin "random-key encrypted swap ordering"

    ^fallocate -l 64M $SWAP_FILE
    $"($SWAP_NAME) ($SWAP_FILE) /dev/urandom swap,cipher=aes-xts-plain64,size=256\n" | save --append /etc/crypttab
    $"/dev/mapper/($SWAP_NAME) none swap defaults 0 0\n" | save --append /etc/fstab
    # tmp.mount (After=swap.target) closes the loop; most images enable it
    # already, but make sure.
    systemctl enable tmp.mount

    bootc_testlib reboot
}

# A monotonic timestamp property of a unit, in microseconds
def timestamp [unit: string, prop: string] {
    ^systemctl show -P $prop $unit | str trim | into int
}

def second_boot [] {
    let cycles = (^journalctl -b 0 -o cat --no-pager
        | lines
        | where { |l| $l | str contains "ordering cycle" })
    assert equal ($cycles | length) 0 $"Ordering cycles at boot:\n($cycles | str join "\n")"

    let swap_unit = (^systemd-escape --path --suffix=swap $"/dev/mapper/($SWAP_NAME)" | str trim)
    let cryptsetup_unit = (^systemd-escape --template=systemd-cryptsetup@.service $SWAP_NAME | str trim)
    mut units = [$cryptsetup_unit $swap_unit "tmp.mount" "systemd-random-seed.service" "systemd-tmpfiles-setup.service"]
    if (tap is_composefs) {
        $units = ($units | append "bootc-early-tmpfiles.service")
    }
    for unit in $units {
        let state = (^systemctl show -P ActiveState $unit | str trim)
        assert equal $state "active" $"($unit) is ($state)"
    }

    # The symptom from the issue: tmpfiles must only start once /tmp is mounted
    let tmp_mounted = (timestamp tmp.mount ActiveEnterTimestampMonotonic)
    let tmpfiles_started = (timestamp systemd-tmpfiles-setup.service InactiveExitTimestampMonotonic)
    assert ($tmp_mounted <= $tmpfiles_started) $"systemd-tmpfiles-setup started at ($tmpfiles_started), before tmp.mount at ($tmp_mounted)"

    tap ok
}

def main [] {
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => initial_setup,
        "1" => second_boot,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
